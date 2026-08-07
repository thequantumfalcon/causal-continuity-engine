"""Execution verification (EV-001, EV-002, EV-006).

A verifier deterministically checks a property of an artifact/action and
returns a normalized VerificationOutcome. Infrastructure failure is NEVER
success: a crashed or timed-out verifier yields 'inconclusive' (EV-006).

**Exit codes are the subject's opinion.** A test suite must import the code
under test, so agent-written code runs inside the runner's own process and
can rewrite the runner's report — six lines in a `conftest.py` turn a red
suite green while the work is undone. No amount of environment hardening
escapes that, because the forgery happens after the sandbox is entered.

CCE answers it three ways, none of which trusts the subject's verdict:

  `value-oracle` kind — the check emits VALUES on stdout as JSON and *this
      runner* compares them against properties the policy declared. The
      subject never renders a verdict, so it has none to forge (ADR-025).
  negative controls   — the check is shown failing on a known-bad state, so
      a check that cannot fail is exposed (ADR-026).
  mutation probes     — see evidence.py: destroy the deliverable, and a
      required check must notice (ADR-027).

The environment is scrubbed with a named threat behind each entry. Every
command runs against a bounded disposable repository snapshot that excludes
CCE trust state, VCS internals, caches, and dependency trees. This prevents a
normal relative-path verifier from reading or rewriting signing material and
the canonical store. It is not an OS sandbox: a process running as the same
user can still address paths it already knows, and kernel network isolation
remains a deployment concern (SEC-008). The runner records the policy it was
asked for so proofs distinguish enforced from advisory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .core import (
    digest_obj,
    sha256_hex,
    strict_json_loads,
    utcnow,
    validate_public_identifier,
)
from .evidence import (
    WORKSPACE_MAX_FILE_BYTES,
    UnsafeWorkspaceError,
    _temporary_workspace_root,
    fingerprint_artifacts,
    materialize_workspace,
    normalize_artifact_paths,
)

VERIFIER_KINDS = {
    "command", "unit-tests", "integration-tests", "lint", "type-check",
    "build", "file-digest", "value-oracle",
}

_MAX_OUTPUT = 256 * 1024
_READ_CHUNK = 64 * 1024
_STDERR_SEPARATOR = b"\n--- stderr ---\n"
_TRUNCATION_MARKER = b"\n--- output truncated by CCE ---\n"

# Programs that hand control to another program named in their arguments.
# Allowing one lets a pinned command become an arbitrary command.
_INDIRECTION = {
    "env", "sh", "bash", "zsh", "dash", "ksh", "csh", "fish", "xargs",
    "timeout", "sudo", "doas", "nohup", "nice", "setsid", "stdbuf", "script",
    "eval", "exec", "command", "cmd", "powershell", "pwsh", "wsl",
}
MAX_VERIFIER_TIMEOUT_SECONDS = 3_600
FILE_DIGEST_MAX_FILES = 10_000
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)

_SAFE_DEFAULT_PATH = os.pathsep.join(
    entry for entry in os.defpath.split(os.pathsep)
    if entry and Path(entry).is_absolute()
)


@dataclass
class VerifierSpec:
    name: str
    kind: str = "command"
    command: str | None = None
    expected_properties: dict = field(default_factory=dict)
    timeout_seconds: int = 300
    required: bool = True
    network: str = "restricted"
    #: A command that MUST fail. Evidence that this check can go red at all.
    expect_fail_command: str | None = None
    #: Deliverables this check is supposed to be about (mutation probe input).
    artifacts: list[str] = field(default_factory=list)
    #: True when the command came from project policy rather than the claimant.
    pinned: bool = False
    #: Keep the working directory off sys.path (PYTHONSAFEPATH). OFF by
    #: default: a test suite must import the code under test, so for the
    #: common case this would break the check rather than harden it. Turn it
    #: on for checks that import nothing from the tree (linters, digest
    #: comparisons, external probes).
    isolate_sys_path: bool = False
    #: Allow `~/.local/lib/.../site-packages` on the path. OFF by default,
    #: because `usercustomize.py` there executes before the check does. Turn
    #: it on only if the verifier tooling is pip --user installed; the better
    #: fix is to pin an absolute interpreter from a virtualenv.
    allow_user_site: bool = False

    def __post_init__(self):
        self.validate()

    def validate(self) -> None:
        """Revalidate mutable public specs at every deciding boundary."""
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("verifier name must be a non-empty string")
        if not isinstance(self.kind, str) or self.kind not in VERIFIER_KINDS:
            raise ValueError(f"unknown verifier kind {self.kind!r}")
        if (self.command is not None
                and (not isinstance(self.command, str)
                     or not self.command.strip())):
            raise ValueError("verifier command must be a non-empty string or null")
        if (self.expect_fail_command is not None
                and (not isinstance(self.expect_fail_command, str)
                     or not self.expect_fail_command.strip())):
            raise ValueError(
                "expect_fail_command must be a non-empty string or null")
        if (isinstance(self.timeout_seconds, bool)
                or not isinstance(self.timeout_seconds, int)
                or not 1 <= self.timeout_seconds <= MAX_VERIFIER_TIMEOUT_SECONDS):
            raise ValueError(
                "verifier timeout_seconds must be an integer from 1 to "
                f"{MAX_VERIFIER_TIMEOUT_SECONDS}")
        for field_name in (
                "required", "pinned", "isolate_sys_path", "allow_user_site"):
            if not isinstance(getattr(self, field_name), bool):
                raise ValueError(f"verifier {field_name} must be a boolean")
        if not isinstance(self.network, str) or not self.network:
            raise ValueError("verifier network posture must be a non-empty string")
        if not isinstance(self.expected_properties, dict):
            raise ValueError("verifier expected_properties must be an object")

        if self.kind == "file-digest":
            if self.command is not None:
                raise ValueError(
                    "file-digest is a built-in adapter and must not declare a command")
            if self.expect_fail_command is not None:
                raise ValueError(
                    "file-digest must not declare a subprocess negative control")
            unknown = sorted(set(self.expected_properties) - {"files"})
            if unknown:
                raise ValueError(
                    f"unknown file-digest expected_properties field(s): {unknown}")
            files = self.expected_properties.get("files", {})
            if not isinstance(files, dict):
                raise ValueError(
                    "file-digest expected_properties.files must be an object")
            if len(files) > FILE_DIGEST_MAX_FILES:
                raise ValueError(
                    "file-digest expected_properties.files exceeds the "
                    f"{FILE_DIGEST_MAX_FILES}-file limit")
            paths = normalize_artifact_paths(list(files))
            normalized_files = {}
            for path in paths:
                expected = files[path]
                if (not isinstance(expected, str)
                        or _SHA256_DIGEST.fullmatch(expected) is None):
                    raise ValueError(
                        f"file-digest expected digest for {path!r} must be "
                        "sha256 followed by 64 lowercase hex digits")
                normalized_files[path] = expected
            declared = normalize_artifact_paths(self.artifacts)
            if declared and set(declared) != set(paths):
                raise ValueError(
                    "file-digest artifacts must exactly match "
                    "expected_properties.files")
            self.expected_properties = {"files": normalized_files}
            self.artifacts = paths
            self.network = "none"
        else:
            if self.kind == "value-oracle":
                unknown = sorted(set(self.expected_properties) - {"values"})
                if unknown:
                    raise ValueError(
                        f"unknown value-oracle expected_properties field(s): "
                        f"{unknown}")
                values = self.expected_properties.get("values", {})
                if not isinstance(values, dict):
                    raise ValueError(
                        "value-oracle expected_properties.values must be an object")
            elif self.expected_properties:
                raise ValueError(
                    f"{self.kind} verifiers do not accept expected_properties; "
                    "use value-oracle or file-digest for built-in comparison")
            self.artifacts = normalize_artifact_paths(self.artifacts)
        try:
            digest_obj(self.expected_properties)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"verifier expected_properties must be finite canonical JSON: "
                f"{exc}") from None

    @property
    def command_digest(self) -> str | None:
        self.validate()
        return sha256_hex(self.command) if self.command is not None else None

    @property
    def normalized_definition(self) -> dict:
        """Canonical, complete semantics of the verifier that will run.

        A command is only one operand of a check.  Its kind, oracle
        expectations, control, artifact surface, timeout and execution
        isolation all affect what a pass means.  Defaults are materialised so
        omitted and explicitly-defaulted policy fields have one identity;
        artifact order is normalised because the runner treats it as a set.
        """
        self.validate()
        return {
            "schema": "cce.verifier-definition.v1",
            "name": self.name,
            "kind": self.kind,
            "command": self.command,
            "expected_properties": self.expected_properties,
            "timeout_seconds": self.timeout_seconds,
            "required": self.required,
            "network": self.network,
            "expect_fail_command": self.expect_fail_command,
            "artifacts": sorted(set(self.artifacts)),
            "pinned": self.pinned,
            "isolate_sys_path": self.isolate_sys_path,
            "allow_user_site": self.allow_user_site,
        }

    @property
    def definition_digest(self) -> str:
        """Content identity of all normalized verifier semantics."""
        return digest_obj(self.normalized_definition)

    @classmethod
    def from_policy(cls, definition: dict) -> "VerifierSpec":
        """Build a spec from a policy required-verifiers declaration."""
        spec = cls(
            name=definition["name"],
            kind=definition.get("kind", "command"),
            command=definition.get("command"),
            expected_properties=definition.get("expected_properties", {}),
            timeout_seconds=definition.get("timeout_seconds", 300),
            required=True,
            expect_fail_command=definition.get("expect_fail_command"),
            artifacts=definition.get("artifacts", []),
            pinned=False,
        )
        spec.pinned = (
            bool(spec.expected_properties["files"])
            if spec.kind == "file-digest"
            else spec.command is not None
        )
        spec.validate()
        return spec


@dataclass
class VerificationOutcome:
    verifier: str
    kind: str
    result: str                      # passed | failed | skipped | missing | inconclusive
    started_at: str
    duration_seconds: float
    exit_code: int | None = None
    output_digest: str | None = None
    evidence_digest: str | None = None
    coverage: dict | None = None
    details: str = ""
    network: str = "restricted"

    #: Provenance: CCE ran this itself, so it can satisfy a required verifier.
    source: str = "executed"
    #: True when the command came from policy, not from the claimant.
    pinned: bool = False
    #: Digest of the exact command line that ran.
    command_digest: str | None = None
    #: Digest of the complete normalized verifier definition that ran.
    definition_digest: str | None = None
    #: Negative-control result (see evidence.ControlResult).
    control: dict | None = None
    #: Values the check emitted, for value-oracle kinds.
    observed: dict | None = None
    # Raw bounded output is staged in memory so an Engine can atomically
    # commit the evidence blob with the proof that references its digest.
    # It is deliberately excluded from the portable outcome dictionary.
    output: bytes | None = field(default=None, repr=False, compare=False)
    # Internal refusal signal: the command rewrote the declared subject in
    # its disposable snapshot. Engines abort rather than persist a proof for
    # a check that chose the bytes it then reported on.
    subject_mutated: bool = field(default=False, repr=False, compare=False)

    def to_dict(self) -> dict:
        return {
            "source": self.source, "pinned": self.pinned,
            "command_digest": self.command_digest,
            "definition_digest": self.definition_digest,
            "verifier": self.verifier, "kind": self.kind, "result": self.result,
            "started_at": self.started_at, "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code, "output_digest": self.output_digest,
            "evidence_digest": self.evidence_digest, "coverage": self.coverage,
            "control": self.control, "observed": self.observed,
            "details": self.details, "network": self.network,
        }


@dataclass
class _BoundedProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    capture_failed: bool
    timed_out: bool


def _drain_bounded(stream, destination: bytearray, truncated: list[bool],
                   failed: list[bool]) -> None:
    """Drain a pipe to EOF while retaining at most one output cap."""
    try:
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                return
            remaining = _MAX_OUTPUT - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated[0] = True
    except (OSError, ValueError):
        # The coordinator closes pipes after a forced timeout so a descendant
        # that inherited a handle cannot strand a reader thread.
        failed[0] = True
        return
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    """Best-effort whole-tree termination using platform-native facilities."""
    if os.name == "nt":
        # Python exposes process groups on Windows but no Job Object API.
        # taskkill /T is the OS-provided tree operation; if it is unavailable,
        # the honest stdlib fallback can terminate only the direct child.
        system_root = os.environ.get("SYSTEMROOT")
        taskkill = (
            Path(system_root) / "System32" / "taskkill.exe"
            if system_root else None
        )
        if taskkill is not None and taskkill.is_file():
            try:
                subprocess.run(
                    [str(taskkill), "/PID", str(proc.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=False, timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        return

    # start_new_session=True makes the child PID the process-group ID. Address
    # that ID directly so descendants are still killable if the leader exited.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    # The leader may exit on SIGTERM while a descendant ignores it. Always
    # follow the grace period with SIGKILL for whatever remains in the group.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass


def _run_bounded_process(argv: list[str], *, cwd: Path, env: dict,
                         timeout: int) -> _BoundedProcessResult:
    """Run with deterministic per-stream prefixes and a hard capture bound."""
    popen_options = {}
    if os.name == "nt":
        popen_options["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_options["start_new_session"] = True
    proc = subprocess.Popen(
        argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_options)
    assert proc.stdout is not None and proc.stderr is not None

    stdout = bytearray()
    stderr = bytearray()
    stdout_truncated = [False]
    stderr_truncated = [False]
    stdout_failed = [False]
    stderr_failed = [False]
    readers = [
        threading.Thread(
            target=_drain_bounded,
            args=(proc.stdout, stdout, stdout_truncated, stdout_failed),
            name="cce-verifier-stdout", daemon=True),
        threading.Thread(
            target=_drain_bounded,
            args=(proc.stderr, stderr, stderr_truncated, stderr_failed),
            name="cce-verifier-stderr", daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        proc.wait(timeout=max(deadline - time.monotonic(), 0.001))
    except subprocess.TimeoutExpired:
        timed_out = True

    if not timed_out:
        for reader in readers:
            reader.join(timeout=max(deadline - time.monotonic(), 0.0))
        # A verifier can fork a background descendant that inherits its pipes.
        # Pipe EOF is therefore part of the same timeout contract as the leader.
        timed_out = any(reader.is_alive() for reader in readers)

    if timed_out:
        _terminate_process_tree(proc)
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        for reader in readers:
            reader.join(timeout=1)

    # A Windows host without taskkill cannot guarantee that an orphaned
    # descendant released an inherited pipe. Reader threads are daemonized and
    # bounded; do not copy a buffer that could still be changing.
    stdout_reader_alive = readers[0].is_alive()
    stderr_reader_alive = readers[1].is_alive()
    return _BoundedProcessResult(
        returncode=proc.returncode,
        stdout=b"" if stdout_reader_alive else bytes(stdout),
        stderr=b"" if stderr_reader_alive else bytes(stderr),
        stdout_truncated=stdout_truncated[0] or stdout_reader_alive,
        stderr_truncated=stderr_truncated[0] or stderr_reader_alive,
        capture_failed=stdout_failed[0] or stderr_failed[0],
        timed_out=timed_out,
    )


def _bounded_transcript(result: _BoundedProcessResult) -> bytes:
    """Render stdout then stderr deterministically within the single cap."""
    combined = result.stdout + _STDERR_SEPARATOR + result.stderr
    truncated = (
        result.stdout_truncated
        or result.stderr_truncated
        or len(combined) > _MAX_OUTPUT
    )
    if not truncated:
        return combined
    retained = max(_MAX_OUTPUT - len(_TRUNCATION_MARKER), 0)
    return combined[:retained] + _TRUNCATION_MARKER[:_MAX_OUTPUT]


# Interpreter/shell messages that mean the check never began, as distinct
# from a check that ran and disagreed with the claim.
_STARTUP_FAILURE = re.compile(
    r"(?im)^[^\r\n]*python(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?: "
    r"(?:No module named (?P<mod>\S+)|can't open file [^\r\n]+)\r?$",
)


def _startup_failure(stderr: bytes) -> str | None:
    text = stderr.decode("utf-8", "replace")[:4000]
    m = _STARTUP_FAILURE.search(text)
    return m.group(0).strip() if m else None


class UnsafeCommandError(ValueError):
    """The command could hand control to a program of the caller's choosing."""


def check_command_safety(command: str, *, require_absolute: bool = False) -> None:
    """Reject commands whose first word delegates to another program.

    A pinned command is only pinned if it names the program that will run.
    `env FOO=1 pytest`, `sh -c '...'` and `timeout 5 anything` all let the
    argument list choose the real executable, which would make pinning
    cosmetic.
    """
    parts = shlex.split(command)
    if not parts:
        raise UnsafeCommandError("empty command")
    executable = Path(parts[0])
    program = executable.name.casefold()
    for suffix in (".exe", ".cmd", ".bat"):
        if program.endswith(suffix):
            program = program[:-len(suffix)]
            break
    if program in _INDIRECTION:
        raise UnsafeCommandError(
            f"{program!r} delegates to a program named in its arguments, so "
            f"pinning this command would not pin what actually runs")
    if require_absolute and not executable.is_absolute():
        raise UnsafeCommandError(
            "policy-pinned verifier executables must use an absolute path; "
            "relative lookup does not pin which program runs")


class VerifierRunner:
    def __init__(self, store=None, workdir: str | Path = ".", *,
                 persist_evidence: bool = True):
        if not isinstance(persist_evidence, bool):
            raise ValueError("persist_evidence must be a boolean")
        self.store = store
        self.workdir = Path(workdir).resolve()
        self.persist_evidence = persist_evidence

    def run(self, spec: VerifierSpec) -> VerificationOutcome:
        started = utcnow()
        if not isinstance(spec, VerifierSpec):
            return VerificationOutcome(
                verifier="<invalid>", kind="invalid", result="inconclusive",
                started_at=started, duration_seconds=0.0, pinned=False,
                details="refused invalid verifier specification: expected "
                        "a VerifierSpec",
                network="restricted")
        try:
            spec.validate()
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            return VerificationOutcome(
                verifier=spec.name if isinstance(spec.name, str) else "<invalid>",
                kind=spec.kind if isinstance(spec.kind, str) else "invalid",
                result="inconclusive", started_at=started,
                duration_seconds=0.0,
                pinned=spec.pinned if isinstance(spec.pinned, bool) else False,
                details=f"refused invalid verifier specification: {exc}",
                network=(
                    spec.network if isinstance(spec.network, str)
                    else "restricted"))
        visibility_error = self._artifact_visibility_error(spec.artifacts)
        if visibility_error:
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started, duration_seconds=0.0,
                pinned=spec.pinned,
                details=("invalid verifier artifact declaration: "
                         f"{visibility_error}"),
                network=spec.network,
                definition_digest=spec.definition_digest)
        if spec.kind == "file-digest":
            outcome = self._run_file_digest(spec, started)
        elif not spec.command:
            outcome = VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="missing",
                started_at=started, duration_seconds=0.0, pinned=spec.pinned,
                details="no command configured", network=spec.network)
        else:
            outcome = self._run_command(spec, started)
            outcome.control = self._run_control(spec)
        outcome.definition_digest = spec.definition_digest
        return outcome

    # ------------------------------------------------------- negative control

    def _run_control(self, spec: VerifierSpec) -> dict:
        """Run the expect-fail control: it MUST fail for the check to count."""
        from .evidence import ControlResult
        if not spec.expect_fail_command:
            return ControlResult(command="", status="absent",
                                 details="no negative control declared").to_dict()
        probe = VerifierSpec(
            name=f"{spec.name}:expect-fail", kind="command",
            command=spec.expect_fail_command,
            timeout_seconds=spec.timeout_seconds, required=False,
            pinned=spec.pinned, isolate_sys_path=spec.isolate_sys_path,
            allow_user_site=spec.allow_user_site)
        result = self._run_command(probe, utcnow())
        if result.result == "failed":
            status, details = "held", "control failed as required"
        elif result.result == "passed":
            status, details = "unmet", (
                "the control PASSED: this check cannot distinguish done from "
                "not-done")
        else:
            status, details = "inconclusive", result.details
        return ControlResult(command=spec.expect_fail_command, status=status,
                             exit_code=result.exit_code,
                             details=details).to_dict()

    # ---------------------------------------------------------------- runners

    def _build_env(self, spec: VerifierSpec, pycache: str) -> dict:
        """Scrubbed environment. Each entry earns its place.

        HOME is deliberately ABSENT: `$HOME/.local/lib/pythonX/site-packages/
        usercustomize.py` executes at interpreter startup, before `-m` — a
        write-anywhere agent could run code before the check begins.

        PYTHONSAFEPATH is opt-in (`spec.isolate_sys_path`), not default. A
        test suite must import the code under test, so keeping the tree off
        sys.path breaks the ordinary case instead of hardening it — and a
        verifier that cannot run gets switched off, which is strictly worse
        than one with a documented weakness. In-process forgery is answered
        by the value-oracle kind and the mutation probe, not by the
        environment.
        """
        env = {
            # Only absolute default locations: Windows' os.defpath begins
            # with '.', which lets the subject shadow a verifier executable.
            "PATH": _SAFE_DEFAULT_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TMPDIR": pycache,
            "CCE_VERIFIER": spec.name,
            **({} if spec.allow_user_site else {"PYTHONNOUSERSITE": "1"}),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": pycache,  # no same-second .pyc shadowing
            **({"SYSTEMROOT": os.environ["SYSTEMROOT"]}
               if "SYSTEMROOT" in os.environ else {}),
        }
        if spec.isolate_sys_path:
            env["PYTHONSAFEPATH"] = "1"
        return env

    def _run_command(self, spec: VerifierSpec, started: str) -> VerificationOutcome:
        t0 = time.monotonic()
        try:
            check_command_safety(spec.command, require_absolute=spec.pinned)
            argv = shlex.split(spec.command)
        except (UnsafeCommandError, ValueError) as exc:
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started, duration_seconds=0.0, pinned=spec.pinned,
                command_digest=spec.command_digest,
                details=f"refused to run: {exc}", network=spec.network)
        try:
            # Policy checks need the source tree, not the trust database beside
            # it. A disposable snapshot makes that distinction structural for
            # relative-path access and also prevents a verifier modifying the
            # operator's working copy. Same-user absolute-path access remains
            # outside what a stdlib process runner can honestly prevent.
            with _temporary_workspace_root(
                    self.workdir, prefix="cce-verify-") as temp_root:
                execution_workdir = self._execution_snapshot(
                    temp_root, spec.artifacts)
                artifact_before = fingerprint_artifacts(
                    execution_workdir, spec.artifacts,
                    temp_root / "artifacts-before")
                pycache = temp_root / "pycache"
                pycache.mkdir()
                proc = _run_bounded_process(
                    argv,
                    cwd=execution_workdir,
                    env=self._build_env(spec, str(pycache)),
                    timeout=spec.timeout_seconds,
                )
                artifact_after = fingerprint_artifacts(
                    execution_workdir, spec.artifacts,
                    temp_root / "artifacts-after")
        except (FileNotFoundError, OSError, UnsafeWorkspaceError) as exc:
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started, duration_seconds=time.monotonic() - t0,
                pinned=spec.pinned, command_digest=spec.command_digest,
                details=f"verifier could not run: {exc}", network=spec.network)
        duration = time.monotonic() - t0
        output = _bounded_transcript(proc)
        output_digest = sha256_hex(output)
        evidence_digest = sha256_hex(output)
        if artifact_after != artifact_before:
            changed = sorted(
                name for name in set(artifact_before) | set(artifact_after)
                if artifact_before.get(name) != artifact_after.get(name))
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started, duration_seconds=round(duration, 3),
                exit_code=proc.returncode, output_digest=output_digest,
                evidence_digest=evidence_digest, pinned=spec.pinned,
                command_digest=spec.command_digest,
                details=("verifier modified declared artifact(s) inside its "
                         f"disposable snapshot: {changed}"),
                network=spec.network, output=output, subject_mutated=True)
        if self.store is not None and self.persist_evidence:
            stored_digest = self.store.put_evidence(
                output, media_type="text/plain")
            if stored_digest != evidence_digest:
                raise RuntimeError("stored verifier evidence digest is inconsistent")
        if proc.timed_out:
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started, duration_seconds=round(duration, 3),
                exit_code=proc.returncode, output_digest=output_digest,
                evidence_digest=evidence_digest, pinned=spec.pinned,
                command_digest=spec.command_digest,
                details=f"timeout after {spec.timeout_seconds}s",
                network=spec.network, output=output)
        if proc.capture_failed:
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started, duration_seconds=round(duration, 3),
                exit_code=proc.returncode, output_digest=output_digest,
                evidence_digest=evidence_digest, pinned=spec.pinned,
                command_digest=spec.command_digest,
                details="verifier output capture failed",
                network=spec.network, output=output)
        coverage = self._parse_coverage(spec.kind, output.decode("utf-8", "replace"))
        observed = None
        returncode = proc.returncode if proc.returncode is not None else -1
        if spec.kind == "value-oracle":
            # The subject reports VALUES; this runner renders the verdict.
            result, details, observed = self._judge_values(
                spec, proc.stdout, returncode)
        elif returncode == 0:
            result, details = "passed", "exit 0"
        else:
            # A check that never started is an infrastructure problem, not a
            # verdict about the work (EV-006). Reporting it as `failed` would
            # be as dishonest as reporting it as passed — and would trip the
            # AUT-005 downgrade for a missing interpreter.
            startup = _startup_failure(proc.stderr)
            if startup:
                result, details = "inconclusive", f"check never ran: {startup}"
            else:
                result, details = "failed", f"exit {returncode}"
        return VerificationOutcome(
            verifier=spec.name, kind=spec.kind, result=result,
            started_at=started, duration_seconds=round(duration, 3),
            exit_code=returncode, output_digest=output_digest,
            evidence_digest=evidence_digest, coverage=coverage,
            pinned=spec.pinned, command_digest=spec.command_digest,
            observed=observed,
            details=details, network=spec.network, output=output)

    def _execution_snapshot(
            self, temp_root: Path, artifacts: list[str]) -> Path:
        """Always copy one bounded subject, excluding local trust/control state."""
        workspace = temp_root / "workspace"
        return materialize_workspace(
            self.workdir, workspace,
            excluded_paths=tuple(self._snapshot_exclusions()),
            preserved_paths=tuple(
                self.workdir.joinpath(*rel.split("/"))
                for rel in artifacts))

    def _artifact_visibility_error(self, artifacts: list[str]) -> str | None:
        """Explain when declared subject bytes overlap omitted trust state."""
        groups = (
            ("store", self._store_files()),
            ("runtime", self._runtime_paths()),
        )
        for rel in artifacts:
            target = Path(os.path.abspath(
                self.workdir.joinpath(*rel.split("/"))))
            for classification, excluded in groups:
                for omitted in excluded:
                    if (target == omitted
                            or target in omitted.parents
                            or omitted in target.parents):
                        return (
                            f"artifact {rel!r} overlaps verifier-omitted "
                            f"{classification} state at {omitted.name!r}")
        return None

    def _snapshot_exclusions(
            self, workdir: str | Path | None = None) -> set[Path]:
        """Local control/runtime paths that cannot be verifier subjects."""
        root = self.workdir if workdir is None else Path(workdir).resolve()
        return self._store_files(root) | self._runtime_paths(root)

    def _runtime_paths(
            self, workdir: str | Path | None = None) -> set[Path]:
        """Nested process-temp state omitted from verifier subjects."""
        root = self.workdir if workdir is None else Path(workdir).resolve()
        configured_temp = Path(tempfile.gettempdir()).resolve()
        if configured_temp != root and root in configured_temp.parents:
            return {configured_temp}
        return set()

    def _store_files(self, workdir: str | Path | None = None) -> set[Path]:
        """Database files that must never become verifier subject bytes."""
        store_files: set[Path] = set()
        if self.store is not None and self.store.path != ":memory:":
            store_path = Path(self.store.path).resolve()
            root = self.workdir if workdir is None else Path(workdir).resolve()
            if store_path == root or root in store_path.parents:
                store_files = {
                    store_path,
                    Path(str(store_path) + "-wal"),
                    Path(str(store_path) + "-shm"),
                }
        return store_files

    def _judge_values(self, spec: VerifierSpec, stdout: bytes,
                      returncode: int) -> tuple[str, str, dict | None]:
        """Compare emitted values against the policy's expectations.

        The check's job is to *report what is true*; deciding whether that
        satisfies the requirement belongs here, outside the process the
        subject controls. A subject that lies must lie about the values —
        which the expectations then catch — rather than about the verdict,
        which it no longer renders.
        """
        expected = spec.expected_properties.get("values")
        if not isinstance(expected, dict) or not expected:
            return ("inconclusive",
                    "value-oracle check declares no expected values", None)
        text = stdout.decode("utf-8", "replace").strip()
        if not text:
            # No report at all is a broken contract, not a verdict about the
            # work. An oracle that means "nothing is true" emits `{}`.
            return ("inconclusive",
                    "value-oracle emitted no report on stdout", None)
        try:
            observed = strict_json_loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            return ("inconclusive",
                    f"value-oracle output is not JSON: {exc}", None)
        if not isinstance(observed, dict):
            return ("inconclusive",
                    f"value-oracle output is {type(observed).__name__}, not an "
                    f"object", None)
        mismatches, missing = [], []
        for key, want in expected.items():
            if key not in observed:
                missing.append(key)
            elif observed[key] != want:
                mismatches.append({"key": key, "expected": want,
                                   "observed": observed[key]})
        if missing or mismatches:
            # Name the keys that were wrong, never the values that were
            # wanted. `details` travels in the signed envelope, which the
            # claimant can read — echoing the expectation back would hand the
            # subject the answer key for its next attempt.
            parts = []
            if missing:
                parts.append(f"values not reported: {sorted(missing)}")
            if mismatches:
                parts.append(
                    f"values did not match the declared expectation: "
                    f"{sorted(m['key'] for m in mismatches)}")
            return "failed", "; ".join(parts), observed
        return ("passed",
                f"{len(expected)} value(s) matched the declared expectation",
                observed)

    def _run_file_digest(self, spec: VerifierSpec, started: str) -> VerificationOutcome:
        expected = spec.expected_properties.get("files", {})
        if not expected:
            # Verifying nothing is not verification. Passing here would give a
            # required check a free green with no declared subject.
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started, duration_seconds=0.0, pinned=spec.pinned,
                details="file-digest check declares no files to verify",
                network="none")
        t0 = time.monotonic()
        try:
            with _temporary_workspace_root(
                    self.workdir, prefix="cce-digest-") as temp_root:
                workspace = materialize_workspace(
                    self.workdir, temp_root / "workspace",
                    excluded_paths=tuple(self._snapshot_exclusions()),
                    preserved_paths=tuple(
                        self.workdir.joinpath(*rel.split("/"))
                        for rel in spec.artifacts))
                mismatches, missing = [], []
                for rel, want in expected.items():
                    path = workspace.joinpath(*rel.split("/"))
                    try:
                        info = os.lstat(path)
                    except FileNotFoundError:
                        missing.append(rel)
                        continue
                    if (stat.S_ISLNK(info.st_mode)
                            or not stat.S_ISREG(info.st_mode)
                            or getattr(info, "st_file_attributes", 0) & 0x400):
                        raise UnsafeWorkspaceError(
                            f"file-digest operand {rel!r} is not a physical "
                            "regular file")
                    if info.st_size > WORKSPACE_MAX_FILE_BYTES:
                        raise UnsafeWorkspaceError(
                            f"file-digest operand {rel!r} exceeds the "
                            f"{WORKSPACE_MAX_FILE_BYTES}-byte limit")
                    digest = hashlib.sha256()
                    size = 0
                    with path.open("rb") as stream:
                        while True:
                            chunk = stream.read(_READ_CHUNK)
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > WORKSPACE_MAX_FILE_BYTES:
                                raise UnsafeWorkspaceError(
                                    f"file-digest operand {rel!r} grew beyond "
                                    "the read limit")
                            digest.update(chunk)
                    got = "sha256:" + digest.hexdigest()
                    if got != want:
                        mismatches.append(rel)
        except (OSError, UnsafeWorkspaceError) as exc:
            return VerificationOutcome(
                verifier=spec.name, kind=spec.kind, result="inconclusive",
                started_at=started,
                duration_seconds=round(time.monotonic() - t0, 3),
                pinned=spec.pinned,
                details=f"file-digest could not safely read its operands: {exc}",
                network="none")
        if missing:
            result, details = "failed", f"missing files: {missing}"
        elif mismatches:
            result, details = "failed", f"digest mismatches: {mismatches}"
        else:
            result, details = "passed", f"{len(expected)} file(s) verified"
        return VerificationOutcome(
            verifier=spec.name, kind=spec.kind, result=result,
            started_at=started,
            duration_seconds=round(time.monotonic() - t0, 3),
            pinned=spec.pinned,
            details=details, network="none")

    @staticmethod
    def _parse_coverage(kind: str, output: str) -> dict | None:
        if kind in ("unit-tests", "integration-tests"):
            m = re.search(r"(\d+) passed", output)
            f = re.search(r"(\d+) failed", output)
            if m or f:
                values = [
                    match.group(1) for match in (m, f) if match is not None]
                if any(len(value) > 9 for value in values):
                    return None
                try:
                    return {
                        "tests_passed": int(m.group(1)) if m else 0,
                        "tests_failed": int(f.group(1)) if f else 0,
                    }
                except ValueError:
                    return None
        return None


def record_verification(graph, outcome: VerificationOutcome, *, tenant_id: str,
                        project_id: str, subject_node_id: str | None = None,
                        event_id: str | None = None) -> dict:
    """Persist an outcome as a verification node and link it to its subject."""
    if not isinstance(outcome, VerificationOutcome):
        raise ValueError("verification outcome must be a VerificationOutcome")
    if subject_node_id is not None:
        subject_node_id = validate_public_identifier(
            subject_node_id, field="verification subject_node_id")
        try:
            graph.get(
                subject_node_id, tenant_id=tenant_id,
                project_id=project_id)
        except KeyError:
            raise ValueError(
                "verification subject_node_id must identify a node in the "
                "requested tenant and project") from None
    with graph.store.transaction():
        node = graph.put_node(
            entity_type="verification", tenant_id=tenant_id,
            project_id=project_id, status=outcome.result,
            authority="verifier_authoritative",
            data=outcome.to_dict() | {"verifier": outcome.verifier},
            event_id=event_id,
        )
        if subject_node_id is not None:
            graph.put_edge(
                edge_type="verifies", src_id=node.id, dst_id=subject_node_id,
                tenant_id=tenant_id, project_id=project_id, event_id=event_id,
            )
    return node
