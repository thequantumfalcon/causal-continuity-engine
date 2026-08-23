"""Bind a release tag exactly to the package version and current commit."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REPOSITORY = "thequantumfalcon/causal-continuity-engine"
RELEASE_SSH_ORIGIN = (
    "ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git"
)
RELEASE_HTTPS_ORIGINS = frozenset({
    "https://github.com/thequantumfalcon/causal-continuity-engine",
    "https://github.com/thequantumfalcon/causal-continuity-engine.git",
})
WORKFLOW_PATHS = {
    "ci": ".github/workflows/ci.yml",
    "attribution": ".github/workflows/no-ai-attribution.yml",
    "secrets": ".github/workflows/secret-scan.yml",
}
# These branch requirements are intentionally excluded from the release
# quorum: neither is a reviewed push-event attestation for the squash commit.
# Any other extra context is rejected until its event/path semantics are added
# here deliberately rather than being ignored by accident.
PR_ONLY_BRANCH_CONTEXTS = frozenset({"dependency-review", "DCO"})
SIGNATURE_MARKERS = (
    "-----BEGIN PGP SIGNATURE-----",
    "-----BEGIN SSH SIGNATURE-----",
)
MAX_GITHUB_JSON_BYTES = 8 * 1024 * 1024
MAX_RULESET_BYTES = 256 * 1024
MAX_GIT_CONFIG_BYTES = 256 * 1024
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_GIT_DIAGNOSTIC_BYTES = 4096
GIT_OPERATION_TIMEOUT_SECONDS = 120
GITHUB_REQUIRED_CHECK_MAX_AGE = timedelta(days=7)
GITHUB_REQUIRED_CHECK_MAX_FUTURE_SKEW = timedelta(minutes=5)
_GITHUB_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z")
_GITHUB_REPOSITORY_COMPONENT = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_SSH_COMMAND_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
_SSH_PUBLIC_KEY_TYPE = re.compile(
    r"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh.com)\Z")


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _github_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile
    capath = paths.openssl_capath
    if os.name == "posix":
        if not (
            (cafile and Path(cafile).is_file())
            or (capath and Path(capath).is_dir())
        ):
            raise SystemExit("GitHub verification has no system TLS trust store")
        context.load_verify_locations(
            cafile=cafile if cafile and Path(cafile).is_file() else None,
            capath=capath if capath and Path(capath).is_dir() else None,
        )
    else:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return context


_GITHUB_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_github_tls_context()),
    _RejectRedirects(),
)


def _strict_json_object(payload: bytes, *, label: str) -> dict:
    if len(payload) > MAX_GITHUB_JSON_BYTES:
        raise SystemExit(f"{label} exceeds the JSON size limit")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SystemExit(f"{label} must contain one JSON object")
    return document


def _release_version() -> str:
    """Use the exact-release verifier's non-executing dynamic-version contract."""
    verifier_path = ROOT / ".github" / "scripts" / "verify_distributions.py"
    spec = importlib.util.spec_from_file_location(
        "causal_continuity_engine_release_identity", verifier_path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release identity verifier")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    _, version = verifier._project_contract(ROOT)
    return version


def _verify_release_metadata(tag: str) -> str:
    path = ROOT / ".github" / "scripts" / "check_release_metadata.py"
    spec = importlib.util.spec_from_file_location(
        "causal_continuity_engine_release_metadata", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release metadata verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    version, _ = module.check(ROOT, release_tag=tag)
    return version


def _required_checks(source_root: Path = ROOT) -> dict[str, tuple[int, str]]:
    """Derive the fixed release quorum from the committed branch ruleset."""
    try:
        ruleset_bytes = (source_root / ".github" / "ruleset.json").read_bytes()
    except OSError as exc:
        raise SystemExit("cannot read the committed branch ruleset") from exc
    if len(ruleset_bytes) > MAX_RULESET_BYTES:
        raise SystemExit("committed branch ruleset exceeds the size limit")
    ruleset = _strict_json_object(
        ruleset_bytes, label="committed branch ruleset")
    if not isinstance(ruleset, dict) or ruleset.get("target") != "branch":
        raise SystemExit("committed branch ruleset has malformed identity")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise SystemExit("committed branch ruleset has malformed rules")
    status_rules = [rule for rule in rules if rule.get("type") == "required_status_checks"]
    if len(status_rules) != 1:
        raise SystemExit("branch ruleset must define exactly one required_status_checks rule")
    parameters = status_rules[0].get("parameters")
    if (
        not isinstance(parameters, dict)
        or parameters.get("strict_required_status_checks_policy") is not True
    ):
        raise SystemExit("branch required checks must use strict head synchronization")
    entries = parameters.get("required_status_checks")
    if not isinstance(entries, list) or not entries:
        raise SystemExit("branch ruleset has no required status contexts")
    derived: dict[str, tuple[int, str]] = {}
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"context", "integration_id"}:
            raise SystemExit("branch ruleset contains malformed required-check metadata")
        context = entry["context"]
        integration_id = entry["integration_id"]
        if (
            not isinstance(context, str)
            or not context
            or isinstance(integration_id, bool)
            or not isinstance(integration_id, int)
            or integration_id <= 0
            or context in seen
        ):
            raise SystemExit("branch ruleset contains invalid or duplicate check context")
        seen.add(context)
        expected_path = WORKFLOW_PATHS.get(context)
        if expected_path is not None:
            derived[context] = (integration_id, expected_path)
        elif context not in PR_ONLY_BRANCH_CONTEXTS:
            raise SystemExit(
                f"branch ruleset contains unclassified required context {context!r}")
    if set(derived) != set(WORKFLOW_PATHS):
        missing = sorted(set(WORKFLOW_PATHS) - set(derived))
        raise SystemExit(
            "branch ruleset omits core release context(s): " + ", ".join(missing))
    return derived


def _path_snapshot(path: Path) -> tuple[int, int, int, int, int, int]:
    metadata = path.stat(follow_symlinks=False)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _reject_writable_path_chain(path: Path, *, label: str) -> None:
    for parent in (path.parent, *path.parents):
        metadata = parent.stat(follow_symlinks=False)
        if metadata.st_uid not in {0, os.getuid()}:
            raise SystemExit(f"{label} has an untrusted parent owner")
        if metadata.st_mode & 0o022:
            if metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX:
                continue
            raise SystemExit(f"{label} has a group- or world-writable parent")


def _trusted_regular_path(
    value: str,
    *,
    label: str,
    root: Path,
    executable: bool,
) -> tuple[Path, tuple[int, int, int, int, int, int]]:
    path = Path(value)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"{label} is unavailable") from exc
    if not path.is_absolute() or path != resolved:
        raise SystemExit(f"{label} must be one canonical absolute path")
    if path.is_symlink() or path == root or root in path.parents:
        raise SystemExit(f"{label} must be a non-repository regular file")
    try:
        metadata = path.stat(follow_symlinks=False)
        _reject_writable_path_chain(path, label=label)
    except OSError as exc:
        raise SystemExit(f"{label} is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or (not executable and metadata.st_nlink != 1):
        raise SystemExit(f"{label} must be a trusted regular file")
    if metadata.st_mode & 0o022:
        raise SystemExit(f"{label} must not be group- or world-writable")
    allowed_owners = {0} if executable else {0, os.getuid()}
    if metadata.st_uid not in allowed_owners:
        raise SystemExit(f"{label} has an untrusted owner")
    if executable and not metadata.st_mode & 0o111:
        raise SystemExit(f"{label} is not executable")
    return path, _path_snapshot(path)


def _trusted_socket_path(
    value: str,
    *,
    root: Path,
) -> tuple[Path, tuple[int, int, int, int, int, int]]:
    path = Path(value)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SystemExit("SSH agent socket is unavailable") from exc
    if not path.is_absolute():
        raise SystemExit("SSH agent socket must be an absolute path")
    if path.is_symlink() or resolved == root or root in resolved.parents:
        raise SystemExit("SSH agent socket must be outside the repository")
    try:
        metadata = resolved.stat(follow_symlinks=False)
        parent_metadata = resolved.parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise SystemExit("SSH agent socket is unavailable") from exc
    private_owner_parent = (
        parent_metadata.st_uid == os.getuid()
        and stat.S_ISDIR(parent_metadata.st_mode)
        and not parent_metadata.st_mode & 0o077
    )
    if not private_owner_parent:
        try:
            _reject_writable_path_chain(resolved, label="SSH agent socket")
        except OSError as exc:
            raise SystemExit("SSH agent socket is unavailable") from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or (metadata.st_mode & 0o022 and not private_owner_parent)
    ):
        raise SystemExit(
            "SSH agent socket must be owner-controlled directly or by its private parent")
    return resolved, _path_snapshot(resolved)


def _private_temp_base() -> Path:
    path = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise SystemExit("release Git temporary directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or not metadata.st_mode & stat.S_ISVTX
    ):
        raise SystemExit("release Git requires a trusted sticky temporary directory")
    return path


def _valid_identity(value: str, *, label: str, email: bool = False) -> str:
    if (
        not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "<" in value
        or ">" in value
        or (email and value.count("@") != 1)
    ):
        raise SystemExit(f"{label} is not a valid explicit release identity")
    return value


def _require_public_key(path: Path, *, label: str) -> None:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"{label} is unavailable") from exc
    if len(payload) > 16 * 1024:
        raise SystemExit(f"{label} exceeds the public-key size limit")
    try:
        text = payload.decode("ascii").strip()
        key_type, encoded, *_ = text.split()
        base64.b64decode(encoded, validate=True)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SystemExit(f"{label} is not one OpenSSH public key") from exc
    if _SSH_PUBLIC_KEY_TYPE.fullmatch(key_type) is None or "\n" in text:
        raise SystemExit(f"{label} is not one OpenSSH public key")


def _bounded_private_git_file(path: Path, *, label: str, limit: int) -> bytes:
    try:
        metadata = path.stat(follow_symlinks=False)
        before = _path_snapshot(path)
    except OSError as exc:
        raise SystemExit(f"{label} is unavailable") from exc
    mode = before[2]
    if (
        path.is_symlink()
        or not stat.S_ISREG(mode)
        or metadata.st_nlink != 1
        or before[3] not in {0, os.getuid()}
        or mode & 0o022
        or before[4] > limit
    ):
        raise SystemExit(f"{label} is not a bounded private regular file")
    try:
        payload = path.read_bytes()
        after = _path_snapshot(path)
    except OSError as exc:
        raise SystemExit(f"{label} is unavailable") from exc
    if before != after:
        raise SystemExit(f"{label} changed while it was inspected")
    return payload


def _reject_git_object_indirection(git_directory: Path) -> None:
    forbidden = (
        (git_directory / "objects" / "info" / "alternates", "Git object alternates"),
        (git_directory / "info" / "grafts", "Git grafts"),
        (git_directory / "shallow", "shallow Git history"),
        (git_directory / "commondir", "a redirected common Git directory"),
        (git_directory / "refs" / "replace", "Git replacement refs"),
    )
    for path, label in forbidden:
        if os.path.lexists(path):
            raise SystemExit(f"release Git refuses {label}")
    packed_refs = git_directory / "packed-refs"
    if os.path.lexists(packed_refs):
        payload = _bounded_private_git_file(
            packed_refs, label="packed Git references", limit=MAX_GIT_OUTPUT_BYTES)
        if any(
            b" refs/replace/" in line
            for line in payload.splitlines()
            if line and not line.startswith((b"#", b"^"))
        ):
            raise SystemExit("release Git refuses packed replacement refs")
    for name in ("exclude", "attributes"):
        path = git_directory / "info" / name
        if not os.path.lexists(path):
            continue
        payload = _bounded_private_git_file(
            path, label=f"Git info {name}", limit=MAX_GIT_CONFIG_BYTES)
        if any(
            line.strip() and not line.lstrip().startswith(b"#")
            for line in payload.splitlines()
        ):
            raise SystemExit(f"release Git refuses active info/{name} rules")


class ReleaseGitCompletedError(SystemExit):
    """A Git child completed, but its bounded postflight could not pass."""

    def __init__(self, message: str, *, returncode: int) -> None:
        super().__init__(message)
        self.returncode = returncode


def _bounded_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    temporary_directory: Path,
    timeout: int,
    limit: int,
    text: bool,
) -> subprocess.CompletedProcess:
    del temporary_directory

    def stop_group(process: subprocess.Popen) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    assert process.stdout is not None and process.stderr is not None
    stdout_descriptor = process.stdout.fileno()
    stderr_descriptor = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    streams = {
        stdout_descriptor: process.stdout,
        stderr_descriptor: process.stderr,
    }
    buffers = {descriptor: bytearray() for descriptor in streams}
    totals = {descriptor: 0 for descriptor in streams}
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    output_limit_exceeded = False
    stopped = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_group(process)
                process.wait()
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in selector.select(min(remaining, 0.25)):
                descriptor = key.fd
                try:
                    chunk = os.read(descriptor, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    streams[descriptor].close()
                    continue
                totals[descriptor] += len(chunk)
                remaining_capacity = max(0, limit - len(buffers[descriptor]))
                buffers[descriptor].extend(chunk[:remaining_capacity])
                if totals[descriptor] > limit:
                    output_limit_exceeded = True
                    if not stopped:
                        stop_group(process)
                        stopped = True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop_group(process)
            process.wait()
            raise subprocess.TimeoutExpired(command, timeout)
        process.wait(timeout=remaining)
    except BaseException:
        if process.poll() is None:
            stop_group(process)
            process.wait()
        raise
    finally:
        selector.close()
        for stream in streams.values():
            stream.close()
    stdout_value = bytes(buffers[stdout_descriptor])
    stderr_value = bytes(buffers[stderr_descriptor])
    if text:
        stdout_value = stdout_value.decode("utf-8", "surrogateescape")
        stderr_value = stderr_value.decode("utf-8", "replace")
    result = subprocess.CompletedProcess(
        command, process.returncode, stdout_value, stderr_value)
    result.output_limit_exceeded = output_limit_exceeded
    return result


class ReleaseGit:
    """Run fixed release Git operations without inherited authority."""

    _COMMON_CONFIG = (
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("credential.helper", ""),
        ("credential.interactive", "never"),
        ("protocol.allow", "never"),
        ("maintenance.auto", "false"),
        ("gc.auto", "0"),
        ("submodule.recurse", "false"),
    )
    _NETWORK_COMMANDS = frozenset({"fetch", "ls-remote", "push"})

    def __init__(
        self,
        *,
        root: Path,
        git_executable: str,
        prepare: bool,
        tagger_name: str | None = None,
        tagger_email: str | None = None,
        signing_key: str | None = None,
        ssh_keygen_executable: str | None = None,
        allowed_signers_file: str | None = None,
        ssh_executable: str | None = None,
        known_hosts_file: str | None = None,
        transport_key: str | None = None,
        ssh_auth_sock: str | None = None,
    ) -> None:
        if os.name != "posix" or not hasattr(os, "getuid"):
            raise SystemExit("release Git profiles require a POSIX platform")
        try:
            self.root = root.resolve(strict=True)
        except OSError as exc:
            raise SystemExit("release repository root is unavailable") from exc
        self.prepare = prepare
        self.git_executable, git_snapshot = _trusted_regular_path(
            git_executable,
            label="Git executable",
            root=self.root,
            executable=True,
        )
        self._trusted_paths = [("Git executable", self.git_executable, git_snapshot)]
        self._temporary = tempfile.TemporaryDirectory(
            prefix="cce-release-git-", dir=_private_temp_base())
        os.chmod(self._temporary.name, 0o700)
        self._private_home = Path(self._temporary.name)
        self.tagger_name = None
        self.tagger_email = None
        self.signing_key = None
        self.ssh_keygen_executable = None
        self.allowed_signers_file = None
        self.ssh_executable = None
        self.known_hosts_file = None
        self.transport_key = None
        self.ssh_auth_sock = None
        try:
            if prepare:
                fields = {
                    "tagger name": tagger_name,
                    "tagger email": tagger_email,
                    "signing key": signing_key,
                    "SSH signing executable": ssh_keygen_executable,
                    "allowed signers file": allowed_signers_file,
                    "SSH executable": ssh_executable,
                    "known hosts file": known_hosts_file,
                    "transport public key": transport_key,
                    "SSH agent socket": ssh_auth_sock,
                }
                missing = [label for label, value in fields.items() if value is None]
                if missing:
                    raise SystemExit(
                        "explicit SSH release profile is missing: " + ", ".join(missing))
                self.tagger_name = _valid_identity(
                    tagger_name or "", label="tagger name")
                self.tagger_email = _valid_identity(
                    tagger_email or "", label="tagger email", email=True)
                self.signing_key = self._add_regular(
                    signing_key or "", "signing key", executable=False)
                _require_public_key(self.signing_key, label="signing key")
                self.ssh_keygen_executable = self._add_regular(
                    ssh_keygen_executable or "", "SSH signing executable", executable=True)
                self.allowed_signers_file = self._add_regular(
                    allowed_signers_file or "", "allowed signers file", executable=False)
                self.ssh_executable = self._add_regular(
                    ssh_executable or "", "SSH executable", executable=True)
                self.known_hosts_file = self._add_regular(
                    known_hosts_file or "", "known hosts file", executable=False)
                self.transport_key = self._add_regular(
                    transport_key or "", "transport public key", executable=False)
                _require_public_key(
                    self.transport_key, label="transport public key")
                self.ssh_auth_sock, snapshot = _trusted_socket_path(
                    ssh_auth_sock or "", root=self.root)
                self._trusted_paths.append(
                    ("SSH agent socket", self.ssh_auth_sock, snapshot))
                for path in (
                    self.ssh_executable,
                    self.known_hosts_file,
                    self.transport_key,
                    self.ssh_auth_sock,
                ):
                    if _SSH_COMMAND_PATH.fullmatch(os.fspath(path)) is None:
                        raise SystemExit(
                            "SSH transport paths may contain only portable path characters")
            self._config_path, self._config_digest, self.origin_url = (
                self._admit_local_config())
        except BaseException:
            self.close()
            raise

    @classmethod
    def checker(cls, *, root: Path, git_executable: str) -> ReleaseGit:
        return cls(root=root, git_executable=git_executable, prepare=False)

    @classmethod
    def owner_profile(cls, **kwargs) -> ReleaseGit:
        return cls(prepare=True, **kwargs)

    def _add_regular(self, value: str, label: str, *, executable: bool) -> Path:
        path, snapshot = _trusted_regular_path(
            value, label=label, root=self.root, executable=executable)
        self._trusted_paths.append((label, path, snapshot))
        return path

    def close(self) -> None:
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()
            self._temporary = None

    def _base_environment(self) -> dict[str, str]:
        private = os.fspath(self._private_home)
        return {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": private,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": private,
            "XDG_CONFIG_HOME": private,
        }

    def _command_prefix(self) -> list[str]:
        command = [
            os.fspath(self.git_executable),
            "--no-pager",
            "--no-replace-objects",
        ]
        for key, value in self._COMMON_CONFIG:
            command.extend(("-c", f"{key}={value}"))
        return command

    def _run_config(self, config_path: Path) -> bytes:
        command = [
            os.fspath(self.git_executable),
            "--no-pager",
            "--no-replace-objects",
            "config", "--file", os.fspath(config_path), "--no-includes", "--null", "--list",
        ]
        try:
            completed = _bounded_process(
                command,
                cwd=self.root,
                environment=self._base_environment(),
                temporary_directory=self._private_home,
                timeout=30,
                limit=MAX_GIT_CONFIG_BYTES,
                text=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemExit("cannot inspect local Git configuration safely") from exc
        if completed.returncode != 0:
            raise SystemExit("cannot inspect local Git configuration safely")
        if completed.output_limit_exceeded:
            raise SystemExit("local Git configuration output exceeds the size limit")
        return completed.stdout

    def _admit_local_config(self) -> tuple[Path, str, str]:
        git_directory = self.root / ".git"
        if git_directory.is_symlink() or not git_directory.is_dir():
            raise SystemExit("release Git requires a regular non-linked working tree")
        if os.path.lexists(git_directory / "config.worktree"):
            raise SystemExit("release Git refuses per-worktree configuration")
        _reject_git_object_indirection(git_directory)
        config_path = git_directory / "config"
        try:
            root_metadata = self.root.stat(follow_symlinks=False)
            git_metadata = git_directory.stat(follow_symlinks=False)
            metadata = config_path.stat(follow_symlinks=False)
            _reject_writable_path_chain(
                config_path, label="local Git configuration")
        except OSError as exc:
            raise SystemExit("local Git configuration is unavailable") from exc
        for label, directory_metadata in (
            ("release repository root", root_metadata),
            ("release Git directory", git_metadata),
        ):
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid not in {0, os.getuid()}
                or directory_metadata.st_mode & 0o022
            ):
                raise SystemExit(f"{label} is not a private owner directory")
        if (
            config_path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_mode & 0o022
        ):
            raise SystemExit("local Git configuration is not a private regular file")
        if metadata.st_size > MAX_GIT_CONFIG_BYTES:
            raise SystemExit("local Git configuration exceeds the size limit")
        try:
            config_bytes = config_path.read_bytes()
        except OSError as exc:
            raise SystemExit("local Git configuration is unavailable") from exc
        output = self._run_config(config_path)
        try:
            config_after = config_path.read_bytes()
        except OSError as exc:
            raise SystemExit("local Git configuration became unavailable") from exc
        if config_after != config_bytes:
            raise SystemExit("local Git configuration changed during admission")
        entries: dict[str, str] = {}
        try:
            records = [record for record in output.split(b"\0") if record]
            for record in records:
                raw_key, separator, raw_value = record.partition(b"\n")
                if not separator:
                    raise ValueError("missing value separator")
                key = raw_key.decode("utf-8").lower()
                value = raw_value.decode("utf-8")
                if key in entries:
                    raise ValueError("duplicate key")
                entries[key] = value
        except (UnicodeDecodeError, ValueError) as exc:
            raise SystemExit("local Git configuration is ambiguous") from exc

        allowed: dict[str, set[str]] = {
            "core.repositoryformatversion": {"0"},
            "core.filemode": {"true", "false"},
            "core.bare": {"false"},
            "core.logallrefupdates": {"true"},
            "core.ignorecase": {"true", "false"},
            "core.precomposeunicode": {"true", "false"},
            "core.hookspath": {".githooks"},
            "gc.auto": {"0"},
            "maintenance.auto": {"false"},
            "remote.origin.fetch": {"+refs/heads/*:refs/remotes/origin/*"},
        }
        origin_urls = {RELEASE_SSH_ORIGIN}
        if not self.prepare:
            origin_urls.update(RELEASE_HTTPS_ORIGINS)
        allowed["remote.origin.url"] = origin_urls
        allowed["remote.origin.pushurl"] = origin_urls
        if self.prepare:
            allowed.update({
                "branch.main.merge": {"refs/heads/main"},
                "branch.main.remote": {"origin"},
            })
        for key, value in entries.items():
            if key not in allowed or value not in allowed[key]:
                raise SystemExit(f"prohibited local Git configuration: {key}")
        required = {
            "core.repositoryformatversion",
            "core.filemode",
            "core.bare",
            "core.logallrefupdates",
            "remote.origin.fetch",
            "remote.origin.url",
        }
        if self.prepare:
            required.update({"branch.main.merge", "branch.main.remote"})
        missing = sorted(required - entries.keys())
        if missing:
            raise SystemExit(
                "local Git configuration lacks required structural key(s): "
                + ", ".join(missing))
        origin = entries["remote.origin.url"]
        if entries.get("remote.origin.pushurl", origin) != origin:
            raise SystemExit("origin fetch and push URLs differ")
        return config_path, hashlib.sha256(config_bytes).hexdigest(), origin

    def _recheck_inputs(self) -> None:
        for label, path, expected in self._trusted_paths:
            try:
                actual = _path_snapshot(path)
            except OSError as exc:
                raise SystemExit(f"{label} became unavailable") from exc
            if actual != expected:
                raise SystemExit(f"{label} changed after profile admission")
        try:
            config_metadata = self._config_path.stat(follow_symlinks=False)
            if config_metadata.st_size > MAX_GIT_CONFIG_BYTES:
                raise SystemExit("local Git configuration exceeds the size limit")
            config_bytes = self._config_path.read_bytes()
        except OSError as exc:
            raise SystemExit("local Git configuration became unavailable") from exc
        if hashlib.sha256(config_bytes).hexdigest() != self._config_digest:
            raise SystemExit("local Git configuration changed after admission")

    def _purpose(self, args: tuple[str, ...]) -> str:
        if not args:
            raise SystemExit("release Git command is empty")
        command = args[0]
        object_id = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
        stable_tag = r"v[0-9]+\.[0-9]+\.[0-9]+"
        stable_ref = rf"refs/tags/{stable_tag}"

        def is_object_id(value: str) -> bool:
            return (
                re.fullmatch(object_id, value) is not None
                and any(character != "0" for character in value)
            )

        if command in self._NETWORK_COMMANDS:
            exact = False
            if command == "fetch":
                exact = args == (
                    "fetch", "--no-tags", RELEASE_SSH_ORIGIN,
                    "refs/heads/main:refs/remotes/origin/main",
                )
            elif command == "ls-remote":
                exact = args == (
                    "ls-remote", "--exit-code", "--heads", RELEASE_SSH_ORIGIN,
                    "refs/heads/main",
                )
                if len(args) == 5 and args[:4] == (
                    "ls-remote", "--exit-code", "--tags", RELEASE_SSH_ORIGIN,
                ):
                    exact = re.fullmatch(stable_ref, args[4]) is not None
            elif command == "push" and len(args) == 5 and args[:4] == (
                "push", "--porcelain", "--no-verify", RELEASE_SSH_ORIGIN,
            ):
                source, separator, destination = args[4].partition(":")
                exact = (
                    separator == ":"
                    and is_object_id(source)
                    and re.fullmatch(stable_ref, destination) is not None
                )
            if not self.prepare or not exact:
                raise SystemExit("release network Git requires the exact explicit SSH origin")
            return "transport"
        if command == "verify-tag":
            if (
                not self.prepare
                or len(args) != 2
                or not is_object_id(args[1])
            ):
                raise SystemExit("release signature verification requires an owner profile")
            return "verify"
        if command == "tag":
            if "--sign" in args:
                expected_message = f"Release {args[3]}" if len(args) > 3 else ""
                if (
                    not self.prepare
                    or len(args) != 6
                    or args[:3] != ("tag", "--sign", "--annotate")
                    or re.fullmatch(
                        r"v[0-9]+\.[0-9]+\.[0-9]+", args[3]) is None
                    or args[4:] != ("--message", expected_message)
                ):
                    raise SystemExit("release Git refuses an unclassified tag operation")
                return "sign"
            raise SystemExit("release Git refuses an unclassified tag operation")
        if command == "update-ref":
            if (
                not self.prepare
                or len(args) != 5
                or args[:3] != ("update-ref", "--no-deref", "-d")
                or re.fullmatch(stable_ref, args[3]) is None
                or not is_object_id(args[4])
            ):
                raise SystemExit("release Git refuses an unclassified ref update")
            return "write"
        exact_read = args in {
            ("status", "--porcelain=v1", "--untracked-files=all"),
            ("symbolic-ref", "--short", "HEAD"),
            ("rev-parse", "HEAD"),
            ("rev-parse", "refs/remotes/origin/main"),
        }
        if command == "show-ref" and len(args) == 4:
            exact_read = (
                args[:3] == ("show-ref", "--verify", "--quiet")
                and re.fullmatch(stable_ref, args[3]) is not None
            )
        elif command == "cat-file" and len(args) == 3:
            exact_read = (
                args[1] in {"-t", "tag"}
                and (
                    re.fullmatch(stable_ref, args[2]) is not None
                    or is_object_id(args[2])
                )
            )
        elif command == "rev-parse":
            if len(args) == 2:
                exact_read = (
                    exact_read
                    or re.fullmatch(
                        rf"{stable_ref}(?:\^\{{(?:tag|commit)\}})?", args[1]) is not None
                    or (
                        args[1].endswith("^{commit}")
                        and is_object_id(args[1][:-9])
                    )
                )
            elif len(args) == 4:
                exact_read = (
                    args[:3] == ("rev-parse", "--verify", "--quiet")
                    and re.fullmatch(stable_ref, args[3]) is not None
                )
        if not exact_read:
            raise SystemExit("release Git refuses an unclassified read operation")
        return "read"

    def _profile(self, purpose: str) -> tuple[list[str], dict[str, str]]:
        config: list[str] = []
        environment: dict[str, str] = {}
        if purpose in {"sign", "verify"}:
            for key, value in (
                ("gpg.format", "ssh"),
                ("user.name", self.tagger_name or ""),
                ("user.email", self.tagger_email or ""),
                ("user.signingKey", os.fspath(self.signing_key)),
                ("gpg.ssh.program", os.fspath(self.ssh_keygen_executable)),
                ("gpg.ssh.allowedSignersFile", os.fspath(self.allowed_signers_file)),
            ):
                config.extend(("-c", f"{key}={value}"))
            if purpose == "sign":
                environment["SSH_AUTH_SOCK"] = os.fspath(self.ssh_auth_sock)
        if purpose == "transport":
            config.extend(("-c", "protocol.ssh.allow=always"))
            ssh_command = " ".join((
                os.fspath(self.ssh_executable),
                "-F", "/dev/null",
                "-oBatchMode=yes",
                "-oPasswordAuthentication=no",
                "-oKbdInteractiveAuthentication=no",
                "-oStrictHostKeyChecking=yes",
                "-oUpdateHostKeys=no",
                "-oClearAllForwardings=yes",
                "-oPermitLocalCommand=no",
                "-oProxyCommand=none",
                f"-oUserKnownHostsFile={self.known_hosts_file}",
                "-oGlobalKnownHostsFile=/dev/null",
                "-oIdentitiesOnly=yes",
                f"-oIdentityAgent={self.ssh_auth_sock}",
                f"-oIdentityFile={self.transport_key}",
            ))
            environment.update({
                "GIT_SSH_COMMAND": ssh_command,
                "GIT_SSH_VARIANT": "ssh",
                "SSH_AUTH_SOCK": os.fspath(self.ssh_auth_sock),
            })
        return config, environment

    def run(self, *args: str, text: bool = True) -> subprocess.CompletedProcess:
        purpose = self._purpose(args)
        self._recheck_inputs()
        profile_config, profile_environment = self._profile(purpose)
        environment = self._base_environment()
        environment.update(profile_environment)
        command = self._command_prefix() + profile_config + list(args)
        try:
            completed = _bounded_process(
                command,
                cwd=self.root,
                environment=environment,
                temporary_directory=self._private_home,
                timeout=GIT_OPERATION_TIMEOUT_SECONDS,
                limit=MAX_GIT_OUTPUT_BYTES,
                text=text,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReleaseGitCompletedError(
                f"release Git {args[0]} timed out after "
                f"{GIT_OPERATION_TIMEOUT_SECONDS}s",
                returncode=-signal.SIGKILL,
            ) from exc
        except OSError as exc:
            raise SystemExit(f"release Git {args[0]} could not start") from exc
        try:
            self._recheck_inputs()
        except SystemExit as exc:
            raise ReleaseGitCompletedError(
                f"release Git {args[0]} completed but postflight failed: {exc}",
                returncode=completed.returncode,
            ) from exc
        if completed.output_limit_exceeded:
            raise ReleaseGitCompletedError(
                f"release Git {args[0]} completed but output exceeded the size limit",
                returncode=completed.returncode,
            )
        return completed

    def output(self, *args: str) -> str:
        completed = self.run(*args)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "no detail").strip()
            detail = detail[:MAX_GIT_DIAGNOSTIC_BYTES]
            raise ReleaseGitCompletedError(
                f"release Git {args[0]} failed: {detail}",
                returncode=completed.returncode,
            )
        return completed.stdout.strip()

    def output_bytes(self, *args: str) -> bytes:
        completed = self.run(*args, text=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or b"no detail")
            detail = detail[:MAX_GIT_DIAGNOSTIC_BYTES].decode("utf-8", "replace").strip()
            raise ReleaseGitCompletedError(
                f"release Git {args[0]} failed: {detail}",
                returncode=completed.returncode,
            )
        return completed.stdout


_RELEASE_GIT: ReleaseGit | None = None


def _set_release_git(release_git: ReleaseGit | None) -> ReleaseGit | None:
    global _RELEASE_GIT
    previous = _RELEASE_GIT
    _RELEASE_GIT = release_git
    return previous


def _release_git() -> ReleaseGit:
    if _RELEASE_GIT is None:
        raise SystemExit("release Git profile is not configured")
    return _RELEASE_GIT


def _git(*args: str) -> str:
    return _release_git().output(*args)


def _git_bytes(*args: str) -> bytes:
    return _release_git().output_bytes(*args)


def _verify_git_object_id(oid: str, kind: str, payload: bytes) -> None:
    algorithms = {40: hashlib.sha1, 64: hashlib.sha256}
    algorithm = algorithms.get(len(oid))
    if algorithm is None or any(character not in "0123456789abcdef" for character in oid):
        raise SystemExit("release Git object has an unsupported identifier")
    header = f"{kind} {len(payload)}\0".encode("ascii")
    if algorithm(header + payload).hexdigest() != oid:
        raise SystemExit("release Git object bytes do not match their identifier")


def _content_scanner():
    path = ROOT / ".github" / "scripts" / "check_content_marks.py"
    name = "causal_continuity_engine_release_content_marks"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release content-integrity scanner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _scan_tag_object(tag: str, payload: bytes) -> None:
    scanner = _content_scanner()
    findings = scanner.scan_blob(f"<tag:{tag}>", payload, text_required=True)
    incomplete = [finding for finding in findings if finding.status == scanner.INCONCLUSIVE]
    if incomplete:
        raise SystemExit(
            f"release tag object content-integrity scan is incomplete: {incomplete[0].code}"
        )
    if findings:
        raise SystemExit(
            f"release tag object contains prohibited content: {findings[0].code}"
        )


def _validated_repository(repository: object) -> str:
    if not isinstance(repository, str) or repository != repository.strip():
        raise SystemExit("GitHub repository must be an owner/name slug")
    parts = repository.split("/")
    if (
        len(parts) != 2
        or any(_GITHUB_REPOSITORY_COMPONENT.fullmatch(part) is None for part in parts)
        or any(part in {".", ".."} for part in parts)
    ):
        raise SystemExit("GitHub repository must be an owner/name slug")
    return repository


def _github_repository() -> str:
    return _validated_repository(os.environ.get("GITHUB_REPOSITORY"))


def _validated_https_url(value: object, *, label: str, origin_only: bool) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SystemExit(f"{label} must be a canonical HTTPS URL")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise SystemExit(f"{label} must be a canonical HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
        or (origin_only and parsed.path not in {"", "/"})
    ):
        raise SystemExit(f"{label} must be a canonical HTTPS URL")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = "" if origin_only else parsed.path.rstrip("/")
    return urllib.parse.urlunsplit(("https", netloc, path, "", ""))


def _github_server_url() -> str:
    raw = os.environ.get("GITHUB_SERVER_URL")
    server = _validated_https_url(
        "https://github.com" if raw is None else raw,
        label="GITHUB_SERVER_URL",
        origin_only=True,
    )
    if server != "https://github.com":
        raise SystemExit("GITHUB_SERVER_URL is outside the public GitHub allowlist")
    return server


def _github_api_url() -> str:
    _github_server_url()
    raw = os.environ.get("GITHUB_API_URL")
    if raw is None:
        raw = "https://api.github.com"
    api = _validated_https_url(
        raw, label="GITHUB_API_URL", origin_only=False)
    if api != "https://api.github.com":
        raise SystemExit(
            "GITHUB_API_URL is outside the public GitHub API allowlist")
    return api


def _github_json(path: str) -> dict:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if (
        not isinstance(token, str)
        or not token
        or token != token.strip()
        or any(ord(char) < 33 or ord(char) == 127 for char in token)
    ):
        raise SystemExit("GitHub verification requires GITHUB_TOKEN or GH_TOKEN")
    api = _github_api_url()
    url = f"{api}/{path.lstrip('/')}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _GITHUB_OPENER.open(request, timeout=15) as response:
            if response.status != 200 or response.geturl() != url:
                raise SystemExit("GitHub verification response changed origin or status")
            payload = response.read(MAX_GITHUB_JSON_BYTES + 1)
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise SystemExit(f"GitHub verification request failed: {exc}") from exc
    return _strict_json_object(payload, label="GitHub response")


def _verification(payload: object, *, label: str) -> dict:
    required = {"verified", "reason", "signature", "payload", "verified_at"}
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise SystemExit(f"GitHub returned malformed {label} verification metadata")
    if (
        type(payload["verified"]) is not bool
        or not isinstance(payload["reason"], str)
        or not payload["reason"]
        or not isinstance(payload["signature"], (str, type(None)))
        or not isinstance(payload["payload"], (str, type(None)))
        or not isinstance(payload["verified_at"], (str, type(None)))
    ):
        raise SystemExit(f"GitHub returned malformed {label} verification metadata")
    if payload["verified"] is True and (
        not isinstance(payload["signature"], str)
        or not payload["signature"]
        or not isinstance(payload["payload"], str)
        or not payload["payload"]
        or not isinstance(payload["verified_at"], str)
        or not payload["verified_at"]
    ):
        raise SystemExit(f"GitHub returned malformed verified {label} metadata")
    return payload


def _verify_github_tag(tag_object: str, repository: str | None = None) -> None:
    repository = urllib.parse.quote(
        _validated_repository(repository) if repository is not None
        else _github_repository(),
        safe="/",
    )
    payload = _github_json(f"repos/{repository}/git/tags/{tag_object}")
    if payload.get("sha") != tag_object:
        raise SystemExit("GitHub returned tag verification for the wrong object")
    verification = _verification(
        payload.get("verification"), label="tag-object signature")
    if verification["verified"] is not True:
        reason = verification.get("reason", "unknown")
        raise SystemExit(f"GitHub did not verify the annotated tag signature: {reason}")


def _verify_github_commit(commit: str, repository: str | None = None) -> None:
    repository = urllib.parse.quote(
        _validated_repository(repository) if repository is not None
        else _github_repository(),
        safe="/",
    )
    payload = _github_json(f"repos/{repository}/commits/{commit}")
    commit_metadata = payload.get("commit")
    if payload.get("sha") != commit or not isinstance(commit_metadata, dict):
        raise SystemExit("GitHub returned commit verification for the wrong object")
    verification = _verification(
        commit_metadata.get("verification"), label="commit signature")
    if verification["verified"] is not True:
        reason = verification.get("reason", "unknown")
        raise SystemExit(f"GitHub did not verify the release commit signature: {reason}")


def _signed_tag_headers(tag_body: str) -> dict[str, str]:
    """Parse the signed annotated-tag headers, excluding message/signature."""
    header_block = tag_body.split("\n\n", 1)[0]
    headers: dict[str, str] = {}
    for line in header_block.splitlines():
        if not line or line[0].isspace():
            continue
        key, separator, value = line.partition(" ")
        if separator and key not in headers:
            headers[key] = value
    return headers


def _workflow_run_id(details_url: object, repository: str) -> str | None:
    if not isinstance(details_url, str):
        return None
    repository = _validated_repository(repository)
    server = _github_server_url()
    prefix = f"{server}/{repository}/actions/runs/"
    if not details_url.startswith(prefix):
        return None
    run_id = details_url[len(prefix):].split("/", 1)[0]
    return run_id if run_id.isdecimal() else None


def _workflow_path_matches(actual: object, expected: str) -> bool:
    """Match GitHub's exact workflow path, with its optional @ref suffix."""
    if not isinstance(actual, str):
        return False
    path, separator, ref = actual.partition("@")
    return path == expected and (not separator or bool(ref))


def _check_runs(repository: str, commit: str) -> list[dict]:
    repository = _validated_repository(repository)
    encoded = urllib.parse.quote(repository, safe="/")
    runs: list[dict] = []
    for page in range(1, 11):
        payload = _github_json(
            f"repos/{encoded}/commits/{commit}/check-runs?"
            f"filter=latest&per_page=100&page={page}")
        batch = payload.get("check_runs")
        if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):
            raise SystemExit("GitHub returned malformed check-run metadata")
        runs.extend(batch)
        if len(batch) < 100:
            return runs
    raise SystemExit("release commit has more than 1,000 check runs; refusing ambiguity")


def _github_completed_at(value: object, *, check_name: str) -> datetime:
    if not isinstance(value, str) or _GITHUB_UTC_TIMESTAMP.fullmatch(value) is None:
        raise SystemExit(
            f"release check {check_name!r} has malformed completed_at metadata")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SystemExit(
            f"release check {check_name!r} has malformed completed_at metadata") from exc


def _latest_required_check(
        check_runs: list[dict], *, check_name: str, commit: str,
        integration_id: int, now: datetime, max_age: timedelta,
        future_skew: timedelta) -> dict | None:
    """Return the sole fresh latest exact-SHA check, irrespective of conclusion."""
    candidates: list[tuple[datetime, dict]] = []
    identifiers: set[int] = set()
    for check in check_runs:
        app = check.get("app") or {}
        if (
            check.get("name") != check_name
            or check.get("head_sha") != commit
            or not isinstance(app, dict)
            or app.get("id") != integration_id
        ):
            continue
        identifier = check.get("id")
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier <= 0:
            raise SystemExit(
                f"release check {check_name!r} has malformed check-run identity")
        if identifier in identifiers:
            raise SystemExit(
                f"release check {check_name!r} has duplicate check-run identity")
        identifiers.add(identifier)
        if check.get("status") != "completed":
            raise SystemExit(
                f"latest release check {check_name!r} is not completed")
        completed_at = _github_completed_at(
            check.get("completed_at"), check_name=check_name)
        if completed_at > now + future_skew:
            raise SystemExit(
                f"release check {check_name!r} completed_at is implausibly in the future")
        candidates.append((completed_at, check))

    if not candidates:
        return None
    latest_time = max(completed_at for completed_at, _ in candidates)
    latest = [check for completed_at, check in candidates if completed_at == latest_time]
    if len(latest) != 1:
        raise SystemExit(
            f"release check {check_name!r} has ambiguous latest completed runs")
    if latest_time < now - max_age:
        raise SystemExit(
            f"release check {check_name!r} is older than GitHub's seven-day "
            "required-check window")
    return latest[0]


def _verify_required_checks(
        commit: str, repository: str | None = None,
        source_root: Path = ROOT, *, now: datetime | None = None,
        max_age: timedelta = GITHUB_REQUIRED_CHECK_MAX_AGE,
        future_skew: timedelta = GITHUB_REQUIRED_CHECK_MAX_FUTURE_SKEW) -> None:
    """Require exact-SHA push checks from their expected Actions workflows."""
    if not isinstance(max_age, timedelta) or not (
            timedelta(0) < max_age <= GITHUB_REQUIRED_CHECK_MAX_AGE):
        raise SystemExit("required-check max_age must be positive and at most seven days")
    if not isinstance(future_skew, timedelta) or not (
            timedelta(0) <= future_skew <= GITHUB_REQUIRED_CHECK_MAX_FUTURE_SKEW):
        raise SystemExit(
            "required-check future_skew must be between zero and five minutes")
    now = now or datetime.now(timezone.utc)
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
    ):
        raise SystemExit("required-check reference time must be timezone-aware UTC")
    now = now.astimezone(timezone.utc)
    repository = (
        _validated_repository(repository) if repository is not None
        else _github_repository()
    )
    check_runs = _check_runs(repository, commit)
    workflow_cache: dict[str, dict] = {}
    missing: list[str] = []
    encoded = urllib.parse.quote(repository, safe="/")

    for check_name, (integration_id, expected_path) in _required_checks(
            source_root).items():
        trusted = False
        check = _latest_required_check(
            check_runs,
            check_name=check_name,
            commit=commit,
            integration_id=integration_id,
            now=now,
            max_age=max_age,
            future_skew=future_skew,
        )
        if check is not None and check.get("conclusion") == "success":
            run_id = _workflow_run_id(check.get("details_url"), repository)
            if run_id is not None and run_id not in workflow_cache:
                workflow_cache[run_id] = _github_json(
                    f"repos/{encoded}/actions/runs/{run_id}")
            run = workflow_cache.get(run_id) if run_id is not None else None
            if isinstance(run, dict) and (
                run.get("head_sha") == commit
                and _workflow_path_matches(run.get("path"), expected_path)
                and run.get("event") == "push"
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
            ):
                trusted = True
        if not trusted:
            missing.append(f"{check_name} from {expected_path}")

    if missing:
        raise SystemExit(
            "release commit lacks successful trusted exact-SHA checks: "
            + ", ".join(missing))


def _check_release_tag(args: argparse.Namespace) -> int:
    version = _release_version()
    metadata_version = _verify_release_metadata(args.tag)
    if metadata_version != version:
        raise SystemExit(
            "release metadata and package identity disagree: "
            f"{metadata_version!r} != {version!r}")
    expected = f"v{version}"
    if args.tag != expected:
        raise SystemExit(f"release tag {args.tag!r} does not match package version {expected!r}")
    tag_type = _git("cat-file", "-t", f"refs/tags/{args.tag}")
    if tag_type != "tag":
        raise SystemExit("release tags must be annotated, not lightweight")
    tag_bytes = _git_bytes("cat-file", "tag", f"refs/tags/{args.tag}")
    _scan_tag_object(args.tag, tag_bytes)
    try:
        tag_body = tag_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("release tag object is not valid UTF-8") from exc
    headers = _signed_tag_headers(tag_body)
    if headers.get("type") != "commit":
        raise SystemExit("release tag object must directly name a commit")
    if headers.get("tag") != args.tag:
        raise SystemExit(
            f"signed tag object names {headers.get('tag')!r}, not "
            f"release ref {args.tag!r}")
    if not any(marker in tag_body for marker in SIGNATURE_MARKERS):
        raise SystemExit("release tags must carry a PGP or SSH signature")
    tag_object = _git("rev-parse", f"refs/tags/{args.tag}^{{tag}}")
    _verify_git_object_id(tag_object, "tag", tag_bytes)
    tagged = _git("rev-parse", f"refs/tags/{args.tag}^{{commit}}")
    if headers.get("object") != tagged:
        raise SystemExit(
            "signed tag object header does not exactly match its peeled commit")
    head = _git("rev-parse", "HEAD")
    if tagged != head:
        raise SystemExit(f"tag points to {tagged}, but the workflow checked out {head}")
    if args.verify_github:
        _verify_github_tag(tag_object)
        _verify_github_commit(tagged)
    if args.verify_required_checks:
        _verify_required_checks(tagged)
    print(f"{args.tag} is a signed annotated tag for package {version} at {head}")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    release_git: ReleaseGit | None = None,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("--git-executable")
    parser.add_argument("--verify-github", action="store_true")
    parser.add_argument("--verify-required-checks", action="store_true")
    args = parser.parse_args(argv)
    owned = release_git is None
    if release_git is None:
        if args.git_executable is None:
            raise SystemExit("--git-executable is required")
        release_git = ReleaseGit.checker(
            root=ROOT, git_executable=args.git_executable)
    previous = _set_release_git(release_git)
    try:
        return _check_release_tag(args)
    finally:
        _set_release_git(previous)
        if owned:
            release_git.close()


if __name__ == "__main__":
    raise SystemExit(main())
