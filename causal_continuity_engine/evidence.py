"""Evidence quality: does a passing check actually mean the work is done?

A green check is not evidence. It is evidence only if it *could have been
red* for this deliverable. Three mechanical probes establish that, none of
which asks the subject to grade itself:

  negative control  — the check is shown failing against a known-bad state,
                      so a check that cannot fail is exposed as vacuous
  mutation probe    — destroy each declared artifact in a sandbox copy; some
                      required check must notice. A check that passes with
                      the deliverable deleted is not bound to the deliverable
  determinism probe — run twice; a check that disagrees with itself is not
                      evidence of anything

These are a mechanical LOWER BOUND on adequacy: they prove a check is bound
to the artifact's existence and content. They cannot prove it checks the
right property. Necessary, never sufficient — the grade is lint, not an
oracle (ADR-027).

The probes deliberately run against a sandbox copy. The real tree is never
touched.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from .core import digest_obj, sha256_hex, utcnow

# Trust state, VCS internals, caches, and dependency trees are not verifier
# subjects. They are omitted by the one materializer used for ordinary runs
# and evidence probes.
_WORKSPACE_IGNORED_NAMES = {
    ".git", ".hg", ".svn", ".cce", ".venv", "venv", "__pycache__",
    "node_modules", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}
WORKSPACE_MAX_ENTRIES = 100_000
WORKSPACE_MAX_FILE_BYTES = 64 * 1024 * 1024
WORKSPACE_MAX_TOTAL_BYTES = 512 * 1024 * 1024
WORKSPACE_MAX_DEPTH = 64
_WORKSPACE_READ_CHUNK = 1024 * 1024
_REPARSE_POINT = 0x400
ARTIFACT_PATH_MAX_LENGTH = 4_096
ARTIFACT_PATH_MAX_DEPTH = 64
ARTIFACT_COMPONENT_MAX_BYTES = 255
ARTIFACT_MAX_PATHS = 10_000

_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def normalize_artifact_path(value: object) -> str:
    """Return one portable physical-worktree route or reject it.

    An artifact declaration is persisted policy and later becomes both a
    filesystem operand and a signed-input label. Accepting host-dependent
    spellings would let the same policy route differently on POSIX and
    Windows, while accepting dot, parent, or empty aliases would let one
    deliverable disappear during set normalization.
    """
    error = (
        "artifact path must be a canonical project-relative path using "
        "forward slashes, with no empty, '.', '..', absolute, drive, UNC, "
        "reserved-device, forbidden-Windows-character, or alternate-stream "
        "component; no verifier-omitted trust, VCS, cache, bytecode, or "
        "dependency-tree component; and within the "
        f"{ARTIFACT_PATH_MAX_LENGTH}-character/"
        f"{ARTIFACT_PATH_MAX_DEPTH}-component and "
        f"{ARTIFACT_COMPONENT_MAX_BYTES}-byte component limits"
    )
    if (not isinstance(value, str) or not value
            or value != value.strip()
            or "\\" in value
            or "\x00" in value
            or len(value) > ARTIFACT_PATH_MAX_LENGTH
            or value.startswith("/")
            or PureWindowsPath(value).drive):
        raise ValueError(error)
    parts = value.split("/")
    if (len(parts) > ARTIFACT_PATH_MAX_DEPTH
            or any(part in ("", ".", "..") for part in parts)):
        raise ValueError(error)
    for part in parts:
        try:
            encoded_length = len(part.encode("utf-8"))
            utf16_units = len(part.encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            raise ValueError(error) from None
        if (":" in part or any(char in '<>"|?*' for char in part)
                or part.endswith((".", " "))
                or any(ord(char) < 32 for char in part)
                or encoded_length > ARTIFACT_COMPONENT_MAX_BYTES
                or utf16_units > ARTIFACT_COMPONENT_MAX_BYTES
                or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
                or _ignored_workspace_name(part)):
            raise ValueError(error)
    return value


def normalize_artifact_paths(values: object) -> list[str]:
    if not isinstance(values, list):
        raise ValueError(
            "verifier artifacts must be a list of canonical "
            "project-relative paths")
    if len(values) > ARTIFACT_MAX_PATHS:
        raise ValueError(
            f"verifier artifacts exceed the {ARTIFACT_MAX_PATHS}-path limit")
    normalized: list[str] = []
    seen: set[str] = set()
    folded: dict[str, str] = {}
    for value in values:
        path = normalize_artifact_path(value)
        if path in seen:
            continue
        alias = path.casefold()
        if alias in folded:
            raise ValueError(
                f"artifact paths {folded[alias]!r} and {path!r} are not "
                "portable because they differ only by case")
        seen.add(path)
        folded[alias] = path
        normalized.append(path)
    return normalized


class UnsafeWorkspaceError(ValueError):
    """The verifier subject cannot be copied into one bounded physical tree."""


@contextmanager
def _temporary_workspace_root(source: str | Path, *, prefix: str):
    """Yield a physical disposable root outside the verifier subject."""
    subject = Path(os.path.abspath(source)).resolve()
    configured = Path(tempfile.gettempdir()).resolve()
    configured_is_inside = (
        configured == subject or subject in configured.parents
    )
    parent = subject.parent if configured_is_inside else configured
    if parent == subject or subject in parent.parents:
        raise UnsafeWorkspaceError(
            "no temporary directory is available outside the verifier workdir")

    with tempfile.TemporaryDirectory(prefix=prefix, dir=parent) as temp:
        root = Path(temp).resolve()
        if root == subject or subject in root.parents:
            raise UnsafeWorkspaceError(
                "disposable verifier workspace resolved inside the workdir")
        try:
            info = os.lstat(root)
        except OSError as exc:
            raise UnsafeWorkspaceError(
                "disposable verifier workspace is unreadable") from exc
        if _workspace_indirect(info) or not stat.S_ISDIR(info.st_mode):
            raise UnsafeWorkspaceError(
                "disposable verifier workspace must be a physical directory")
        yield root


def _workspace_stat_key(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
        getattr(info, "st_file_attributes", 0),
        getattr(info, "st_reparse_tag", 0),
    )


def _workspace_identity_key(info: os.stat_result) -> tuple:
    """Identity and route-safety fields unaffected by lazy timestamp refresh."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        getattr(info, "st_file_attributes", 0),
        getattr(info, "st_reparse_tag", 0),
    )


def _workspace_path_content_key(info: os.stat_result) -> tuple:
    """Stable path view; Windows path stats can lag descriptor ctime."""
    return (
        *_workspace_identity_key(info),
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
    )


def _workspace_indirect(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _ignored_workspace_name(name: str) -> bool:
    folded = name.casefold()
    return folded in _WORKSPACE_IGNORED_NAMES or folded.endswith(".pyc")


def _copy_workspace_file(
        source: Path, destination: Path, before: os.stat_result,
        counters: dict[str, int]) -> None:
    if before.st_size > WORKSPACE_MAX_FILE_BYTES:
        raise UnsafeWorkspaceError(
            f"workspace file {source.name!r} exceeds the "
            f"{WORKSPACE_MAX_FILE_BYTES}-byte per-file limit")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise UnsafeWorkspaceError(
            f"workspace file {source.name!r} is unreadable or changed") from exc
    copied = 0
    try:
        opened = os.fstat(descriptor)
        if (_workspace_indirect(opened)
                or not stat.S_ISREG(opened.st_mode)
                or _workspace_identity_key(opened)
                != _workspace_identity_key(before)):
            raise UnsafeWorkspaceError(
                f"workspace file {source.name!r} changed before copying")
        if opened.st_size > WORKSPACE_MAX_FILE_BYTES:
            raise UnsafeWorkspaceError(
                f"workspace file {source.name!r} exceeds the "
                f"{WORKSPACE_MAX_FILE_BYTES}-byte per-file limit")
        with destination.open("xb") as output:
            while True:
                chunk = os.read(descriptor, _WORKSPACE_READ_CHUNK)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > WORKSPACE_MAX_FILE_BYTES:
                    raise UnsafeWorkspaceError(
                        f"workspace file {source.name!r} grew beyond the "
                        f"{WORKSPACE_MAX_FILE_BYTES}-byte per-file limit")
                if counters["bytes"] + len(chunk) > WORKSPACE_MAX_TOTAL_BYTES:
                    raise UnsafeWorkspaceError(
                        "workspace exceeds the "
                        f"{WORKSPACE_MAX_TOTAL_BYTES}-byte total limit")
                output.write(chunk)
                counters["bytes"] += len(chunk)
        after_open = os.fstat(descriptor)
        after_path = os.lstat(source)
        if (_workspace_indirect(after_path)
                or _workspace_stat_key(after_open) != _workspace_stat_key(opened)
                or _workspace_path_content_key(after_path)
                != _workspace_path_content_key(opened)
                or copied != opened.st_size):
            raise UnsafeWorkspaceError(
                f"workspace file {source.name!r} changed while copying")
        os.chmod(destination, stat.S_IMODE(opened.st_mode))
    except OSError as exc:
        raise UnsafeWorkspaceError(
            f"workspace file {source.name!r} is unreadable or changed") from exc
    finally:
        os.close(descriptor)


def materialize_workspace(
        source: str | Path, destination: str | Path, *,
        excluded_paths: tuple[str | Path, ...] = (),
        preserved_paths: tuple[str | Path, ...] = (),
        _counters: dict[str, int] | None = None,
        _ignore_names: bool = True) -> Path:
    """Copy one bounded, physical verifier subject without following portals."""
    source = Path(os.path.abspath(source))
    destination = Path(destination)
    excluded = {
        Path(os.path.abspath(path))
        for path in excluded_paths
    }
    preserved = {
        Path(os.path.abspath(path))
        for path in preserved_paths
    }

    def is_preserved(path: Path) -> bool:
        return any(
            path == declared
            or path in declared.parents
            or declared in path.parents
            for declared in preserved
        )
    try:
        root_before = os.lstat(source)
    except OSError as exc:
        raise UnsafeWorkspaceError("verifier workdir is unreadable") from exc
    if _workspace_indirect(root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise UnsafeWorkspaceError(
            "verifier workdir must be a physical directory")
    if destination.exists():
        raise UnsafeWorkspaceError("workspace destination already exists")
    destination.mkdir(parents=True)
    counters = _counters if _counters is not None else {"entries": 0, "bytes": 0}

    def copy_directory(current: Path, target: Path, depth: int) -> None:
        if depth > WORKSPACE_MAX_DEPTH:
            raise UnsafeWorkspaceError(
                f"workspace exceeds the {WORKSPACE_MAX_DEPTH}-level depth limit")
        try:
            before_dir = os.lstat(current)
            names = sorted(os.listdir(current))
        except OSError as exc:
            raise UnsafeWorkspaceError(
                f"workspace directory {current.name!r} is unreadable") from exc
        if _workspace_indirect(before_dir) or not stat.S_ISDIR(before_dir.st_mode):
            raise UnsafeWorkspaceError(
                f"workspace route {current.name!r} is not a physical directory")
        for name in names:
            child = current / name
            # Excluded trust/control bytes always win. Ignored cache or
            # dependency names are retained only when they are descendants
            # of a declared directory artifact, so the command sees exactly
            # the bytes committed by that declaration.
            if (child in excluded
                    or (_ignore_names and _ignored_workspace_name(name)
                        and not is_preserved(child))):
                continue
            counters["entries"] += 1
            if counters["entries"] > WORKSPACE_MAX_ENTRIES:
                raise UnsafeWorkspaceError(
                    "workspace exceeds the "
                    f"{WORKSPACE_MAX_ENTRIES}-entry limit")
            try:
                before = os.lstat(child)
            except OSError as exc:
                raise UnsafeWorkspaceError(
                    f"workspace entry {name!r} changed before copying") from exc
            if _workspace_indirect(before):
                raise UnsafeWorkspaceError(
                    f"workspace entry {name!r} is a symlink or reparse point")
            child_target = target / name
            if stat.S_ISDIR(before.st_mode):
                child_target.mkdir()
                copy_directory(child, child_target, depth + 1)
                try:
                    after = os.lstat(child)
                except OSError as exc:
                    raise UnsafeWorkspaceError(
                        f"workspace directory {name!r} changed while copying") from exc
                if _workspace_identity_key(after) != _workspace_identity_key(before):
                    raise UnsafeWorkspaceError(
                        f"workspace directory {name!r} changed while copying")
                os.chmod(child_target, stat.S_IMODE(before.st_mode))
            elif stat.S_ISREG(before.st_mode):
                _copy_workspace_file(child, child_target, before, counters)
            else:
                raise UnsafeWorkspaceError(
                    f"workspace entry {name!r} is not a regular file or directory")
        try:
            after_dir = os.lstat(current)
            after_names = sorted(os.listdir(current))
        except OSError as exc:
            raise UnsafeWorkspaceError(
                f"workspace directory {current.name!r} changed while copying") from exc
        if (_workspace_identity_key(after_dir)
                != _workspace_identity_key(before_dir)
                or after_names != names):
            raise UnsafeWorkspaceError(
                f"workspace directory {current.name!r} changed while copying")

    try:
        copy_directory(source, destination, 0)
        root_after = os.lstat(source)
        if (_workspace_indirect(root_after)
                or _workspace_identity_key(root_after)
                != _workspace_identity_key(root_before)):
            raise UnsafeWorkspaceError(
                "verifier workdir changed while copying")
        os.chmod(destination, stat.S_IMODE(root_before.st_mode))
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return destination


def _verify_artifact_route(route: list[tuple[Path, tuple]], rel: str) -> None:
    for path, identity in route:
        try:
            current = os.lstat(path)
        except OSError as exc:
            raise UnsafeWorkspaceError(
                f"declared artifact {rel!r} route changed") from exc
        if (_workspace_indirect(current)
                or _workspace_identity_key(current) != identity):
            raise UnsafeWorkspaceError(
                f"declared artifact {rel!r} route changed")


def _copied_tree_digest(root: Path) -> str:
    records: list[dict] = []

    def visit(directory: Path, prefix: str = "") -> None:
        for name in sorted(os.listdir(directory)):
            child = directory / name
            logical = f"{prefix}/{name}" if prefix else name
            info = os.lstat(child)
            if _workspace_indirect(info):
                raise UnsafeWorkspaceError(
                    "artifact fingerprint copy contains an indirect route")
            if stat.S_ISDIR(info.st_mode):
                records.append({
                    "kind": "directory", "path": logical,
                    "mode": stat.S_IMODE(info.st_mode),
                })
                visit(child, logical)
            elif stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256()
                with child.open("rb") as stream:
                    while chunk := stream.read(_WORKSPACE_READ_CHUNK):
                        digest.update(chunk)
                records.append({
                    "kind": "file", "path": logical,
                    "mode": stat.S_IMODE(info.st_mode),
                    "size": info.st_size,
                    "digest": "sha256:" + digest.hexdigest(),
                })
            else:
                raise UnsafeWorkspaceError(
                    "artifact fingerprint copy contains a special file")

    visit(root)
    return digest_obj({"kind": "directory", "entries": records})


def fingerprint_artifacts(
        root: str | Path, artifacts: list[str], scratch: str | Path) -> dict[str, str]:
    """Bounded physical fingerprints for declared artifacts in one snapshot.

    The helper is deliberately separate from command exit-code handling: a
    verifier may create ordinary build outputs, but it may not rewrite the
    deliverable it is being trusted to evaluate. Missing paths, files, and
    complete directory trees all receive distinct deterministic identities.
    """
    root = Path(os.path.abspath(root))
    artifacts = normalize_artifact_paths(artifacts)
    scratch = Path(scratch)
    scratch.mkdir(parents=True)
    counters = {"entries": 0, "bytes": 0}
    fingerprints: dict[str, str] = {}
    root_info = os.lstat(root)
    if _workspace_indirect(root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise UnsafeWorkspaceError(
            "artifact fingerprint root must be a physical directory")

    for index, rel in enumerate(artifacts):
        route = [(root, _workspace_identity_key(root_info))]
        cursor = root
        target_info = None
        absent = False
        missing_route = False
        for position, part in enumerate(rel.split("/")):
            cursor /= part
            try:
                info = os.lstat(cursor)
            except FileNotFoundError:
                absent = True
                missing_route = True
                break
            except OSError as exc:
                raise UnsafeWorkspaceError(
                    f"declared artifact {rel!r} is unreadable") from exc
            if _workspace_indirect(info):
                raise UnsafeWorkspaceError(
                    f"declared artifact {rel!r} uses a symlink or reparse point")
            if position < len(rel.split("/")) - 1 and not stat.S_ISDIR(info.st_mode):
                absent = True
                break
            route.append((cursor, _workspace_identity_key(info)))
            target_info = info

        if absent or target_info is None:
            _verify_artifact_route(route, rel)
            if missing_route:
                try:
                    os.lstat(cursor)
                except FileNotFoundError:
                    pass
                else:
                    raise UnsafeWorkspaceError(
                        f"declared artifact {rel!r} route appeared while fingerprinting")
            fingerprints[rel] = sha256_hex("<absent>")
            continue

        artifact_scratch = scratch / f"artifact-{index:05d}"
        if stat.S_ISREG(target_info.st_mode):
            artifact_scratch.mkdir()
            copied = artifact_scratch / "value"
            counters["entries"] += 1
            if counters["entries"] > WORKSPACE_MAX_ENTRIES:
                raise UnsafeWorkspaceError(
                    f"artifact fingerprints exceed the {WORKSPACE_MAX_ENTRIES}-entry limit")
            _copy_workspace_file(cursor, copied, target_info, counters)
            digest = hashlib.sha256()
            with copied.open("rb") as stream:
                while chunk := stream.read(_WORKSPACE_READ_CHUNK):
                    digest.update(chunk)
            fingerprints[rel] = digest_obj({
                "kind": "file", "mode": stat.S_IMODE(target_info.st_mode),
                "size": target_info.st_size,
                "digest": "sha256:" + digest.hexdigest(),
            })
        elif stat.S_ISDIR(target_info.st_mode):
            materialize_workspace(
                cursor, artifact_scratch, _counters=counters,
                _ignore_names=False)
            fingerprints[rel] = digest_obj({
                "kind": "directory",
                "mode": stat.S_IMODE(target_info.st_mode),
                "tree": _copied_tree_digest(artifact_scratch),
            })
        else:
            raise UnsafeWorkspaceError(
                f"declared artifact {rel!r} is not a regular file or directory")
        _verify_artifact_route(route, rel)
    return fingerprints


MUTATIONS = ("absent", "truncate")

GRADES = ("A", "B", "C", "D", "F")


@dataclass
class ControlResult:
    """A negative control: a command that MUST fail. If it passes, the check
    cannot distinguish done from not-done."""

    command: str
    status: str            # held | unmet | absent | inconclusive
    exit_code: int | None = None
    details: str = ""

    def to_dict(self) -> dict:
        return {"command_present": bool(self.command), "status": self.status,
                "exit_code": self.exit_code, "details": self.details}


@dataclass
class MutationReport:
    artifacts: list[str] = field(default_factory=list)
    detected: list[dict] = field(default_factory=list)
    undetected: list[dict] = field(default_factory=list)
    #: Mutations where no check FAILED but at least one crashed or timed out.
    #: A third state, because "the check did not run" is neither evidence of
    #: binding nor evidence of its absence (ADR-066).
    inconclusive: list[dict] = field(default_factory=list)
    #: Each check's result on an UNMUTATED copy, which is what makes an
    #: inconclusive mutated run readable. See run_mutation_probe.
    baseline: dict[str, str] = field(default_factory=dict)
    ran_at: str = ""
    error: str | None = None

    @property
    def bound(self) -> bool:
        """Every mutation of every declared artifact was noticed by a check
        that actually ran and FAILED.

        An inconclusive run used to count as a detection, so a check that
        crashed in the sandbox — a missing dependency, a different cwd, no
        network — reported every mutation as caught and graded the evidence
        as bound. That is the engine's own rule inverted: absence of success
        is never success, and a check that did not run observed nothing.
        """
        return (bool(self.artifacts) and bool(self.baseline)
                and all(result == "passed" for result in self.baseline.values())
                and bool(self.detected) and not self.undetected
                and not self.inconclusive and not self.error)

    def to_dict(self) -> dict:
        return {"artifacts": self.artifacts, "detected": self.detected,
                "undetected": self.undetected,
                "inconclusive": self.inconclusive, "baseline": self.baseline,
                "bound": self.bound, "ran_at": self.ran_at,
                "error": self.error}


@dataclass
class EvidenceGrade:
    grade: str
    reasons: list[str] = field(default_factory=list)
    caps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"grade": self.grade, "reasons": self.reasons, "caps": self.caps}

    def at_least(self, minimum: str) -> bool:
        return GRADES.index(self.grade) <= GRADES.index(minimum)


class SandboxEscape(Exception):
    """The artifact resolves outside the sandbox, so mutating it would
    destroy the real thing."""


def _resolved_inside(sandbox: Path, target: Path) -> Path:
    """Resolve through symlinks and refuse anything that leaves the sandbox.

    Physical subject materialization now rejects links before a probe starts.
    This remains a defence-in-depth boundary for a synthetic or independently
    supplied sandbox: writing through a link could otherwise truncate a real
    file outside the probe. The string guard on the artifact name cannot catch
    that escape because it lives in the filesystem, not the path text.
    """
    root = sandbox.resolve()
    resolved = target.resolve()
    if resolved != root and root not in resolved.parents:
        raise SandboxEscape(
            f"{target.name!r} resolves to {resolved}, outside the probe sandbox")
    return resolved


def _apply_mutation(sandbox: Path, artifact: str, mutation: str) -> bool:
    """Destroy one artifact inside the sandbox. Returns False if absent.

    Never follows a symlink out of the sandbox: a link is removed as a link,
    and anything resolving outside raises SandboxEscape.
    """
    target = sandbox / artifact
    if target.is_symlink():
        # Mutating the LINK is the honest interpretation: the deliverable is
        # the link, and destroying it must not touch whatever it points at.
        _resolved_inside(sandbox, target.parent)
        if mutation == "absent":
            target.unlink()
            return True
        # "truncate" of a symlink: retarget it at nothing rather than write
        # through it.
        target.unlink()
        target.symlink_to(sandbox / "__cce_probe_missing__")
        return True
    if not target.exists():
        return False
    _resolved_inside(sandbox, target)
    if mutation == "absent":
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    elif mutation == "truncate":
        if target.is_dir():
            for child in target.rglob("*"):
                if child.is_symlink() or not child.is_file():
                    continue
                _resolved_inside(sandbox, child)
                child.write_bytes(b"")
        else:
            target.write_bytes(b"")
    else:
        raise ValueError(f"unknown mutation {mutation!r}")
    return True


def run_mutation_probe(
    *,
    workdir: str | Path,
    artifacts: list[str],
    specs: list,
    runner_factory,
    mutations: tuple[str, ...] = MUTATIONS,
    excluded_paths: tuple[str | Path, ...] = (),
) -> MutationReport:
    """Copy the tree, destroy each declared artifact, re-run the checks.

    `runner_factory(sandbox_path)` returns a VerifierRunner bound to the
    sandbox. Every mutation must make at least one required check fail; a
    mutation that survives proves the evidence is not bound to the outcome's
    deliverable.

    A BASELINE run on an unmutated copy comes first. Only a mutated run that
    reaches an actual failed verdict counts as detection. A crash, timeout, or
    startup failure observed after mutation remains inconclusive even when the
    baseline passed: it shows correlation with the mutation, not that the
    check evaluated the promised property (ADR-066).
    """
    try:
        artifacts = normalize_artifact_paths(artifacts)
    except ValueError as exc:
        report = MutationReport(artifacts=[], ran_at=utcnow())
        report.error = str(exc)
        report.undetected.append({
            "artifact": "<invalid-declaration>",
            "mutation": "n/a",
            "why": str(exc),
        })
        return report
    report = MutationReport(artifacts=list(artifacts), ran_at=utcnow())
    if not artifacts:
        report.error = "no declared artifacts: binding cannot be established"
        return report
    if not specs:
        report.error = "no checks to probe"
        return report
    source = Path(os.path.abspath(workdir))
    preserved_artifacts = tuple(
        source.joinpath(*artifact.split("/")) for artifact in artifacts)

    try:
        with _temporary_workspace_root(
                source, prefix="cce-probe-base-") as temp_root:
            pristine = temp_root / "workspace"
            materialize_workspace(
                source, pristine, excluded_paths=excluded_paths,
                preserved_paths=preserved_artifacts)
            baseline_runner = runner_factory(str(pristine))
            for spec in specs:
                report.baseline[spec.name] = baseline_runner.run(spec).result
    except (UnsafeWorkspaceError, OSError) as exc:
        report.error = f"could not materialize verifier workspace: {exc}"
        report.inconclusive.append({
            "artifact": "<unmutated-tree>", "mutation": "baseline",
            "why": report.error,
        })
        return report

    baseline_failures = {name: result for name, result in report.baseline.items()
                         if result != "passed"}
    if baseline_failures:
        # A verifier that is already red on the pristine tree cannot be
        # credited for also being red after destruction. That is no causal
        # contrast at all: the mutation changed neither the verdict nor what
        # the check established.
        detail = ", ".join(f"{name}={result}" for name, result
                           in sorted(baseline_failures.items()))
        report.error = f"baseline did not pass: {detail}"
        report.inconclusive.append({
            "artifact": "<unmutated-tree>", "mutation": "baseline",
            "why": "required checks must pass before mutation detection can be measured",
            "checks": baseline_failures,
        })
        return report

    for artifact in artifacts:
        for mutation in mutations:
            try:
                with _temporary_workspace_root(
                        source, prefix="cce-probe-") as temp_root:
                    sandbox = temp_root / "workspace"
                    materialize_workspace(
                        source, sandbox, excluded_paths=excluded_paths,
                        preserved_paths=preserved_artifacts)
                    try:
                        applied = _apply_mutation(sandbox, artifact, mutation)
                    except SandboxEscape as exc:
                        report.undetected.append({
                            "artifact": artifact, "mutation": mutation,
                            "why": f"refused: {exc}"})
                        continue
                    except OSError as exc:
                        report.undetected.append({
                            "artifact": artifact, "mutation": mutation,
                            "why": f"could not mutate the artifact: {exc}"})
                        continue
                    if not applied:
                        report.undetected.append({
                            "artifact": artifact, "mutation": mutation,
                            "why": "artifact not present in the tree at probe time"})
                        continue
                    runner = runner_factory(str(sandbox))
                    noticed_by, crashed = None, []
                    for spec in specs:
                        outcome = runner.run(spec)
                        if outcome.result == "failed":
                            noticed_by = spec.name
                            break
                        if outcome.result == "inconclusive":
                            crashed.append(
                                f"{spec.name}: {outcome.details}"[:160])
                    if noticed_by:
                        report.detected.append({
                            "artifact": artifact, "mutation": mutation,
                            "noticed_by": noticed_by})
                    elif crashed:
                        report.inconclusive.append({
                            "artifact": artifact, "mutation": mutation,
                            "why": "no check failed, and these did not run to a "
                                   "verdict, so binding is undetermined",
                            "checks": crashed})
                    else:
                        report.undetected.append({
                            "artifact": artifact, "mutation": mutation,
                            "why": "every required check still passed with the "
                                   "deliverable destroyed"})
            except (UnsafeWorkspaceError, OSError) as exc:
                report.inconclusive.append({
                    "artifact": artifact, "mutation": mutation,
                    "why": f"could not materialize verifier workspace: {exc}",
                })
    return report


def run_determinism_probe(spec, runner) -> dict:
    """Run a check twice. Stability requires two successful verdicts."""
    first = runner.run(spec)
    second = runner.run(spec)
    results = [first.result, second.result]
    stable = results == ["passed", "passed"]
    if stable:
        note = ""
    elif first.result != second.result:
        note = "check is flaky: two runs disagreed"
    else:
        note = ("check repeated a non-passing verdict; consistency of failure "
                "does not establish usable evidence")
    return {
        "stable": stable,
        "results": results,
        "checked_at": utcnow(),
        "note": note,
    }


def grade_evidence(
    *,
    outcomes: list[dict],
    required: list[str],
    controls: dict[str, dict] | None = None,
    mutation: MutationReport | None = None,
    determinism: dict[str, dict] | None = None,
    unpinned_required: list[str] | None = None,
) -> EvidenceGrade:
    """Grade how hard this evidence would be to fake. Lint, not an oracle.

    A  every required check executed by CCE under a pinned command, each with
       a negative control shown holding, deliverables mutation-bound, and no
       flaky check
    B  as A but without mutation binding OR without a determinism probe
    C  executed and pinned, but no negative control: the check has not been
       shown capable of failing
    D  a required check ran under a command the claimant chose, or a declared
       deliverable survived destruction unnoticed
    F  a required result was self-asserted, missing, or failing
    """
    if (not isinstance(outcomes, list)
            or any(not isinstance(outcome, dict) for outcome in outcomes)):
        raise ValueError("evidence outcomes must be an array of objects")

    def verifier_names(value, *, field: str) -> list[str]:
        if (not isinstance(value, list)
                or any(not isinstance(name, str) or not name for name in value)):
            raise ValueError(
                f"evidence {field} must be an array of non-empty strings")
        if len(value) != len(set(value)):
            raise ValueError(
                f"evidence {field} must not contain duplicate names")
        return list(value)

    required = verifier_names(required, field="required")
    if controls is None:
        controls = {}
    if (not isinstance(controls, dict)
            or any(not isinstance(name, str) or not name
                   or not isinstance(control, dict)
                   for name, control in controls.items())):
        raise ValueError(
            "evidence controls must be an object of verifier objects")
    if determinism is None:
        determinism = {}
    if (not isinstance(determinism, dict)
            or any(not isinstance(name, str) or not name
                   or not isinstance(probe, dict)
                   for name, probe in determinism.items())):
        raise ValueError(
            "evidence determinism must be an object of verifier objects")
    if unpinned_required is None:
        unpinned_required = []
    unpinned_required = verifier_names(
        unpinned_required, field="unpinned_required")
    if mutation is not None and not isinstance(mutation, MutationReport):
        raise ValueError(
            "evidence mutation must be a MutationReport or null")
    reasons: list[str] = []
    caps: list[str] = []

    by_name = {o.get("verifier"): o for o in outcomes}

    # --- F conditions: the evidence does not exist -----------------------
    for name in required:
        outcome = by_name.get(name)
        if outcome is None:
            reasons.append(f"required check {name!r} produced no result")
            return EvidenceGrade("F", reasons, caps)
        if outcome.get("result") != "passed":
            reasons.append(
                f"required check {name!r} is {outcome.get('result')!r}")
            return EvidenceGrade("F", reasons, caps)
        if outcome.get("source") != "executed":
            reasons.append(
                f"required check {name!r} was {outcome.get('source')}, not run by CCE")
            return EvidenceGrade("F", reasons, caps)
    if not required:
        reasons.append("no required checks are declared")
        return EvidenceGrade("F", reasons, caps)

    grade = "A"

    def cap(at: str, why: str):
        nonlocal grade
        caps.append(why)
        if GRADES.index(at) > GRADES.index(grade):
            grade = at

    # --- D conditions: ran, but not bound to anything the claimant can't pick
    for name in required:
        if name in unpinned_required:
            cap("D", f"required check {name!r} ran a command the claimant "
                     f"supplied; the policy pins no command for it")
    if mutation is not None and not mutation.bound:
        if mutation.error:
            detail = mutation.error
        elif mutation.undetected:
            detail = f"{len(mutation.undetected)} mutation(s) survived"
        else:
            # Undetermined, not disproven. Still not an A/B claim of binding,
            # but it is a different failure from a mutation that survived, and
            # saying so is the difference between "your check ignores the
            # deliverable" and "your check never ran" (ADR-066).
            detail = (f"{len(mutation.inconclusive)} mutation(s) left binding "
                      f"undetermined: a required check did not run to a verdict")
        cap("D", f"deliverables are not bound to the checks: {detail}")

    # --- C condition: never shown capable of failing ---------------------
    missing_controls = [n for n in required
                        if controls.get(n, {}).get("status") != "held"]
    if missing_controls:
        unmet = [n for n in missing_controls
                 if controls.get(n, {}).get("status") == "unmet"]
        if unmet:
            cap("C", f"negative control did not fail for {unmet}: the check "
                     f"cannot distinguish done from not-done")
        else:
            cap("C", f"no negative control for {missing_controls}: never shown "
                     f"capable of failing")

    # --- B conditions: shown-good but unproven binding / stability --------
    if mutation is None:
        cap("B", "no mutation probe: artifact binding unproven")
    missing_determinism = [n for n in required if n not in determinism]
    unstable = [n for n in required if n in determinism and (
        not determinism[n].get("stable", False)
        or determinism[n].get("results") != ["passed", "passed"])]
    if unstable:
        cap("C", f"unstable check(s) {unstable}: determinism requires two passes")
    if missing_determinism:
        cap("B", f"no determinism probe for {missing_determinism}: stability unproven")

    if grade == "A":
        reasons.append("every required check was executed under a pinned "
                       "command, shown able to fail, bound to the deliverable, "
                       "and stable across runs")
    return EvidenceGrade(grade, reasons, caps)
