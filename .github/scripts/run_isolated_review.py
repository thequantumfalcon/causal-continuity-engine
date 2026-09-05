"""Run an external reviewer across a one-way, Git-free boundary.

This launcher is deliberately stricter than a normal development sandbox.
A trusted root supervisor starts the command under an explicitly named,
dedicated, non-admin operating-system account that cannot write the protected
repository.  Seatbelt then denies the entire review process tree both read and
write access to every worktree and the common Git store, and denies writes
everywhere except a new quarantine directory.

Only bounded scalar finding coordinates can cross back through stdout.  Raw
review output remains quarantined, and the protected manifest must still
match before a successful result is accepted.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import resource
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_PROTECTED_ENTRIES = 200_000
MAX_PROTECTED_BYTES = 1 << 30
MAX_EXPORT_FILES = 100_000
MAX_EXPORT_FILE_BYTES = 64 << 20
MAX_EXPORT_BYTES = 512 << 20
MAX_FINDINGS = 1_000
MAX_FINDINGS_BYTES = 1 << 20
MAX_XATTR_BYTES = 4 << 20
MAX_QUARANTINE_ENTRIES = 10_000
MAX_QUARANTINE_BYTES = 256 << 20
DEFAULT_TIMEOUT_SECONDS = 1_800
REVIEW_COMMAND_FAILURE = 124
BOUNDARY_FAILURE = 125
FINDINGS_SCHEMA = "cce.external-review-findings.v1"
INPUT_SCHEMA = "cce.external-review-input.v1"
FINDING_CATEGORIES = frozenset(
    {"correctness", "security", "performance", "consistency", "reversibility"}
)
FINDING_SEVERITIES = frozenset({"blocker", "high", "medium", "low"})
_TRUSTED_LAUNCHER_ROOTS = (
    Path("/Library/PrivilegedHelperTools"),
    Path("/usr/local/libexec"),
)


class BoundaryError(RuntimeError):
    """The isolation boundary could not be established or verified."""


@dataclass(frozen=True)
class ManifestEntry:
    root: bytes
    relative_path: bytes
    kind: str
    mode: int
    uid: int
    gid: int
    device: int
    inode: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int
    digest: bytes
    xattr_digest: bytes


@dataclass(frozen=True)
class SnapshotEntry:
    file_id: int
    relative_path: bytes
    size: int
    digest: bytes
    line_count: int


@dataclass(frozen=True)
class ReviewerIdentity:
    name: str
    uid: int
    gid: int
    home: Path
    supplementary_groups: tuple[int, ...]


@dataclass(frozen=True)
class _SourceEntry:
    relative_path: bytes
    index_mode: int | None


@dataclass(frozen=True)
class _SourceState:
    relative_path: bytes
    present: bool
    identity: tuple[int, ...] | None
    digest: bytes | None


def _git(repo: Path, *arguments: str) -> bytes:
    try:
        safe_directory = repo.expanduser().resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("cannot resolve repository path") from exc
    try:
        result = subprocess.run(
            [
                "/usr/bin/git",
                "-c",
                f"safe.directory={safe_directory}",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                os.fspath(safe_directory),
                *arguments,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": "/var/empty",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )
    except OSError as exc:
        raise BoundaryError("cannot execute Git") from exc
    if result.returncode != 0:
        raise BoundaryError("Git repository query failed")
    return result.stdout


def _git_path(output: bytes, *, label: str) -> Path:
    diagnostics = {
        "repository root": (
            "Git returned an invalid repository root",
            "cannot resolve repository root",
            "repository root is not a directory",
        ),
        "common Git directory": (
            "Git returned an invalid common Git directory",
            "cannot resolve common Git directory",
            "common Git path is not a directory",
        ),
    }
    invalid, unresolved, not_directory = diagnostics.get(
        label,
        ("Git returned an invalid path", "cannot resolve Git path", "Git path is not a directory"),
    )
    raw = output[:-1] if output.endswith(b"\n") else output
    if not raw or b"\x00" in raw:
        raise BoundaryError(invalid)
    try:
        path = Path(os.fsdecode(raw)).resolve(strict=True)
    except OSError as exc:
        raise BoundaryError(unresolved) from exc
    if not path.is_dir():
        raise BoundaryError(not_directory)
    return path


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def discover_repository(repo: Path) -> tuple[Path, tuple[Path, ...]]:
    root = _git_path(
        _git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel"),
        label="repository root",
    )
    common_git = _git_path(
        _git(root, "rev-parse", "--path-format=absolute", "--git-common-dir"),
        label="common Git directory",
    )

    worktree_output = _git(root, "worktree", "list", "--porcelain", "-z")
    worktrees: list[Path] = []
    for field in worktree_output.split(b"\x00"):
        if not field.startswith(b"worktree "):
            continue
        raw = field.removeprefix(b"worktree ")
        try:
            candidate = Path(os.fsdecode(raw)).resolve(strict=True)
        except OSError as exc:
            raise BoundaryError("registered worktree is unavailable") from exc
        if not candidate.is_dir():
            raise BoundaryError("registered worktree is not a directory")
        worktrees.append(candidate)
    if root not in worktrees:
        raise BoundaryError("current repository root is absent from git worktree inventory")

    candidates = sorted(
        set(worktrees + [common_git]), key=lambda item: (len(item.parts), os.fspath(item))
    )
    protected: list[Path] = []
    for candidate in candidates:
        if not any(_is_within(candidate, parent) for parent in protected):
            protected.append(candidate)
    return root, tuple(protected)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _trusted_file_digest(path: Path, *, allowed_roots: tuple[Path, ...] = ()) -> bytes:
    """Verify an immutable root-owned file and every ancestor, then hash it."""
    if not path.is_absolute():
        raise BoundaryError("trusted executable path is not absolute")
    path = path.absolute()
    if allowed_roots and not any(_is_within(path, root) for root in allowed_roots):
        raise BoundaryError("trusted launcher is outside an approved installation root")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise BoundaryError("trusted executable path is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise BoundaryError("trusted executable path contains a symlink")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise BoundaryError("trusted executable path is not root-controlled")
        if current == path:
            if not stat.S_ISREG(info.st_mode):
                raise BoundaryError("trusted executable is not a regular file")
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise BoundaryError("trusted executable has a privileged mode bit")
        elif not stat.S_ISDIR(info.st_mode):
            raise BoundaryError("trusted executable ancestor is not a directory")
    return _stable_file_digest(os.fsencode(path), os.lstat(path))


def _verify_trusted_directory(path: Path) -> None:
    if not path.is_absolute():
        raise BoundaryError("trusted runtime import path is not absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise BoundaryError("trusted runtime import path is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise BoundaryError("trusted runtime import path contains a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise BoundaryError("trusted runtime import path is not a directory")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise BoundaryError("trusted runtime import path is not root-controlled")


def _verify_trusted_runtime() -> None:
    if sys.version_info < (3, 9):
        raise BoundaryError("trusted launcher requires Python 3.9 or newer")
    if not (
        sys.flags.isolated
        and sys.flags.no_user_site
        and sys.flags.ignore_environment
        and getattr(sys.flags, "safe_path", sys.flags.isolated)
    ):
        raise BoundaryError("trusted launcher requires Python isolated mode")
    _trusted_file_digest(Path(__file__), allowed_roots=_TRUSTED_LAUNCHER_ROOTS)
    executable = Path(sys.executable)
    _verify_trusted_directory(executable.parent)
    try:
        executable_info = os.lstat(executable)
        resolved_executable = executable.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("trusted interpreter is unavailable") from exc
    if executable_info.st_uid != 0 or stat.S_IMODE(executable_info.st_mode) & 0o022:
        raise BoundaryError("trusted interpreter path is not root-controlled")
    _trusted_file_digest(resolved_executable)
    for entry in sys.path:
        if not entry:
            raise BoundaryError("trusted runtime contains a relative import path")
        path = Path(entry).absolute()
        if path.exists():
            _verify_trusted_directory(path)


def _verify_review_command(
    command: list[str],
    expected_digest: str,
    forbidden_roots: tuple[Path, ...],
) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_digest):
        raise BoundaryError("review command digest is invalid")
    executable = Path(command[0])
    if not executable.is_absolute():
        raise BoundaryError("review command executable must be an absolute path")
    absolute = executable.absolute()
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("review command executable is unavailable") from exc
    if resolved != absolute:
        raise BoundaryError("review command executable path is not canonical")
    if any(_is_within(absolute, root) for root in forbidden_roots):
        raise BoundaryError("review command executable is inside forbidden state")
    digest = _trusted_file_digest(absolute)
    if not secrets.compare_digest(digest.hex(), expected_digest.lower()):
        raise BoundaryError("review command executable digest does not match")


def _stable_file_digest(path: bytes, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BoundaryError("cannot open a manifest file") from exc
    try:
        before = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(expected) or not stat.S_ISREG(
            before.st_mode
        ):
            raise BoundaryError("manifest file changed before read")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        if _file_identity(os.fstat(descriptor)) != _file_identity(before):
            raise BoundaryError("manifest file changed during read")
        return digest.digest()
    finally:
        os.close(descriptor)


def _xattr_dump(path: bytes) -> bytes:
    if hasattr(os, "listxattr") and hasattr(os, "getxattr"):
        try:
            names = sorted(os.fsencode(name) for name in os.listxattr(path, follow_symlinks=False))
            output = bytearray()
            for name in names:
                value = os.getxattr(path, name, follow_symlinks=False)
                output.extend(len(name).to_bytes(8, "big"))
                output.extend(name)
                output.extend(len(value).to_bytes(8, "big"))
                output.extend(value)
                if len(output) > MAX_XATTR_BYTES:
                    raise BoundaryError(
                        "extended attributes exceed the byte limit"
                    )
            return bytes(output)
        except BoundaryError:
            raise
        except OSError as exc:
            raise BoundaryError(
                "cannot inspect extended attributes"
            ) from exc
    try:
        result = subprocess.run(
            [b"/usr/bin/xattr", b"-l", b"-x", b"-s", b"--", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise BoundaryError(
            "cannot inspect extended attributes"
        ) from exc
    if result.returncode != 0:
        raise BoundaryError("cannot inspect extended attributes")
    if len(result.stdout) > MAX_XATTR_BYTES:
        raise BoundaryError(
            "extended attributes exceed the byte limit"
        )
    return result.stdout


def _xattr_names(path: bytes) -> tuple[bytes, ...]:
    if hasattr(os, "listxattr"):
        try:
            return tuple(
                sorted(os.fsencode(name) for name in os.listxattr(path, follow_symlinks=False))
            )
        except OSError as exc:
            raise BoundaryError(
                "cannot inspect snapshot attributes"
            ) from exc
    try:
        result = subprocess.run(
            [b"/usr/bin/xattr", b"-s", b"--", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise BoundaryError(
            "cannot inspect snapshot attributes"
        ) from exc
    if result.returncode != 0:
        raise BoundaryError("cannot inspect snapshot attributes")
    return tuple(sorted(result.stdout.splitlines()))


def _stable_xattr_digest(path: bytes, expected: os.stat_result) -> bytes:
    output = _xattr_dump(path)
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise BoundaryError("cannot restat protected path") from exc
    if _file_identity(after) != _file_identity(expected):
        raise BoundaryError("protected path changed during extended-attribute read")
    return hashlib.sha256(output).digest()


def _snapshot_has_source_xattrs(path: bytes) -> bool:
    # Current macOS creates com.apple.provenance on every new inode and does
    # not permit its durable removal.  It is local output metadata, not copied
    # from the source.  Every other attribute makes the byte-only export fail.
    return any(name != b"com.apple.provenance" for name in _xattr_names(path))


def protected_manifest(roots: tuple[Path, ...]) -> tuple[ManifestEntry, ...]:
    entries: list[ManifestEntry] = []
    total_bytes = 0
    for root in roots:
        root_bytes = os.fsencode(root)
        pending: list[tuple[bytes, bytes]] = [(b".", root_bytes)]
        while pending:
            relative, physical = pending.pop()
            try:
                info = os.lstat(physical)
            except OSError as exc:
                raise BoundaryError(
                    "cannot inspect protected path"
                ) from exc
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                kind = "directory"
                size = 0
                content_digest = b""
                try:
                    children = sorted(
                        os.scandir(physical), key=lambda item: item.name, reverse=True
                    )
                except OSError as exc:
                    raise BoundaryError(
                        "cannot enumerate protected path"
                    ) from exc
                for child in children:
                    child_relative = (
                        child.name if relative == b"." else relative + b"/" + child.name
                    )
                    pending.append((child_relative, os.path.join(physical, child.name)))
            elif stat.S_ISREG(info.st_mode):
                kind = "file"
                size = info.st_size
                total_bytes += size
                if total_bytes > MAX_PROTECTED_BYTES:
                    raise BoundaryError("protected manifest exceeds the byte limit")
                content_digest = _stable_file_digest(physical, info)
            elif stat.S_ISLNK(info.st_mode):
                kind = "symlink"
                try:
                    target = os.readlink(physical)
                except OSError as exc:
                    raise BoundaryError(
                        "cannot read protected symlink"
                    ) from exc
                target_bytes = target if isinstance(target, bytes) else os.fsencode(target)
                size = len(target_bytes)
                content_digest = hashlib.sha256(target_bytes).digest()
            else:
                raise BoundaryError("unsupported protected file type")
            xattr_digest = _stable_xattr_digest(physical, info)
            entries.append(
                ManifestEntry(
                    root_bytes,
                    relative,
                    kind,
                    mode,
                    info.st_uid,
                    info.st_gid,
                    info.st_dev,
                    info.st_ino,
                    info.st_nlink,
                    size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                    content_digest,
                    xattr_digest,
                )
            )
            if len(entries) > MAX_PROTECTED_ENTRIES:
                raise BoundaryError("protected manifest exceeds the entry limit")
    return tuple(sorted(entries, key=lambda item: (item.root, item.relative_path)))


def _require_single_link_protected_files(
    entries: tuple[ManifestEntry, ...],
) -> None:
    if any(entry.kind == "file" and entry.link_count != 1 for entry in entries):
        raise BoundaryError("protected regular file does not have exactly one link")


def _changed_entries(
    before: tuple[ManifestEntry, ...], after: tuple[ManifestEntry, ...]
) -> tuple[tuple[bytes, bytes], ...]:
    before_by_path = {(entry.root, entry.relative_path): entry for entry in before}
    after_by_path = {(entry.root, entry.relative_path): entry for entry in after}
    paths = set(before_by_path) | set(after_by_path)
    return tuple(
        sorted(path for path in paths if before_by_path.get(path) != after_by_path.get(path))
    )


def _validate_source_path(path: bytes) -> None:
    components = path.split(b"/")
    if (
        not path
        or path.startswith(b"/")
        or b"" in components
        or b".." in components
        or b"." in components
        or b".git" in components
    ):
        raise BoundaryError("unsafe source path in Git inventory")


def _tracked_and_untracked_paths(root: Path) -> tuple[_SourceEntry, ...]:
    staged = _git(root, "ls-files", "--stage", "-z")
    entries: dict[bytes, _SourceEntry] = {}
    for record in staged.split(b"\x00"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise BoundaryError("Git returned a malformed index entry")
        mode_bytes, _object_id, stage_bytes = fields
        _validate_source_path(path)
        if stage_bytes != b"0":
            raise BoundaryError("unmerged index entry cannot be exported")
        try:
            mode = int(mode_bytes, 8)
        except ValueError as exc:
            raise BoundaryError("Git returned an invalid index mode") from exc
        if mode == 0o160000:
            raise BoundaryError("gitlink cannot enter a review snapshot")
        if mode == 0o120000:
            raise BoundaryError("source symlink requires explicit review")
        if mode not in {0o100644, 0o100755}:
            raise BoundaryError("unsupported Git entry mode")
        if path in entries:
            raise BoundaryError("duplicate Git inventory path")
        entries[path] = _SourceEntry(path, mode)

    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    for path in untracked.split(b"\x00"):
        if not path:
            continue
        _validate_source_path(path)
        if path in entries:
            raise BoundaryError("duplicate Git inventory path")
        entries[path] = _SourceEntry(path, None)

    if len(entries) > MAX_EXPORT_FILES:
        raise BoundaryError("review export exceeds the file-count limit")
    ordered = tuple(entries[path] for path in sorted(entries))
    paths = {entry.relative_path for entry in ordered}
    for path in paths:
        parent = path
        while b"/" in parent:
            parent = parent.rsplit(b"/", 1)[0]
            if parent in paths:
                raise BoundaryError("source path overlaps another entry")
    return ordered


def _path_is_ignored(root: Path, relative: bytes) -> bool:
    root_bytes = os.fsencode(root)
    try:
        result = subprocess.run(
            [
                b"/usr/bin/git",
                b"-c",
                b"safe.directory=" + root_bytes,
                b"-c",
                b"core.fsmonitor=false",
                b"-c",
                b"core.hooksPath=/dev/null",
                b"-C",
                root_bytes,
                b"check-ignore",
                b"-q",
                b"--",
                relative,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            env={
                b"GIT_CONFIG_GLOBAL": b"/dev/null",
                b"GIT_CONFIG_NOSYSTEM": b"1",
                b"GIT_TERMINAL_PROMPT": b"0",
                b"HOME": b"/var/empty",
                b"LANG": b"C",
                b"LC_ALL": b"C",
                b"PATH": b"/usr/bin:/bin",
            },
        )
    except OSError as exc:
        raise BoundaryError("cannot check Git ignore rules") from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise BoundaryError("Git ignore check failed")


def _reject_unexportable_specials(root: Path) -> None:
    root_bytes = os.fsencode(root)
    pending: list[tuple[bytes, bytes]] = [(b"", root_bytes)]
    while pending:
        relative_parent, physical_parent = pending.pop()
        try:
            children = list(os.scandir(physical_parent))
        except OSError as exc:
            raise BoundaryError("cannot inspect source tree for special files") from exc
        for child in children:
            if not relative_parent and child.name == b".git":
                continue
            relative = child.name if not relative_parent else relative_parent + b"/" + child.name
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise BoundaryError(
                    "cannot inspect source path"
                ) from exc
            if stat.S_ISDIR(info.st_mode):
                if not _path_is_ignored(root, relative):
                    pending.append((relative, child.path))
                continue
            if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                continue
            if not _path_is_ignored(root, relative):
                raise BoundaryError("unsupported source export type")


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise BoundaryError("short write while exporting review snapshot")
        offset += written


def _copy_plain_file(
    source: bytes,
    target: bytes,
    expected: os.stat_result,
    expected_digest: bytes,
    destination_mode: int,
) -> tuple[int, int]:
    source_flags = os.O_RDONLY
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        target_flags |= os.O_NOFOLLOW
    try:
        source_descriptor = os.open(source, source_flags)
    except OSError as exc:
        raise BoundaryError(
            "cannot open source export file"
        ) from exc
    target_descriptor: int | None = None
    try:
        opened = os.fstat(source_descriptor)
        if _file_identity(opened) != _file_identity(expected) or not stat.S_ISREG(opened.st_mode):
            raise BoundaryError("source changed before copy")
        if opened.st_nlink != 1:
            raise BoundaryError("source hardlink cannot enter snapshot")
        try:
            target_descriptor = os.open(target, target_flags, 0o600)
        except OSError as exc:
            raise BoundaryError(
                "cannot create snapshot file"
            ) from exc
        digest = hashlib.sha256()
        line_count = 0
        last_byte = b""
        copied_size = 0
        while True:
            chunk = os.read(source_descriptor, 1 << 20)
            if not chunk:
                break
            _write_all(target_descriptor, chunk)
            digest.update(chunk)
            line_count += chunk.count(b"\n")
            last_byte = chunk[-1:]
            copied_size += len(chunk)
        if copied_size and last_byte != b"\n":
            line_count += 1
        if _file_identity(os.fstat(source_descriptor)) != _file_identity(opened):
            raise BoundaryError("source changed during copy")
        copied = os.fstat(target_descriptor)
        if (
            not stat.S_ISREG(copied.st_mode)
            or copied.st_nlink != 1
            or copied.st_size != copied_size
        ):
            raise BoundaryError("snapshot target is not a new plain file")
        if digest.digest() != expected_digest:
            raise BoundaryError("source changed between digest and copy")
        os.fsync(target_descriptor)
        os.fchmod(target_descriptor, destination_mode)
        if _snapshot_has_source_xattrs(target):
            raise BoundaryError(
                "snapshot file inherited extended attributes"
            )
        return copied_size, line_count
    finally:
        if target_descriptor is not None:
            os.close(target_descriptor)
        os.close(source_descriptor)


def _assert_source_unchanged(root: bytes, state: _SourceState) -> None:
    source = os.path.join(root, state.relative_path)
    try:
        info = os.lstat(source)
    except FileNotFoundError:
        if state.present:
            raise BoundaryError(
                "source disappeared during export"
            )
        return
    except OSError as exc:
        raise BoundaryError(
            "cannot recheck source path"
        ) from exc
    if not state.present:
        raise BoundaryError("source appeared during export")
    if state.identity != _file_identity(info):
        raise BoundaryError("source changed during export")
    if state.digest != _stable_file_digest(source, info):
        raise BoundaryError(
            "source content changed during export"
        )


def _clear_directory_xattrs(path: Path) -> None:
    if _snapshot_has_source_xattrs(os.fsencode(path)):
        raise BoundaryError("snapshot directory inherited extended attributes")


def export_snapshot(root: Path, destination: Path) -> tuple[SnapshotEntry, ...]:
    _reject_unexportable_specials(root)
    inventory = _tracked_and_untracked_paths(root)
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise BoundaryError("cannot create review snapshot") from exc
    root_bytes = os.fsencode(root)
    destination_bytes = os.fsencode(destination)
    total_bytes = 0
    snapshot_entries: list[SnapshotEntry] = []
    source_states: list[_SourceState] = []
    created_directories: set[Path] = {destination}
    for source_entry in inventory:
        relative = source_entry.relative_path
        source = os.path.join(root_bytes, relative)
        target = os.path.join(destination_bytes, relative)
        try:
            info = os.lstat(source)
        except FileNotFoundError:
            if source_entry.index_mode is None:
                raise BoundaryError("untracked source disappeared")
            source_states.append(_SourceState(relative, False, None, None))
            continue
        except OSError as exc:
            raise BoundaryError(
                "cannot inspect source export path"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise BoundaryError(
                "source symlink requires explicit review"
            )
        if not stat.S_ISREG(info.st_mode):
            raise BoundaryError("unsupported source export type")
        if info.st_nlink != 1:
            raise BoundaryError("source hardlink cannot enter snapshot")
        if info.st_size > MAX_EXPORT_FILE_BYTES:
            raise BoundaryError(
                "source export file exceeds the size limit"
            )
        total_bytes += info.st_size
        if total_bytes > MAX_EXPORT_BYTES:
            raise BoundaryError("review export exceeds the aggregate byte limit")
        digest = _stable_file_digest(source, info)
        target_parent = Path(os.fsdecode(os.path.dirname(target)))
        try:
            target_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise BoundaryError("cannot create snapshot directory") from exc
        current = target_parent
        while _is_within(current, destination):
            created_directories.add(current)
            if current == destination:
                break
            current = current.parent
        destination_mode = 0o555 if source_entry.index_mode == 0o100755 else 0o444
        size, line_count = _copy_plain_file(
            source, target, info, digest, destination_mode
        )
        snapshot_entries.append(
            SnapshotEntry(len(snapshot_entries) + 1, relative, size, digest, line_count)
        )
        source_states.append(_SourceState(relative, True, _file_identity(info), digest))

    if inventory != _tracked_and_untracked_paths(root):
        raise BoundaryError("Git inventory changed during review export")
    for state in source_states:
        _assert_source_unchanged(root_bytes, state)
    for directory in sorted(created_directories, key=lambda item: len(item.parts), reverse=True):
        _clear_directory_xattrs(directory)
        try:
            os.chmod(directory, 0o555, follow_symlinks=False)
        except OSError as exc:
            raise BoundaryError("cannot make snapshot directory read-only") from exc
    return tuple(snapshot_entries)


def _uid_processes(uid: int) -> tuple[int, ...]:
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "uid=,pid="],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except OSError as exc:
        raise BoundaryError("cannot inspect reviewer processes") from exc
    if result.returncode != 0:
        raise BoundaryError("cannot inspect reviewer processes")
    processes: list[int] = []
    try:
        for line in result.stdout.splitlines():
            process_uid, process_id = line.split()
            if int(process_uid) == uid:
                processes.append(int(process_id))
    except (TypeError, ValueError) as exc:
        raise BoundaryError("reviewer process inventory is malformed") from exc
    return tuple(sorted(processes))


def _require_no_reviewer_processes(identity: ReviewerIdentity) -> None:
    if _uid_processes(identity.uid):
        raise BoundaryError("dedicated reviewer account already has a running process")


def _kill_reviewer_processes(identity: ReviewerIdentity) -> None:
    for _attempt in range(20):
        processes = _uid_processes(identity.uid)
        if not processes:
            return
        for process_id in processes:
            try:
                os.kill(process_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                raise BoundaryError("cannot terminate every reviewer process") from exc
        time.sleep(0.05)
    raise BoundaryError("reviewer processes remain after forced termination")


def _sudo_prefix(identity: ReviewerIdentity) -> list[str]:
    return ["/usr/bin/sudo", "-n", "-H", "-u", identity.name, "--"]


def _reviewer_cannot_write_protected(
    identity: ReviewerIdentity, roots: tuple[Path, ...]
) -> None:
    program = """
import os
import stat
import sys

for root in sys.argv[1:]:
    if os.access(os.path.dirname(root), os.W_OK, effective_ids=True):
        raise SystemExit(10)
    pending = [os.fsencode(root)]
    while pending:
        path = pending.pop()
        if os.access(path, os.W_OK, effective_ids=True, follow_symlinks=False):
            raise SystemExit(11)
        try:
            info = os.lstat(path)
        except OSError:
            raise SystemExit(12)
        if stat.S_ISDIR(info.st_mode):
            try:
                pending.extend(entry.path for entry in os.scandir(path))
            except PermissionError:
                pass
            except OSError:
                raise SystemExit(13)
"""
    try:
        result = subprocess.run(
            [
                *_sudo_prefix(identity),
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "/usr/bin/python3",
                "-I",
                "-E",
                "-s",
                "-c",
                program,
                *(os.fspath(root) for root in roots),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        raise BoundaryError("cannot verify reviewer write permissions") from exc
    if result.returncode != 0:
        raise BoundaryError("reviewer can write or cannot safely inspect protected state")


def _reviewer_has_sudo_privilege(identity: ReviewerIdentity) -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "-l", "-U", identity.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
        )
    except OSError as exc:
        raise BoundaryError("cannot audit reviewer privilege configuration") from exc
    if result.returncode == 0:
        return True
    diagnostic = result.stderr + result.stdout
    if result.returncode == 1 and b" is not allowed to run sudo on " in diagnostic:
        return False
    raise BoundaryError("reviewer privilege configuration is inconclusive")


def _verify_provider_proxy(port: int) -> None:
    """Require every listener on the allowed loopback port to be root-owned.

    Seatbelt can restrict the child to a loopback TCP port, but cannot prove
    what an HTTP proxy forwards upstream.  The proxy is therefore trusted
    boundary infrastructure, and its exact upstream allowlist remains an
    operator prerequisite.
    """
    try:
        result = subprocess.run(
            [
                "/usr/sbin/lsof",
                "-nP",
                "-a",
                f"-iTCP:{port}",
                "-sTCP:LISTEN",
                "-Fpu",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
        )
    except OSError as exc:
        raise BoundaryError("cannot inspect the provider proxy") from exc
    if result.returncode != 0:
        raise BoundaryError("provider proxy is unavailable")
    process_ids: set[int] = set()
    owner_ids: list[int] = []
    try:
        for line in result.stdout.splitlines():
            if line.startswith("p"):
                process_ids.add(int(line[1:]))
            elif line.startswith("u"):
                owner_ids.append(int(line[1:]))
    except ValueError as exc:
        raise BoundaryError("provider proxy inventory is malformed") from exc
    if not process_ids or not owner_ids or any(owner_id != 0 for owner_id in owner_ids):
        raise BoundaryError("provider proxy is not exclusively root-owned")


def _safe_quarantine_parent(parent: Path) -> None:
    try:
        info = os.lstat(parent)
    except OSError as exc:
        raise BoundaryError("quarantine parent is unavailable") from exc
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise BoundaryError("quarantine parent is not root-controlled")
    if mode & 0o022 and not (mode & stat.S_ISVTX):
        raise BoundaryError("quarantine parent is replaceable")


def require_supervisor_and_reviewer(
    reviewer_name: str, roots: tuple[Path, ...]
) -> ReviewerIdentity:
    if os.geteuid() != 0:
        raise BoundaryError("the isolated-review supervisor must run as root")
    if not reviewer_name or not reviewer_name.isascii():
        raise BoundaryError("reviewer account name is invalid")
    try:
        account = pwd.getpwnam(reviewer_name)
        home = Path(account.pw_dir).resolve(strict=True)
        groups = tuple(sorted(set(os.getgrouplist(account.pw_name, account.pw_gid))))
    except (KeyError, OSError) as exc:
        raise BoundaryError("reviewer account is unavailable") from exc
    if account.pw_uid < 500 or account.pw_uid == 0:
        raise BoundaryError("reviewer account is not an unprivileged local account")
    if account.pw_shell not in {"/usr/bin/false", "/sbin/nologin", "/usr/bin/nologin"}:
        raise BoundaryError("reviewer account must have a non-login shell")
    owner_uids = set()
    try:
        owner_uids = {os.lstat(root).st_uid for root in roots}
    except OSError as exc:
        raise BoundaryError("protected ownership cannot be inspected") from exc
    if account.pw_uid in owner_uids:
        raise BoundaryError("reviewer and repository owner must be different accounts")
    privileged_groups = {
        "admin",
        "wheel",
        "operator",
        "sudo",
        "_developer",
        "_appserveradm",
        "_lpadmin",
        "_lpoperator",
        "com.apple.access_ssh",
        "com.apple.access_screensharing",
        "com.apple.access_remote_ae",
    }
    try:
        group_names = {grp.getgrgid(group_id).gr_name for group_id in groups}
    except KeyError as exc:
        raise BoundaryError("reviewer group inventory is incomplete") from exc
    if group_names & privileged_groups or any(
        name.startswith("com.apple.access_") for name in group_names
    ):
        raise BoundaryError("reviewer account belongs to a privileged access group")
    identity = ReviewerIdentity(account.pw_name, account.pw_uid, account.pw_gid, home, groups)
    _require_no_reviewer_processes(identity)
    credential_paths = (
        home / ".aws",
        home / ".config" / "gh",
        home / ".config" / "gcloud",
        home / ".git-credentials",
        home / ".netrc",
        home / ".ssh",
        home / "Library" / "Keychains",
    )
    if any(path.exists() or path.is_symlink() for path in credential_paths):
        raise BoundaryError("reviewer account contains a known credential surface")
    if _reviewer_has_sudo_privilege(identity):
        raise BoundaryError("reviewer account has sudo privileges")
    _require_no_reviewer_processes(identity)
    _reviewer_cannot_write_protected(identity, roots)
    _require_no_reviewer_processes(identity)
    return identity


def _profile_string(path: Path) -> str:
    value = os.fspath(path)
    if any(ord(character) < 0x20 or 0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise BoundaryError("sandbox path cannot be encoded safely")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _repository_owner_homes(protected: tuple[Path, ...]) -> tuple[Path, ...]:
    homes: set[Path] = set()
    for path in protected:
        try:
            owner_uid = os.lstat(path).st_uid
            account = pwd.getpwuid(owner_uid)
            home = Path(account.pw_dir).resolve(strict=True)
        except (KeyError, OSError) as exc:
            raise BoundaryError("cannot resolve protected owner's home") from exc
        if home == Path("/"):
            raise BoundaryError("protected owner's home cannot be the filesystem root")
        homes.add(home)
    ordered = sorted(homes, key=lambda item: (len(item.parts), os.fspath(item)))
    minimal: list[Path] = []
    for home in ordered:
        if not any(_is_within(home, parent) for parent in minimal):
            minimal.append(home)
    return tuple(minimal)


def sandbox_profile(
    protected: tuple[Path, ...],
    quarantine: Path,
    snapshot: Path,
    identity: ReviewerIdentity,
    *,
    provider_proxy_port: int | None,
) -> str:
    snapshot_value = _profile_string(snapshot)
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny appleevent-send)",
        "(deny darwin-notification-post distributed-notification-post)",
        "(deny lsopen)",
        "(deny mach*)",
        "(deny ipc*)",
        "(deny signal (target others))",
        "(deny process-info* (target others))",
        "(deny network*)",
        "(deny file-write*)",
        f"(deny file-write* (subpath {snapshot_value}))",
    ]
    if provider_proxy_port is not None:
        if provider_proxy_port < 1 or provider_proxy_port > 1_023:
            raise BoundaryError("provider proxy port is invalid")
        lines.append(
            "(allow network-outbound "
            f'(remote tcp "localhost:{provider_proxy_port}"))'
        )
    for name in ("home", "output", "tmp"):
        lines.append(
            f"(allow file-write* (subpath {_profile_string(quarantine / name)}))"
        )
    for fixed_name in ("INPUT.json", "NOTICE.txt"):
        lines.append(
            f"(deny file-write* (literal {_profile_string(quarantine / fixed_name)}))"
        )
    for path in protected:
        encoded = _profile_string(path)
        lines.append(f"(deny file-read* (subpath {encoded}))")
        lines.append(f"(deny file-write* (subpath {encoded}))")
    for home in _repository_owner_homes(protected):
        encoded = _profile_string(home)
        lines.append(f"(deny file-read* (subpath {encoded}))")
        lines.append(f"(deny file-write* (subpath {encoded}))")
    reviewer_home = _profile_string(identity.home)
    lines.append(f"(deny file-read* (subpath {reviewer_home}))")
    lines.append(f"(deny file-write* (subpath {reviewer_home}))")
    return "\n".join(lines)


def _quarantine_path(requested: str | None, protected: tuple[Path, ...]) -> Path:
    if requested is None:
        try:
            parent = Path("/private/tmp").resolve(strict=True)
        except OSError as exc:
            raise BoundaryError("cannot resolve the temporary directory") from exc
        _safe_quarantine_parent(parent)
        if any(_is_within(parent, path) or _is_within(path, parent) for path in protected):
            raise BoundaryError("temporary directory overlaps protected repository state")
        try:
            return Path(tempfile.mkdtemp(prefix="cce-review-quarantine-", dir=parent))
        except OSError as exc:
            raise BoundaryError("cannot create quarantine directory") from exc

    requested_path = Path(requested).expanduser().absolute()
    if requested_path.exists() or requested_path.is_symlink():
        raise BoundaryError("quarantine destination already exists")
    try:
        parent = requested_path.parent.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("quarantine parent is unavailable") from exc
    destination = parent / requested_path.name
    if any(_is_within(destination, path) or _is_within(path, destination) for path in protected):
        raise BoundaryError("quarantine destination overlaps protected repository state")
    _safe_quarantine_parent(parent)
    try:
        destination.mkdir(mode=0o700)
        return destination.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("cannot create quarantine directory") from exc


def clean_child_environment(
    snapshot: Path,
    quarantine: Path,
    *,
    identity: ReviewerIdentity,
    provider_proxy_port: int | None,
) -> dict[str, str]:
    environment = {
        "CCE_REVIEW_INPUT": os.fspath(quarantine / "INPUT.json"),
        "CCE_REVIEW_QUARANTINE": os.fspath(quarantine),
        "CCE_REVIEW_SNAPSHOT": os.fspath(snapshot),
        "GIT_CEILING_DIRECTORIES": os.fspath(quarantine),
        "HOME": os.fspath(quarantine / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": identity.name,
        "PATH": os.defpath,
        "TMPDIR": os.fspath(quarantine / "tmp"),
        "USER": identity.name,
    }
    if provider_proxy_port is not None:
        proxy = f"http://127.0.0.1:{provider_proxy_port}"
        environment.update(
            {
                "ALL_PROXY": proxy,
                "HTTP_PROXY": proxy,
                "HTTPS_PROXY": proxy,
                "NO_PROXY": "",
                "all_proxy": proxy,
                "http_proxy": proxy,
                "https_proxy": proxy,
                "no_proxy": "",
            }
        )
    return environment


def _prepare_runtime_directories(quarantine: Path, identity: ReviewerIdentity) -> None:
    try:
        os.chmod(quarantine, 0o755, follow_symlinks=False)
        for name in ("home", "output", "tmp"):
            directory = quarantine / name
            directory.mkdir(mode=0o700)
            os.chown(directory, identity.uid, identity.gid, follow_symlinks=False)
            os.chmod(directory, 0o700, follow_symlinks=False)
    except OSError as exc:
        raise BoundaryError("cannot prepare isolated reviewer runtime directories") from exc


def _quarantine_identity(quarantine: Path) -> tuple[int, ...]:
    try:
        return _file_identity(os.lstat(quarantine))
    except OSError as exc:
        raise BoundaryError("cannot inspect quarantine root") from exc


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BoundaryError("review result contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    del value
    raise BoundaryError("non-finite JSON number is not permitted")


def _bounded_json_integer(value: str) -> int:
    if len(value) > 10:
        raise BoundaryError("JSON integer exceeds the coordinate limit")
    number = int(value)
    if abs(number) > 1_000_000_000:
        raise BoundaryError("JSON integer exceeds the coordinate limit")
    return number


def _exact_integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        del field
        raise BoundaryError("finding coordinate must be an integer")
    return value


def validate_findings(
    payload: bytes, entries: tuple[SnapshotEntry, ...]
) -> tuple[dict[str, int | str], ...]:
    if len(payload) > MAX_FINDINGS_BYTES:
        raise BoundaryError("review result exceeds the byte limit")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise BoundaryError("review result is not UTF-8") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_duplicate_rejector,
            parse_constant=_reject_nonfinite,
            parse_int=_bounded_json_integer,
        )
    except BoundaryError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise BoundaryError("review result is not strict JSON") from exc
    if not isinstance(document, dict):
        raise BoundaryError("review result must be one JSON object")
    if set(document) != {"schema", "findings"}:
        raise BoundaryError("review result must contain exactly schema and findings")
    if document["schema"] != FINDINGS_SCHEMA:
        raise BoundaryError("review result uses an unsupported schema")
    raw_findings = document["findings"]
    if not isinstance(raw_findings, list):
        raise BoundaryError("review findings must be an array")
    if len(raw_findings) > MAX_FINDINGS:
        raise BoundaryError("review result exceeds the finding-count limit")
    by_id = {entry.file_id: entry for entry in entries}
    accepted: list[dict[str, int | str]] = []
    seen: set[tuple[int, int, int, str, str]] = set()
    exact_keys = {"file_id", "start_line", "end_line", "category", "severity"}
    for raw in raw_findings:
        if not isinstance(raw, dict) or set(raw) != exact_keys:
            raise BoundaryError("each finding must contain exactly the closed scalar fields")
        file_id = _exact_integer(raw["file_id"], field="file_id")
        start_line = _exact_integer(raw["start_line"], field="start_line")
        end_line = _exact_integer(raw["end_line"], field="end_line")
        entry = by_id.get(file_id)
        if entry is None:
            raise BoundaryError("finding references an unknown file id")
        if start_line < 1 or end_line < start_line or end_line > entry.line_count:
            raise BoundaryError("finding has an invalid line range")
        category = raw["category"]
        severity = raw["severity"]
        if not isinstance(category, str) or category not in FINDING_CATEGORIES:
            raise BoundaryError("finding category is outside the closed vocabulary")
        if not isinstance(severity, str) or severity not in FINDING_SEVERITIES:
            raise BoundaryError("finding severity is outside the closed vocabulary")
        key = (file_id, start_line, end_line, category, severity)
        if key in seen:
            raise BoundaryError("duplicate finding is ambiguous")
        seen.add(key)
        accepted.append(
            {
                "file_id": file_id,
                "start_line": start_line,
                "end_line": end_line,
                "category": category,
                "severity": severity,
            }
        )
    return tuple(
        sorted(
            accepted,
            key=lambda item: (
                item["file_id"],
                item["start_line"],
                item["end_line"],
                item["category"],
                item["severity"],
            ),
        )
    )


def _input_document(entries: tuple[SnapshotEntry, ...]) -> bytes:
    files = []
    for entry in entries:
        try:
            relative_path = entry.relative_path.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise BoundaryError("review export contains a non-UTF-8 path") from exc
        files.append(
            {
                "file_id": entry.file_id,
                "line_count": entry.line_count,
                "path": relative_path,
                "sha256": entry.digest.hex(),
                "size": entry.size,
            }
        )
    return (
        json.dumps({"schema": INPUT_SCHEMA, "files": files}, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _write_control_file(path: Path, data: bytes, *, mode: int = 0o444) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise BoundaryError("cannot create quarantine control file") from exc


def _sandbox_executable() -> Path:
    sandbox = Path("/usr/bin/sandbox-exec")
    if not sandbox.is_file() or not os.access(sandbox, os.X_OK):
        raise BoundaryError("macOS sandbox-exec is unavailable")
    return sandbox


def _limit_child_output(timeout_seconds: int) -> None:
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    del soft
    limit = MAX_FINDINGS_BYTES + 1
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for name, requested in (("RLIMIT_NPROC", 128), ("RLIMIT_NOFILE", 256)):
        if hasattr(resource, name):
            resource_id = getattr(resource, name)
            _soft, hard = resource.getrlimit(resource_id)
            bounded = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
            resource.setrlimit(resource_id, (bounded, bounded))
    if hasattr(resource, "RLIMIT_CPU"):
        _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
        cpu_limit = timeout_seconds + 30
        if hard != resource.RLIM_INFINITY:
            cpu_limit = min(cpu_limit, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))


def _quarantine_usage(quarantine: Path) -> tuple[int, int]:
    entries = 0
    total_bytes = 0
    pending = [quarantine]
    while pending:
        path = pending.pop()
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise BoundaryError("cannot inspect quarantine state") from exc
        entries += 1
        if entries > MAX_QUARANTINE_ENTRIES:
            raise BoundaryError("quarantine exceeds the entry limit")
        if stat.S_ISDIR(info.st_mode):
            try:
                pending.extend(Path(entry.path) for entry in os.scandir(path))
            except OSError as exc:
                raise BoundaryError("cannot inspect quarantine state") from exc
        elif stat.S_ISREG(info.st_mode):
            total_bytes += info.st_size
            if total_bytes > MAX_QUARANTINE_BYTES:
                raise BoundaryError("quarantine exceeds the byte limit")
        elif not stat.S_ISLNK(info.st_mode):
            raise BoundaryError("quarantine contains an unsupported file type")
    return entries, total_bytes


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait()


def _read_start_marker(
    marker_path: Path, marker_token: str, identity: ReviewerIdentity
) -> None:
    if len(marker_token) != 64 or not hasattr(os, "O_NOFOLLOW"):
        raise BoundaryError("isolated command startup marker cannot be validated")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(marker_path, flags)
    except OSError as exc:
        raise BoundaryError("isolated command did not cross the sandbox boundary") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != identity.uid
            or before.st_gid != identity.gid
            or before.st_size != 64
        ):
            raise BoundaryError("isolated command startup marker is invalid")
        payload = bytearray()
        while len(payload) <= 64:
            chunk = os.read(descriptor, 65 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        if _file_identity(os.fstat(descriptor)) != _file_identity(before):
            raise BoundaryError("isolated command startup marker changed during read")
    finally:
        os.close(descriptor)
    if len(payload) != 64 or not secrets.compare_digest(
        bytes(payload), marker_token.encode("ascii")
    ):
        raise BoundaryError("isolated command startup marker is invalid")


_SEATBELT_PROBE = r"""
import errno
import json
import os
import socket
import subprocess
import sys

mode, protected, snapshot, output, forbidden, supervisor, network_port, probe_source = sys.argv[1:]

def denied(call):
    try:
        call()
    except OSError as exc:
        return exc.errno in {errno.EACCES, errno.EPERM}
    return False

def succeeded(call):
    try:
        call()
    except OSError:
        return False
    return True

def create(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)

def connect():
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect(("127.0.0.1", int(network_port)))
    finally:
        connection.close()

result = {
    "allowed_write": succeeded(lambda: create(os.path.join(output, "allowed-" + mode))),
    "network_denied": denied(connect),
    "notification_denied": subprocess.run(
        ["/usr/bin/notifyutil", "-p", "org.cce.isolated-review-probe"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode != 0,
    "outside_write_denied": denied(lambda: create(forbidden + "-" + mode)),
    "pasteboard_denied": subprocess.run(
        ["/usr/bin/pbcopy"],
        input=b"isolated-review-probe",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode != 0,
    "protected_read_denied": denied(lambda: os.listdir(protected)),
    "signal_denied": denied(lambda: os.kill(int(supervisor), 0)),
    "snapshot_write_denied": denied(
        lambda: create(os.path.join(snapshot, "forbidden-" + mode))
    ),
}
if mode == "direct":
    child = subprocess.run(
        [
            sys.executable,
            "-I",
            "-E",
            "-s",
            "-c",
            probe_source,
            "grandchild",
            protected,
            snapshot,
            output,
            forbidden,
            supervisor,
            network_port,
            probe_source,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    try:
        grandchild = json.loads(child.stdout.decode("ascii"))
    except Exception:
        grandchild = None
    report = {"direct": result, "grandchild": grandchild, "grandchild_status": child.returncode}
else:
    report = result
sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
"""


def _run_seatbelt_negative_control(
    sandbox: Path,
    profile: str,
    identity: ReviewerIdentity,
    protected: tuple[Path, ...],
    snapshot: Path,
    quarantine: Path,
    environment: dict[str, str],
) -> None:
    forbidden = Path("/private/tmp") / (
        f"cce-isolated-review-denied-{os.getpid()}-{time.time_ns()}"
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        network_port = listener.getsockname()[1]
        result = _run_command(
            sandbox,
            profile,
            [
                "/usr/bin/python3",
                "-I",
                "-E",
                "-s",
                "-c",
                _SEATBELT_PROBE,
                "direct",
                os.fspath(protected[0]),
                os.fspath(snapshot),
                os.fspath(quarantine / "output"),
                os.fspath(forbidden),
                str(os.getpid()),
                str(network_port),
                _SEATBELT_PROBE,
            ],
            identity=identity,
            cwd=snapshot,
            environment=environment,
            quarantine=quarantine,
            timeout_seconds=30,
            output_stem="boundary-probe",
        )
    except OSError as exc:
        raise BoundaryError("cannot initialize the isolation negative control") from exc
    finally:
        listener.close()
    leaked_paths = (forbidden.with_name(forbidden.name + "-direct"),)
    leaked_paths += (forbidden.with_name(forbidden.name + "-grandchild"),)
    leaked = False
    for path in leaked_paths:
        if path.exists() or path.is_symlink():
            leaked = True
            try:
                path.unlink()
            except OSError:
                pass
    if leaked or result.returncode != 0:
        raise BoundaryError("isolation negative control failed")
    try:
        report = json.loads(result.stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise BoundaryError("isolation negative control returned an invalid result") from exc
    expected_checks = {
        "allowed_write": True,
        "network_denied": True,
        "notification_denied": True,
        "outside_write_denied": True,
        "pasteboard_denied": True,
        "protected_read_denied": True,
        "signal_denied": True,
        "snapshot_write_denied": True,
    }
    expected = {
        "direct": expected_checks,
        "grandchild": expected_checks,
        "grandchild_status": 0,
    }
    if report != expected:
        raise BoundaryError("isolation negative control did not enforce every boundary")


def _run_command(
    sandbox: Path,
    profile: str,
    command: list[str],
    *,
    identity: ReviewerIdentity,
    cwd: Path,
    environment: dict[str, str],
    quarantine: Path,
    timeout_seconds: int,
    output_stem: str,
    command_status: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    if not re.fullmatch(r"[a-z-]+", output_stem):
        raise BoundaryError("internal output name is invalid")
    _require_no_reviewer_processes(identity)
    stdout_path = quarantine / "output" / f"{output_stem}-stdout.bin"
    stderr_path = quarantine / "output" / f"{output_stem}-stderr.bin"
    marker_path = quarantine / "output" / f"{output_stem}-started"
    marker_token = secrets.token_hex(32)
    wrapper = r"""
import os
import sys

marker, token, arguments = sys.argv[1], sys.argv[2], sys.argv[3:]
read_descriptor, write_descriptor = os.pipe()
process_id = os.fork()
if process_id == 0:
    os.close(read_descriptor)
    os.set_inheritable(write_descriptor, False)
    try:
        os.execv(arguments[0], arguments)
    except OSError:
        try:
            os.write(write_descriptor, b"x")
        finally:
            os._exit(126)
os.close(write_descriptor)
exec_failed = bool(os.read(read_descriptor, 1))
os.close(read_descriptor)
if exec_failed:
    os.waitpid(process_id, 0)
    raise SystemExit(126)
descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(descriptor, token.encode("ascii"))
os.fsync(descriptor)
os.close(descriptor)
status = os.waitpid(process_id, 0)[1]
if os.WIFEXITED(status):
    raise SystemExit(os.WEXITSTATUS(status))
raise SystemExit(128 + os.WTERMSIG(status))
"""
    try:
        stdout_handle = open(stdout_path, "x+b", buffering=0)
        try:
            stderr_handle = open(stderr_path, "x+b", buffering=0)
        except OSError:
            stdout_handle.close()
            raise
    except OSError as exc:
        raise BoundaryError("cannot create quarantined output capture") from exc
    process: subprocess.Popen[bytes] | None = None
    returncode: int | None = None
    process_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    with stdout_handle, stderr_handle:
        try:
            environment_arguments = [
                f"{name}={value}" for name, value in sorted(environment.items())
            ]
            process = subprocess.Popen(
                [
                    *_sudo_prefix(identity),
                    "/usr/bin/env",
                    "-i",
                    *environment_arguments,
                    os.fspath(sandbox),
                    "-p",
                    profile,
                    "--",
                    "/usr/bin/python3",
                    "-I",
                    "-E",
                    "-s",
                    "-c",
                    wrapper,
                    os.fspath(marker_path),
                    marker_token,
                    *command,
                ],
                cwd=cwd,
                env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                start_new_session=True,
                preexec_fn=lambda: _limit_child_output(timeout_seconds),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            process_error = BoundaryError("cannot start isolated review")
            process_error.__cause__ = exc
        try:
            if process is not None:
                returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process_error = BoundaryError("isolated review exceeded its time limit")
            process_error.__cause__ = exc
        except BaseException as exc:
            process_error = exc
        try:
            if process is not None:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    _terminate_process_group(process)
                if process.poll() is None:
                    process.kill()
                    process.wait()
        except BaseException as exc:
            cleanup_error = exc
        try:
            _kill_reviewer_processes(identity)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        try:
            _require_no_reviewer_processes(identity)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        stdout_handle.seek(0)
        payload = stdout_handle.read(MAX_FINDINGS_BYTES + 1)
    if cleanup_error is not None:
        raise cleanup_error
    if process_error is not None:
        raise process_error
    if returncode is None:
        raise BoundaryError("isolated review produced no process status")
    _read_start_marker(marker_path, marker_token, identity)
    if not command_status and returncode != 0:
        raise BoundaryError("isolation control command failed")
    return subprocess.CompletedProcess(command, returncode, payload, None)


def _print_changes(changes: tuple[tuple[bytes, bytes], ...]) -> None:
    print(
        f"ERROR: {len(changes)} protected manifest entries changed during isolated review.",
        file=sys.stderr,
    )


def run_isolated_review(
    repo: Path,
    command: list[str],
    *,
    reviewer_user: str,
    command_sha256: str,
    quarantine_dir: str | None = None,
    provider_proxy_port: int | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> int:
    if sys.platform != "darwin":
        raise BoundaryError(
            "this launcher requires macOS Seatbelt inside a dedicated user account; "
            "use a VM otherwise"
        )
    if not command:
        raise BoundaryError("no review command was supplied")
    if timeout_seconds < 1:
        raise BoundaryError("review timeout must be positive")
    if provider_proxy_port is not None and not 1 <= provider_proxy_port <= 1_023:
        raise BoundaryError("provider proxy port is invalid")
    _verify_trusted_runtime()
    sandbox = _sandbox_executable()
    root, protected = discover_repository(repo)
    identity = require_supervisor_and_reviewer(reviewer_user, protected)
    if provider_proxy_port is not None:
        _verify_provider_proxy(provider_proxy_port)
    before_export = protected_manifest(protected)
    _require_single_link_protected_files(before_export)
    quarantine = _quarantine_path(
        quarantine_dir,
        protected + _repository_owner_homes(protected) + (identity.home,),
    )
    snapshot = quarantine / "snapshot"
    entries = export_snapshot(root, snapshot)
    after_export = protected_manifest(protected)
    _require_single_link_protected_files(after_export)
    export_changes = _changed_entries(before_export, after_export)
    if export_changes:
        _print_changes(export_changes)
        raise BoundaryError("repository changed while the review snapshot was exported")
    snapshot_before = protected_manifest((snapshot,))

    _write_control_file(quarantine / "INPUT.json", _input_document(entries))
    _write_control_file(
        quarantine / "NOTICE.txt",
        b"Quarantined review session. Do not copy output into a protected repository.\n",
    )
    _prepare_runtime_directories(quarantine, identity)
    quarantine_identity = _quarantine_identity(quarantine)
    forbidden_command_roots = (
        protected + _repository_owner_homes(protected) + (identity.home, quarantine)
    )
    _verify_review_command(command, command_sha256, forbidden_command_roots)
    environment = clean_child_environment(
        snapshot,
        quarantine,
        identity=identity,
        provider_proxy_port=provider_proxy_port,
    )
    profile = sandbox_profile(
        protected,
        quarantine,
        snapshot,
        identity,
        provider_proxy_port=provider_proxy_port,
    )
    _run_seatbelt_negative_control(
        sandbox,
        profile,
        identity,
        protected,
        snapshot,
        quarantine,
        environment,
    )
    if _quarantine_identity(quarantine) != quarantine_identity:
        raise BoundaryError("quarantine root changed before review")
    _verify_review_command(command, command_sha256, forbidden_command_roots)
    if provider_proxy_port is not None:
        _verify_provider_proxy(provider_proxy_port)

    result: subprocess.CompletedProcess[bytes] | None = None
    command_error: BaseException | None = None
    try:
        result = _run_command(
            sandbox,
            profile,
            command,
            identity=identity,
            cwd=snapshot,
            environment=environment,
            quarantine=quarantine,
            timeout_seconds=timeout_seconds,
            output_stem="review",
            command_status=True,
        )
    except BaseException as exc:
        command_error = exc

    try:
        _require_no_reviewer_processes(identity)
        rediscovered_root, rediscovered_protected = discover_repository(root)
        if rediscovered_root != root or rediscovered_protected != protected:
            raise BoundaryError("registered worktree inventory changed during isolated review")
        after_review = protected_manifest(protected)
        _require_single_link_protected_files(after_review)
        snapshot_after = protected_manifest((snapshot,))
        _quarantine_usage(quarantine)
        if _quarantine_identity(quarantine) != quarantine_identity:
            raise BoundaryError("quarantine root changed during isolated review")
        _verify_review_command(command, command_sha256, forbidden_command_roots)
        if provider_proxy_port is not None:
            _verify_provider_proxy(provider_proxy_port)
    except BoundaryError as exc:
        raise BoundaryError("post-review verification is incomplete") from exc
    changes = _changed_entries(after_export, after_review)
    if changes:
        _print_changes(changes)
        raise BoundaryError("protected repository state changed during isolated review")
    snapshot_changes = _changed_entries(snapshot_before, snapshot_after)
    if snapshot_changes:
        raise BoundaryError("review snapshot changed during isolated review")
    if command_error is not None:
        raise command_error
    if result is None:
        raise BoundaryError("isolated review produced no process result")
    if result.returncode != 0:
        return REVIEW_COMMAND_FAILURE

    findings = validate_findings(result.stdout, entries)
    accepted = json.dumps(
        {"schema": FINDINGS_SCHEMA, "findings": findings},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    _write_control_file(quarantine / "accepted-findings.json", accepted)
    print(f"isolated review accepted {len(findings)} scalar finding coordinate(s)")
    print(f"quarantine retained at {quarantine}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "run a command in a Git-free quarantine from a trusted root supervisor, "
            "using an explicitly named dedicated non-admin reviewer account"
        )
    )
    parser.add_argument("--repo", default=".", help="repository to export for review")
    parser.add_argument(
        "--reviewer-user",
        required=True,
        help="dedicated non-admin, non-login account used only for isolated review",
    )
    parser.add_argument(
        "--command-sha256",
        required=True,
        help="expected SHA-256 of the root-installed review executable",
    )
    parser.add_argument(
        "--quarantine-dir",
        help="new directory that will retain the review snapshot and output",
    )
    parser.add_argument(
        "--provider-proxy-port",
        type=int,
        metavar="PORT",
        help="root-controlled localhost proxy restricted to the required provider",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help="hard review time limit",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run_isolated_review(
            Path(args.repo),
            command,
            reviewer_user=args.reviewer_user,
            command_sha256=args.command_sha256,
            quarantine_dir=args.quarantine_dir,
            provider_proxy_port=args.provider_proxy_port,
            timeout_seconds=args.timeout,
        )
    except BoundaryError as exc:
        print(f"ERROR: isolated review boundary unavailable: {exc}", file=sys.stderr)
        return BOUNDARY_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
