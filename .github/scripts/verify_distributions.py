"""Prove that release artifacts retain CCE's independent audit surface."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import email.policy
import gzip
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import threading
import time
import tomllib
import unicodedata
import venv
import zipfile
import zlib
from collections import Counter
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]

DISTRIBUTION_NAME = "causal-continuity-engine"
IMPORT_PACKAGE = "causal_continuity_engine"
CONSOLE_COMMAND = "cce-engine"
EGG_INFO = f"{IMPORT_PACKAGE}.egg-info"
ENTRY_POINTS_BYTES = (
    f"[console_scripts]\n{CONSOLE_COMMAND} = {IMPORT_PACKAGE}.cli:main\n"
).encode("ascii")
TOP_LEVEL_BYTES = (
    f"{IMPORT_PACKAGE}\n").encode("ascii")
WHEEL_AUDIT_DIRECTORY = "share/causal-continuity-engine/audit"

SDIST_ROOT_FILES = {
    ".editorconfig", ".gitattributes", ".gitignore", ".gitleaks.toml",
    ".pre-commit-config.yaml", "AGENTS.md", "CHANGELOG.md", "LICENSE.txt",
    "CITATION.cff", "MANIFEST.in", "NOTICE", "README.md", "SPEC.md", "justfile",
    "pyproject.toml", "requirements-dev.in", "requirements-dev.lock",
}
GITHUB_ROOT_FILES = {
    ".github/CODEOWNERS",
    ".github/CONTRIBUTING.md",
    ".github/SECURITY.md",
    ".github/SUPPORT.md",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    ".github/release.yml",
    ".github/ruleset.README.md",
    ".github/ruleset.json",
    ".github/tag-ruleset.json",
}
GITHUB_SOURCE_TREES = {
    ".github/ISSUE_TEMPLATE": {".yml"},
    ".github/scripts": {".py"},
    ".github/workflows": {".yml"},
}
GITHOOK_FILES = {
    ".githooks/commit-msg",
    ".githooks/pre-commit",
}
SDIST_SOURCE_TREES = {
    "benchmarks": {".py"},
    IMPORT_PACKAGE: {".py", "py.typed"},
    "docs": {".md", ".png", ".svg"},
    "examples": {".py"},
    "schemas": {".json"},
    "tests": {".py"},
    "vectors": {".json", ".py"},
    "verifiers": {".py"},
}
SDIST_GENERATED_FILES = {
    "PKG-INFO",
    "setup.cfg",
    f"{EGG_INFO}/PKG-INFO",
    f"{EGG_INFO}/SOURCES.txt",
    f"{EGG_INFO}/dependency_links.txt",
    f"{EGG_INFO}/entry_points.txt",
    f"{EGG_INFO}/requires.txt",
    f"{EGG_INFO}/top_level.txt",
}
WHEEL_BEHAVIOR_TESTS = (
    "tests/test_distribution_environment.py",
    "tests/test_store_graph.py",
    "tests/test_invalidation_resume.py",
    "tests/test_trust.py",
    "tests/test_cli.py",
    "tests/test_conformance.py",
    "tests/test_mcp_server.py",
)
WHEEL_EVIDENCE_TREES = {
    "benchmarks": {".py"},
    "tests": {".py"},
    "vectors": {".json", ".py"},
    "verifiers": {".py"},
}
WHEEL_DIST_INFO_FILES = {
    "METADATA",
    "RECORD",
    "WHEEL",
    "entry_points.txt",
    "licenses/LICENSE.txt",
    "licenses/NOTICE",
    "top_level.txt",
}
AUDIT_TOOL_DISTRIBUTIONS = {
    "attrs",
    "iniconfig",
    "jsonschema",
    "jsonschema-specifications",
    "packaging",
    "pluggy",
    "pygments",
    "pytest",
    "referencing",
    "rpds-py",
}
AUDIT_TOOL_IMPORTS = {
    "attrs": ("attr", "attrs"),
    "iniconfig": ("iniconfig",),
    "jsonschema": ("jsonschema",),
    "jsonschema-specifications": ("jsonschema_specifications",),
    "packaging": ("packaging",),
    "pluggy": ("pluggy",),
    "pygments": ("pygments",),
    "pytest": ("pytest", "_pytest"),
    "referencing": ("referencing",),
    "rpds-py": ("rpds",),
    "colorama": ("colorama",),
    "typing-extensions": ("typing_extensions",),
}
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}

# Generous ceilings for the reviewed project, but finite bounds for hostile
# compressed input, tar bookkeeping, and materialized source bytes.
MAX_SDIST_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_SDIST_MEMBER_BYTES = 16 * 1024 * 1024
MAX_SDIST_TOTAL_BYTES = 128 * 1024 * 1024
GIT_READ_TIMEOUT_SECONDS = 30
MAX_SDIST_MEMBERS = 4096
MAX_SDIST_TAR_BYTES = 160 * 1024 * 1024
MAX_WHEEL_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_WHEEL_MEMBER_BYTES = 32 * 1024 * 1024
MAX_WHEEL_TOTAL_BYTES = 256 * 1024 * 1024
MAX_WHEEL_MEMBERS = 4096
MAX_SUBPROCESS_OUTPUT_BYTES = 1024 * 1024
ENSUREPIP_TIMEOUT_SECONDS = 300
SUBPROCESS_READ_CHUNK_BYTES = 64 * 1024
SUBPROCESS_OUTPUT_MARKER = b"\n...[output truncated at release-verifier cap]...\n"
MIN_SOURCE_EPOCH = 315532800  # 1980-01-01, the ZIP timestamp floor.
MAX_SOURCE_EPOCH = (1 << 32) - 1  # The gzip MTIME field is unsigned 32-bit.

_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
_ZIP_END_OF_CENTRAL_DIRECTORY = struct.Struct("<4s4H2LH")

_CONTENT_MARK_SCANNER = None


def _content_mark_scanner():
    """Load the repository's single scanner without importing package code."""
    global _CONTENT_MARK_SCANNER
    if _CONTENT_MARK_SCANNER is not None:
        return _CONTENT_MARK_SCANNER
    path = Path(__file__).with_name("check_content_marks.py")
    spec = importlib.util.spec_from_file_location(
        "causal_continuity_engine_content_mark_scanner", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the content-integrity scanner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise SystemExit("cannot initialize the content-integrity scanner") from exc
    if not callable(getattr(module, "scan_blob", None)):
        raise SystemExit("content-integrity scanner has no scan_blob API")
    _CONTENT_MARK_SCANNER = module
    return module


def _scan_distribution_payloads(payloads: dict[str, bytes], *, label: str) -> None:
    """Require complete clean scans of member names and uncompressed bytes."""
    scanner = _content_mark_scanner()
    allowed_statuses = {
        scanner.PRESENT,
        scanner.MALFORMED,
        scanner.INCONCLUSIVE,
        scanner.SUSPICIOUS,
    }
    for name, body in sorted(payloads.items()):
        try:
            name_findings = scanner.scan_blob(
                "<archive-member-name>", name.encode("utf-8"), text_required=True)
            body_findings = scanner.scan_blob(name, body)
        except Exception as exc:
            raise SystemExit(
                f"{label} content-integrity scan did not complete for {name}"
            ) from exc
        findings = name_findings + body_findings
        if not isinstance(findings, tuple) or any(
            getattr(finding, "status", None) not in allowed_statuses
            or not isinstance(getattr(finding, "code", None), str)
            for finding in findings
        ):
            raise SystemExit(f"{label} content-integrity scanner returned an invalid result")
        if any(finding.status == scanner.INCONCLUSIVE for finding in findings):
            raise SystemExit(
                f"{label} content-integrity scan is incomplete for {name}"
            )
        if findings:
            raise SystemExit(f"{label} contains prohibited content in {name}")


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _venv_entrypoint(root: Path, name: str) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    directory = "Scripts" if sys.platform == "win32" else "bin"
    return root / directory / f"{name}{suffix}"


def _prepare_cli_smoke_directory(root: Path) -> Path:
    project = root / "cli-project"
    project.mkdir(mode=0o755)
    return project


def _portable_archive_key(name: str, *, label: str = "wheel") -> str:
    raw = name[:-1] if name.endswith("/") else name
    parts = raw.split("/")
    unsafe = (
        not raw
        or name.startswith("/")
        or "\\" in name
        or any(not part or part in {".", ".."} for part in parts)
        or any(":" in part for part in parts)
        or any(any(char in '<>"|?*' for char in part) for part in parts)
        or any(part.endswith((" ", ".")) for part in parts)
        or any(any(ord(char) < 32 or ord(char) == 127 for char in part)
               for part in parts)
        or unicodedata.normalize("NFC", raw) != raw
        or any(part.rstrip(" .").split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
               for part in parts)
    )
    if unsafe or PurePosixPath(raw).is_absolute():
        raise SystemExit(f"{label} contains unsafe archive path: {name}")
    return unicodedata.normalize("NFC", raw).casefold()


def _validate_archive_path_graph(
        entries: list[tuple[str, bool]], *, label: str) -> None:
    """Reject path aliases and file/directory conflicts on portable filesystems."""
    portable_files: dict[str, str] = {}
    portable_directories: dict[str, str] = {}
    for name, is_directory in entries:
        key = _portable_archive_key(name, label=label)
        raw = name[:-1] if name.endswith("/") else name
        parts = PurePosixPath(raw).parts
        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index])
            prefix_key = prefix.casefold()
            previous_prefix = portable_directories.setdefault(
                prefix_key, prefix)
            if previous_prefix != prefix:
                raise SystemExit(
                    f"{label} directory prefixes collide cross-platform: "
                    f"{previous_prefix}, {prefix}")
            if prefix_key in portable_files:
                raise SystemExit(
                    f"{label} file/directory paths collide cross-platform: "
                    f"{portable_files[prefix_key]}, {name}")

        if is_directory:
            if key in portable_files:
                raise SystemExit(
                    f"{label} file/directory paths collide cross-platform: "
                    f"{portable_files[key]}, {name}")
            previous_directory = portable_directories.setdefault(key, raw)
            if previous_directory != raw:
                raise SystemExit(
                    f"{label} directory paths collide cross-platform: "
                    f"{previous_directory}, {raw}")
            continue

        if key in portable_directories:
            raise SystemExit(
                f"{label} file/directory paths collide cross-platform: "
                f"{name}, {portable_directories[key]}")
        previous_file = portable_files.setdefault(key, name)
        if previous_file != name:
            raise SystemExit(
                f"{label} archive paths collide cross-platform: "
                f"{previous_file}, {name}")


def _archive_names_are_safe(archive: zipfile.ZipFile) -> None:
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise SystemExit(
            "wheel contains duplicate archive entries: " + ", ".join(duplicates))
    _validate_archive_path_graph(
        [(entry.filename, entry.is_dir()) for entry in entries], label="wheel")


def _canonical_wheel_bytes(payloads: dict[str, bytes], epoch: int) -> bytes:
    """Reconstruct the one accepted complete ZIP representation."""
    # Raw DEFLATE bytes can vary between zlib releases. The release workflow's
    # two builds and final verification intentionally run in one pinned Python
    # tool environment, so this is a same-runtime canonical-byte contract.
    rendered = io.BytesIO()
    timestamp = time.gmtime(epoch)[:6]
    with zipfile.ZipFile(rendered, "w") as archive:
        for name, payload in sorted(payloads.items()):
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                info, payload, compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9)
    return rendered.getvalue()


def _zip_dos_datetime(epoch: int) -> tuple[int, int]:
    year, month, day, hour, minute, second = time.gmtime(epoch)[:6]
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    return dos_time, dos_date


def _verify_wheel_zip_layout(
        raw: bytes, infos: list[zipfile.ZipInfo], epoch: int) -> None:
    """Validate ZIP framing independently of the DEFLATE implementation."""
    if len(raw) < _ZIP_END_OF_CENTRAL_DIRECTORY.size:
        raise SystemExit("wheel ZIP archive is truncated")
    eocd_offset = len(raw) - _ZIP_END_OF_CENTRAL_DIRECTORY.size
    try:
        (
            signature, disk_number, central_disk, disk_entries,
            total_entries, central_size, central_offset, comment_size,
        ) = _ZIP_END_OF_CENTRAL_DIRECTORY.unpack_from(raw, eocd_offset)
    except struct.error as exc:
        raise SystemExit("wheel ZIP archive is truncated") from exc
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or central_disk != 0
        or disk_entries != len(infos)
        or total_entries != len(infos)
        or comment_size != 0
        or central_offset + central_size != eocd_offset
    ):
        raise SystemExit("wheel ZIP envelope is not canonical: invalid central directory")

    dos_time, dos_date = _zip_dos_datetime(epoch)
    local_offset = 0
    for info in infos:
        if info.header_offset != local_offset:
            raise SystemExit("wheel ZIP envelope is not canonical: local-entry gap")
        try:
            (
                signature, extract_version, flags, compression,
                local_time, local_date, crc, compressed_size,
                file_size, name_size, extra_size,
            ) = _ZIP_LOCAL_HEADER.unpack_from(raw, local_offset)
        except struct.error as exc:
            raise SystemExit("wheel ZIP archive has a truncated local header") from exc
        name_start = local_offset + _ZIP_LOCAL_HEADER.size
        data_start = name_start + name_size + extra_size
        try:
            expected_name = info.filename.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SystemExit(
                "wheel ZIP envelope is not canonical: member names must be ASCII") from exc
        if (
            signature != b"PK\x03\x04"
            or extract_version != info.extract_version
            or flags != info.flag_bits
            or compression != info.compress_type
            or local_time != dos_time
            or local_date != dos_date
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or raw[name_start:name_start + name_size] != expected_name
            or extra_size != 0
        ):
            raise SystemExit("wheel ZIP envelope is not canonical: invalid local header")
        local_offset = data_start + info.compress_size
    if local_offset != central_offset:
        raise SystemExit("wheel ZIP envelope is not canonical: invalid local payload span")

    cursor = central_offset
    for info in infos:
        try:
            (
                signature, create_version, extract_version, flags, compression,
                central_time, central_date, crc, compressed_size, file_size,
                name_size, extra_size, member_comment_size, disk_start,
                internal_attr, external_attr, header_offset,
            ) = _ZIP_CENTRAL_HEADER.unpack_from(raw, cursor)
        except struct.error as exc:
            raise SystemExit("wheel ZIP archive has a truncated central header") from exc
        name_start = cursor + _ZIP_CENTRAL_HEADER.size
        entry_end = name_start + name_size + extra_size + member_comment_size
        expected_create_version = (info.create_system << 8) | info.create_version
        if (
            signature != b"PK\x01\x02"
            or create_version != expected_create_version
            or extract_version != info.extract_version
            or flags != info.flag_bits
            or compression != info.compress_type
            or central_time != dos_time
            or central_date != dos_date
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or raw[name_start:name_start + name_size] != info.filename.encode("ascii")
            or extra_size != 0
            or member_comment_size != 0
            or disk_start != info.volume
            or internal_attr != info.internal_attr
            or external_attr != info.external_attr
            or header_offset != info.header_offset
        ):
            raise SystemExit("wheel ZIP envelope is not canonical: invalid central header")
        cursor = entry_end
    if cursor != central_offset + central_size:
        raise SystemExit("wheel ZIP envelope is not canonical: central-entry gap")


def _verify_wheel_semantic_envelope(
        raw: bytes, infos: list[zipfile.ZipInfo],
        payloads: dict[str, bytes], epoch: int) -> None:
    """Require canonical metadata while permitting zlib-dependent DEFLATE bytes."""
    if [info.filename for info in infos] != sorted(payloads):
        raise SystemExit("wheel ZIP envelope is not canonical: member order")
    canonical = _canonical_wheel_bytes(payloads, epoch)
    with zipfile.ZipFile(io.BytesIO(canonical)) as expected_archive:
        expected_infos = expected_archive.infolist()
    fields = (
        "filename", "date_time", "compress_type", "comment", "extra",
        "create_system", "create_version", "extract_version", "flag_bits",
        "volume", "internal_attr", "external_attr", "file_size", "CRC",
    )
    if len(infos) != len(expected_infos):
        raise SystemExit("wheel ZIP envelope is not canonical: member count")
    for info, expected in zip(infos, expected_infos, strict=True):
        if any(getattr(info, field) != getattr(expected, field) for field in fields):
            raise SystemExit(
                "wheel ZIP envelope is not canonical: member metadata differs")
    _verify_wheel_zip_layout(raw, infos, epoch)


def _verify_wheel_envelope(
        path: Path, source_root: Path = ROOT, *,
        expected_epoch: int | None = None,
        verify_recompression_bytes: bool = True) -> None:
    """Reject unsafe ZIPs; optionally enforce same-runtime compression bytes."""
    epoch = (
        _commit_epoch(source_root) if expected_epoch is None
        else _validated_source_epoch(expected_epoch)
    )
    size = path.stat().st_size
    if size <= 0 or size > MAX_WHEEL_ARCHIVE_BYTES:
        raise SystemExit("wheel archive exceeds the size limit")
    raw = path.read_bytes()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            _archive_names_are_safe(archive)
            infos = archive.infolist()
            if len(infos) > MAX_WHEEL_MEMBERS:
                raise SystemExit("wheel exceeds the member-count limit")
            if any(info.is_dir() for info in infos):
                raise SystemExit("canonical wheel must not contain directory entries")
            total_size = 0
            payloads = {}
            for info in infos:
                if info.file_size < 0 or info.file_size > MAX_WHEEL_MEMBER_BYTES:
                    raise SystemExit(
                        "wheel member exceeds the size limit: " + info.filename)
                total_size += info.file_size
                if total_size > MAX_WHEEL_TOTAL_BYTES:
                    raise SystemExit(
                        "wheel exceeds the total uncompressed-size limit")
                payloads[info.filename] = archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise SystemExit("wheel is not a valid bounded ZIP archive") from exc
    _verify_wheel_semantic_envelope(raw, infos, payloads, epoch)
    _scan_distribution_payloads(payloads, label="wheel")
    if verify_recompression_bytes and raw != _canonical_wheel_bytes(payloads, epoch):
        raise SystemExit("wheel complete ZIP envelope is not canonical")


def _expected_sdist_source_payload(
        source_root: Path = ROOT) -> dict[str, bytes]:
    """Materialize only index/ledger-owned files in the reviewed source policy."""
    source_root = source_root.resolve()
    names = _reviewed_source_names(source_root)
    expected: dict[str, bytes] = {}
    total_size = 0

    def add(relative: str) -> None:
        nonlocal total_size
        path = source_root.joinpath(*PurePosixPath(relative).parts)
        cursor = source_root
        for part in PurePosixPath(relative).parts:
            cursor /= part
            if cursor.is_symlink():
                raise SystemExit(
                    "sdist source manifest cannot include symlinks: " + relative)
        if path.is_symlink():
            raise SystemExit(
                "sdist source manifest cannot include symlinks: " + relative)
        if not path.is_file():
            raise SystemExit(
                "sdist source manifest is missing: " + relative)
        size = path.stat().st_size
        if size > MAX_SDIST_MEMBER_BYTES:
            raise SystemExit(
                "sdist source file exceeds the size limit: " + relative)
        total_size += size
        if total_size > MAX_SDIST_TOTAL_BYTES:
            raise SystemExit("sdist source payload exceeds the size limit")
        expected[relative] = path.read_bytes()

    for relative in sorted(names):
        add(relative)
    return expected


def _source_path_is_allowed(relative: str) -> bool:
    """Return whether a source path belongs to the explicit shipped surface."""
    path = PurePosixPath(relative)
    parts = path.parts
    if not parts or any(
            part in {".cce", "__pycache__", ".DS_Store"}
            or (index > 0 and part.startswith("."))
            for index, part in enumerate(parts)):
        return False
    if len(parts) == 1:
        return relative in SDIST_ROOT_FILES
    if relative in GITHUB_ROOT_FILES or relative in GITHOOK_FILES:
        return True
    for tree, selectors in GITHUB_SOURCE_TREES.items():
        prefix = tree + "/"
        if relative.startswith(prefix):
            return (
                len(parts) == 3
                and (path.suffix in selectors or path.name in selectors)
            )
    selectors = SDIST_SOURCE_TREES.get(parts[0])
    if selectors is None:
        return False
    if parts[0] in {
            "examples", "schemas", "tests", "vectors", "verifiers",
    } and len(parts) != 2:
        return False
    if parts[0] == "benchmarks" and not (
            len(parts) == 2
            or (len(parts) == 3 and parts[1] == "continuitybench")):
        return False
    return path.suffix in selectors or path.name in selectors


def _validated_source_names(names: list[str], *, label: str) -> set[str]:
    """Validate a NUL/ledger-derived source name set cross-platform."""
    if len(names) > MAX_SDIST_MEMBERS:
        raise SystemExit(f"{label} exceeds the source member-count limit")
    if len(names) != len(set(names)):
        raise SystemExit(f"{label} contains duplicate paths")
    portable_files: dict[str, str] = {}
    portable_directories: dict[str, str] = {}
    for name in names:
        try:
            name.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SystemExit(f"{label} path must be ASCII: {name}") from exc
        key = _portable_archive_key(name, label=label)
        previous = portable_files.setdefault(key, name)
        if previous != name:
            raise SystemExit(
                f"{label} paths collide cross-platform: {previous}, {name}")
        parts = PurePosixPath(name).parts
        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index])
            prefix_key = prefix.casefold()
            previous_prefix = portable_directories.setdefault(
                prefix_key, prefix)
            if previous_prefix != prefix:
                raise SystemExit(
                    f"{label} directory prefixes collide cross-platform: "
                    f"{previous_prefix}, {prefix}")
            if prefix_key in portable_files:
                raise SystemExit(
                    f"{label} file/directory paths collide cross-platform: "
                    f"{portable_files[prefix_key]}, {name}")
        if key in portable_directories:
            raise SystemExit(
                f"{label} file/directory paths collide cross-platform: "
                f"{name}, {portable_directories[key]}")
    return set(names)


def _isolated_git_reader(source_root: Path) -> tuple[str, dict[str, str]]:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("distribution verification requires Git")
    git_path = Path(git).resolve()
    path_entries = [str(git_path.parent)]
    environment = {
        "HOME": str(source_root / ".git" / "cce-no-global-home"),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if not system_root:
            raise SystemExit("cannot construct isolated Windows Git environment")
        system_root_path = Path(system_root).resolve()
        environment.update({
            "SystemRoot": str(system_root_path),
            "WINDIR": str(system_root_path),
            "COMSPEC": str(system_root_path / "System32" / "cmd.exe"),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        })
        path_entries.append(str(system_root_path / "System32"))
    else:
        path_entries.extend(["/usr/bin", "/bin"])
    environment["PATH"] = os.pathsep.join(dict.fromkeys(path_entries))
    return str(git_path), environment


def _git_source_names(source_root: Path) -> set[str] | None:
    """Return tracked plus nonignored development files for this exact worktree."""
    if shutil.which("git") is None:
        return None
    git, environment = _isolated_git_reader(source_root)
    try:
        top_level = subprocess.check_output(
            [git, "rev-parse", "--show-toplevel"], cwd=source_root,
            env=environment, stderr=subprocess.DEVNULL,
            timeout=GIT_READ_TIMEOUT_SECONDS).rstrip(b"\r\n")
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired):
        return None
    if Path(os.fsdecode(top_level)).resolve() != source_root:
        return None
    try:
        listed = subprocess.check_output(
            [
                git, "ls-files", "-z", "--cached", "--others",
                "--exclude-standard",
            ],
            cwd=source_root, env=environment,
            timeout=GIT_READ_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise SystemExit("cannot read the reviewed Git source inventory") from exc
    names = [os.fsdecode(raw) for raw in listed.split(b"\0") if raw]
    return _validated_source_names(names, label="Git source inventory")


def _git_index_entries(source_root: Path) -> dict[str, tuple[str, str]]:
    """Return canonical stage-zero index mode/object metadata by source path."""
    git, environment = _isolated_git_reader(source_root)
    try:
        listed = subprocess.check_output(
            [git, "ls-files", "-z", "--stage"],
            cwd=source_root,
            env=environment,
            timeout=GIT_READ_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise SystemExit("cannot read exact Git index object metadata") from exc
    entries: dict[str, tuple[str, str]] = {}
    raw_names: list[str] = []
    for entry in listed.split(b"\0"):
        if not entry:
            continue
        metadata, separator, raw_name = entry.partition(b"\t")
        fields = metadata.split()
        if separator != b"\t" or len(fields) != 3:
            raise SystemExit("Git index contains malformed source metadata")
        raw_mode, raw_object, raw_stage = fields
        name = os.fsdecode(raw_name)
        raw_names.append(name)
        if (
            raw_stage != b"0"
            or raw_mode not in {b"100644", b"100755"}
            or re.fullmatch(
                rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", raw_object) is None
            or name in entries
        ):
            raise SystemExit(
                "Git index contains noncanonical, conflicted, or duplicate source "
                f"metadata: {name}")
        entries[name] = (raw_mode.decode("ascii"), raw_object.decode("ascii"))
    _validated_source_names(raw_names, label="Git index source inventory")
    return entries


def _require_exact_git_source(source_root: Path = ROOT) -> None:
    """Bind every release input byte to stage zero and the exact HEAD tree."""
    source_root = source_root.resolve()
    names = _git_source_names(source_root)
    if names is None:
        raise SystemExit("exact release source verification requires a Git worktree")
    # Apply the complete shipped-source allowlist before invoking hash-object.
    if _reviewed_source_names(source_root) != names:
        raise SystemExit("Git source inventory changed during release verification")
    entries = _git_index_entries(source_root)
    tracked = set(entries)
    if not tracked.issubset(names):
        raise SystemExit("Git index source inventory is inconsistent")
    untracked = sorted(names - tracked)
    if untracked:
        raise SystemExit(
            "exact release source contains untracked files: " + ", ".join(untracked))

    git, environment = _isolated_git_reader(source_root)
    try:
        index_status = subprocess.run(
            [git, "diff-index", "--cached", "--quiet", "HEAD", "--"],
            cwd=source_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=GIT_READ_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("cannot bind the release index to HEAD") from exc
    if index_status.returncode != 0:
        raise SystemExit("release index differs from the exact HEAD tree")

    ordered = sorted(tracked)
    expected_modes = {
        name: "100755" if _canonical_sdist_mode(name, directory=False) == 0o755
        else "100644"
        for name in ordered
    }
    wrong_modes = sorted(
        name for name in ordered if entries[name][0] != expected_modes[name])
    if wrong_modes:
        raise SystemExit(
            "Git index modes differ from the canonical release modes: "
            + ", ".join(wrong_modes))

    path_input = "".join(f"{name}\n" for name in ordered).encode("ascii")
    try:
        rendered_hashes = subprocess.check_output(
            [git, "hash-object", "--no-filters", "--stdin-paths"],
            cwd=source_root,
            env=environment,
            input=path_input,
            stderr=subprocess.DEVNULL,
            timeout=GIT_READ_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise SystemExit("cannot hash exact physical release source bytes") from exc
    observed = rendered_hashes.decode("ascii", errors="strict").splitlines()
    if len(observed) != len(ordered) or any(
            re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", item) is None
            for item in observed):
        raise SystemExit("Git returned malformed physical source hashes")
    changed = [
        name for name, digest in zip(ordered, observed, strict=True)
        if digest != entries[name][1]
    ]
    if changed:
        raise SystemExit(
            "physical source bytes differ from the exact Git index blob "
            "(clean/smudge or EOL normalization can hide this): "
            + ", ".join(changed))


def _require_source_payload_matches_git_index(
        source_root: Path, payload: dict[str, bytes]) -> None:
    """Bind already captured source bytes to the exact stage-zero Git blobs."""
    entries = _git_index_entries(source_root.resolve())
    if set(payload) != set(entries):
        missing = sorted(set(entries) - set(payload))
        unexpected = sorted(set(payload) - set(entries))
        raise SystemExit(
            "captured release source inventory differs from the Git index: "
            f"missing={missing!r}, unexpected={unexpected!r}")
    mismatched = []
    for name, body in sorted(payload.items()):
        if not isinstance(body, bytes):
            raise SystemExit(f"captured release source is not bytes: {name}")
        expected_object = entries[name][1]
        git_object = f"blob {len(body)}\0".encode("ascii") + body
        if len(expected_object) == 40:
            observed = hashlib.sha1(
                git_object, usedforsecurity=False).hexdigest()
        else:
            observed = hashlib.sha256(git_object).hexdigest()
        if observed != expected_object:
            mismatched.append(name)
    if mismatched:
        raise SystemExit(
            "captured release source bytes differ from the exact Git index blob: "
            + ", ".join(mismatched))


def _sdist_ledger_source_names(source_root: Path) -> set[str]:
    """Read the closed setuptools ledger when Git metadata is unavailable."""
    ledger = source_root / EGG_INFO / "SOURCES.txt"
    if not ledger.is_file():
        raise SystemExit(
            "source verification requires either the exact Git worktree or "
            f"an extracted sdist with {EGG_INFO}/SOURCES.txt")
    try:
        payload = ledger.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("sdist source ledger must be UTF-8") from exc
    if "\r" in payload or not payload.endswith("\n"):
        raise SystemExit("sdist source ledger must use canonical LF text")
    lines = payload.splitlines()
    if lines != sorted(lines) or len(lines) != len(set(lines)):
        raise SystemExit("sdist source ledger must be unique and lexically ordered")
    generated_ledger = {
        name for name in SDIST_GENERATED_FILES
        if name.startswith(EGG_INFO + "/")
    }
    if not generated_ledger.issubset(lines):
        raise SystemExit("sdist source ledger omits required generated metadata")
    names = [name for name in lines if name not in generated_ledger]
    return _validated_source_names(names, label="sdist source ledger")


def _reviewed_source_names(source_root: Path = ROOT) -> set[str]:
    """Resolve and validate the authoritative source-file inventory."""
    source_root = source_root.resolve()
    names = _git_source_names(source_root)
    if names is None:
        names = _sdist_ledger_source_names(source_root)
    outside = sorted(name for name in names if not _source_path_is_allowed(name))
    if outside:
        raise SystemExit(
            "source inventory contains files outside the shipped allowlist: "
            + ", ".join(outside))
    required = SDIST_ROOT_FILES | GITHUB_ROOT_FILES | GITHOOK_FILES
    missing = sorted(required - names)
    if missing:
        raise SystemExit(
            "sdist source manifest is missing required files: " + ", ".join(missing))
    required_trees = set(SDIST_SOURCE_TREES) | set(GITHUB_SOURCE_TREES)
    empty_trees = sorted(
        tree for tree in required_trees
        if not any(name.startswith(tree + "/") for name in names))
    if empty_trees:
        raise SystemExit(
            "sdist source manifest is missing required trees: "
            + ", ".join(empty_trees))
    return names


def _sdist_expected_directories(files: set[str]) -> set[str]:
    directories: set[str] = set()
    for name in files:
        for parent in PurePosixPath(name).parents:
            rendered = parent.as_posix()
            if rendered != ".":
                directories.add(rendered)
    return directories


def _validated_source_epoch(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < MIN_SOURCE_EPOCH
        or value > MAX_SOURCE_EPOCH
    ):
        raise SystemExit(
            f"source epoch must be an integer from {MIN_SOURCE_EPOCH} "
            f"through {MAX_SOURCE_EPOCH}")
    return value


def _commit_epoch(source_root: Path = ROOT) -> int:
    git, environment = _isolated_git_reader(source_root)
    try:
        rendered = subprocess.check_output(
            [git, "log", "-1", "--format=%ct"], cwd=source_root,
            env=environment, text=True,
            timeout=GIT_READ_TIMEOUT_SECONDS).strip()
        epoch = int(rendered)
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, ValueError) as exc:
        raise SystemExit("cannot determine the source commit timestamp") from exc
    return _validated_source_epoch(epoch)


def _canonical_sdist_mode(relative: str, *, directory: bool) -> int:
    if directory:
        return 0o755
    executable = relative.startswith(".githooks/") or relative.endswith(".sh")
    return 0o755 if executable else 0o644


def _canonical_ustar_bytes(
        root: str, directories: set[str], payload: dict[str, bytes],
        epoch: int) -> bytes:
    """Reconstruct the one accepted raw USTAR representation."""
    entries = [(root, tarfile.DIRTYPE, "", b"")]
    entries.extend(
        (f"{root}/{relative}", tarfile.DIRTYPE, relative, b"")
        for relative in directories)
    entries.extend(
        (f"{root}/{relative}", tarfile.REGTYPE, relative, body)
        for relative, body in payload.items())
    rendered = io.BytesIO()
    with tarfile.open(
            fileobj=rendered, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, member_type, relative, body in sorted(entries):
            member = tarfile.TarInfo(name)
            member.type = member_type
            member.size = len(body) if member_type == tarfile.REGTYPE else 0
            member.mtime = epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mode = _canonical_sdist_mode(
                relative, directory=member_type == tarfile.DIRTYPE)
            archive.addfile(
                member,
                io.BytesIO(body) if member_type == tarfile.REGTYPE else None)
    return rendered.getvalue()


def _canonical_gzip_bytes(payload: bytes, epoch: int) -> bytes:
    # See _canonical_wheel_bytes: this exact compression check is deliberately
    # evaluated in the same pinned runtime that produced the release artifacts.
    rendered = io.BytesIO()
    with gzip.GzipFile(
            filename="", mode="wb", fileobj=rendered, mtime=epoch,
            compresslevel=9) as archive:
        archive.write(payload)
    return rendered.getvalue()


def _sdist_member_map(
        archive: tarfile.TarFile, expected_root: str, *,
        expected_epoch: int | None = None) -> dict[str, tarfile.TarInfo]:
    """Reject ambiguous/special tar entries and return root-relative members."""
    if archive.pax_headers:
        raise SystemExit("sdist must not contain global PAX headers")
    members = []
    total_size = 0
    for member in archive:
        members.append(member)
        if len(members) > MAX_SDIST_MEMBERS:
            raise SystemExit("sdist exceeds the member-count limit")
        if member.size < 0 or member.size > MAX_SDIST_MEMBER_BYTES:
            raise SystemExit(
                "sdist member exceeds the size limit: " + member.name)
        total_size += member.size
        if total_size > MAX_SDIST_TOTAL_BYTES:
            raise SystemExit("sdist exceeds the total uncompressed-size limit")

    names = [member.name for member in members]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise SystemExit(
            "sdist contains duplicate archive entries: " + ", ".join(duplicates))

    _validate_archive_path_graph(
        [(member.name, member.type == tarfile.DIRTYPE) for member in members],
        label="sdist",
    )
    relative_members: dict[str, tarfile.TarInfo] = {}
    for member in members:
        if member.name.endswith("/"):
            raise SystemExit(
                "sdist member names must not use trailing separators: "
                + member.name)
        name = member.name[:-1] if member.name.endswith("/") else member.name
        if member.type not in {tarfile.REGTYPE, tarfile.DIRTYPE}:
            raise SystemExit(
                "sdist contains a non-regular archive member: " + member.name)
        if name != expected_root and not name.startswith(expected_root + "/"):
            raise SystemExit(
                "sdist members must share the single canonical root "
                f"{expected_root}: {member.name}")
        relative = name[len(expected_root):].removeprefix("/")
        if member.pax_headers:
            raise SystemExit(
                "sdist members must not use extended/PAX headers: " + member.name)
        if member.linkname:
            raise SystemExit(
                "sdist regular members must not carry link fields: " + member.name)
        if member.devmajor != 0 or member.devminor != 0:
            raise SystemExit(
                "sdist regular members must not carry device fields: " + member.name)
        if (member.uid, member.gid, member.uname, member.gname) != (0, 0, "", ""):
            raise SystemExit(
                "sdist ownership headers are not canonical: " + member.name)
        if expected_epoch is not None and member.mtime != expected_epoch:
            raise SystemExit(
                "sdist member mtime differs from the source commit: " + member.name)
        expected_mode = _canonical_sdist_mode(
            relative, directory=member.type == tarfile.DIRTYPE)
        if member.mode != expected_mode:
            raise SystemExit(
                "sdist member mode is not canonical: " + member.name)
        if relative in relative_members:
            raise SystemExit(
                "sdist contains an ambiguous root-relative member: " + relative)
        relative_members[relative] = member

    if names != sorted(names):
        raise SystemExit("sdist members are not in canonical lexical order")
    root = relative_members.get("")
    if root is None or not root.isdir():
        raise SystemExit(
            f"sdist must contain exactly one directory root named {expected_root}")
    return relative_members


def _sdist_file_bytes(
        archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise SystemExit("sdist regular file cannot be read: " + member.name)
    payload = extracted.read()
    if len(payload) != member.size:
        raise SystemExit("sdist member size is inconsistent: " + member.name)
    return payload


def _runtime_version(source_root: Path = ROOT) -> str:
    """Read the one literal runtime version without executing package code."""
    init_path = source_root / IMPORT_PACKAGE / "__init__.py"
    try:
        tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        raise SystemExit("cannot parse the runtime package version source") from exc
    definitions = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(
                    isinstance(target, ast.Name) and target.id == "__version__"
                    for target in node.targets):
                definitions.append(node)
        elif (
                isinstance(node, (ast.AnnAssign, ast.AugAssign))
                and isinstance(node.target, ast.Name)
                and node.target.id == "__version__"
        ):
            definitions.append(node)
    if len(definitions) != 1:
        raise SystemExit("runtime package must define __version__ exactly once")
    definition = definitions[0]
    if (
        not isinstance(definition, ast.Assign)
        or len(definition.targets) != 1
        or not isinstance(definition.targets[0], ast.Name)
        or not isinstance(definition.value, ast.Constant)
        or not isinstance(definition.value.value, str)
    ):
        raise SystemExit("runtime __version__ must be one literal string assignment")
    version = definition.value.value
    if not version.isascii() or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version) is None:
        raise SystemExit("runtime __version__ is not safe release metadata")
    return version


def _citation_version(source_root: Path = ROOT) -> str:
    """Read the required top-level CFF software version as a strict scalar."""
    citation_path = source_root / "CITATION.cff"
    try:
        lines = citation_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit("cannot read CITATION.cff") from exc
    matches = [
        match.group(1)
        for line in lines
        if (match := re.fullmatch(r"version:\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)", line))
    ]
    if len(matches) != 1:
        raise SystemExit(
            "CITATION.cff must contain exactly one simple top-level version")
    return matches[0]


def _project_contract(source_root: Path = ROOT) -> tuple[dict, str]:
    """Bind PEP 621 metadata to the runtime package's sole version source."""
    project_file = source_root / "pyproject.toml"
    try:
        document = tomllib.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit("cannot parse pyproject.toml") from exc
    project = document.get("project")
    if not isinstance(project, dict) or project.get("name") != DISTRIBUTION_NAME:
        raise SystemExit(
            f"pyproject.toml project name must be {DISTRIBUTION_NAME}")
    if "version" in project or project.get("dynamic") != ["version"]:
        raise SystemExit("pyproject.toml version must be exclusively dynamic")
    dynamic = (
        document.get("tool", {}).get("setuptools", {}).get("dynamic", {})
    )
    expected = {"attr": f"{IMPORT_PACKAGE}.__version__"}
    if not isinstance(dynamic, dict) or dynamic.get("version") != expected:
        raise SystemExit(
            "setuptools dynamic version must read the runtime package __version__")
    runtime_version = _runtime_version(source_root)
    if _citation_version(source_root) != runtime_version:
        raise SystemExit("CITATION.cff version differs from runtime __version__")
    return document, runtime_version


def _distribution_filename_stem(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _verify_sdist_metadata(payload: bytes, source_root: Path = ROOT) -> None:
    project, runtime_version = _project_contract(source_root)
    metadata = BytesParser(policy=email.policy.default).parsebytes(payload)
    expected_headers = (
        ("Name", project["project"]["name"]),
        ("Version", runtime_version),
        ("Requires-Python", project["project"]["requires-python"]),
    )
    for header, expected in expected_headers:
        if _single_header(metadata, header) != expected:
            raise SystemExit(
                f"sdist PKG-INFO {header} differs from reviewed source metadata")
    if metadata.get_all("Provides-Extra", []) != ["dev"]:
        raise SystemExit("sdist PKG-INFO must declare exactly the dev extra")
    expected = {
        _canonical_distribution_name(requirement.split("==", 1)[0]): requirement
        for requirement in project["project"]["optional-dependencies"]["dev"]
    }
    actual = {}
    for requirement in metadata.get_all("Requires-Dist", []):
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)==([^ ;]+)\s*;\s*extra\s*==\s*[\"']dev[\"']",
            str(requirement))
        if match is None:
            raise SystemExit(
                "sdist PKG-INFO contains a runtime or non-exact dependency: "
                + str(requirement))
        name = _canonical_distribution_name(match.group(1))
        if name in actual:
            raise SystemExit(f"sdist PKG-INFO repeats dependency {name}")
        actual[name] = f"{match.group(1)}=={match.group(2)}"
    expected_versions = {
        name: requirement.split("==", 1)[1]
        for name, requirement in expected.items()
    }
    actual_versions = {
        name: requirement.split("==", 1)[1]
        for name, requirement in actual.items()
    }
    if actual_versions != expected_versions:
        raise SystemExit("sdist PKG-INFO dev dependencies differ from pyproject.toml")


def _verify_sdist_contract(
        archive: tarfile.TarFile, wheel: zipfile.ZipFile | None = None,
        source_root: Path = ROOT, *, expected_epoch: int | None = None,
        ) -> tuple[str, dict[str, tarfile.TarInfo], set[str], set[str]]:
    """Prove exhaustive, portable, byte-exact source and wheel equivalence."""
    project, project_version = _project_contract(source_root)
    project_name = project["project"]["name"]
    expected_root = (
        f"{_distribution_filename_stem(project_name)}-{project_version}")
    members = _sdist_member_map(
        archive, expected_root, expected_epoch=expected_epoch)
    source_payload = _expected_sdist_source_payload(source_root)
    expected_files = set(source_payload) | SDIST_GENERATED_FILES
    expected_directories = _sdist_expected_directories(expected_files)
    expected_members = {""} | expected_files | expected_directories
    actual_members = set(members)
    missing = sorted(expected_members - actual_members)
    unexpected = sorted(actual_members - expected_members)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise SystemExit(
            "sdist exhaustive member manifest differs ("
            + "; ".join(details) + ")")
    wrong_types = sorted(
        name for name in expected_files if not members[name].isfile())
    wrong_types += sorted(
        name for name in expected_directories | {""}
        if not members[name].isdir())
    if wrong_types:
        raise SystemExit(
            "sdist members have incorrect file/directory types: "
            + ", ".join(wrong_types))
    changed = sorted(
        name for name, source_bytes in source_payload.items()
        if _sdist_file_bytes(archive, members[name]) != source_bytes)
    if changed:
        raise SystemExit(
            "sdist source bytes differ from the reviewed tree: "
            + ", ".join(changed))

    root_metadata = _sdist_file_bytes(archive, members["PKG-INFO"])
    egg_metadata = _sdist_file_bytes(
        archive, members[f"{EGG_INFO}/PKG-INFO"])
    if root_metadata != egg_metadata:
        raise SystemExit("sdist root and egg-info PKG-INFO are not byte-identical")
    _verify_sdist_metadata(root_metadata, source_root)
    dist_root = None
    if wheel is not None:
        wheel_metadata_names = [
            name for name in wheel.namelist()
            if name.endswith(".dist-info/METADATA")]
        if len(wheel_metadata_names) != 1:
            raise SystemExit("wheel must contain exactly one METADATA for sdist parity")
        dist_root = wheel_metadata_names[0].removesuffix("/METADATA")
        if root_metadata != wheel.read(wheel_metadata_names[0]):
            raise SystemExit(
                "sdist PKG-INFO and wheel METADATA are not byte-identical")

    sources = _sdist_file_bytes(
        archive, members[f"{EGG_INFO}/SOURCES.txt"])
    try:
        sources_text = sources.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("sdist SOURCES.txt must be UTF-8") from exc
    if "\r" in sources_text or not sources_text.endswith("\n"):
        raise SystemExit("sdist SOURCES.txt must use canonical LF text")
    source_lines = sources_text.splitlines()
    if source_lines != sorted(source_lines) or len(source_lines) != len(set(source_lines)):
        raise SystemExit("sdist SOURCES.txt must be unique and lexically ordered")
    expected_sources = set(source_payload) | {
        name for name in SDIST_GENERATED_FILES
        if name.startswith(EGG_INFO + "/")
    }
    if set(source_lines) != expected_sources:
        raise SystemExit(
            "sdist SOURCES.txt does not exactly ledger source and egg-info files")

    setup_cfg = _sdist_file_bytes(archive, members["setup.cfg"])
    if setup_cfg != b"[egg_info]\ntag_build = \ntag_date = 0\n\n":
        raise SystemExit("sdist setup.cfg contains unmodeled build configuration")
    if _sdist_file_bytes(
            archive, members[f"{EGG_INFO}/dependency_links.txt"]) != b"\n":
        raise SystemExit("sdist dependency links must be empty")

    entry_points = _sdist_file_bytes(
        archive, members[f"{EGG_INFO}/entry_points.txt"])
    top_level = _sdist_file_bytes(
        archive, members[f"{EGG_INFO}/top_level.txt"])
    if entry_points != ENTRY_POINTS_BYTES:
        raise SystemExit("sdist console entry points differ from the reviewed command")
    if top_level != TOP_LEVEL_BYTES:
        raise SystemExit("sdist top-level packages differ from the reviewed package set")
    if wheel is not None and entry_points != wheel.read(
            f"{dist_root}/entry_points.txt"):
        raise SystemExit("sdist and wheel console entry points differ")
    if wheel is not None and top_level != wheel.read(f"{dist_root}/top_level.txt"):
        raise SystemExit("sdist and wheel top-level package ledgers differ")

    dev_requirements = project["project"]["optional-dependencies"]["dev"]
    expected_requires = (
        "\n[dev]\n" + "\n".join(dev_requirements) + "\n").encode("utf-8")
    if _sdist_file_bytes(
            archive, members[f"{EGG_INFO}/requires.txt"]) != expected_requires:
        raise SystemExit("sdist dev requirements differ from pyproject.toml")
    return expected_root, members, expected_files, expected_directories


def _verify_sdist_envelope(
        path: Path, source_root: Path = ROOT, *, expected_epoch: int) -> bytes:
    expected_epoch = _validated_source_epoch(expected_epoch)
    project, version = _project_contract(source_root)
    expected_name = (
        f"{_distribution_filename_stem(project['project']['name'])}-"
        f"{version}.tar.gz")
    if path.name != expected_name:
        raise SystemExit(
            f"sdist filename must be exactly {expected_name}: {path.name}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_SDIST_ARCHIVE_BYTES:
        raise SystemExit("sdist compressed archive exceeds the size limit")
    compressed = path.read_bytes()
    header = compressed[:10]
    canonical_prefix = b"\x1f\x8b\x08\x00"
    if (
        len(header) != 10
        or header[:4] != canonical_prefix
        or int.from_bytes(header[4:8], "little") != expected_epoch
        or header[8:] != b"\x02\xff"
    ):
        raise SystemExit("sdist gzip header is not canonical or commit-dated")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw_tar = decoder.decompress(compressed, MAX_SDIST_TAR_BYTES + 1)
    except zlib.error as exc:
        raise SystemExit("sdist gzip stream is corrupt") from exc
    if len(raw_tar) > MAX_SDIST_TAR_BYTES or decoder.unconsumed_tail:
        raise SystemExit("sdist decompressed tar exceeds the size limit")
    if not decoder.eof:
        raise SystemExit("sdist gzip stream is truncated")
    if decoder.unused_data:
        raise SystemExit("sdist must contain exactly one gzip stream and no tail")
    try:
        raw_tar += decoder.flush(MAX_SDIST_TAR_BYTES - len(raw_tar) + 1)
    except zlib.error as exc:
        raise SystemExit("sdist gzip stream cannot be finalized") from exc
    if len(raw_tar) > MAX_SDIST_TAR_BYTES:
        raise SystemExit("sdist decompressed tar exceeds the size limit")
    return raw_tar


def _validated_sdist_payload(
        path: Path, source_root: Path = ROOT, *,
        expected_epoch: int | None = None,
        wheel: zipfile.ZipFile | None = None,
        verify_recompression_bytes: bool = True,
        ) -> tuple[str, set[str], dict[str, bytes]]:
    """Fully validate an sdist, then materialize only its reviewed file set."""
    epoch = (
        _commit_epoch(source_root) if expected_epoch is None
        else _validated_source_epoch(expected_epoch)
    )
    raw_tar = _verify_sdist_envelope(path, source_root, expected_epoch=epoch)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
            root, members, files, directories = _verify_sdist_contract(
                archive, wheel, source_root, expected_epoch=epoch)
            payload = {
                name: _sdist_file_bytes(archive, members[name])
                for name in sorted(files)
            }
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit("sdist is not a valid gzip-compressed tar archive") from exc
    if raw_tar != _canonical_ustar_bytes(root, directories, payload, epoch):
        raise SystemExit("sdist raw USTAR envelope is not canonical")
    if (
        verify_recompression_bytes
        and path.read_bytes() != _canonical_gzip_bytes(raw_tar, epoch)
    ):
        raise SystemExit("sdist complete gzip envelope is not canonical")
    _scan_distribution_payloads(payload, label="sdist")
    return root, directories, payload


def _extract_validated_sdist(
        path: Path, destination: Path, source_root: Path = ROOT, *,
        expected_epoch: int | None = None,
        verify_recompression_bytes: bool = True) -> Path:
    """Extract no archive member until the entire closed-world contract passes."""
    root_name, directories, payload = _validated_sdist_payload(
        path, source_root, expected_epoch=expected_epoch,
        verify_recompression_bytes=verify_recompression_bytes)
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise SystemExit("validated sdist extraction destination must be empty")
    root = destination / root_name
    root.mkdir(mode=0o755)
    for relative in sorted(directories):
        target = root.joinpath(*PurePosixPath(relative).parts)
        target.mkdir(mode=0o755, parents=True, exist_ok=True)
    for relative, body in sorted(payload.items()):
        target = root.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(body)
        target.chmod(_canonical_sdist_mode(relative, directory=False))
    return root


def _compare_exact_payload(
        archive: zipfile.ZipFile, expected: dict[str, bytes],
        actual_names: set[str], *, label: str) -> None:
    expected_names = set(expected)
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise SystemExit(f"wheel {label} membership differs (" + "; ".join(details) + ")")
    changed = sorted(
        name for name, source_bytes in expected.items()
        if archive.read(name) != source_bytes
    )
    if changed:
        raise SystemExit(
            f"wheel {label} bytes differ from source: " + ", ".join(changed))


def _verify_wheel_runtime_payload(
        archive: zipfile.ZipFile, source_root: Path = ROOT) -> None:
    """Require the wheel's complete importable CCE payload to equal the tree."""
    source_payload = _expected_sdist_source_payload(source_root)
    expected = {
        name: body for name, body in source_payload.items()
        if name.startswith(IMPORT_PACKAGE + "/")
    }
    if not expected:
        raise SystemExit("source tree has no CCE runtime payload to verify")
    actual = {
        name for name in archive.namelist()
        if name.startswith(IMPORT_PACKAGE + "/") and not name.endswith("/")
    }
    _compare_exact_payload(
        archive, expected, actual, label="CCE runtime payload")


def _verify_wheel_evidence_payload(
        archive: zipfile.ZipFile, source_root: Path = ROOT) -> None:
    """Bind non-importable wheel audit data to the reviewed source tree."""
    file_names = {name for name in archive.namelist() if not name.endswith("/")}
    data_roots = {
        name.split("/", 1)[0] for name in file_names
        if name.split("/", 1)[0].endswith(".data")
    }
    if len(data_roots) != 1:
        raise SystemExit("wheel must contain exactly one .data root")
    audit_prefix = f"{next(iter(data_roots))}/data/{WHEEL_AUDIT_DIRECTORY}/"
    source_payload = _expected_sdist_source_payload(source_root)
    expected: dict[str, bytes] = {}
    for tree in WHEEL_EVIDENCE_TREES:
        expected.update({
            audit_prefix + name: body
            for name, body in source_payload.items()
            if name.startswith(tree + "/")
        })
    actual = {
        name for name in file_names
        if any(
            name.startswith(audit_prefix + tree + "/")
            for tree in WHEEL_EVIDENCE_TREES
        )
    }
    forbidden = sorted(
        name for name in file_names
        if any(name.startswith(tree + "/") for tree in WHEEL_EVIDENCE_TREES)
    )
    if forbidden:
        raise SystemExit(
            "wheel exposes generic top-level audit namespaces: "
            + ", ".join(forbidden))
    _compare_exact_payload(
        archive, expected, actual, label="auditable evidence payload")


def _verify_wheel_normative_payload(
        archive: zipfile.ZipFile, source_root: Path = ROOT) -> None:
    source_payload = _expected_sdist_source_payload(source_root)
    spec_entries = [
        name for name in archive.namelist()
        if name.endswith(f".data/data/{WHEEL_AUDIT_DIRECTORY}/SPEC.md")
    ]
    if len(spec_entries) != 1:
        raise SystemExit("wheel must contain exactly one normative SPEC.md")
    if archive.read(spec_entries[0]) != source_payload["SPEC.md"]:
        raise SystemExit("wheel normative SPEC.md bytes differ from source")

    marker = f".data/data/{WHEEL_AUDIT_DIRECTORY}/schemas/"
    data_root = spec_entries[0][:-len("SPEC.md")]
    source_schemas = {
        PurePosixPath(name).name: body
        for name, body in source_payload.items()
        if name.startswith("schemas/")
    }
    expected_entries = {
        data_root + "schemas/" + name: body
        for name, body in source_schemas.items()
    }
    actual_entries = {name for name in archive.namelist() if marker in name}
    missing = sorted(set(expected_entries) - actual_entries)
    unexpected = sorted(actual_entries - set(expected_entries))
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise SystemExit(
            "wheel schema membership differs (" + "; ".join(details) + ")")
    changed = sorted(
        name for name, source_bytes in expected_entries.items()
        if archive.read(name) != source_bytes
    )
    if changed:
        raise SystemExit(
            "wheel schema bytes differ from source: " + ", ".join(changed))


def _canonical_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _single_header(message, name: str) -> str:
    values = message.get_all(name, [])
    if len(values) != 1:
        raise SystemExit(f"wheel METADATA must contain exactly one {name} header")
    return str(values[0])


def _verify_wheel_record(
        archive: zipfile.ZipFile, record_name: str, file_names: set[str]) -> None:
    try:
        rows = list(csv.reader(io.StringIO(
            archive.read(record_name).decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise SystemExit("wheel RECORD is not valid UTF-8 CSV") from exc
    if any(len(row) != 3 for row in rows):
        raise SystemExit("wheel RECORD rows must have exactly three columns")
    recorded = [row[0] for row in rows]
    if len(recorded) != len(set(recorded)):
        raise SystemExit("wheel RECORD contains duplicate paths")
    if set(recorded) != file_names:
        raise SystemExit("wheel RECORD membership differs from archive files")
    for name, recorded_hash, recorded_size in rows:
        if name == record_name:
            if recorded_hash or recorded_size:
                raise SystemExit("wheel RECORD must leave its own hash and size empty")
            continue
        payload = archive.read(name)
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        expected_hash = "sha256=" + digest.decode("ascii")
        if recorded_hash != expected_hash or recorded_size != str(len(payload)):
            raise SystemExit(f"wheel RECORD digest or size differs for {name}")


def _verify_wheel_generated_contract(
        archive: zipfile.ZipFile, source_root: Path = ROOT) -> None:
    """Reject every unmodeled install payload and validate generated metadata."""
    file_names = {name for name in archive.namelist() if not name.endswith("/")}
    dist_roots = {
        name.split("/", 1)[0] for name in file_names
        if name.split("/", 1)[0].endswith(".dist-info")
    }
    data_roots = {
        name.split("/", 1)[0] for name in file_names
        if name.split("/", 1)[0].endswith(".data")
    }
    if len(dist_roots) != 1 or len(data_roots) != 1:
        raise SystemExit("wheel must contain exactly one .dist-info and one .data root")
    dist_root = next(iter(dist_roots))
    data_root = next(iter(data_roots))
    project, runtime_version = _project_contract(source_root)
    expected_build_root = (
        f"{_distribution_filename_stem(project['project']['name'])}-"
        f"{runtime_version}")
    if (
        dist_root != expected_build_root + ".dist-info"
        or data_root != expected_build_root + ".data"
    ):
        raise SystemExit(
            "wheel .dist-info and .data roots differ from the reviewed identity")

    source_payload = _expected_sdist_source_payload(source_root)
    expected: dict[str, bytes] = {
        name: body for name, body in source_payload.items()
        if name.startswith(IMPORT_PACKAGE + "/")
    }
    audit_prefix = f"{data_root}/data/{WHEEL_AUDIT_DIRECTORY}/"
    for tree in WHEEL_EVIDENCE_TREES:
        expected.update({
            audit_prefix + name: body
            for name, body in source_payload.items()
            if name.startswith(tree + "/")
        })
    expected[audit_prefix + "SPEC.md"] = source_payload["SPEC.md"]
    for name, body in source_payload.items():
        if name.startswith("schemas/"):
            expected[audit_prefix + name] = body
    expected[f"{dist_root}/licenses/LICENSE.txt"] = (
        source_payload["LICENSE.txt"])
    expected[f"{dist_root}/licenses/NOTICE"] = source_payload["NOTICE"]

    generated = {
        f"{dist_root}/{relative}" for relative in WHEEL_DIST_INFO_FILES
        if not relative.startswith("licenses/")
    }
    allowed = set(expected) | generated
    missing = sorted(allowed - file_names)
    unexpected = sorted(file_names - allowed)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise SystemExit(
            "wheel exhaustive member manifest differs (" + "; ".join(details) + ")")
    changed = sorted(
        name for name, source_bytes in expected.items()
        if archive.read(name) != source_bytes
    )
    if changed:
        raise SystemExit(
            "wheel modeled source bytes differ: " + ", ".join(changed))

    metadata_name = f"{dist_root}/METADATA"
    metadata = BytesParser(policy=email.policy.default).parsebytes(
        archive.read(metadata_name))
    if _single_header(metadata, "Name") != project["project"]["name"]:
        raise SystemExit("wheel METADATA project name differs from pyproject.toml")
    if _single_header(metadata, "Version") != runtime_version:
        raise SystemExit("wheel METADATA version differs from runtime __version__")
    if _single_header(metadata, "Requires-Python") != project["project"]["requires-python"]:
        raise SystemExit("wheel METADATA Requires-Python differs from pyproject.toml")
    if metadata.get_all("Provides-Extra", []) != ["dev"]:
        raise SystemExit("wheel METADATA must declare exactly the dev extra")

    expected_dev = {}
    for requirement in project["project"]["optional-dependencies"]["dev"]:
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^ ;]+)", requirement)
        if match is None:
            raise SystemExit(f"project dev requirement is not exact: {requirement}")
        expected_dev[_canonical_distribution_name(match.group(1))] = match.group(2)
    actual_dev = {}
    for requirement in metadata.get_all("Requires-Dist", []):
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)==([^ ;]+)\s*;\s*extra\s*==\s*[\"']dev[\"']",
            str(requirement),
        )
        if match is None:
            raise SystemExit(
                "wheel METADATA contains a runtime or non-exact dependency: "
                + str(requirement))
        name = _canonical_distribution_name(match.group(1))
        if name in actual_dev:
            raise SystemExit(f"wheel METADATA repeats dependency {name}")
        actual_dev[name] = match.group(2)
    if actual_dev != expected_dev:
        raise SystemExit("wheel METADATA dev dependencies differ from pyproject.toml")

    wheel_metadata = BytesParser(policy=email.policy.default).parsebytes(
        archive.read(f"{dist_root}/WHEEL"))
    build_backend = project["build-system"]["requires"]
    backend_match = re.fullmatch(r"setuptools==([^ ;]+)", build_backend[0])
    expected_generator = (
        f"setuptools ({backend_match.group(1)})" if backend_match else None)
    if (
        _single_header(wheel_metadata, "Wheel-Version") != "1.0"
        or _single_header(wheel_metadata, "Generator") != expected_generator
        or _single_header(wheel_metadata, "Root-Is-Purelib").lower() != "true"
        or wheel_metadata.get_all("Tag", []) != ["py3-none-any"]
    ):
        raise SystemExit("wheel WHEEL metadata differs from the reviewed pure-Python build")
    if archive.read(f"{dist_root}/entry_points.txt") != ENTRY_POINTS_BYTES:
        raise SystemExit("wheel console entry points differ from the reviewed command")
    if archive.read(f"{dist_root}/top_level.txt") != TOP_LEVEL_BYTES:
        raise SystemExit("wheel top-level packages differ from the reviewed package set")
    _verify_wheel_record(
        archive, f"{dist_root}/RECORD", file_names)


def _expected_runtime_modules(source_root: Path = ROOT) -> list[str]:
    modules = {IMPORT_PACKAGE}
    source_payload = _expected_sdist_source_payload(source_root)
    for name in source_payload:
        if not name.startswith(IMPORT_PACKAGE + "/") or not name.endswith(".py"):
            continue
        parts = list(PurePosixPath(name).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        if parts:
            modules.add(".".join(parts))
    return sorted(modules)


def _clean_subprocess_environment(
        isolation_root: Path, executable_directory: Path | None = None,
        *, parent_environment: dict[str, str] | None = None) -> dict[str, str]:
    """Construct a minimal offline environment for artifact-carried code."""
    parent = os.environ if parent_environment is None else parent_environment
    isolation_root = isolation_root.resolve()
    home = isolation_root / "home"
    temp = isolation_root / "tmp"
    cache = isolation_root / "cache"
    config = isolation_root / "config"
    for directory in (home, temp, cache, config):
        directory.mkdir(parents=True, exist_ok=True)
    path_entries = []
    if executable_directory is not None:
        path_entries.append(str(executable_directory.resolve()))
    environment: dict[str, str] = {}
    if os.name == "nt":
        system_root = parent.get("SystemRoot") or parent.get("WINDIR")
        if not system_root:
            raise SystemExit("cannot construct isolated Windows process environment")
        system_root_path = Path(system_root).resolve()
        environment.update({
            "SystemRoot": str(system_root_path),
            "WINDIR": str(system_root_path),
            "COMSPEC": str(system_root_path / "System32" / "cmd.exe"),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        })
        path_entries.extend([
            str(system_root_path / "System32"),
            str(system_root_path),
        ])
    else:
        path_entries.extend(["/usr/bin", "/bin"])
        environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    environment.update({
        "PATH": os.pathsep.join(dict.fromkeys(path_entries)),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(config),
        "LOCALAPPDATA": str(cache),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "TMP": str(temp),
        "TEMP": str(temp),
        "TMPDIR": str(temp),
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_CACHE_DIR": str(cache / "pip"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "CCE_RELEASE_ENVIRONMENT": "isolated",
    })
    return environment


def _drain_subprocess_pipe(
        stream, destination: bytearray, truncated: list[bool],
        failed: list[bool], overflow: threading.Event) -> None:
    """Drain one pipe concurrently while retaining a fixed prefix only."""
    try:
        while True:
            chunk = stream.read(SUBPROCESS_READ_CHUNK_BYTES)
            if not chunk:
                return
            remaining = MAX_SUBPROCESS_OUTPUT_BYTES - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated[0] = True
                overflow.set()
    except (OSError, ValueError):
        failed[0] = True
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _terminate_subprocess_tree(
        process: subprocess.Popen, environment: dict[str, str]) -> None:
    """Best-effort platform-native termination of the artifact process tree."""
    if os.name == "nt":
        system_root = environment.get("SystemRoot") or environment.get("WINDIR")
        taskkill = (
            Path(system_root) / "System32" / "taskkill.exe"
            if system_root else None
        )
        if taskkill is not None and taskkill.is_file():
            try:
                subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=environment, check=False,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _bounded_subprocess_transcript(
        stdout: bytes, stderr: bytes,
        stdout_truncated: bool, stderr_truncated: bool) -> str:
    if stdout_truncated:
        stdout += SUBPROCESS_OUTPUT_MARKER
    if stderr_truncated:
        stderr += SUBPROCESS_OUTPUT_MARKER
    rendered = b"[stdout]\n" + stdout + b"\n[stderr]\n" + stderr
    return rendered.decode("utf-8", errors="replace").strip()


def _run_checked(
        command: list[str], *, cwd: str | Path,
        environment: dict[str, str], label: str,
        timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    """Run a child with a deadline, output cap, and process-tree cleanup."""
    if isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive integer")
    popen_options = {}
    if os.name == "nt":
        popen_options["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_options["start_new_session"] = True
    try:
        process = subprocess.Popen(
            command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_options)
    except OSError as exc:
        raise SystemExit(f"{label} could not start") from exc
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    stdout_truncated = [False]
    stderr_truncated = [False]
    stdout_failed = [False]
    stderr_failed = [False]
    overflow = threading.Event()
    readers = [
        threading.Thread(
            target=_drain_subprocess_pipe,
            args=(
                process.stdout, stdout, stdout_truncated,
                stdout_failed, overflow,
            ),
            name="cce-release-stdout", daemon=True),
        threading.Thread(
            target=_drain_subprocess_pipe,
            args=(
                process.stderr, stderr, stderr_truncated,
                stderr_failed, overflow,
            ),
            name="cce-release-stderr", daemon=True),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    while process.poll() is None and not overflow.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        overflow.wait(min(remaining, 0.02))
    if process.poll() is not None and not overflow.is_set():
        for reader in readers:
            reader.join(timeout=max(deadline - time.monotonic(), 0.0))
        timed_out = any(reader.is_alive() for reader in readers)
    output_exceeded = overflow.is_set()
    if timed_out or output_exceeded:
        _terminate_subprocess_tree(process, environment)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                process.kill()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        for reader in readers:
            reader.join(timeout=1)
    else:
        process.wait()
    capture_failed = stdout_failed[0] or stderr_failed[0] or any(
        reader.is_alive() for reader in readers)
    stdout_bytes = bytes(stdout)
    stderr_bytes = bytes(stderr)
    transcript = _bounded_subprocess_transcript(
        stdout_bytes, stderr_bytes,
        stdout_truncated[0], stderr_truncated[0])
    if timed_out:
        raise SystemExit(
            f"{label} timed out after {timeout_seconds}s\n{transcript}")
    if output_exceeded:
        raise SystemExit(
            f"{label} exceeded the output limit\n{transcript}")
    if capture_failed:
        raise SystemExit(f"{label} output capture failed\n{transcript}")
    if process.returncode:
        raise SystemExit(
            f"{label} failed ({process.returncode})\n{transcript}")
    return subprocess.CompletedProcess(
        command, process.returncode,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"))


def _lock_marker_is_active(marker: str | None) -> bool:
    if marker is None:
        return True
    normalized = " ".join(marker.split())
    if normalized == "os_name == 'nt' or sys_platform == 'win32'":
        return os.name == "nt" or sys.platform == "win32"
    if normalized == "python_full_version < '3.13'":
        return sys.version_info < (3, 13)
    raise SystemExit("requirements-dev.lock contains an unreviewed marker: " + marker)


def _locked_dev_versions(source_root: Path = ROOT) -> dict[str, str]:
    """Parse active exact pins and require a SHA-256 lock for every entry."""
    lock = source_root / "requirements-dev.lock"
    try:
        lines = lock.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SystemExit("cannot read requirements-dev.lock as UTF-8") from exc
    entries: list[tuple[int, str, str, str | None]] = []
    pattern = re.compile(
        r"([A-Za-z0-9_.-]+)==([^\s;\\]+)(?:\s*;\s*(.*?))?\s*\\?$")
    for index, line in enumerate(lines):
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        match = pattern.fullmatch(line)
        if match is None:
            raise SystemExit(
                "requirements-dev.lock contains a non-exact requirement: " + line)
        marker = match.group(3)
        if marker is not None:
            marker = marker.removesuffix("\\").rstrip()
        entries.append((index, match.group(1), match.group(2), marker))
    versions: dict[str, str] = {}
    for entry_index, (line_index, raw_name, version, marker) in enumerate(entries):
        block_end = (
            entries[entry_index + 1][0]
            if entry_index + 1 < len(entries) else len(lines)
        )
        block = "\n".join(lines[line_index:block_end])
        if re.search(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)", block) is None:
            raise SystemExit(
                f"requirements-dev.lock entry {raw_name} has no SHA-256 hash")
        if not _lock_marker_is_active(marker):
            continue
        name = _canonical_distribution_name(raw_name)
        if name in versions:
            raise SystemExit("requirements-dev.lock repeats distribution " + name)
        versions[name] = version
    return versions


def _active_audit_tool_distributions() -> set[str]:
    names = set(AUDIT_TOOL_DISTRIBUTIONS)
    if os.name == "nt" or sys.platform == "win32":
        names.add("colorama")
    if sys.version_info < (3, 13):
        names.add("typing-extensions")
    return names


_LOCKED_TOOL_PROBE = r"""
import importlib
import json
import sys
from importlib.metadata import distribution
from importlib.util import find_spec
from pathlib import Path

expected_versions = json.loads(sys.argv[1])
expected_imports = json.loads(sys.argv[2])
purelib = Path(sys.argv[3]).resolve()
for name, version in sorted(expected_versions.items()):
    installed = distribution(name)
    if installed.version != version:
        raise SystemExit(
            f"child audit tool {name} version differs: {installed.version} != {version}")
    metadata_root = Path(installed._path).resolve()
    if purelib not in metadata_root.parents:
        raise SystemExit(f"child audit tool metadata is outside its venv: {metadata_root}")
for name, modules in sorted(expected_imports.items()):
    for module_name in modules:
        spec = find_spec(module_name)
        if spec is None or spec.origin is None:
            raise SystemExit(f"child audit tool import is missing: {module_name}")
        origin = Path(spec.origin).resolve()
        if purelib not in origin.parents:
            raise SystemExit(f"child audit tool import is outside its venv: {origin}")
        importlib.import_module(module_name)
for forbidden in ("benchmarks", "tests", "vectors", "verifiers"):
    if find_spec(forbidden) is not None:
        raise SystemExit(f"audit-tool copy exposed forbidden namespace: {forbidden}")
"""


def _install_locked_audit_tools(
        python: Path, clean_environment: dict[str, str],
        source_root: Path = ROOT) -> None:
    """Copy only the exact locked pytest/jsonschema closure into the child venv."""
    locked = _locked_dev_versions(source_root)
    selected = _active_audit_tool_distributions()
    missing_lock = sorted(selected - locked.keys())
    if missing_lock:
        raise SystemExit(
            "requirements-dev.lock omits audit tools: " + ", ".join(missing_lock))
    expected_versions = {name: locked[name] for name in selected}
    host_roots = {
        Path(value).resolve()
        for key in ("purelib", "platlib")
        if (value := sysconfig.get_path(key)) is not None
    }
    purelib_result = _run_checked(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        cwd=source_root, environment=clean_environment,
        label="child audit-tool location probe", timeout_seconds=30)
    child_purelib = Path(purelib_result.stdout.strip()).resolve()
    copied: dict[Path, bytes] = {}
    for name in sorted(selected):
        try:
            installed = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise SystemExit(f"locked audit distribution is not installed: {name}") from exc
        if installed.version != expected_versions[name]:
            raise SystemExit(
                f"host audit tool {name} version differs from requirements-dev.lock: "
                f"{installed.version} != {expected_versions[name]}")
        if installed.files is None:
            raise SystemExit(f"host audit distribution has no file ledger: {name}")
        copied_for_distribution = 0
        for entry in installed.files:
            source = Path(installed.locate_file(entry)).resolve()
            if not source.is_file() or source.suffix in {".pyc", ".pyo"}:
                continue
            relative = None
            for host_root in host_roots:
                try:
                    relative = source.relative_to(host_root)
                    break
                except ValueError:
                    continue
            if relative is None:
                continue
            if source.is_symlink() or "__pycache__" in relative.parts:
                continue
            body = source.read_bytes()
            target = child_purelib / relative
            previous = copied.get(target)
            if previous is not None and previous != body:
                raise SystemExit(
                    "locked audit distributions collide at " + relative.as_posix())
            if target.exists() and target.read_bytes() != body:
                raise SystemExit(
                    "child venv already contains different audit-tool bytes: "
                    + relative.as_posix())
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(source, target)
            copied[target] = body
            copied_for_distribution += 1
        if copied_for_distribution == 0:
            raise SystemExit(f"host audit distribution has no copyable files: {name}")
    expected_imports = {name: AUDIT_TOOL_IMPORTS[name] for name in selected}
    _run_checked(
        [
            str(python), "-I", "-c", _LOCKED_TOOL_PROBE,
            json.dumps(expected_versions, sort_keys=True),
            json.dumps(expected_imports, sort_keys=True),
            str(child_purelib),
        ],
        cwd=source_root, environment=clean_environment,
        label="child locked audit-tool probe", timeout_seconds=60)


_IMPORT_PROBE = r"""
import importlib
import json
import pkgutil
import sys
from importlib.metadata import distribution
from importlib.util import find_spec
from pathlib import Path

import causal_continuity_engine as runtime_package

prefix = Path(sys.prefix).resolve()
package = Path(runtime_package.__file__).resolve()
if prefix not in package.parents:
    raise SystemExit(
        f"causal_continuity_engine was imported outside verification venv: {package}")
expected = json.loads(sys.argv[1])
expected_version = sys.argv[2]
observed = sorted({
    "causal_continuity_engine",
    *(item.name for item in pkgutil.walk_packages(
        runtime_package.__path__, runtime_package.__name__ + "."))
})
if observed != expected:
    raise SystemExit(f"installed module membership differs: {observed!r} != {expected!r}")
if runtime_package.__version__ != expected_version:
    raise SystemExit(
        "installed runtime __version__ differs from reviewed source: "
        f"{runtime_package.__version__!r} != {expected_version!r}")
installed_distribution = distribution("causal-continuity-engine")
installed_version = installed_distribution.version
if installed_version != expected_version:
    raise SystemExit(
        "installed distribution metadata differs from runtime __version__: "
        f"{installed_version!r} != {expected_version!r}")
for name in expected:
    module = importlib.import_module(name)
    module_file = getattr(module, "__file__", None)
    if module_file is None or prefix not in Path(module_file).resolve().parents:
        raise SystemExit(f"{name} was imported outside verification venv: {module_file}")
for bootstrap_tool in ("pip", "setuptools"):
    if find_spec(bootstrap_tool) is not None:
        raise SystemExit(
            f"installed runtime probe retained bootstrap tool: {bootstrap_tool}")
for forbidden in ("benchmarks", "tests", "vectors", "verifiers"):
    if find_spec(forbidden) is not None:
        raise SystemExit(
            f"installed audit namespace is publicly importable: {forbidden}")
audit_suffix = "/share/causal-continuity-engine/audit/tests/test_cli.py"
audit_markers = []
for entry in installed_distribution.files or ():
    normalized = "/" + str(entry).replace("\\", "/")
    if normalized.endswith(audit_suffix):
        audit_markers.append(Path(installed_distribution.locate_file(entry)).resolve())
if len(audit_markers) != 1:
    raise SystemExit(
        f"installed distribution has {len(audit_markers)} owned audit markers")
audit_root = audit_markers[0].parent.parent
if (
    prefix not in audit_root.parents
    or audit_root.name != "audit"
    or audit_root.parent.name != "causal-continuity-engine"
    or audit_root.parent.parent.name != "share"
):
    raise SystemExit(f"installed audit root is outside verification venv: {audit_root}")
print("CCE_WHEEL_PROBE=" + json.dumps({
    "site_root": str(package.parent.parent),
    "audit_root": str(audit_root),
}))
"""


_AUDIT_IMPORT_PROBE = r"""
import importlib
import sys
from pathlib import Path

audit_root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(audit_root))
for name in ("tests", "tests.schema_validation", "verifiers", "verifiers.verify_proof"):
    module = importlib.import_module(name)
    origin = Path(module.__file__).resolve()
    if audit_root not in origin.parents:
        raise SystemExit(f"installed audit module bound outside owned root: {name} -> {origin}")
"""


_AUDIT_MODULE_LAUNCHER = r"""
import runpy
import sys
from pathlib import Path

audit_root = Path(sys.argv.pop(1)).resolve(strict=True)
module_name = sys.argv.pop(1)
sys.path.insert(0, str(audit_root))
runpy.run_module(module_name, run_name="__main__", alter_sys=True)
"""


def _bootstrap_venv_pip(
        python: Path, working_directory: Path,
        clean_environment: dict[str, str]) -> None:
    """Install interpreter-bundled pip under artifact-audit limits."""
    _run_checked(
        [str(python), "-Im", "ensurepip", "--upgrade", "--default-pip"],
        cwd=working_directory,
        environment=clean_environment,
        label="artifact verifier ensurepip bootstrap",
        timeout_seconds=ENSUREPIP_TIMEOUT_SECONDS,
    )


def _remove_venv_bootstrap_tools(
        python: Path, working_directory: Path,
        clean_environment: dict[str, str]) -> None:
    """Remove installation-only tools before exercising the zero-dependency wheel."""
    _run_checked(
        [
            str(python), "-Im", "pip", "uninstall", "--yes",
            "setuptools", "pip",
        ],
        cwd=working_directory,
        environment=clean_environment,
        label="artifact verifier bootstrap-tool removal",
        timeout_seconds=120,
    )


def _audit_module_command(
        python: Path, audit_root: Path, module_name: str,
        arguments: list[str], *, warnings_as_errors: bool = False) -> list[str]:
    command = [str(python)]
    if warnings_as_errors:
        command.extend(["-W", "error"])
    command.extend([
        "-P", "-c", _AUDIT_MODULE_LAUNCHER,
        str(audit_root.resolve()), module_name, *arguments,
    ])
    return command


def _wheel_behavior_test_command(
        python: Path, audit_root: Path, tests: list[str]) -> list[str]:
    return _audit_module_command(
        python, audit_root, "pytest",
        ["--import-mode=importlib", "-q", *tests],
        warnings_as_errors=True,
    )


def _verify_installed_wheel(wheel: Path) -> None:
    """Exercise imports, the console entry point, and behavior outside checkout."""
    with tempfile.TemporaryDirectory(prefix="cce-wheel-") as temp:
        temp_root = Path(temp)
        environment_root = temp_root / "venv"
        venv.EnvBuilder(with_pip=False).create(environment_root)
        python = _venv_python(environment_root)
        clean_env = _clean_subprocess_environment(
            temp_root / "process-environment", python.parent)
        _bootstrap_venv_pip(python, temp_root, clean_env)
        _run_checked(
            [str(python), "-m", "pip", "install", "--no-index", "--no-deps",
             str(wheel.resolve())],
            cwd=temp_root, environment=clean_env, label="wheel installation",
            timeout_seconds=120)
        _remove_venv_bootstrap_tools(python, temp_root, clean_env)

        expected_modules = _expected_runtime_modules()
        _, expected_version = _project_contract()
        probe = _run_checked(
            [
                str(python), "-I", "-c", _IMPORT_PROBE,
                json.dumps(expected_modules), expected_version,
            ],
            cwd=temp_root, environment=clean_env, label="installed-module probe",
            timeout_seconds=30)
        marker = next(
            (line for line in probe.stdout.splitlines()
             if line.startswith("CCE_WHEEL_PROBE=")), None)
        if marker is None:
            raise SystemExit("installed-module probe did not identify wheel site root")
        probe_result = json.loads(marker.split("=", 1)[1])
        audit_root = Path(probe_result["audit_root"])

        _install_locked_audit_tools(python, clean_env)
        _run_checked(
            [
                str(python), "-I", "-c", _IMPORT_PROBE,
                json.dumps(expected_modules), expected_version,
            ],
            cwd=temp_root, environment=clean_env,
            label="post-tool installed-module probe", timeout_seconds=30)
        _run_checked(
            [str(python), "-P", "-c", _AUDIT_IMPORT_PROBE, str(audit_root)],
            cwd=temp_root, environment=clean_env,
            label="owned audit-module origin probe", timeout_seconds=30)
        _run_checked(
            [str(python), "-P", "-m", "causal_continuity_engine.capabilities"],
            cwd=temp_root, environment=clean_env,
            label="installed capability verification", timeout_seconds=60)
        entrypoint = _venv_entrypoint(environment_root, CONSOLE_COMMAND)
        help_result = _run_checked(
            [str(entrypoint), "--help"], cwd=temp_root,
            environment=clean_env, label="installed CLI help", timeout_seconds=30)
        if f"usage: {CONSOLE_COMMAND}" not in help_result.stdout.lower():
            raise SystemExit(
                f"installed CLI did not expose the {CONSOLE_COMMAND} command surface")
        cli_project = _prepare_cli_smoke_directory(temp_root)
        init_result = _run_checked(
            [str(entrypoint), "--dir", str(cli_project),
             "--json", "init"], cwd=temp_root, environment=clean_env,
            label="installed CLI initialization", timeout_seconds=60)
        try:
            initialized = json.loads(init_result.stdout)
        except json.JSONDecodeError as exc:
            raise SystemExit("installed CLI initialization emitted invalid JSON") from exc
        if not str(initialized.get("project_id", "")).startswith("prj_"):
            raise SystemExit("installed CLI initialization did not create a project")

        tests = [str(audit_root / relative) for relative in WHEEL_BEHAVIOR_TESTS]
        missing_tests = [path for path in tests if not Path(path).is_file()]
        if missing_tests:
            raise SystemExit(
                "installed wheel is missing behavior tests: " + ", ".join(missing_tests))
        _run_checked(
            _wheel_behavior_test_command(python, audit_root, tests),
            cwd=temp_root, environment=clean_env,
            label="wheel-isolated behavioral and conformance suite",
            timeout_seconds=300)


def _verify_checksums(dist: Path, artifacts: list[Path]) -> None:
    manifest = dist / "SHA256SUMS"
    if not manifest.is_file():
        raise SystemExit("distribution is missing SHA256SUMS")
    expected = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in sorted(artifacts, key=lambda item: item.name))
    try:
        actual = manifest.read_text(encoding="ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit("SHA256SUMS must be ASCII") from exc
    if actual != expected:
        raise SystemExit("SHA256SUMS does not exactly describe the wheel and sdist")


def _release_assets(dist: Path) -> tuple[Path, Path]:
    """Require the exact set that the release workflow will publish."""
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("expected exactly one wheel and one sdist")
    allowed = {wheels[0].name, sdists[0].name, "SHA256SUMS"}
    unexpected = sorted(path.name for path in dist.iterdir()
                        if path.name not in allowed)
    if unexpected:
        raise SystemExit(
            "distribution contains unexpected release assets: "
            + ", ".join(unexpected))
    project, version = _project_contract()
    stem = _distribution_filename_stem(project["project"]["name"])
    expected_wheel = f"{stem}-{version}-py3-none-any.whl"
    expected_sdist = f"{stem}-{version}.tar.gz"
    if wheels[0].name != expected_wheel or sdists[0].name != expected_sdist:
        raise SystemExit(
            "release artifact filenames differ from the reviewed project identity")
    return wheels[0], sdists[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", nargs="?", type=Path, default=Path("dist"))
    parser.add_argument(
        "--portable-semantic", action="store_true",
        help=(
            "validate canonical archive semantics while tolerating only "
            "runtime-dependent ZIP/gzip recompression bytes"
        ),
    )
    parser.add_argument(
        "--source-epoch", type=int,
        help="explicit source commit Unix timestamp for --portable-semantic",
    )
    args = parser.parse_args(argv)
    if args.portable_semantic:
        if args.source_epoch is None:
            parser.error("--portable-semantic requires --source-epoch")
        epoch = _validated_source_epoch(args.source_epoch)
    else:
        if args.source_epoch is not None:
            parser.error("--source-epoch requires --portable-semantic")
        epoch = _commit_epoch(ROOT)
    _require_exact_git_source(ROOT)
    verify_recompression_bytes = not args.portable_semantic
    wheel, sdist = _release_assets(args.dist)
    _verify_checksums(args.dist, [wheel, sdist])
    _verify_wheel_envelope(
        wheel, ROOT, expected_epoch=epoch,
        verify_recompression_bytes=verify_recompression_bytes)

    with zipfile.ZipFile(wheel) as archive:
        _archive_names_are_safe(archive)
        _validated_sdist_payload(
            sdist, ROOT, expected_epoch=epoch, wheel=archive,
            verify_recompression_bytes=verify_recompression_bytes)
        _verify_wheel_runtime_payload(archive)
        _verify_wheel_evidence_payload(archive)
        _verify_wheel_normative_payload(archive)
        _verify_wheel_generated_contract(archive)

    _verify_installed_wheel(wheel)
    mode = "portable-semantic" if args.portable_semantic else "strict exact-byte"
    print(
        f"{mode} verification passed: sdist and wheel are exhaustive, "
        "source-equivalent, metadata-consistent, and pass wheel-isolated behavior")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
