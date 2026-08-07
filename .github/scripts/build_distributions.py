"""Build byte-reproducible release artifacts from one source revision."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
GIT_READ_TIMEOUT_SECONDS = 30
BUILD_BACKEND_TIMEOUT_SECONDS = 300
_GENERATED_SDIST_TEXT = {
    "PKG-INFO",
    "setup.cfg",
    "causal_continuity_engine.egg-info/PKG-INFO",
    "causal_continuity_engine.egg-info/SOURCES.txt",
    "causal_continuity_engine.egg-info/dependency_links.txt",
    "causal_continuity_engine.egg-info/entry_points.txt",
    "causal_continuity_engine.egg-info/requires.txt",
    "causal_continuity_engine.egg-info/top_level.txt",
}
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_ARCHIVE_READ_CHUNK_BYTES = 1024 * 1024


def _archive_stat_key(info: os.stat_result) -> tuple:
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


def _archive_identity_key(info: os.stat_result) -> tuple:
    """Physical identity fields shared by path and descriptor stat views."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        getattr(info, "st_file_attributes", 0),
        getattr(info, "st_reparse_tag", 0),
    )


def _archive_path_content_key(info: os.stat_result) -> tuple:
    """Stable cross-view fields; Windows descriptor ctime may refresh later."""
    return (
        *_archive_identity_key(info),
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
    )


def _bounded_physical_file_bytes(
        path: Path, maximum: int, *, label: str) -> bytes:
    """Read one stable regular file without following an indirect endpoint."""
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise SystemExit(f"{label} is unreadable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or getattr(before, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise SystemExit(f"{label} must be a physical regular file")
    if not 0 < before.st_size <= maximum:
        raise SystemExit(f"{label} exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SystemExit(f"{label} is unreadable or changed") from exc
    payload = bytearray()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _archive_identity_key(opened) != _archive_identity_key(before)
        ):
            raise SystemExit(f"{label} changed before it could be read")
        while len(payload) <= maximum:
            chunk = os.read(
                descriptor,
                min(_ARCHIVE_READ_CHUNK_BYTES, maximum + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > maximum:
            raise SystemExit(f"{label} grew beyond the size limit")
        after_open = os.fstat(descriptor)
        after_path = os.lstat(path)
        if (
            len(payload) != opened.st_size
            or _archive_stat_key(after_open) != _archive_stat_key(opened)
            or _archive_path_content_key(after_path)
            != _archive_path_content_key(opened)
        ):
            raise SystemExit(f"{label} changed while it was read")
    except OSError as exc:
        raise SystemExit(f"{label} is unreadable or changed") from exc
    finally:
        os.close(descriptor)
    return bytes(payload)


def _bounded_backend_sdist_tar_bytes(path: Path) -> bytes:
    """Bound gzip input and expansion before tar metadata is interpreted."""
    verifier = _release_verifier()
    compressed = _bounded_physical_file_bytes(
        path,
        verifier.MAX_SDIST_ARCHIVE_BYTES,
        label="backend sdist compressed archive",
    )
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw_tar = decoder.decompress(
            compressed, verifier.MAX_SDIST_TAR_BYTES + 1)
    except zlib.error as exc:
        raise SystemExit("backend sdist gzip stream is corrupt") from exc
    if len(raw_tar) > verifier.MAX_SDIST_TAR_BYTES or decoder.unconsumed_tail:
        raise SystemExit("backend sdist decompressed tar exceeds the size limit")
    if not decoder.eof:
        raise SystemExit("backend sdist gzip stream is truncated")
    if decoder.unused_data:
        raise SystemExit(
            "backend sdist must contain exactly one gzip stream and no tail")
    try:
        raw_tar += decoder.flush(
            verifier.MAX_SDIST_TAR_BYTES - len(raw_tar) + 1)
    except zlib.error as exc:
        raise SystemExit("backend sdist gzip stream cannot be finalized") from exc
    if len(raw_tar) > verifier.MAX_SDIST_TAR_BYTES:
        raise SystemExit("backend sdist decompressed tar exceeds the size limit")
    return raw_tar


def _clean_build_environment(
        isolation_root: Path, executable_directory: Path,
        *, parent_environment: dict[str, str] | None = None) -> dict[str, str]:
    """Construct a minimal offline environment for Git and build backends."""
    parent = os.environ if parent_environment is None else parent_environment
    isolation_root = isolation_root.resolve()
    home = isolation_root / "home"
    temp = isolation_root / "tmp"
    cache = isolation_root / "cache"
    config = isolation_root / "config"
    for directory in (home, temp, cache, config):
        directory.mkdir(parents=True, exist_ok=True)
    parent_path = parent.get("PATH")
    if not isinstance(parent_path, str) or not parent_path:
        raise SystemExit(
            "distribution build requires an explicit nonempty parent PATH")
    git = shutil.which("git", path=parent_path)
    if git is None:
        raise SystemExit("distribution build requires Git on the parent executable path")
    path_entries = [
        str(executable_directory.resolve()),
        str(Path(git).resolve().parent),
    ]
    environment: dict[str, str] = {}
    if os.name == "nt":
        system_root = parent.get("SystemRoot") or parent.get("WINDIR")
        if not system_root:
            raise SystemExit("cannot construct isolated Windows build environment")
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
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_CACHE_DIR": str(cache / "pip"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "CCE_RELEASE_ENVIRONMENT": "build-isolated",
    })
    return environment


def _source_snapshot(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Digest every tracked or unignored source file around backend execution."""
    try:
        listed = subprocess.check_output(
            [
                "git", "ls-files", "-z", "--cached", "--others",
                "--exclude-standard",
            ],
            cwd=ROOT, env=environment, timeout=GIT_READ_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise SystemExit("cannot read the build source inventory") from exc
    snapshot: dict[str, str] = {}
    for raw_name in listed.split(b"\0"):
        if not raw_name:
            continue
        name = os.fsdecode(raw_name)
        path = ROOT / name
        if path.is_symlink():
            payload = f"symlink:{os.readlink(path)}".encode("utf-8", "surrogateescape")
        elif path.is_file():
            payload = path.read_bytes()
        else:
            payload = b"<missing-or-non-file>"
        snapshot[name] = hashlib.sha256(payload).hexdigest()
    return snapshot


def _require_unchanged_source(before: dict[str, str], after: dict[str, str]) -> None:
    changed = sorted(
        name for name in before.keys() | after.keys()
        if before.get(name) != after.get(name)
    )
    if changed:
        rendered = "\n  ".join(changed)
        raise SystemExit(
            "build backend changed tracked or unignored source files:\n  " + rendered)


def _source_epoch(environment: dict[str, str] | None = None) -> str:
    try:
        value = subprocess.check_output(
            ["git", "log", "-1", "--format=%ct"], cwd=ROOT,
            env=environment, text=True,
            timeout=GIT_READ_TIMEOUT_SECONDS).strip()
        epoch = int(value)
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, ValueError) as exc:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from exc
    if epoch < 315532800:  # ZIP cannot represent a date before 1980-01-01.
        raise SystemExit("SOURCE_DATE_EPOCH must be at least 315532800")
    return str(epoch)


def _release_verifier():
    path = ROOT / ".github" / "scripts" / "verify_distributions.py"
    spec = importlib.util.spec_from_file_location("cce_release_verifier", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_backend(
        distribution: str, source: Path, output: Path,
        environment: dict[str, str]) -> None:
    verifier = _release_verifier()
    verifier._run_checked(
        [
            sys.executable, "-m", "build", f"--{distribution}",
            "--no-isolation", "--outdir", str(output), str(source),
        ],
        cwd=source,
        environment=environment,
        label=f"{distribution} build backend",
        timeout_seconds=BUILD_BACKEND_TIMEOUT_SECONDS,
    )


def _materialize_source_payload(
        destination: Path, payload: dict[str, bytes]) -> None:
    """Write the reviewed source bytes into one empty disposable directory."""
    if not isinstance(payload, dict):
        raise SystemExit("invalid captured source payload")
    validated: list[tuple[str, PurePosixPath, bytes]] = []
    portable_names: set[str] = set()
    file_names: set[str] = set()
    for relative, body in payload.items():
        if not isinstance(relative, str) or not isinstance(body, bytes):
            raise SystemExit("invalid captured source payload entry")
        try:
            relative.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SystemExit("invalid captured source payload entry") from exc
        path = PurePosixPath(relative)
        portable = relative.casefold()
        if (
            path.is_absolute()
            or not path.parts
            or path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(char in relative for char in ("\\", ":", "\0"))
            or any(
                part.endswith((" ", "."))
                or any(char in '<>"|?*' for char in part)
                or part.rstrip(" .").split(".", 1)[0].upper()
                in _WINDOWS_RESERVED_NAMES
                or any(ord(char) < 32 or ord(char) == 127 for char in part)
                for part in path.parts
            )
            or portable in portable_names
        ):
            raise SystemExit("invalid captured source payload entry")
        portable_names.add(portable)
        file_names.add(portable)
        validated.append((relative, path, body))
    for _relative, path, _body in validated:
        if any(
                parent.as_posix().casefold() in file_names
                for parent in path.parents
                if parent != PurePosixPath(".")):
            raise SystemExit("invalid captured source payload entry")
    try:
        verifier = _release_verifier()
        verifier._validated_source_names(
            [relative for relative, _path, _body in validated],
            label="captured source payload",
        )
    except SystemExit as exc:
        raise SystemExit("invalid captured source payload entry") from exc

    try:
        destination.mkdir(parents=True, exist_ok=True)
        destination_info = os.lstat(destination)
    except OSError as exc:
        raise SystemExit("cannot create isolated backend source directory") from exc
    if (
        not stat.S_ISDIR(destination_info.st_mode)
        or stat.S_ISLNK(destination_info.st_mode)
        or getattr(destination_info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise SystemExit("isolated backend source directory is not physical")
    try:
        if any(destination.iterdir()):
            raise SystemExit("isolated backend source directory is not empty")
        for relative, path, body in sorted(validated):
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
    except OSError as exc:
        raise SystemExit("cannot materialize isolated backend source") from exc


def _single_artifact(directory: Path, pattern: str, label: str) -> Path:
    artifacts = sorted(directory.glob(pattern))
    if len(artifacts) != 1:
        raise SystemExit(f"backend must produce exactly one {label}")
    return artifacts[0]


def _build(
        output: Path, epoch: str,
        environment: dict[str, str] | None = None) -> None:
    if environment is None:
        with tempfile.TemporaryDirectory(prefix="cce-build-process-") as process_dir:
            clean = _clean_build_environment(
                Path(process_dir), Path(sys.executable).parent)
            _build(output, epoch, clean)
        return
    output.mkdir(parents=True, exist_ok=True)
    env = {
        **environment,
        "SOURCE_DATE_EPOCH": epoch,
        "PYTHONHASHSEED": "0",
    }
    verifier = _release_verifier()
    verifier._require_exact_git_source(ROOT)
    # Refuse unsafe tracked/unignored paths before executing the backend. The
    # post-build closed-manifest comparison independently rejects anything the
    # backend selects that was not in this reviewed inventory.
    source_payload = verifier._expected_sdist_source_payload(ROOT)
    verifier._require_source_payload_matches_git_index(ROOT, source_payload)
    before = _source_snapshot(env)
    try:
        with tempfile.TemporaryDirectory(prefix="cce-release-source-") as source_dir, \
                tempfile.TemporaryDirectory(prefix="cce-release-stage-") as stage_dir, \
                tempfile.TemporaryDirectory(prefix="cce-sdist-extract-") as extract_dir:
            isolated_source = Path(source_dir)
            _materialize_source_payload(isolated_source, source_payload)
            stage = Path(stage_dir)
            _run_backend("sdist", isolated_source, stage, env)
            sdist = _single_artifact(stage, "*.tar.gz", "sdist")
            if list(stage.glob("*.whl")):
                raise SystemExit("sdist phase unexpectedly produced a wheel")
            _normalize_sdist(sdist, int(epoch))

            # Validation completes before this function creates a single path
            # from the archive, and the wheel backend only sees that materialized
            # closed-world payload.
            extracted = verifier._extract_validated_sdist(
                sdist, Path(extract_dir), ROOT, expected_epoch=int(epoch))
            _run_backend("wheel", extracted, stage, env)
            wheel = _single_artifact(stage, "*.whl", "wheel")
            _normalize_wheel(wheel, int(epoch))
            with zipfile.ZipFile(wheel) as wheel_archive:
                verifier._validated_sdist_payload(
                    sdist, ROOT, expected_epoch=int(epoch), wheel=wheel_archive)

            for artifact in (sdist, wheel):
                shutil.copyfile(artifact, output / artifact.name)
    finally:
        _require_unchanged_source(before, _source_snapshot(env))


def _normalize_sdist(path: Path, epoch: int) -> None:
    """Remove timestamps, owners and host file modes left by setuptools."""
    replacement = path.with_suffix(path.suffix + ".normalized")
    verifier = _release_verifier()
    raw_tar = _bounded_backend_sdist_tar_bytes(path)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as source:
            members = []
            total_size = 0
            for member in source:
                if len(members) >= verifier.MAX_SDIST_MEMBERS:
                    raise SystemExit("backend sdist exceeds the member-count limit")
                if member.name.endswith("/"):
                    raise SystemExit(
                        "backend sdist member names must not use trailing separators: "
                        + member.name)
                if member.type not in {tarfile.REGTYPE, tarfile.DIRTYPE}:
                    raise SystemExit(
                        "backend sdist contains a non-regular member: " + member.name)
                if member.size < 0 or member.size > verifier.MAX_SDIST_MEMBER_BYTES:
                    raise SystemExit("backend sdist member exceeds the size limit")
                total_size += member.size
                if total_size > verifier.MAX_SDIST_TOTAL_BYTES:
                    raise SystemExit("backend sdist exceeds the uncompressed-size limit")
                members.append(member)

            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise SystemExit("backend sdist contains duplicate archive entries")
            verifier._validate_archive_path_graph(
                [(member.name, member.type == tarfile.DIRTYPE) for member in members],
                label="backend sdist",
            )

            captured = []
            for member in members:
                relative = member.name.split("/", 1)[1] \
                    if "/" in member.name else ""
                body = b""
                if member.type == tarfile.REGTYPE:
                    extracted = source.extractfile(member)
                    if extracted is None:
                        raise SystemExit("backend sdist member cannot be read")
                    body = extracted.read()
                    if len(body) != member.size:
                        raise SystemExit("backend sdist member size is inconsistent")
                    if relative in _GENERATED_SDIST_TEXT:
                        body = body.replace(b"\r\n", b"\n")
                        if relative == "causal_continuity_engine.egg-info/SOURCES.txt":
                            source_lines = body.rstrip(b"\n").split(b"\n")
                            body = b"\n".join(sorted(source_lines)) + b"\n"
                captured.append((member.name, member.type, relative, body))
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit("backend sdist is not a valid bounded tar archive") from exc

    with replacement.open("wb") as raw, gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=epoch,
            compresslevel=9) as compressed:
        with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
                ) as target:
            for name, member_type, relative, body in sorted(captured):
                canonical = tarfile.TarInfo(name)
                canonical.type = member_type
                canonical.size = len(body) if member_type == tarfile.REGTYPE else 0
                canonical.mtime = epoch
                canonical.uid = canonical.gid = 0
                canonical.uname = canonical.gname = ""
                canonical.mode = verifier._canonical_sdist_mode(
                    relative, directory=member_type == tarfile.DIRTYPE)
                target.addfile(
                    canonical,
                    io.BytesIO(body) if member_type == tarfile.REGTYPE else None)
    os.replace(replacement, path)


def _bounded_backend_wheel_payloads(path: Path) -> dict[str, bytes]:
    """Read one backend wheel only after complete bounded metadata preflight."""
    verifier = _release_verifier()
    raw = _bounded_physical_file_bytes(
        path,
        verifier.MAX_WHEEL_ARCHIVE_BYTES,
        label="backend wheel compressed archive",
    )
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as source:
            verifier._archive_names_are_safe(source)
            infos = source.infolist()
            if len(infos) > verifier.MAX_WHEEL_MEMBERS:
                raise SystemExit("backend wheel exceeds the member-count limit")
            if any(info.is_dir() for info in infos):
                raise SystemExit("backend wheel must not contain directory entries")
            total_size = 0
            for info in infos:
                unix_kind = stat.S_IFMT(info.external_attr >> 16)
                if info.create_system == 3 and unix_kind not in {0, stat.S_IFREG}:
                    raise SystemExit(
                        "backend wheel contains a non-regular member: "
                        + info.filename)
                if (
                    info.file_size < 0
                    or info.file_size > verifier.MAX_WHEEL_MEMBER_BYTES
                ):
                    raise SystemExit(
                        "backend wheel member exceeds the size limit: "
                        + info.filename)
                total_size += info.file_size
                if total_size > verifier.MAX_WHEEL_TOTAL_BYTES:
                    raise SystemExit(
                        "backend wheel exceeds the total uncompressed-size limit")
            return {info.filename: source.read(info) for info in infos}
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise SystemExit("backend wheel is not a valid bounded ZIP archive") from exc


def _normalize_wheel(path: Path, epoch: int) -> None:
    """Canonicalize generated text, ZIP metadata, and the RECORD ledger."""
    replacement = path.with_suffix(path.suffix + ".normalized")
    payloads = _bounded_backend_wheel_payloads(path)
    record_names = [
        name for name in payloads if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        raise SystemExit("built wheel must contain exactly one RECORD")
    record_name = record_names[0]
    del payloads[record_name]
    generated_suffixes = (
        ".dist-info/METADATA",
        ".dist-info/WHEEL",
        ".dist-info/entry_points.txt",
        ".dist-info/top_level.txt",
    )
    for name in payloads:
        if name.endswith(generated_suffixes):
            payloads[name] = payloads[name].replace(b"\r\n", b"\n")

    record_buffer = io.StringIO(newline="")
    writer = csv.writer(record_buffer, lineterminator="\n")
    for name, payload in sorted(payloads.items()):
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        writer.writerow((name, f"sha256={digest}", str(len(payload))))
    writer.writerow((record_name, "", ""))
    payloads[record_name] = record_buffer.getvalue().encode("utf-8")

    replacement.write_bytes(
        _release_verifier()._canonical_wheel_bytes(payloads, epoch))
    os.replace(replacement, path)


def _digests(output: Path) -> dict[str, str]:
    return {
        artifact.name: hashlib.sha256(artifact.read_bytes()).hexdigest()
        for artifact in sorted(output.iterdir())
        if artifact.is_file()
    }


def _execute_build(args, epoch: str, environment: dict[str, str]) -> int:
    if not args.check_reproducible:
        _build(args.outdir.resolve(), epoch, environment)
        return 0

    with tempfile.TemporaryDirectory(prefix="cce-build-a-") as first_dir, \
            tempfile.TemporaryDirectory(prefix="cce-build-b-") as second_dir:
        first, second = Path(first_dir), Path(second_dir)
        _build(first, epoch, environment)
        _build(second, epoch, environment)
        first_hashes, second_hashes = _digests(first), _digests(second)
        if first_hashes != second_hashes:
            print("release artifacts are not byte-reproducible", file=sys.stderr)
            print(f"first:  {first_hashes}", file=sys.stderr)
            print(f"second: {second_hashes}", file=sys.stderr)
            return 1
        args.outdir.mkdir(parents=True, exist_ok=True)
        for pattern in (
                "causal_continuity_engine-*.whl",
                "causal_continuity_engine-*.tar.gz",
                "SHA256SUMS"):
            for stale in args.outdir.glob(pattern):
                stale.unlink()
        for artifact in first.iterdir():
            if artifact.is_file():
                shutil.copyfile(artifact, args.outdir / artifact.name)
        checksum_manifest = "".join(
            f"{digest}  {name}\n" for name, digest in sorted(first_hashes.items()))
        (args.outdir / "SHA256SUMS").write_text(
            checksum_manifest, encoding="ascii", newline="\n")
        for name, digest in first_hashes.items():
            print(f"sha256:{digest}  {name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", type=Path, default=ROOT / "dist")
    parser.add_argument("--check-reproducible", action="store_true")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="cce-build-process-") as process_dir:
        environment = _clean_build_environment(
            Path(process_dir), Path(sys.executable).parent)
        epoch = _source_epoch(environment)
        return _execute_build(args, epoch, environment)


if __name__ == "__main__":
    raise SystemExit(main())
