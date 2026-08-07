"""CCE command-line interface (PLT-004).

Headless-friendly: every command emits JSON with --json, human-readable
otherwise. State lives in .cce/cce.db under the target directory.

Signing and transport secrets live in separate files under ``.cce/secrets``
rather than in metadata, and are created as 0600 beneath 0700 directories on
POSIX. Windows' stdlib chmod does not manage discretionary ACLs, so the local
reference relies on the user's existing profile ACL there. This separation
and the verifier snapshot stop ordinary relative-path disclosure; they do not
isolate two hostile processes running as the same OS account.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from .capsule import CapsuleError
from .core import (
    Signer,
    canonical_json,
    strict_json_loads,
    validate_public_identifier,
    validate_repository_name,
)
from .engine import Engine
from .github import SUBSCRIBED_EVENTS, WebhookError
from .ontology import (
    ASSUMPTION_STATES,
    CRITICALITY_LEVELS,
    MVP_MAX_AUTONOMY,
)
from .policy import PolicyEngine
from .store import AnchorExportError

_SIGNING_KEY_FILE = "secrets/signing.key"
_API_TOKEN_FILE = "secrets/api.token"
_WEBHOOK_SECRET_FILE = "secrets/github-webhook.secret"
_MAX_POLICY_BYTES = 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024
_MAX_SECRET_BYTES = 64 * 1024
_MAX_INGEST_BYTES = 1024 * 1024
_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_CAPSULE_BYTES = 4 * 1024 * 1024
_MAX_ANCHOR_BYTES = 1024 * 1024
_MAX_TOKEN_BUDGET = 100_000
_READ_CHUNK = 64 * 1024
_HEX_KEY = re.compile(r"[0-9a-fA-F]{64}\Z", re.ASCII)

# Receipt verification distinguishes a valid-but-stale decision from a forged
# or malformed artifact.  Scripts must not have to parse prose to preserve
# that distinction (the same three-way contract as Engine.verify_*).
_RECEIPT_CURRENT = 0
_RECEIPT_HISTORICAL = 3
_RECEIPT_INVALID = 4
_CHECK_NOT_SUCCESS = 1


class CLIOutputError(RuntimeError):
    """The application attempted to emit a value outside strict JSON."""


_BIDI_CONTROLS = {
    0x061C, 0x200E, 0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
}


def _sanitize_human(value: object) -> str:
    """Make terminal/log control characters visible without losing text."""
    text = str(value)
    return "".join(
        char
        if (char in ("\n", "\t")
            or (ord(char) >= 0x20
                and not 0x7F <= ord(char) <= 0x9F
                and ord(char) not in _BIDI_CONTROLS
                and not 0xD800 <= ord(char) <= 0xDFFF
                and not 0xFDD0 <= ord(char) <= 0xFDEF
                and ord(char) & 0xFFFF not in (0xFFFE, 0xFFFF)))
        else f"\\u{ord(char):04x}"
        for char in text
    )


def _print_error(value: object) -> None:
    print(_sanitize_human(value), file=sys.stderr)


class SafeArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        super()._print_message(
            _sanitize_human(message) if message else message, file)


def _nonempty_argument(value: str) -> str:
    if not value or "\x00" in value:
        raise argparse.ArgumentTypeError("must be non-empty and contain no NUL")
    return value


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if not 1 <= parsed <= 2**63 - 1:
        raise argparse.ArgumentTypeError(
            "must be a positive signed 64-bit integer")
    return parsed


def _token_budget(value: str) -> int:
    parsed = _positive_int(value)
    if parsed > _MAX_TOKEN_BUDGET:
        raise argparse.ArgumentTypeError(
            f"must be at most {_MAX_TOKEN_BUDGET}")
    return parsed


def _autonomy_level(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"must be an integer from 0 to {MVP_MAX_AUTONOMY}") from None
    if not 0 <= parsed <= MVP_MAX_AUTONOMY:
        raise argparse.ArgumentTypeError(
            f"must be an integer from 0 to {MVP_MAX_AUTONOMY}")
    return parsed


def _public_identifier(value: str) -> str:
    try:
        return validate_public_identifier(value, field="identifier")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _repository_name(value: str) -> str:
    try:
        return validate_repository_name(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _assumption_statuses(value: str) -> str:
    statuses = value.split(",")
    if (not statuses
            or any(status not in ASSUMPTION_STATES for status in statuses)
            or len(statuses) != len(set(statuses))):
        allowed = ", ".join(sorted(ASSUMPTION_STATES))
        raise argparse.ArgumentTypeError(
            f"must be distinct comma-separated assumption states: {allowed}")
    return value


def _tcp_port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "must be an integer between 1 and 65535") from None
    if not 1 <= parsed <= 65_535:
        raise argparse.ArgumentTypeError(
            "must be an integer between 1 and 65535")
    return parsed


def _private_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


def _is_reparse_point(path: Path) -> bool:
    """Whether *path itself* redirects filesystem traversal."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if attributes & reparse_flag:
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _file_identity(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        getattr(info, "st_file_attributes", 0),
        getattr(info, "st_reparse_tag", 0),
    )


def _file_content_view(info: os.stat_result) -> tuple:
    return (
        _file_identity(info),
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
    )


def _read_bounded_file(
        path: str | Path, limit: int, *, label: str,
        require_private: bool = False) -> bytes:
    """Read one stable physical regular file with a hard byte ceiling."""
    path = Path(path)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable: {exc}") from None
    if _is_reparse_point(path) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a physical regular file")
    if before.st_size > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte limit")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable: {exc}") from None
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or _file_identity(opened) != _file_identity(before)):
            raise ValueError(f"{label} changed before it could be read")
        if require_private and os.name != "nt":
            if opened.st_mode & 0o077:
                raise PermissionError(
                    f"refusing overly permissive {label}; require mode 0600")
            if opened.st_uid != os.geteuid():
                raise PermissionError(
                    f"{label} is not owned by the current user")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError(f"{label} exceeds the {limit}-byte limit")
        after_open = os.fstat(descriptor)
        after_path = os.lstat(path)
        if (_file_content_view(after_open) != _file_content_view(opened)
                or _file_content_view(after_path) != _file_content_view(opened)
                or total != opened.st_size):
            raise ValueError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_bounded_stream(stream, limit: int, *, label: str) -> bytes:
    """Read stdin-like input without allowing an unbounded allocation."""
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = stream.read(min(_READ_CHUNK, limit + 1 - total))
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        elif not isinstance(chunk, bytes):
            raise ValueError(f"{label} stream returned non-byte content")
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ValueError(f"{label} exceeds the {limit}-byte limit")
    return b"".join(chunks)


def _strict_json_text(value: object, *, indent: int | None = None) -> str:
    try:
        # Validate the full I-JSON/JCS data model before writing a byte.
        # json.dumps alone accepts integer object keys, surrogates, and
        # integers it cannot represent portably.
        canonical_json(value)
        return json.dumps(
            value, indent=indent, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CLIOutputError(
            f"CLI attempted to serialize non-canonical JSON: {exc}") from exc


def _physical_cce_directory(project_root: Path, cce_dir: Path) -> tuple[Path, Path]:
    """Return resolved local-state paths only for a physical direct child."""
    root = project_root.resolve(strict=True)
    if not root.is_dir():
        raise PermissionError(f"project root is not a directory: {root}")
    try:
        info = cce_dir.lstat()
    except FileNotFoundError:
        raise PermissionError(f"local state directory does not exist: {cce_dir}") from None
    if _is_reparse_point(cce_dir):
        raise PermissionError(
            ".cce must be a physical directory, not a symlink, junction, "
            "or reparse point")
    if not stat.S_ISDIR(info.st_mode):
        raise PermissionError(".cce must be a physical directory")
    resolved = cce_dir.resolve(strict=True)
    if resolved.parent != root or resolved.name != ".cce":
        raise PermissionError(".cce must be a direct child of the project root")
    return root, resolved


def _sync_directory(path: Path) -> None:
    """Persist directory entries where the platform exposes directory fsync."""
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_json_output_target(
        path: str | Path, *,
        project_root: str | Path | None = None) -> Path:
    target = Path(os.path.abspath(path))
    parent = target.parent if target.parent != Path("") else Path(".")
    if not parent.is_dir():
        raise ValueError(f"output parent is not a directory: {parent}")
    resolved_parent = parent.resolve(strict=True)
    candidate = resolved_parent / target.name
    if project_root is not None:
        root = Path(project_root).resolve(strict=True)
        control = (root / ".cce").resolve(strict=True)
        resolved_candidate = (
            target.resolve(strict=True)
            if os.path.lexists(target) else candidate)
        if (candidate == control or control in candidate.parents
                or resolved_candidate == control
                or control in resolved_candidate.parents):
            raise PermissionError(
                "refusing to overwrite files beneath the project's .cce "
                "trust directory")
    if os.path.lexists(target):
        existing = os.lstat(target)
        if _is_reparse_point(target) or not stat.S_ISREG(existing.st_mode):
            raise ValueError(
                "existing output must be a physical regular file")
    return target


def _write_json_artifact(
        path: str | Path, value: object, *,
        project_root: str | Path | None = None) -> Path:
    """Atomically publish strict JSON without overwriting local trust state.

    An existing physical regular output is replaced atomically. Indirect or
    special targets are refused, and no public artifact may be published
    anywhere beneath the bound project's ``.cce`` control directory.
    """
    target = _validate_json_output_target(
        path, project_root=project_root)
    parent = target.parent
    data = (_strict_json_text(value, indent=2) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        _sync_directory(parent)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return target


def _cleanup_init_stage(stage: Path, project_root: Path) -> None:
    """Remove only an init directory created as a direct sibling of .cce."""
    if (stage.parent.resolve(strict=True) != project_root.resolve(strict=True)
            or not stage.name.startswith(".cce-init-")):
        raise RuntimeError("refusing to clean an unrecognized init staging path")
    if not os.path.lexists(stage):
        return
    if _is_reparse_point(stage):
        stage.unlink()
        return
    shutil.rmtree(stage)


def _write_private(path: Path, value: bytes):
    """Create a secret without a world-readable creation window."""
    _private_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    if os.name != "nt":
        path.chmod(0o600)


def _replace_private_json(path: Path, value: dict):
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    _write_private(
        temp, (_strict_json_text(value, indent=2) + "\n").encode("utf-8"))
    os.replace(temp, path)
    if os.name != "nt":
        path.chmod(0o600)


def _secret_path(cce_dir: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute():
        raise PermissionError("secret path must be relative to .cce")
    if _is_reparse_point(cce_dir):
        raise PermissionError(
            ".cce must be a physical directory, not a symlink, junction, "
            "or reparse point")
    root = cce_dir.resolve(strict=True)
    requested = cce_dir / relative_path
    candidate = requested.resolve()
    if candidate != root and root not in candidate.parents:
        raise PermissionError("secret path escapes .cce")
    cursor = requested
    while cursor != cce_dir:
        if _is_reparse_point(cursor):
            raise PermissionError(
                "secret path must not contain symbolic links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            raise PermissionError("secret path must be relative to .cce")
        cursor = parent
    return candidate


def _read_private(path: Path) -> bytes:
    return _read_bounded_file(
        path, _MAX_SECRET_BYTES, label=f"secret {path}",
        require_private=True)


_METADATA_KEYS = frozenset({
    "tenant_id", "project_id", "key_id", "signing_key_file",
    "api_token_file", "webhook_secret_file", "signing_key_hex",
    "repository", "repository_id", "github_installation_id",
})
_FIXED_SECRET_PATHS = {
    "signing_key_file": _SIGNING_KEY_FILE,
    "api_token_file": _API_TOKEN_FILE,
    "webhook_secret_file": _WEBHOOK_SECRET_FILE,
}


def _validate_metadata(meta: object, *, allow_legacy: bool) -> dict:
    """Validate the closed metadata shape before any migration can write."""
    if not isinstance(meta, dict):
        raise ValueError("metadata must be a JSON object")
    unknown = sorted(set(meta) - _METADATA_KEYS)
    if unknown:
        raise ValueError(f"unknown metadata field(s): {unknown}")
    for field in ("tenant_id", "project_id", "key_id"):
        if field not in meta:
            raise ValueError(f"metadata is missing {field}")
        validate_public_identifier(meta[field], field=field)

    validate_repository_name(
        meta.get("repository"), field="metadata repository", optional=True)
    for field in ("repository_id", "github_installation_id"):
        value = meta.get(field)
        if (value is not None
                and (isinstance(value, bool)
                     or not isinstance(value, int)
                     or not 1 <= value <= 2**63 - 1)):
            raise ValueError(
                f"metadata {field} must be null or a positive 64-bit integer")
    if (meta.get("github_installation_id") is not None
            and meta.get("repository_id") is None):
        raise ValueError(
            "metadata github_installation_id requires repository_id")

    legacy = meta.get("signing_key_hex")
    if legacy is not None:
        if not allow_legacy:
            raise ValueError("legacy signing_key_hex remains after migration")
        if "signing_key_file" in meta:
            raise ValueError(
                "metadata cannot contain both signing_key_hex and signing_key_file")
        if not isinstance(legacy, str) or _HEX_KEY.fullmatch(legacy) is None:
            raise ValueError(
                "legacy signing_key_hex must be exactly 64 hexadecimal characters")
    elif meta.get("signing_key_file") != _SIGNING_KEY_FILE:
        raise ValueError(
            f"metadata signing_key_file must be {_SIGNING_KEY_FILE!r}")

    for field, expected in _FIXED_SECRET_PATHS.items():
        if field in meta and meta[field] != expected:
            raise ValueError(f"metadata {field} must be {expected!r}")
        if not allow_legacy and field not in meta:
            raise ValueError(f"metadata is missing {field}")
    return dict(meta)


def _migrate_legacy_signing_key(cce_dir: Path, meta_path: Path, meta: dict) -> dict:
    """Move the round-1 key out of metadata without changing its identity."""
    legacy = meta.get("signing_key_hex")
    if legacy is None:
        return meta
    key = bytes.fromhex(legacy)
    key_path = _secret_path(cce_dir, _SIGNING_KEY_FILE)
    if key_path.exists():
        if _read_private(key_path) != key:
            raise PermissionError("legacy and separated signing keys disagree")
    else:
        _write_private(key_path, key)
    migrated = dict(meta)
    migrated.pop("signing_key_hex", None)
    migrated["signing_key_file"] = _SIGNING_KEY_FILE
    _replace_private_json(meta_path, migrated)
    return migrated


def _ensure_runtime_secrets(cce_dir: Path, meta_path: Path, meta: dict) -> dict:
    """Provision separate API/webhook credentials for pre-hardening projects."""
    updated = dict(meta)
    additions = (
        ("api_token_file", _API_TOKEN_FILE),
        ("webhook_secret_file", _WEBHOOK_SECRET_FILE),
    )
    changed = False
    for field, relative in additions:
        if field in updated:
            continue
        secret_path = _secret_path(cce_dir, relative)
        if secret_path.exists():
            # Recover safely if a crash persisted the secret before metadata.
            existing = _read_private(secret_path)
            if not existing:
                raise PermissionError(f"refusing empty runtime secret {secret_path}")
        else:
            _write_private(
                secret_path,
                secrets.token_urlsafe(32).encode("ascii"))
        updated[field] = relative
        changed = True
    if changed:
        _replace_private_json(meta_path, updated)
    return updated


def _engine(args) -> tuple[Engine, dict]:
    directory = getattr(args, "dir", ".")
    root = Path("." if directory is None else directory)
    cce_dir = root / ".cce"
    root, cce_dir = _physical_cce_directory(root, cce_dir)
    meta_path = _secret_path(cce_dir, "meta.json")
    if not meta_path.exists():
        _print_error("error: not a CCE project (run `cce-engine init` first)")
        raise SystemExit(2)
    try:
        meta = strict_json_loads(_read_bounded_file(
            meta_path, _MAX_METADATA_BYTES, label="CCE metadata"))
        meta = _validate_metadata(meta, allow_legacy=True)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _print_error(f"error: invalid CCE metadata: {exc}")
        raise SystemExit(2) from None
    meta = _migrate_legacy_signing_key(cce_dir, meta_path, meta)
    meta = _validate_metadata(meta, allow_legacy=True)
    key_path = _secret_path(cce_dir, meta["signing_key_file"])
    key = _read_private(key_path)
    if len(key) != 32:
        raise PermissionError("signing key must be exactly 32 bytes")
    # Runtime credentials are recoverable additions, but the signing key is
    # the trust root. Never mutate metadata or create new secrets until that
    # existing trust root has been validated.
    meta = _ensure_runtime_secrets(cce_dir, meta_path, meta)
    meta = _validate_metadata(meta, allow_legacy=False)
    database_path = _secret_path(cce_dir, "cce.db")
    engine = Engine(database_path, tenant_id=meta["tenant_id"],
                    signer=Signer(meta["key_id"], key), workdir=root)
    opened = getattr(args, "_opened_engines", None)
    if isinstance(opened, list):
        opened.append(engine)
    return engine, meta


def _emit(args, obj, human: str | None = None):
    if getattr(args, "json", False) or human is None:
        sys.stdout.write(_strict_json_text(obj, indent=2) + "\n")
    else:
        print(_sanitize_human(human))


def cmd_init(args):
    root = Path("." if args.dir is None else args.dir).resolve(strict=True)
    if not root.is_dir():
        raise PermissionError(f"project root is not a directory: {root}")
    cce_dir = root / ".cce"
    if os.path.lexists(cce_dir):
        # Validate before even checking metadata: a dangling link reports
        # exists=False and an ordinary chmod/read would otherwise follow it.
        _, existing = _physical_cce_directory(root, cce_dir)
        meta_path = _secret_path(existing, "meta.json")
        message = "already initialized" if meta_path.exists() else (
            "refusing pre-existing .cce directory without trusted metadata")
        _print_error(message)
        raise SystemExit(1)

    stage = Path(tempfile.mkdtemp(prefix=".cce-init-", dir=root))
    engine = None
    try:
        _private_directory(stage)
        signer = Signer.generate("local")
        _write_private(_secret_path(stage, _SIGNING_KEY_FILE), signer._key)
        _write_private(
            _secret_path(stage, _API_TOKEN_FILE),
            secrets.token_urlsafe(32).encode("ascii"))
        _write_private(
            _secret_path(stage, _WEBHOOK_SECRET_FILE),
            secrets.token_urlsafe(32).encode("ascii"))
        meta = {
            "tenant_id": "ten_local",
            "key_id": "local",
            "signing_key_file": _SIGNING_KEY_FILE,
            "api_token_file": _API_TOKEN_FILE,
            "webhook_secret_file": _WEBHOOK_SECRET_FILE,
            "repository": args.repo,
            "repository_id": args.repo_id,
            "github_installation_id": args.github_installation_id,
        }
        database_path = _secret_path(stage, "cce.db")
        engine = Engine(
            database_path, tenant_id=meta["tenant_id"], signer=signer,
            workdir=root)
        project = engine.create_project(
            root.name if args.repo is None else args.repo,
            repository=args.repo,
            repository_id=args.repo_id,
            github_installation_id=args.github_installation_id,
            capture_mode=args.capture_mode,
            config={"require_proof_for": ["task_complete", "pr_ready"]})
        meta["project_id"] = project["node_id"]
        _write_private(
            _secret_path(stage, "meta.json"),
            (_strict_json_text(meta, indent=2) + "\n").encode("utf-8"))
        engine.close()
        engine = None
        _sync_directory(stage / "secrets")
        _sync_directory(stage)

        # os.rename is atomic on one filesystem. Check immediately beforehand
        # and never use os.replace: an existing local trust root is not ours to
        # overwrite or adopt.
        if os.path.lexists(cce_dir):
            raise FileExistsError("refusing local state created during initialization")
        os.rename(stage, cce_dir)
        stage = None
        _sync_directory(root)
    except BaseException:
        try:
            if engine is not None:
                engine.close()
        finally:
            if stage is not None:
                _cleanup_init_stage(stage, root)
        raise

    _, cce_dir = _physical_cce_directory(root, cce_dir)
    _emit(args, {
        "project_id": project["node_id"], "capture_mode": args.capture_mode,
        "github_ingestion_bound": args.repo_id is not None,
        "api_token_file": str(_secret_path(cce_dir, _API_TOKEN_FILE)),
        "webhook_secret_file": str(
            _secret_path(cce_dir, _WEBHOOK_SECRET_FILE)),
    }, f"initialized CCE project {project['node_id']} "
       f"(capture: {args.capture_mode}); local API credentials are in "
       f"{cce_dir / 'secrets'}")


def cmd_ingest(args):
    try:
        stdin = getattr(sys.stdin, "buffer", sys.stdin)
        raw = (_read_bounded_file(
            args.file, _MAX_INGEST_BYTES, label="ingest payload")
            if args.file != "-" else _read_bounded_stream(
                stdin, _MAX_INGEST_BYTES, label="ingest payload"))
        payload = strict_json_loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("ingest payload must be a JSON object")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _print_error(f"error: invalid ingest JSON: {exc}")
        raise SystemExit(2) from None
    engine, meta = _engine(args)
    report = engine.ingest_github(
        meta["project_id"], args.event, args.delivery_id, payload)
    if report is None:
        _emit(args, {"status": "duplicate"}, "duplicate delivery: ignored")
    else:
        _emit(args, report,
              f"ingested {args.event}: {len(report['created'])} node(s),"
              f" {len(report['invalidations'])} invalidation(s),"
              f" {len(report['conflicts'])} conflict(s)")
    engine.close()


def cmd_resume(args):
    engine, meta = _engine(args)
    result = engine.resume_packet(
        meta["project_id"],
        target={"issue": args.issue} if args.issue is not None else None,
        token_budget=args.token_budget, fmt=args.format)
    if args.format == "markdown":
        print(_sanitize_human(result))
    else:
        _emit(args, result)
    engine.close()


def cmd_assumptions(args):
    engine, meta = _engine(args)
    statuses = (
        None if args.status is None else args.status.split(","))
    nodes = engine.graph.current(
        meta["project_id"], "assumption", status=statuses,
        tenant_id=engine.tenant_id)
    if args.criticality:
        nodes = [n for n in nodes if n.get("criticality") == args.criticality]
    rows = [{"node_id": n["node_id"], "status": n["status"],
             "criticality": n["criticality"], "confidence": n["confidence"],
             "statement": n["data"].get("statement")} for n in nodes]
    _emit(args, rows, "\n".join(
        f"[{r['status']}/{r['criticality']}] {r['statement']}  ({r['node_id']})"
        for r in rows) or "no assumptions")
    engine.close()


def cmd_invalidations(args):
    engine, meta = _engine(args)
    if args.explain:
        inv = engine.graph.get(
            args.explain, tenant_id=engine.tenant_id,
            project_id=meta["project_id"], entity_type="invalidation")
        _emit(args, inv["data"],
              f"{inv['data'].get('trigger_type')}: {inv['data'].get('reason')}\n"
              f"path: {' '.join(map(str, inv['data'].get('minimal_causal_path', [])))}\n"
              f"affected: {inv['data'].get('affected_count')}"
              f" severity: {inv['data'].get('severity')}\n"
              f"action: {inv['data'].get('recommended_action')}")
    else:
        invs = engine.invalidation.open_invalidations(meta["project_id"])
        rows = [{"node_id": i["node_id"], "status": i["status"],
                 "trigger": i["data"].get("trigger_type"),
                 "severity": i["data"].get("severity"),
                 "target": i["data"].get("target_summary")} for i in invs]
        _emit(args, rows, "\n".join(
            f"[{r['severity']}] {r['trigger']} -> {r['target']} ({r['node_id']})"
            for r in rows) or "no open invalidations")
    engine.close()


def cmd_verify(args):
    engine, meta = _engine(args)
    proof = engine.attest_action(
        meta["project_id"], intent_type=args.intent,
        intent_statement=(
            f"verify {args.intent}"
            if args.statement is None else args.statement),
        actor={"agent": "cli", "model": "n/a"},
        action_type="run_verifier")
    _emit(args, proof,
          f"proof {proof['proof_id']}: {proof['status']}\n"
          + "\n".join(f"  {v['verifier']}: {v['result']}"
                      for v in proof["verifications"]))
    engine.close()
    if proof["status"] != "verified":
        raise SystemExit(1)


def cmd_check(args):
    receipt = None
    if args.export_receipt is not None:
        _validate_json_output_target(
            args.export_receipt, project_root=args.dir)
    if args.verify_receipt is not None:
        try:
            raw = _read_bounded_file(
                args.verify_receipt, _MAX_RECEIPT_BYTES,
                label="continuity receipt")
            receipt = strict_json_loads(raw)
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                TypeError, ValueError, OverflowError) as exc:
            result = {
                "verdict": "INVALID",
                "current": False,
                "reason": f"receipt file is not strict JSON: {exc}",
            }
            _emit(
                args, result,
                f"continuity receipt {result['verdict']}: {result['reason']}")
            raise SystemExit(_RECEIPT_INVALID)

    engine, meta = _engine(args)
    if receipt is not None:
        result = engine.verify_continuity_receipt(
            meta["project_id"], receipt)
        _emit(
            args, result,
            f"continuity receipt {result['verdict']}: {result['reason']}")
        engine.close()
        code = {
            "CURRENT": _RECEIPT_CURRENT,
            "AUTHENTIC_HISTORICAL": _RECEIPT_HISTORICAL,
            "INVALID": _RECEIPT_INVALID,
        }.get(result.get("verdict"), _RECEIPT_INVALID)
        if code:
            raise SystemExit(code)
        return

    check = engine.continuity_check(meta["project_id"])
    exported = None
    if args.export_receipt is not None:
        exported = _write_json_artifact(
            args.export_receipt, check["continuity_receipt"],
            project_root=args.dir)
    human = (f"CCE Continuity: {check['conclusion']}"
             f" (open invalidations: {len(check['open_invalidations'])})")
    if exported is not None:
        human += f"\nreceipt: {exported}"
    _emit(args, check, human)
    engine.close()
    # A CI gate must fail closed: cancelled/neutral are absence of success,
    # not successful continuity.
    if check["conclusion"] != "success":
        raise SystemExit(_CHECK_NOT_SUCCESS)


def cmd_migrate(args):
    capsule = None
    output_path = "capsule.json" if args.out is None else args.out
    if args.action == "prepare":
        _validate_json_output_target(
            output_path, project_root=args.dir)
    if args.action == "validate":
        try:
            capsule = strict_json_loads(
                _read_bounded_file(
                    args.capsule, _MAX_CAPSULE_BYTES,
                    label="session capsule"))
            if not isinstance(capsule, dict):
                raise ValueError("capsule must be a JSON object")
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                TypeError, ValueError) as exc:
            _print_error(f"error: invalid capsule JSON: {exc}")
            raise SystemExit(2) from None
    engine, meta = _engine(args)
    if args.action == "prepare":
        capsule = engine.capsules.export(
            tenant_id=meta["tenant_id"], project_id=meta["project_id"],
            session_id=args.session,
            source_model=(
                "unknown" if args.source_model is None else args.source_model),
            source_runtime=(
                "unknown" if args.source_runtime is None else args.source_runtime),
            target_adapter=(
                "generic" if args.target is None else args.target),
            signer=engine.signer)
        out = _write_json_artifact(
            output_path, capsule, project_root=args.dir)
        _emit(args, {"capsule_id": capsule["capsule_id"], "path": str(out)},
              f"exported capsule {capsule['capsule_id']} -> {out}")
    else:  # validate
        from .capsule import CapsuleError
        try:
            result = engine.capsules.import_capsule(
                capsule, signer=engine.signer,
                target_model=(
                    "generic" if args.target is None else args.target),
                target_runtime=(
                    "generic" if args.target_runtime is None
                    else args.target_runtime),
                expected_tenant_id=meta["tenant_id"],
                expected_project_id=meta["project_id"])
        except CapsuleError as exc:
            _emit(args, {"valid": False, "error": str(exc)},
                  f"capsule REJECTED: {exc}")
            engine.close()
            raise SystemExit(1)
        challenge = result["challenge"]
        _emit(args, {"session_id": result["session"]["node_id"],
                     "challenge": challenge},
              f"imported as session {result['session']['node_id']};"
              f" challenge {'PASSED' if challenge['passed'] else 'FAILED'}"
              f" (score {challenge['migration_score']})\n"
              + "\n".join(f"  - {q}" for q in challenge["questions"]))
    engine.close()


def cmd_replay(args):
    engine, meta = _engine(args)
    node = engine.replay.start(
        tenant_id=meta["tenant_id"], project_id=meta["project_id"],
        from_event_id=args.from_event,
        fork=(
            {"model": args.fork_model}
            if args.fork_model is not None else None))
    _emit(args, {"replay_node": node["node_id"], "fidelity": node["data"]["fidelity"]},
          f"replay ready from {args.from_event}"
          f" (fidelity: {node['data']['fidelity']})")
    engine.close()


def cmd_rebuild(args):
    """Exit 0 MATCHES · 1 DIVERGES · 3 UNDECIDABLE (retention cleared inputs).

    The third code exists because 'the log disagrees with the projection' and
    'the log no longer contains what it would take to check' are opposite
    diagnoses, and collapsing them either hides real divergence behind any
    redaction or fails a CI gate forever after the first sweep (ADR-063).
    """
    engine, meta = _engine(args)
    project_id = meta["project_id"]
    completeness = engine.replay_completeness(project_id)
    before = engine.projection_fingerprint(project_id)
    fresh = engine.rebuild_projection(project_id)
    args._opened_engines.append(fresh)
    after = fresh.projection_fingerprint(project_id)
    match = before == after

    payload = {"before": before, "after": after, "match": match,
               "replay_completeness": completeness}
    if match:
        verdict, code = "MATCHES", 0
    elif completeness["replayable"]:
        verdict, code = "DIVERGES", 1
    else:
        partial = engine.replay_agrees_where_replayable(project_id, fresh)
        payload["partial_agreement"] = partial
        if partial["agrees"]:
            verdict, code = "UNDECIDABLE (retention)", 3
        else:
            # Retention explains the missing nodes; it does not explain a node
            # that replayed to a DIFFERENT value.
            verdict, code = "DIVERGES", 1
    note = completeness["note"]
    _emit(args, payload,
          f"projection rebuild {verdict}" + (f"\n  {note}" if note else "")
          + ("\n  every node the replay could still produce agrees with the"
             " live projection"
             if code == 3 else ""))
    engine.close()
    fresh.close()
    if code:
        raise SystemExit(code)


def cmd_audit(args):
    """Tamper evidence: chain integrity and external anchors (ADR-028)."""
    anchor = None
    output_path = "anchor.json" if args.out is None else args.out
    if args.action == "anchor":
        _validate_json_output_target(
            output_path, project_root=args.dir)
    elif args.action == "check-anchor":
        try:
            anchor = strict_json_loads(_read_bounded_file(
                args.anchor, _MAX_ANCHOR_BYTES, label="audit anchor"))
            if not isinstance(anchor, dict):
                raise ValueError("anchor must be a JSON object")
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                TypeError, ValueError) as exc:
            _print_error(f"error: invalid anchor JSON: {exc}")
            raise SystemExit(2) from None
    engine, meta = _engine(args)
    if args.action == "verify":
        results = {t: engine.store.verify_chain(t) for t in ("events", "audit_log")}
        intact = all(r["intact"] for r in results.values())
        _emit(args, results, "\n".join(
            f"{t}: {'INTACT' if r['intact'] else 'BROKEN at ' + str(r.get('broken_at'))}"
            f" ({r.get('entries', r.get('checked'))} entries)"
            + ("" if r["intact"] else f" — {r['reason']}")
            for t, r in results.items()))
        engine.close()
        raise SystemExit(0 if intact else 1)
    if args.action == "anchor":
        try:
            anchor = engine.store.export_anchor(
                args.table, tenant_id=engine.tenant_id,
                project_id=meta["project_id"])
        except AnchorExportError as exc:
            _emit(
                args,
                {"ok": False, "reason": str(exc)},
                f"ANCHOR NOT WRITTEN: {exc}")
            engine.close()
            raise SystemExit(1) from None
        out = _write_json_artifact(
            output_path, anchor, project_root=args.dir)
        _emit(args, anchor,
              f"anchored {anchor['count']} {args.table} entries at {anchor['tip'][:23]}…\n"
              f"wrote {out} — publish this somewhere you do not control, or it\n"
              f"proves nothing (an anchor you hand over at verify time agrees\n"
              f"with whatever your store currently says).")
        engine.close()
        return
    # check-anchor
    result = engine.store.verify_against_anchor(
        anchor, expected_tenant_id=engine.tenant_id,
        expected_project_id=meta["project_id"])
    _emit(args, result,
          ("chain still carries the anchored prefix"
           f" (+{result['appended_since']} appended since)" if result["ok"]
           else f"ANCHOR MISMATCH: {result['reason']}"))
    engine.close()
    raise SystemExit(0 if result["ok"] else 1)


def cmd_evidence(args):
    """Evidence quality: mutation probe, determinism, grade (ADR-027)."""
    engine, meta = _engine(args)
    pid = meta["project_id"]
    if args.action == "probe":
        report = engine.probe_evidence(
            pid,
            artifacts=(
                None if args.artifact is None else args.artifact))
        _emit(args, report.to_dict(),
              f"artifacts: {report.artifacts or 'none declared'}\n"
              f"bound: {report.bound}"
              + ("" if report.bound else "\n" + "\n".join(
                  f"  UNDETECTED {u['artifact']} ({u['mutation']}): {u['why']}"
                  for u in report.undetected)))
        engine.close()
        raise SystemExit(0 if report.bound else 1)
    # determinism
    out = engine.probe_determinism(pid)
    flaky = [n for n, d in out.items() if not d["stable"]]
    _emit(args, out, "\n".join(
        f"{n}: {'stable' if d['stable'] else 'FLAKY ' + str(d['results'])}"
        for n, d in out.items()) or "no pinned required verifiers")
    engine.close()
    raise SystemExit(1 if flaky else 0)


def cmd_policy(args):
    config = None
    policy_path = None
    if args.action == "configure":
        try:
            policy_path = Path(args.file)
            config = strict_json_loads(_read_bounded_file(
                policy_path, _MAX_POLICY_BYTES, label="policy file"))
            if not isinstance(config, dict):
                raise ValueError("policy JSON must be an object")
            config = PolicyEngine.validate_project_config(config)
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                TypeError, ValueError, OverflowError) as exc:
            _print_error(f"error: invalid policy file: {exc}")
            raise SystemExit(2) from None
    engine, meta = _engine(args)
    pid = meta["project_id"]
    if args.action == "configure":
        if args.project is None or args.file is None:
            _print_error(
                "error: policy configure requires --project and --file")
            engine.close()
            raise SystemExit(2)
        if args.project != pid:
            _print_error(
                f"error: local CCE project is {pid}, not {args.project}")
            engine.close()
            raise SystemExit(2)
        # PolicyEngine is the single validator and persistence boundary;
        # this command deliberately has no NAME=COMMAND or shell option.
        engine.policy.set_project_config(
            pid, config, actor=args.by)
        configured = engine.policy.project_config(pid)
        _emit(
            args, {"project_id": pid, "config": configured},
            f"configured policy for {pid} from {policy_path}")
    elif args.action == "grant":
        gid = engine.policy.grant(project_id=pid, level=args.level,
                                  granted_by=args.by, expires_at=args.expires,
                                  reason=args.reason)
        _emit(args, {"grant_id": gid, "level": args.level},
              f"granted level {args.level} ({gid})")
    elif args.action == "revoke":
        engine.policy.revoke(
            args.grant_id, actor=args.by,
            reason="" if args.reason is None else args.reason)
        _emit(args, {"revoked": args.grant_id}, f"revoked {args.grant_id}")
    elif args.action == "clear-downgrades":
        engine.policy.clear_downgrades(pid, actor=args.by)
        _emit(args, {"cleared": True}, "downgrades cleared")
    else:  # show
        _emit(args, {
            "effective_level": engine.policy.effective_level(pid),
            "config": engine.policy.project_config(pid),
            "active_grants": engine.policy.active_grants(pid),
            "downgrade_ceiling": engine.policy.active_downgrade_ceiling(pid),
        })
    engine.close()


def cmd_serve(args):
    from .api import serve
    engine, meta = _engine(args)
    root = Path("." if args.dir is None else args.dir)
    _, cce_dir = _physical_cce_directory(root, root / ".cce")
    api_token = _read_private(_secret_path(cce_dir, meta["api_token_file"])) \
        .decode("ascii")
    webhook_secret = _read_private(
        _secret_path(cce_dir, meta["webhook_secret_file"]))
    print(_sanitize_human(
        f"serving authenticated CCE API on 127.0.0.1:{args.port} "
        f"(project {meta['project_id']}; credentials: {cce_dir / 'secrets'})"))
    serve(
        engine, meta["project_id"], port=args.port,
        api_token=api_token, webhook_secret=webhook_secret)


def main(argv=None):
    p = SafeArgumentParser(
        prog="cce-engine", description="Causal Continuity Engine")
    p.add_argument(
        "--dir", default=".", type=_nonempty_argument,
        help="project directory")
    p.add_argument("--json", action="store_true", help="JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="initialize a CCE project")
    s.add_argument("--repo", type=_repository_name, help="owner/repo")
    s.add_argument(
        "--repo-id", type=_positive_int,
        help="immutable numeric GitHub repository id (required for webhooks)")
    s.add_argument(
        "--github-installation-id", type=_positive_int,
        help="optional numeric GitHub App installation id to pin")
    s.add_argument("--capture-mode", default="redacted",
                   choices=["metadata_only", "redacted", "full"])
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("ingest", help="ingest a GitHub webhook payload")
    s.add_argument("--event", required=True, choices=sorted(SUBSCRIBED_EVENTS))
    s.add_argument("--delivery-id", required=True, type=_public_identifier)
    s.add_argument(
        "--file", default="-", type=_nonempty_argument,
        help="payload JSON file (default stdin)")
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser("resume", help="compose a Resume Packet")
    s.add_argument("--issue", type=_nonempty_argument)
    s.add_argument("--token-budget", type=_token_budget, default=4000)
    s.add_argument("--format", default="markdown", choices=["markdown", "json"])
    s.set_defaults(fn=cmd_resume)

    s = sub.add_parser("assumptions", help="list assumptions")
    s.add_argument(
        "--status", type=_assumption_statuses,
        help="comma-separated assumption states")
    s.add_argument("--criticality", choices=sorted(CRITICALITY_LEVELS))
    s.set_defaults(fn=cmd_assumptions)

    s = sub.add_parser("invalidations", help="list or explain invalidations")
    s.add_argument(
        "--explain", metavar="INVALIDATION_ID", type=_public_identifier)
    s.set_defaults(fn=cmd_invalidations)

    s = sub.add_parser(
        "verify",
        help="run the complete configured policy verifier set and produce a proof")
    s.add_argument(
        "--intent", default="task_complete", type=_nonempty_argument)
    s.add_argument("--statement")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser(
        "check", help=(
            "compute or verify a CCE Continuity receipt "
            "(computed checks exit 0 only on success)"))
    receipts = s.add_mutually_exclusive_group()
    receipts.add_argument(
        "--export-receipt", metavar="FILE", type=_nonempty_argument,
        help="write the newly computed signed receipt to FILE")
    receipts.add_argument(
        "--verify-receipt", metavar="FILE", type=_nonempty_argument,
        help=("verify FILE against this project "
              "(exit CURRENT=0, AUTHENTIC_HISTORICAL=3, INVALID=4)"))
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("migrate", help="export/validate a Session Capsule")
    s.add_argument("action", choices=["prepare", "validate"])
    s.add_argument("--session", type=_public_identifier)
    s.add_argument(
        "--capsule", type=_nonempty_argument,
        help="capsule file (validate)")
    s.add_argument("--target", type=_nonempty_argument)
    s.add_argument("--target-runtime", type=_nonempty_argument)
    s.add_argument("--source-model", type=_nonempty_argument)
    s.add_argument("--source-runtime", type=_nonempty_argument)
    s.add_argument("--out", type=_nonempty_argument)
    s.set_defaults(fn=cmd_migrate)

    s = sub.add_parser("replay", help="prepare a sandbox replay")
    s.add_argument("--from-event", required=True, type=_public_identifier)
    s.add_argument("--fork-model", type=_nonempty_argument)
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("rebuild", help="verify projection rebuilds from event log")
    s.set_defaults(fn=cmd_rebuild)

    s = sub.add_parser("audit", help="tamper evidence: chain + external anchor")
    s.add_argument("action", choices=["verify", "anchor", "check-anchor"])
    s.add_argument("--table", default="events", choices=["events", "audit_log"])
    s.add_argument(
        "--out", type=_nonempty_argument, help="anchor output file")
    s.add_argument(
        "--anchor", type=_nonempty_argument,
        help="anchor file (check-anchor)")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("evidence", help="evidence quality probes")
    s.add_argument("action", choices=["probe", "determinism"])
    s.add_argument("--artifact", action="append", type=_nonempty_argument,
                   help="deliverable to mutate (repeatable)")
    s.set_defaults(fn=cmd_evidence)

    s = sub.add_parser(
        "policy", help="autonomy policy: show/configure/grant/revoke")
    s.add_argument(
        "action",
        choices=["show", "configure", "grant", "revoke", "clear-downgrades"])
    s.add_argument(
        "--project", type=_public_identifier,
        help="project id (required for configure)")
    s.add_argument(
        "--file", type=_nonempty_argument,
        help="JSON policy file (required for configure)")
    s.add_argument("--level", type=_autonomy_level)
    s.add_argument("--by", default="operator", type=_nonempty_argument)
    s.add_argument("--expires", type=_nonempty_argument)
    s.add_argument("--reason", type=_nonempty_argument)
    s.add_argument("--grant-id", type=_public_identifier)
    s.set_defaults(fn=cmd_policy)

    s = sub.add_parser("serve", help="serve the HTTP API")
    s.add_argument("--port", type=_tcp_port, default=8199)
    s.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    if (args.cmd == "init" and args.github_installation_id is not None
            and args.repo_id is None):
        p.error("init --github-installation-id requires --repo-id")
    if (args.cmd == "migrate" and args.action == "validate"
            and args.capsule is None):
        p.error("migrate validate requires --capsule FILE")
    if (args.cmd == "audit" and args.action == "check-anchor"
            and args.anchor is None):
        p.error("audit check-anchor requires --anchor FILE")
    if args.cmd == "policy":
        if (args.action == "configure"
                and (args.project is None or args.file is None)):
            p.error("policy configure requires --project ID and --file FILE")
        if args.action == "grant" and args.level is None:
            p.error("policy grant requires --level LEVEL")
        if args.action == "revoke" and args.grant_id is None:
            p.error("policy revoke requires --grant-id GRANT_ID")

    args._opened_engines = []
    active_exception = False
    try:
        args.fn(args)
    except CLIOutputError as exc:
        active_exception = True
        _print_error(f"error: {exc}")
        raise SystemExit(1) from None
    except (
            OSError, UnicodeError, ValueError, KeyError,
            WebhookError, CapsuleError) as exc:
        active_exception = True
        detail = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        _print_error(f"error: {detail}")
        raise SystemExit(2) from None
    except BaseException:
        active_exception = True
        raise
    finally:
        closed: set[int] = set()
        for opened in reversed(args._opened_engines):
            if id(opened) in closed:
                continue
            closed.add(id(opened))
            try:
                opened.close()
            except Exception:
                if not active_exception:
                    raise


if __name__ == "__main__":
    main()
