"""CCE engine facade: canonical event processing and project operations.

  accept -> store immutable envelope (redacted per capture policy)
         -> normalize -> extract -> dedup + graph write -> conflict &
         invalidation detection -> active-state/packet recompute flag
         -> policy/check publication -> metrics.

Extracted nodes use deterministic content-derived ids (stable_key) so a
clean-database replay of the event log rebuilds an equivalent projection
(CCG-006); runtime nodes (sessions, checkpoints) keep random ids and are
compared by type/status counts.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from collections import Counter
from pathlib import Path

from .capsule import CapsuleManager
from .core import (
    Signer,
    canonical_json,
    digest_obj,
    is_canonical_utc_timestamp,
    is_rfc3339_datetime,
    new_id,
    sha256_hex,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
    validate_repository_name,
)
from .evidence import (
    EvidenceGrade,
    MutationReport,
    grade_evidence,
    normalize_artifact_path,
    normalize_artifact_paths,
    run_determinism_probe,
    run_mutation_probe,
)
from .extraction import DeterministicExtractor, normalize_statement
from .github import (
    TRUSTED_ASSOCIATIONS,
    WEBHOOK_BODY_MAX_BYTES,
    WebhookPayloadError,
    continuity_conclusion,
    normalize,
    validate_webhook_secret,
    verify_signature,
)
from .graph import Graph
from .invalidation import InvalidationEngine
from .learning import EvalGenerator, FailureComposter, ReplayManager, SkillProposer
from .memory import Memory
from .ontology import authority_rank
from .partial import PartialProgressManager
from .policy import ACTION_CLASSES, PolicyEngine, proof_policy_verifier_gaps
from .proof import (
    AUTHORITATIVE_SOURCES,
    SELF_ASSERTED,
    ProofEnvelope,
    detect_stale,
    validate_envelope_shape,
    verify_envelope,
)
from .redaction import CAPTURE_MODES, apply_capture_mode
from .resume import ResumeComposer
from .store import (
    DuplicateEventError,
    Store,
    serialized_access,
)
from .verifiers import VerifierRunner, VerifierSpec, record_verification

PROCESSOR_VERSION = "cce-processor/1.1.0"
# Version of the statement normalization contract that feeds stable_node_id.
# It is deliberately separate from the extractor version: pattern behavior can
# change without changing identity, while an identity change survives forever
# in event history (ADR-106).
STABLE_NODE_ID_VERSION = "cce.statement-id.v2"

_KIND_PREFIX = {"assumption": "asm", "requirement": "req", "constraint": "cst",
                "decision": "dec", "claim": "clm", "task": "tsk"}

_CONTINUITY_LINK_TYPES = {
    "task_ids": "task",
    "requirement_ids": "requirement",
    "decision_ids": "decision",
    "assumption_ids": "assumption",
    "artifact_ids": "artifact",
    "evidence_ids": "evidence",
    "action_ids": "action",
}

_CONTINUITY_STATE_FIELDS = (
    "node_id", "version", "entity_type", "tenant_id", "project_id",
    "status", "criticality", "authority", "confidence", "scope", "data",
    "valid_from", "valid_to", "event_id", "extractor",
    "extractor_version",
)

_AUTHORIZED_ASSOCIATIONS = TRUSTED_ASSOCIATIONS

_VOLATILE_PROJECTION_KEYS = {
    "captured_at", "checked_at", "completed_at", "composed_at", "created_at",
    "decided_at", "fired_at", "generated_at", "packet_generation_time",
    "ran_at", "started_at", "superseded_at",
}
_INTERNAL_RANDOM_ID = re.compile(
    r"^(act|art|asm|cap|ckp|clm|cst|dec|edg|evd|evl|flr|grt|inv|nod|"
    r"out|pln|prf|req|rpl|rsp|ses|skl|tsk|ver)_[0-9a-f]{24}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

_CONTINUITY_PAYLOAD_TYPE = (
    "https://raw.githubusercontent.com/thequantumfalcon/"
    "causal-continuity-engine/v0.1.0/schemas/"
    "cce.continuity-receipt.v1.json")
_CONTINUITY_PREDICATE_NAMES = frozenset({
    "critical_invalidations_empty",
    "human_approvals_complete",
    "authority_conflicts_empty",
    "active_proof_failures_empty",
    "required_verifiers_current",
    "resume_packet_current",
    "revision_frontier_decidable",
    "integrity_chains_intact",
})

def _continuity_predicates(project_id: str, state: dict) -> list[dict]:
    """Derive every v1 witness predicate from its committed decision state."""
    invalidations = state.get("invalidations") or []
    critical_ids = [
        item.get("node_id") for item in invalidations
        if item.get("severity") in ("high", "critical")]
    pending_ids = [
        item.get("node_id") for item in invalidations
        if item.get("status") == "pending_confirmation"]
    conflicts = state.get("conflicts") or []
    proofs = state.get("proofs") or []
    gaps = sorted(state.get("verifier_gaps") or [])
    trusted_passes = state.get("trusted_passes") or []
    packet = state.get("packet") or {}
    revision = state.get("revision") or {}
    integrity = state.get("integrity") or {}
    revision_decidable = not (
        bool(revision.get("uncertain"))
        or bool(revision.get("external_without_frontier")))
    chains_intact = bool(
        integrity.get("event_log_intact")
        and integrity.get("audit_log_intact"))
    return [
        {
            "predicate": "critical_invalidations_empty",
            "subject": project_id,
            "observed": len(critical_ids), "required": 0,
            "satisfied": not critical_ids,
            "evidence_digest": digest_obj(critical_ids),
            "remediation": (
                "resolve or narrow every high/critical invalidation"),
        },
        {
            "predicate": "human_approvals_complete",
            "subject": project_id,
            "observed": len(pending_ids), "required": 0,
            "satisfied": not pending_ids,
            "evidence_digest": digest_obj(pending_ids),
            "remediation": "record each required human confirmation",
        },
        {
            "predicate": "authority_conflicts_empty",
            "subject": project_id,
            "observed": len(conflicts), "required": 0,
            "satisfied": not conflicts,
            "evidence_digest": digest_obj(conflicts),
            "remediation": (
                "resolve every contested authoritative statement"),
        },
        {
            "predicate": "active_proof_failures_empty",
            "subject": project_id,
            "observed": len(proofs), "required": 0,
            "satisfied": not proofs,
            "evidence_digest": digest_obj(proofs),
            "remediation": (
                "re-attest or explicitly resolve failed proof claims"),
        },
        {
            "predicate": "required_verifiers_current",
            "subject": project_id,
            "observed": gaps, "required": [],
            "satisfied": not gaps,
            "evidence_digest": digest_obj(trusted_passes),
            "remediation": (
                "configure and run every required verifier at the bound "
                "frontier"),
        },
        {
            "predicate": "resume_packet_current",
            "subject": project_id,
            "observed": bool(packet.get("current")), "required": True,
            "satisfied": bool(packet.get("current")),
            "evidence_digest": digest_obj(packet),
            "remediation": (
                "compose a resume packet after the latest control-state change"),
        },
        {
            "predicate": "revision_frontier_decidable",
            "subject": revision.get("tracked_ref"),
            "observed": revision_decidable, "required": True,
            "satisfied": revision_decidable,
            "evidence_digest": digest_obj(revision),
            "remediation": (
                "reconcile the tracked ref and establish its current SHA"),
        },
        {
            "predicate": "integrity_chains_intact",
            "subject": project_id,
            "observed": chains_intact, "required": True,
            "satisfied": chains_intact,
            "evidence_digest": digest_obj(integrity),
            "remediation": (
                "restore from a trusted checkpoint and verify external anchors"),
        },
    ]


def _continuity_decision(predicates: list[dict]) -> str:
    """Recompute the GitHub conclusion from the typed predicate frontier."""
    values = {item["predicate"]: bool(item["satisfied"])
              for item in predicates}
    return continuity_conclusion(
        critical_invalidation=not values["critical_invalidations_empty"],
        proof_ok=(values["active_proof_failures_empty"]
                  and values["required_verifiers_current"]),
        packet_current=values["resume_packet_current"],
        authority_conflict=not values["authority_conflicts_empty"],
        approval_needed=not values["human_approvals_complete"],
        trust_unavailable=(not values["revision_frontier_decidable"]
                           or not values["integrity_chains_intact"]),
    )


_EVIDENCE_FLOOR_RANK = {None: 0, "D": 1, "C": 2, "B": 3, "A": 4}


class AttestationInputError(ValueError):
    """Caller-controlled proof input failed before any verifier or mutation."""


class GitHubDeliveryError(PermissionError):
    """A GitHub delivery failed the configured project identity boundary."""


class UnsafeArtifactError(ValueError):
    """A declared artifact reaches bytes through an unstable filesystem link."""


_REPARSE_POINT = 0x400  # Windows FILE_ATTRIBUTE_REPARSE_POINT
_POSIX_ARTIFACT_FD_SNAPSHOT = bool(
    os.name == "posix"
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in getattr(os, "supports_dir_fd", set())
    and os.stat in getattr(os, "supports_dir_fd", set())
    and os.stat in getattr(os, "supports_follow_symlinks", set())
    and os.listdir in getattr(os, "supports_fd", set())
)


def _artifact_identity_key(info: os.stat_result) -> tuple:
    """Physical entry identity, excluding mutable directory contents."""
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        getattr(info, "st_file_attributes", 0),
        getattr(info, "st_reparse_tag", 0),
    )


def _artifact_stat_key(info: os.stat_result) -> tuple:
    """Metadata that must bracket one regular-file content read."""
    return _artifact_identity_key(info) + (
        info.st_mode,
        info.st_nlink,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _artifact_is_indirect(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _hash_artifact_file(path: str | Path, *, fd: int | None = None) -> str:
    """Stream one file from a held descriptor when the host supports it."""
    digest = hashlib.sha256()
    if fd is not None:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return "sha256:" + digest.hexdigest()
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _artifact_changed(rel: str, detail: str = "") -> UnsafeArtifactError:
    suffix = f": {detail}" if detail else ""
    return UnsafeArtifactError(
        f"declared artifact {rel!r} changed while hashing{suffix}")


def _artifact_link(
        rel: str, location: str, *, nested: bool = False
) -> UnsafeArtifactError:
    relation = "contains" if nested else "uses"
    return UnsafeArtifactError(
        f"declared artifact {rel!r} {relation} a symlink or reparse "
        f"{'point' if nested else 'route'} at {location}")


def _posix_stat_at(parent_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def _posix_open_stable(
        parent_fd: int, name: str, before: os.stat_result, *,
        directory: bool, rel: str) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise _artifact_changed(
            rel, f"route changed or became unreadable at {name!r}") from exc
    try:
        opened = os.fstat(fd)
        current = _posix_stat_at(parent_fd, name)
        key = (
            _artifact_stat_key
            if directory or stat.S_ISREG(before.st_mode)
            else _artifact_identity_key
        )
        if (_artifact_is_indirect(opened)
                or _artifact_is_indirect(current)
                or key(opened) != key(before)
                or key(current) != key(before)):
            raise _artifact_changed(rel, f"route changed at {name!r}")
    except Exception:
        os.close(fd)
        raise
    return fd


def _snapshot_posix_directory(
        fd: int, path: Path, rel: str, prefix: str = "") -> list[dict]:
    before_dir = os.fstat(fd)
    try:
        before_names = sorted(os.listdir(fd))
    except OSError as exc:
        raise _artifact_changed(
            rel, "directory inventory became unreadable") from exc
    before_entries: dict[str, os.stat_result] = {}
    records: list[dict] = []
    for name in before_names:
        logical = f"{prefix}/{name}" if prefix else name
        try:
            before = _posix_stat_at(fd, name)
        except OSError as exc:
            raise _artifact_changed(
                rel, f"entry vanished at {logical!r}") from exc
        before_entries[name] = before
        if _artifact_is_indirect(before):
            raise _artifact_link(rel, logical, nested=True)
        if stat.S_ISREG(before.st_mode):
            child_fd = _posix_open_stable(
                fd, name, before, directory=False, rel=rel)
            try:
                file_digest = _hash_artifact_file(
                    path / name, fd=child_fd)
                opened_after = os.fstat(child_fd)
                entry_after = _posix_stat_at(fd, name)
                if (_artifact_is_indirect(entry_after)
                        or _artifact_stat_key(opened_after)
                        != _artifact_stat_key(before)
                        or _artifact_stat_key(entry_after)
                        != _artifact_stat_key(before)):
                    raise _artifact_changed(rel, f"file changed at {logical!r}")
            except OSError as exc:
                raise _artifact_changed(
                    rel, f"file changed at {logical!r}") from exc
            finally:
                os.close(child_fd)
            records.append({
                "kind": "file", "path": logical, "digest": file_digest})
        elif stat.S_ISDIR(before.st_mode):
            child_fd = _posix_open_stable(
                fd, name, before, directory=True, rel=rel)
            try:
                records.append({"kind": "directory", "path": logical})
                records.extend(_snapshot_posix_directory(
                    child_fd, path / name, rel, logical))
                opened_after = os.fstat(child_fd)
                entry_after = _posix_stat_at(fd, name)
                if (_artifact_stat_key(opened_after)
                        != _artifact_stat_key(before)
                        or _artifact_stat_key(entry_after)
                        != _artifact_stat_key(before)):
                    raise _artifact_changed(
                        rel, f"directory changed at {logical!r}")
            except OSError as exc:
                raise _artifact_changed(
                    rel, f"directory changed at {logical!r}") from exc
            finally:
                os.close(child_fd)
        else:
            raise UnsafeArtifactError(
                f"declared artifact {rel!r} contains unsupported physical "
                f"entry {logical!r}")

    try:
        after_names = sorted(os.listdir(fd))
        after_dir = os.fstat(fd)
    except OSError as exc:
        raise _artifact_changed(
            rel, "directory inventory became unreadable") from exc
    if (after_names != before_names
            or _artifact_stat_key(after_dir)
            != _artifact_stat_key(before_dir)):
        raise _artifact_changed(rel, "directory inventory changed")
    for name in after_names:
        try:
            after = _posix_stat_at(fd, name)
        except OSError as exc:
            raise _artifact_changed(rel, f"entry vanished at {name!r}") from exc
        if (_artifact_is_indirect(after)
                or _artifact_stat_key(after)
                != _artifact_stat_key(before_entries[name])):
            raise _artifact_changed(rel, f"entry changed at {name!r}")
    return records


def _verify_posix_route(
        root: Path, root_fd: int, root_identity: tuple,
        route: list[tuple[int, str, int, tuple]], rel: str) -> None:
    try:
        root_now = os.lstat(root)
        if (_artifact_is_indirect(root_now)
                or _artifact_identity_key(root_now) != root_identity
                or _artifact_identity_key(os.fstat(root_fd)) != root_identity):
            raise _artifact_changed(rel, "verifier workdir route changed")
        for parent_fd, name, child_fd, identity in route:
            entry = _posix_stat_at(parent_fd, name)
            if (_artifact_is_indirect(entry)
                    or _artifact_identity_key(entry) != identity
                    or _artifact_identity_key(os.fstat(child_fd)) != identity):
                raise _artifact_changed(rel, f"route changed at {name!r}")
    except UnsafeArtifactError:
        raise
    except OSError as exc:
        raise _artifact_changed(rel, "artifact route changed") from exc


def _snapshot_artifact_posix(root: Path, rel: str) -> str:
    root_before = os.lstat(root)
    if _artifact_is_indirect(root_before):
        raise _artifact_link(rel, "<verifier-workdir>")
    if not stat.S_ISDIR(root_before.st_mode):
        raise UnsafeArtifactError("verifier workdir is not a physical directory")
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        raise _artifact_changed(rel, "verifier workdir route changed") from exc
    route: list[tuple[int, str, int, tuple]] = []
    opened_route_fds: list[int] = []
    try:
        root_identity = _artifact_identity_key(root_before)
        if _artifact_identity_key(os.fstat(root_fd)) != root_identity:
            raise _artifact_changed(rel, "verifier workdir route changed")
        parent_fd = root_fd
        cursor = root
        parts = rel.split("/")
        for part in parts[:-1]:
            try:
                before = _posix_stat_at(parent_fd, part)
            except FileNotFoundError:
                _verify_posix_route(
                    root, root_fd, root_identity, route, rel)
                try:
                    _posix_stat_at(parent_fd, part)
                except FileNotFoundError:
                    return sha256_hex("<absent>")
                raise _artifact_changed(rel, f"route appeared at {part!r}")
            if _artifact_is_indirect(before):
                raise _artifact_link(rel, str((cursor / part).relative_to(root)))
            if not stat.S_ISDIR(before.st_mode):
                _verify_posix_route(
                    root, root_fd, root_identity, route, rel)
                try:
                    after = _posix_stat_at(parent_fd, part)
                except OSError as exc:
                    raise _artifact_changed(
                        rel, f"route changed at {part!r}") from exc
                if _artifact_stat_key(after) != _artifact_stat_key(before):
                    raise _artifact_changed(rel, f"route changed at {part!r}")
                return sha256_hex("<absent>")
            child_fd = _posix_open_stable(
                parent_fd, part, before, directory=True, rel=rel)
            identity = _artifact_identity_key(before)
            route.append((parent_fd, part, child_fd, identity))
            opened_route_fds.append(child_fd)
            parent_fd = child_fd
            cursor /= part

        name = parts[-1]
        try:
            before = _posix_stat_at(parent_fd, name)
        except FileNotFoundError:
            _verify_posix_route(root, root_fd, root_identity, route, rel)
            try:
                _posix_stat_at(parent_fd, name)
            except FileNotFoundError:
                return sha256_hex("<absent>")
            raise _artifact_changed(rel, "artifact appeared during snapshot")
        if _artifact_is_indirect(before):
            raise _artifact_link(rel, rel)
        target = root.joinpath(*parts)
        if stat.S_ISREG(before.st_mode):
            target_fd = _posix_open_stable(
                parent_fd, name, before, directory=False, rel=rel)
            try:
                digest = _hash_artifact_file(target, fd=target_fd)
                opened_after = os.fstat(target_fd)
                entry_after = _posix_stat_at(parent_fd, name)
                if (_artifact_is_indirect(entry_after)
                        or _artifact_stat_key(opened_after)
                        != _artifact_stat_key(before)
                        or _artifact_stat_key(entry_after)
                        != _artifact_stat_key(before)):
                    raise _artifact_changed(rel)
            except OSError as exc:
                raise _artifact_changed(rel) from exc
            finally:
                os.close(target_fd)
        elif stat.S_ISDIR(before.st_mode):
            target_fd = _posix_open_stable(
                parent_fd, name, before, directory=True, rel=rel)
            try:
                records = _snapshot_posix_directory(
                    target_fd, target, rel)
                opened_after = os.fstat(target_fd)
                entry_after = _posix_stat_at(parent_fd, name)
                if (_artifact_stat_key(opened_after)
                        != _artifact_stat_key(before)
                        or _artifact_stat_key(entry_after)
                        != _artifact_stat_key(before)):
                    raise _artifact_changed(rel)
                digest = sha256_hex(canonical_json(records))
            except OSError as exc:
                raise _artifact_changed(rel) from exc
            finally:
                os.close(target_fd)
        else:
            raise UnsafeArtifactError(
                f"declared artifact {rel!r} is not a regular file or directory")
        _verify_posix_route(root, root_fd, root_identity, route, rel)
        return digest
    finally:
        for fd in reversed(opened_route_fds):
            os.close(fd)
        os.close(root_fd)


def _verify_fallback_route(
        route: list[tuple[Path, tuple]], rel: str) -> None:
    for path, identity in route:
        try:
            current = os.lstat(path)
        except OSError as exc:
            raise _artifact_changed(
                rel, f"route vanished at {path.name!r}") from exc
        if (_artifact_is_indirect(current)
                or _artifact_identity_key(current) != identity):
            raise _artifact_changed(rel, f"route changed at {path.name!r}")


def _snapshot_fallback_directory(
        path: Path, rel: str, prefix: str = "") -> list[dict]:
    before_dir = os.lstat(path)
    if _artifact_is_indirect(before_dir):
        raise _artifact_link(rel, prefix or rel, nested=bool(prefix))
    try:
        before_names = sorted(os.listdir(path))
    except OSError as exc:
        raise _artifact_changed(
            rel, "directory inventory became unreadable") from exc
    before_entries: dict[str, os.stat_result] = {}
    records: list[dict] = []
    for name in before_names:
        child = path / name
        logical = f"{prefix}/{name}" if prefix else name
        try:
            before = os.lstat(child)
        except OSError as exc:
            raise _artifact_changed(
                rel, f"entry vanished at {logical!r}") from exc
        before_entries[name] = before
        if _artifact_is_indirect(before):
            raise _artifact_link(rel, logical, nested=True)
        if stat.S_ISREG(before.st_mode):
            try:
                file_digest = _hash_artifact_file(child)
                after = os.lstat(child)
            except OSError as exc:
                raise _artifact_changed(
                    rel, f"file changed at {logical!r}") from exc
            if (_artifact_is_indirect(after)
                    or _artifact_stat_key(after)
                    != _artifact_stat_key(before)):
                raise _artifact_changed(rel, f"file changed at {logical!r}")
            records.append({
                "kind": "file", "path": logical, "digest": file_digest})
        elif stat.S_ISDIR(before.st_mode):
            records.append({"kind": "directory", "path": logical})
            records.extend(_snapshot_fallback_directory(
                child, rel, logical))
            try:
                after = os.lstat(child)
            except OSError as exc:
                raise _artifact_changed(
                    rel, f"directory changed at {logical!r}") from exc
            if (_artifact_stat_key(after) != _artifact_stat_key(before)
                    or _artifact_is_indirect(after)):
                raise _artifact_changed(
                    rel, f"directory changed at {logical!r}")
        else:
            raise UnsafeArtifactError(
                f"declared artifact {rel!r} contains unsupported physical "
                f"entry {logical!r}")

    try:
        after_names = sorted(os.listdir(path))
        after_dir = os.lstat(path)
    except OSError as exc:
        raise _artifact_changed(
            rel, "directory inventory became unreadable") from exc
    if (after_names != before_names
            or _artifact_stat_key(after_dir) != _artifact_stat_key(before_dir)):
        raise _artifact_changed(rel, "directory inventory changed")
    for name in after_names:
        try:
            after = os.lstat(path / name)
        except OSError as exc:
            raise _artifact_changed(rel, f"entry vanished at {name!r}") from exc
        if _artifact_is_indirect(after):
            raise _artifact_link(rel, name, nested=True)
        if (_artifact_stat_key(after)
                != _artifact_stat_key(before_entries[name])):
            raise _artifact_changed(rel, f"entry changed at {name!r}")
    return records


def _snapshot_artifact_fallback(root: Path, rel: str) -> str:
    try:
        root_before = os.lstat(root)
    except OSError:
        raise
    if _artifact_is_indirect(root_before):
        raise _artifact_link(rel, "<verifier-workdir>")
    if not stat.S_ISDIR(root_before.st_mode):
        raise UnsafeArtifactError("verifier workdir is not a physical directory")
    route: list[tuple[Path, tuple]] = [
        (root, _artifact_identity_key(root_before))]
    cursor = root
    parts = rel.split("/")
    for part in parts[:-1]:
        cursor /= part
        try:
            before = os.lstat(cursor)
        except FileNotFoundError:
            _verify_fallback_route(route, rel)
            try:
                os.lstat(cursor)
            except FileNotFoundError:
                return sha256_hex("<absent>")
            raise _artifact_changed(rel, f"route appeared at {part!r}")
        if _artifact_is_indirect(before):
            raise _artifact_link(rel, str(cursor.relative_to(root)))
        if not stat.S_ISDIR(before.st_mode):
            _verify_fallback_route(route, rel)
            try:
                after = os.lstat(cursor)
            except OSError as exc:
                raise _artifact_changed(
                    rel, f"route changed at {part!r}") from exc
            if _artifact_stat_key(after) != _artifact_stat_key(before):
                raise _artifact_changed(rel, f"route changed at {part!r}")
            return sha256_hex("<absent>")
        route.append((cursor, _artifact_identity_key(before)))

    target = root.joinpath(*parts)
    try:
        before = os.lstat(target)
    except FileNotFoundError:
        _verify_fallback_route(route, rel)
        try:
            os.lstat(target)
        except FileNotFoundError:
            return sha256_hex("<absent>")
        raise _artifact_changed(rel, "artifact appeared during snapshot")
    if _artifact_is_indirect(before):
        raise _artifact_link(rel, rel)
    if stat.S_ISREG(before.st_mode):
        try:
            digest = _hash_artifact_file(target)
            after = os.lstat(target)
        except OSError as exc:
            raise _artifact_changed(rel) from exc
        if (_artifact_is_indirect(after)
                or _artifact_stat_key(after) != _artifact_stat_key(before)):
            raise _artifact_changed(rel)
    elif stat.S_ISDIR(before.st_mode):
        records = _snapshot_fallback_directory(target, rel)
        try:
            after = os.lstat(target)
        except OSError as exc:
            raise _artifact_changed(rel) from exc
        if (_artifact_is_indirect(after)
                or _artifact_stat_key(after) != _artifact_stat_key(before)):
            raise _artifact_changed(rel)
        digest = sha256_hex(canonical_json(records))
    else:
        raise UnsafeArtifactError(
            f"declared artifact {rel!r} is not a regular file or directory")
    _verify_fallback_route(route, rel)
    return digest


def _snapshot_artifact(root: Path, rel: str) -> str:
    if _POSIX_ARTIFACT_FD_SNAPSHOT:
        return _snapshot_artifact_posix(root, rel)
    return _snapshot_artifact_fallback(root, rel)


def _policy_strength_covers(current: dict, previous: dict) -> bool:
    """Whether a successful retry is comparable and at least as demanding.

    Required verifiers are comparable only when their complete normalized
    definitions are identical.  A different timeout, oracle expectation,
    negative control or artifact surface changes what a pass establishes just
    as surely as changing the command does.
    """
    if not isinstance(current, dict) or not isinstance(previous, dict):
        return False
    current_defs = {
        item.get("name"): item for item in current.get("required", [])
        if isinstance(item, dict) and item.get("name")}
    previous_defs = {
        item.get("name"): item for item in previous.get("required", [])
        if isinstance(item, dict) and item.get("name")}
    for name, old in previous_defs.items():
        new = current_defs.get(name)
        if (new is None
                or not old.get("definition_digest")
                or new.get("definition_digest") != old["definition_digest"]):
            return False
    return _EVIDENCE_FLOOR_RANK.get(current.get("min_evidence_grade"), -1) >= \
        _EVIDENCE_FLOOR_RANK.get(previous.get("min_evidence_grade"), -1)


def _preflight_proof_body(body: dict, verifications: list[dict]) -> None:
    """Validate caller-controlled proof semantics before executing anything."""
    try:
        candidate = strict_json_loads(canonical_json(body))
        candidate["verifications"] = strict_json_loads(
            canonical_json(verifications))
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise AttestationInputError(
            "attestation inputs must be finite canonical JSON") from None
    candidate["verification_summary"] = {
        "unbacked_self_assertions": [],
        "required": [],
        "missing": [],
        "failed": [],
        "inconclusive": [],
        "skipped": [],
        "passed": [],
    }
    candidate["proof_digest"] = digest_obj({})
    candidate["signature"] = {
        "key_id": "preflight",
        "algorithm": "hmac-sha256",
        "value": "preflight",
    }
    errors = validate_envelope_shape(candidate)
    if errors:
        raise AttestationInputError(
            "invalid attestation input: " + "; ".join(errors))

# Packet freshness watermark (CI-006). Persisted so a fresh process — every
# CLI invocation is one — sees the same staleness state as a long-lived
# service; an in-memory flag would make `cce-engine check` report success on state
# that no packet has ever reflected.
_ENGINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS packet_watermark (
    project_id          TEXT PRIMARY KEY,
    last_event_seq      INTEGER NOT NULL,
    composed_at         TEXT NOT NULL,
    packet_id           TEXT,
    packet_digest       TEXT,
    control_basis_digest TEXT,
    audit_entry_hash    TEXT
);

-- Single-use proofs (ADR-018) enforced by the database rather than by a
-- read-then-write. Scanning for a prior spend and then writing is two
-- statements, so two processes both find nothing and both proceed; the
-- PRIMARY KEY makes the second one an error (ADR-059).
CREATE TABLE IF NOT EXISTS spent_proofs (
    tenant_id  TEXT NOT NULL,
    project_id TEXT NOT NULL,
    proof_id   TEXT NOT NULL,
    task_id    TEXT NOT NULL,
    spent_at   TEXT NOT NULL,
    PRIMARY KEY (tenant_id, project_id, proof_id)
);
"""


def _restates(existing: dict, item, ref: str, authority: str) -> bool:
    """Whether this extraction asserts exactly what the node already records."""
    data = existing.get("data") or {}
    return (
        data.get("statement") == item.statement
        and ref in _source_refs(existing)
        and existing.get("authority") == authority
        and existing.get("criticality") == item.criticality
        and existing.get("confidence") == item.confidence
        and data.get("done", item.meta.get("done")) == item.meta.get("done")
    )


def _proof_covers(proof: dict, task_id: str) -> bool:
    """Whether a signed envelope names this task as its subject.

    Task completion requires the typed task_ids continuity relation. Merely
    mentioning a task under an unrelated link, requirement id, or subject
    label does not make that task the action's completion target.
    """
    task_ids = (proof.get("continuity_links") or {}).get("task_ids")
    return (
        isinstance(task_ids, list)
        and all(isinstance(value, str) for value in task_ids)
        and task_id in task_ids
    )


def _source_refs(node: dict | None) -> set[str]:
    """Every source ref that currently states this node's content.

    `source_refs` is authoritative once written; `source_ref` (the most
    recent single writer, kept for readability) is only a fallback for nodes
    that predate the list, and must never re-add a retracted ref.
    """
    if not node:
        return set()
    data = node.get("data") or {}
    refs = data.get("source_refs")
    if refs is not None:
        return set(refs)
    return {data["source_ref"]} if data.get("source_ref") else set()


def stable_node_id(project_id: str, kind: str, statement: str) -> str:
    """Derive a v2 statement id; compatibility behavior is pinned in ADR-106."""
    key = f"{project_id}|{kind}|{normalize_statement(statement)}"
    return f"{_KIND_PREFIX.get(kind, 'nod')}_{hashlib.sha256(key.encode()).hexdigest()[:24]}"


class Engine:
    def __init__(self, path=":memory:", *, tenant_id: str = "ten_local",
                 signer: Signer | None = None, tenant_max_level: int = 3,
                 workdir: str = "."):
        self.tenant_id = validate_public_identifier(
            tenant_id, field="tenant_id")
        if signer is None:
            signer = Signer.generate(f"{tenant_id}:default")
        elif (not callable(getattr(signer, "sign", None))
              or not callable(getattr(signer, "verify", None))):
            raise ValueError(
                "signer must provide callable sign and verify methods")
        # Validate and preserve an explicitly supplied implementation before
        # opening storage.  Pluggable signer objects may intentionally be
        # falsey; truthiness is not an interface or an authorization signal.
        self.signer = signer
        self.store = Store(path)
        try:
            self._initialize_components_and_schema(
                tenant_max_level=tenant_max_level, workdir=workdir)
        except BaseException as initialization_error:
            try:
                self.store.close()
            except Exception as cleanup_error:
                initialization_error.add_note(
                    f"additionally failed to close engine storage: "
                    f"{cleanup_error!r}")
            raise

    def _initialize_components_and_schema(
            self, *, tenant_max_level: int, workdir: str) -> None:
        self.graph = Graph(self.store)
        self.memory = Memory(
            self.store, self.graph, tenant_id=self.tenant_id)
        self.policy = PolicyEngine(
            self.store, tenant_max_level=tenant_max_level,
            graph=self.graph, tenant_id=self.tenant_id)
        self.invalidation = InvalidationEngine(self.store, self.graph,
                                               policy=self.policy,
                                               tenant_id=self.tenant_id)
        self.composer = ResumeComposer(
            self.store, self.graph, self.memory, self.policy,
            tenant_id=self.tenant_id)
        self.capsules = CapsuleManager(self.store, self.graph, self.composer,
                                       policy=self.policy, tenant_id=self.tenant_id,
                                       state_basis_provider=self._packet_state_basis)
        self.partial = PartialProgressManager(
            self.store, self.graph, self.memory, tenant_id=self.tenant_id)
        self.replay = ReplayManager(
            self.store, self.graph, tenant_id=self.tenant_id)
        self.composter = FailureComposter(
            self.store, self.graph, tenant_id=self.tenant_id)
        self.evalgen = EvalGenerator(
            self.store, self.graph, tenant_id=self.tenant_id)
        self.skills = SkillProposer(
            self.store, self.graph, tenant_id=self.tenant_id)
        self.extractor = DeterministicExtractor()
        self.verifier_runner = VerifierRunner(self.store, workdir)
        with self.store._lock:
            conn = self.store._conn
            conn.executescript(_ENGINE_SCHEMA)
            # Cross-process startup must serialize inspection with ALTER;
            # a process-local RLock cannot stop another Engine connection.
            conn.execute("BEGIN IMMEDIATE")
            try:
                # SQLite's CREATE TABLE IF NOT EXISTS does not add columns to
                # an existing installation. These nullable additions preserve
                # old stores; a legacy watermark intentionally reads as stale
                # until a new, authenticated packet is composed.
                watermark_columns = {
                    row["name"] for row in conn.execute(
                        "PRAGMA table_info(packet_watermark)")
                }
                for name in (
                        "packet_digest", "control_basis_digest",
                        "audit_entry_hash"):
                    if name not in watermark_columns:
                        conn.execute(
                            f"ALTER TABLE packet_watermark ADD COLUMN {name} TEXT")
            except BaseException:
                if conn.in_transaction:
                    conn.rollback()
                raise
            else:
                conn.commit()
            # This migration owns an explicit BEGIN IMMEDIATE transaction;
            # run it only after the general schema transaction has closed.
            self._migrate_spent_proofs_scope()
        self._backfill_spent_proofs()

    def _migrate_spent_proofs_scope(self) -> bool:
        """Upgrade the legacy global proof-id key without unspending it.

        A proof identifier is meaningful only inside its tenant and project.
        The old global primary key both denied an unrelated tenant on a
        collision and disclosed the other tenant's task id in the rejection.
        Migration resolves every legacy row through the immutable task
        identity; an orphan is a hard failure because guessing its tenant
        would silently make a previously spent proof reusable.
        """
        with self.store._lock:
            conn = self.store._conn
            if conn.in_transaction:
                raise RuntimeError(
                    "spent_proofs migration requires transaction ownership")
            conn.execute("BEGIN IMMEDIATE")
            try:
                columns = conn.execute(
                    "PRAGMA table_info(spent_proofs)").fetchall()
                expected_pk = {
                    "tenant_id": 1, "project_id": 2, "proof_id": 3,
                    "task_id": 0, "spent_at": 0,
                }
                if ({row["name"]: row["pk"] for row in columns}
                        == expected_pk):
                    conn.commit()
                    return False

                legacy_rows = conn.execute(
                    "SELECT * FROM spent_proofs").fetchall()
                legacy_tables = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                    "AND name = 'spent_proofs_legacy_scope'").fetchone()
                if legacy_tables is not None:
                    raise RuntimeError(
                        "cannot migrate spent_proofs: a prior legacy table remains")

                migrated = []
                column_names = {row["name"] for row in columns}
                for row in legacy_rows:
                    tenant_id = (
                        row["tenant_id"] if "tenant_id" in column_names else None)
                    if tenant_id is None:
                        tenants = conn.execute(
                            "SELECT DISTINCT tenant_id FROM nodes "
                            "WHERE node_id = ? AND project_id = ?",
                            (row["task_id"], row["project_id"])).fetchall()
                        if len(tenants) != 1:
                            raise RuntimeError(
                                "cannot safely scope legacy spent proof "
                                f"{row['proof_id']!r}: its task identity is missing "
                                "or ambiguous")
                        tenant_id = tenants[0]["tenant_id"]
                    migrated.append((
                        tenant_id, row["project_id"], row["proof_id"],
                        row["task_id"], row["spent_at"]))

                conn.execute(
                    "ALTER TABLE spent_proofs "
                    "RENAME TO spent_proofs_legacy_scope")
                conn.execute(
                    "CREATE TABLE spent_proofs ("
                    "tenant_id TEXT NOT NULL, project_id TEXT NOT NULL, "
                    "proof_id TEXT NOT NULL, task_id TEXT NOT NULL, "
                    "spent_at TEXT NOT NULL, "
                    "PRIMARY KEY (tenant_id, project_id, proof_id))")
                conn.executemany(
                    "INSERT INTO spent_proofs "
                    "(tenant_id, project_id, proof_id, task_id, spent_at) "
                    "VALUES (?,?,?,?,?)", migrated)
                conn.execute("DROP TABLE spent_proofs_legacy_scope")
            except BaseException:
                if conn.in_transaction:
                    conn.rollback()
                raise
            else:
                conn.commit()
                return True

    def _backfill_spent_proofs(self) -> int:
        """Seed spent_proofs from completions recorded before it existed.

        ADR-059 moved single-use from a scan of task.completion_evidence to a
        PRIMARY KEY, so two concurrent completions could not both win. On a
        store written before that change the new table is created EMPTY by
        `CREATE TABLE IF NOT EXISTS`, which silently un-spent every proof the
        project had ever used: each one could complete a second task after the
        upgrade. The replacement mechanism has to inherit the old one's
        history, not start from zero (ADR-064).

        The scan is tenant-scoped and idempotent. It cannot stop merely
        because some other tenant already has a spend row.
        """
        # The inherited spend and its audit record are one migration fact.
        # If either write fails, leave both absent so the next startup retries
        # the complete operation instead of silently retaining an unaudited
        # spend row.
        with self.store.transaction():
            rows = self.store._conn.execute(
                "SELECT node_id, version, tenant_id, project_id, data, tx_from "
                "FROM nodes WHERE entity_type = 'task' AND tenant_id = ? "
                "ORDER BY project_id, tx_from, node_id, version",
                (self.tenant_id,)).fetchall()
            seeded = 0
            seen: set[tuple[str, str, str]] = set()
            for row in rows:
                try:
                    proof_id = (strict_json_loads(row["data"]) or {}).get(
                        "completion_evidence")
                except (ValueError, TypeError):
                    continue
                if not isinstance(proof_id, str) or not proof_id:
                    continue
                identity = (row["tenant_id"], row["project_id"], proof_id)
                if identity in seen:
                    continue
                seen.add(identity)
                cur = self.store._conn.execute(
                    "INSERT OR IGNORE INTO spent_proofs (tenant_id, project_id,"
                    " proof_id, task_id, spent_at) VALUES (?,?,?,?,?)",
                    (row["tenant_id"], row["project_id"], proof_id,
                     row["node_id"],
                     row["tx_from"]))
                seeded += cur.rowcount
            if seeded:
                self.store.audit(
                    actor="cce", action="spent_proofs.backfill",
                    authority="verifier_authoritative",
                    detail=f"carried {seeded} pre-existing completion(s) into the"
                           f" single-use table (ADR-064)")
        return seeded

    @serialized_access
    def close(self):
        self.store.close()

    def _require_project(self, project_id: str) -> dict:
        """Return this engine tenant's project or fail without leaking it."""
        validate_public_identifier(project_id, field="project_id")
        try:
            return self.graph.get(
                project_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="project")
        except KeyError:
            raise PermissionError(
                f"project {project_id!r} does not exist in tenant "
                f"{self.tenant_id!r} or belongs to another scope") from None

    @staticmethod
    def _github_numeric_id(value, field: str, *, optional: bool = False):
        if value is None and optional:
            return None
        if (isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 2**63 - 1):
            suffix = " or null" if optional else ""
            raise ValueError(
                f"{field} must be a positive signed 64-bit integer{suffix}")
        return value

    # ---------------------------------------------------------------- project

    @serialized_access
    def create_project(self, name: str, *, repository: str | None = None,
                       repository_id: int | None = None,
                       github_installation_id: int | None = None,
                       capture_mode: str = "redacted", config: dict | None = None,
                       project_id: str | None = None) -> dict:
        name = validate_human_text(name, field="project name")
        repository = validate_repository_name(
            repository, field="repository", optional=True)
        if (not isinstance(capture_mode, str)
                or capture_mode not in CAPTURE_MODES):
            raise ValueError(f"unknown capture mode {capture_mode!r}")
        if repository_id is not None:
            repository_id = self._github_numeric_id(
                repository_id, "repository_id")
        if github_installation_id is not None:
            github_installation_id = self._github_numeric_id(
                github_installation_id, "github_installation_id")
            if repository_id is None:
                raise ValueError(
                    "github_installation_id requires repository_id")
        # Validate before creating the graph identity, then commit identity,
        # policy and audit as one unit. An invalid policy must not leave a
        # live project running under permissive defaults.
        config = self.policy.validate_project_config(
            {} if config is None else config)
        project_id = (
            new_id("project") if project_id is None
            else validate_public_identifier(project_id, field="project_id")
        )
        with self.store.transaction():
            # Project ids are identities, not update handles.  Graph.put_node
            # versions an existing id by design, so creation must reserve the
            # identity while holding the same BEGIN IMMEDIATE transaction as
            # the graph, policy and audit writes.  The database lock makes
            # concurrent creators observe the winner before either can
            # mutate its state.
            if self.store._conn.execute(
                    "SELECT 1 FROM nodes WHERE node_id = ? LIMIT 1",
                    (project_id,)).fetchone() is not None:
                raise ValueError(
                    f"project_id {project_id!r} is already in use")
            node = self.graph.put_node(
                entity_type="project", tenant_id=self.tenant_id,
                project_id=project_id, node_id=project_id, status="active",
                data={"name": name, "repository": repository,
                      "repository_id": repository_id,
                      "github_installation_id": github_installation_id,
                      "capture_mode": capture_mode, "created_at": utcnow()},
            )
            self.policy.set_project_config(project_id, config)
            self.store.audit(
                actor="cce", action="project.create", object_id=project_id,
                detail=name)
        return node

    @serialized_access
    def project_capture_mode(self, project_id: str) -> str:
        return self._require_project(project_id)["data"].get(
            "capture_mode", "redacted")

    # ------------------------------------------------------------------ ingest

    @serialized_access
    def ingest_github(
        self,
        project_id: str,
        event_name: str,
        delivery_id: str,
        payload: dict,
        *,
        raw_body: bytes | None = None,
        signature_header: str | None = None,
        webhook_secret: str | None = None,
    ) -> dict | None:
        """Verify (when a secret is configured), normalize, persist, process.
        Returns the processing report, or None for a benign duplicate."""
        # Validate before project lookup or signature checks: rejection audit
        # rows interpolate this value, so a malformed identifier must not
        # reach either persistence or log text.
        validate_public_identifier(delivery_id, field="delivery_id")
        secret = None
        if webhook_secret is not None:
            secret = validate_webhook_secret(webhook_secret)
            if not isinstance(raw_body, bytes):
                raise ValueError(
                    "raw_body must be the exact signed webhook bytes")
            if not raw_body or len(raw_body) > WEBHOOK_BODY_MAX_BYTES:
                raise ValueError(
                    f"raw_body must contain 1-{WEBHOOK_BODY_MAX_BYTES} bytes")
            if not isinstance(signature_header, str):
                raise ValueError("signature_header must be a string")
        try:
            project = self._require_project(project_id)
        except PermissionError:
            self.store.audit(
                actor="connector", action="webhook.rejected",
                object_id=project_id,
                detail=f"unknown project for delivery {delivery_id}")
            raise GitHubDeliveryError(
                f"GitHub delivery targets unknown project {project_id}") from None
        if secret is not None:
            if not verify_signature(secret, raw_body, signature_header):
                self.store.audit(actor="connector", action="webhook.rejected",
                                 detail=f"bad signature for {delivery_id}")
                raise GitHubDeliveryError("webhook signature verification failed")
            try:
                signed_payload = strict_json_loads(raw_body)
                supplied_payload = strict_json_loads(canonical_json(payload))
                if not isinstance(signed_payload, dict):
                    raise ValueError("signed webhook body must be a JSON object")
                if canonical_json(signed_payload) != canonical_json(supplied_payload):
                    raise ValueError(
                        "payload does not match the signed webhook body")
            except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                self.store.audit(
                    actor="connector", action="webhook.rejected",
                    object_id=project_id,
                    detail=f"invalid signed body for delivery {delivery_id}")
                raise WebhookPayloadError(str(exc)) from None
            payload = signed_payload
        envelope = normalize(event_name, delivery_id, payload)
        configured_id = project["data"].get("repository_id")
        delivered_id = envelope.get("repository_id")
        if (isinstance(configured_id, bool)
                or not isinstance(configured_id, int)
                or configured_id <= 0):
            self.store.audit(
                actor="connector", action="webhook.rejected",
                object_id=project_id,
                detail=(f"unbound immutable repository id for delivery "
                        f"{delivery_id}"))
            raise GitHubDeliveryError(
                "GitHub ingestion is disabled until the project is bound to "
                "a positive numeric repository_id")
        if event_name == "installation":
            configured_installation = project["data"].get(
                "github_installation_id")
            if (isinstance(configured_installation, bool)
                    or not isinstance(configured_installation, int)
                    or configured_installation <= 0):
                raise GitHubDeliveryError(
                    "installation events require a project-bound positive "
                    "github_installation_id")
        elif event_name == "installation_repositories":
            delivered_ids = envelope.get("repository_ids", [])
            if configured_id not in delivered_ids:
                raise GitHubDeliveryError(
                    "installation_repositories delivery does not include the "
                    "project repository_id")
            envelope["repository_id"] = configured_id
        elif (isinstance(delivered_id, bool)
              or not isinstance(delivered_id, int)
              or delivered_id <= 0
              or delivered_id != configured_id):
            self.store.audit(
                actor="connector", action="webhook.rejected",
                object_id=project_id,
                detail=(f"repository id mismatch for {delivery_id}: expected "
                        f"{configured_id!r}, received {delivered_id!r}"))
            raise GitHubDeliveryError(
                "GitHub delivery repository_id does not match the project")
        configured_installation = project["data"].get(
            "github_installation_id")
        delivered_installation = envelope.get("installation_id")
        if configured_installation is not None and (
                isinstance(configured_installation, bool)
                or not isinstance(configured_installation, int)
                or configured_installation <= 0
                or isinstance(delivered_installation, bool)
                or not isinstance(delivered_installation, int)
                or delivered_installation != configured_installation):
            self.store.audit(
                actor="connector", action="webhook.rejected",
                object_id=project_id,
                detail=(f"installation id mismatch for {delivery_id}: expected "
                        f"{configured_installation!r}, received "
                        f"{delivered_installation!r}"))
            raise GitHubDeliveryError(
                "GitHub delivery installation_id does not match the project")
        return self._ingest(project_id, envelope)

    @serialized_access
    def ingest_agent_trace(self, project_id: str, *, session_id: str | None,
                           span_id: str, payload: dict,
                           observed_at: str | None = None) -> dict | None:
        validate_public_identifier(project_id, field="project_id")
        span_id = validate_public_identifier(span_id, field="span_id")
        if not isinstance(payload, dict):
            raise ValueError("trace payload must be a JSON object")
        try:
            payload = strict_json_loads(canonical_json(payload))
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"trace payload must be finite canonical JSON: {exc}") from None
        message = payload.get("message")
        if message is not None and not isinstance(message, str):
            raise ValueError("trace payload message must be a string or null")
        if isinstance(message, str) and len(message) > 65_536:
            raise ValueError(
                "trace payload message must be at most 65536 characters")
        if observed_at is not None and (
                not isinstance(observed_at, str)
                or not is_rfc3339_datetime(observed_at)):
            raise ValueError("trace observed_at must be an RFC 3339 timestamp or null")
        self._require_project(project_id)
        if session_id is not None:
            session_id = validate_public_identifier(
                session_id, field="session_id")
            try:
                self.graph.get(
                    session_id, tenant_id=self.tenant_id,
                    project_id=project_id, entity_type="session")
            except KeyError:
                raise ValueError(
                    "session_id is not a session in the requested project"
                ) from None
        envelope = {
            "source_type": "agent_trace",
            "source_id": span_id,
            "idempotency_key": f"trace:{span_id}",
            "authority": "agent_observed",
            "observed_at": observed_at,
            "payload": payload | (
                {"session_id": session_id} if session_id is not None else {}),
            "text_blocks": [
                {"text": payload.get("message", ""), "authority": "agent_inference",
                 "ref": f"trace:{span_id}"}
            ] if payload.get("message") else [],
            "flags": {},
        }
        return self._ingest(project_id, envelope)

    @serialized_access
    def ingest_human_decision(self, project_id: str, *, actor: str, decision: str,
                              scope: dict | None = None,
                              request_id: str | None = None) -> dict | None:
        validate_public_identifier(project_id, field="project_id")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("human decision actor must be a non-empty string")
        actor = validate_human_text(actor, field="human decision actor")
        if not isinstance(decision, str) or not decision.strip():
            raise ValueError("human decision must be a non-empty string")
        decision = validate_human_text(
            decision, field="human decision", max_length=4096)
        if scope is not None and not isinstance(scope, dict):
            raise ValueError("human decision scope must be an object or null")
        try:
            scope = (
                None if scope is None
                else strict_json_loads(canonical_json(scope)))
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"human decision scope must be finite canonical JSON: {exc}"
            ) from None
        request_id = (
            new_id("event") if request_id is None
            else validate_public_identifier(request_id, field="request_id")
        )
        self._require_project(project_id)
        envelope = {
            "source_type": "human_decision",
            "source_id": actor,
            "idempotency_key": f"cce:{request_id}",
            "authority": "human_decision",
            "observed_at": None,
            "payload": {"decision": decision, "actor": actor, "scope": scope},
            "text_blocks": [{"text": decision, "authority": "human_decision",
                             "ref": f"decision:{request_id}"}],
            "flags": {},
        }
        return self._ingest(project_id, envelope)

    def _ingest(self, project_id: str, envelope: dict) -> dict | None:
        try:
            project = self.graph.get(
                project_id, tenant_id=self.tenant_id, project_id=project_id)
        except KeyError:
            self.store.audit(
                actor="connector", action="ingest.rejected",
                object_id=project_id, detail="unknown project")
            raise PermissionError(
                f"ingestion targets unknown project {project_id}") from None
        if project.get("entity_type") != "project":
            raise PermissionError(f"{project_id} is not a project")
        mode = self.project_capture_mode(project_id)
        raw = envelope.get("payload")
        if raw is not None and not isinstance(raw, dict):
            raise ValueError("ingestion payload must be a JSON object or null")
        raw_canonical = canonical_json(raw) if raw is not None else ""
        payload, capture_report = apply_capture_mode(raw, mode)
        # Idempotency compares the digest of what the SOURCE sent, not of what
        # survived redaction. Under metadata_only two genuinely different
        # bodies reduce to the same stored form, so digesting the redacted
        # payload would silently accept a changed redelivery as a duplicate
        # instead of flagging it (CCG-001).
        raw_digest = sha256_hex(raw_canonical)
        try:
            event = self.store.append_event(
                tenant_id=self.tenant_id,
                project_id=project_id,
                source_type=envelope["source_type"],
                source_id=envelope.get("source_id"),
                idempotency_key=envelope["idempotency_key"],
                payload=payload,
                payload_digest=raw_digest,
                authority=envelope.get("authority", "untrusted_content"),
                observed_at=envelope.get("observed_at"),
                capture_mode=mode,
                sensitivity="internal",
            )
        except DuplicateEventError:
            return None
        try:
            # Process the STORED event, not the incoming envelope: extraction
            # must see exactly what durably persisted. Handing it the raw
            # envelope would write unredacted text into graph nodes (defeating
            # the capture mode) and make replay diverge from live processing.
            # This is the same path rebuild_projection takes (CCG-006).
            # The event log is canonical and intentionally commits first.
            # Its rebuildable projection is one atomic unit: a processor
            # failure may quarantine the event, but must not leave half of
            # its nodes, edges, invalidations, or audits visible.
            with self.store.transaction():
                report = self.process_event(event)
                # The success marker is part of the projection commit. If it
                # cannot be written, every node/edge/audit mutation rolls
                # back and the outer failure path records quarantine alone.
                self.store.mark_processed(
                    event["event_id"], PROCESSOR_VERSION, "ok")
        except Exception as exc:  # quarantine and preserve replayability (ADR-036)
            self.store.mark_processed(event["event_id"], PROCESSOR_VERSION,
                                      "quarantined", repr(exc))
            raise
        report["capture"] = capture_report
        return report

    # ----------------------------------------------------------------- process

    @serialized_access
    def process_event(self, event: dict, envelope: dict | None = None) -> dict:
        """Process one stored event through the canonical projection path."""
        # Public direct callers get the same all-or-nothing projection
        # guarantee as ingest(). When ingest already owns a transaction this
        # becomes a nested savepoint, so both entry paths remain atomic.
        with self.store.transaction():
            return self._process_event(event, envelope)

    def _process_event(self, event: dict, envelope: dict | None = None) -> dict:
        """Project one canonical stored event inside an owned transaction."""
        if not isinstance(event, dict):
            raise TypeError("processed event must be a canonical stored event object")
        supplied_event = event
        event_id = event.get("event_id")
        project_id = event.get("project_id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("processed event must name a non-empty event_id")
        if event.get("tenant_id") != self.tenant_id:
            raise PermissionError("processed event is outside this Engine tenant")
        if not isinstance(project_id, str) or not project_id:
            raise ValueError("processed event must name a non-empty project_id")
        self._require_project(project_id)
        try:
            event = self.store.get_event(
                event_id, tenant_id=self.tenant_id, project_id=project_id)
        except (KeyError, TypeError):
            raise PermissionError(
                "processed event must resolve in this Engine tenant/project") from None
        if set(supplied_event) != set(event):
            raise ValueError(
                "processed event fields differ from the canonical stored event")
        try:
            supplied_semantics = canonical_json(supplied_event)
            stored_semantics = canonical_json(event)
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise ValueError("processed event is not canonical JSON") from None
        if supplied_semantics != stored_semantics:
            raise ValueError(
                "processed event differs from the canonical stored event")
        canonical_envelope = self._re_envelope(event)
        if envelope is not None:
            try:
                supplied = canonical_json(envelope)
                expected = canonical_json(canonical_envelope)
            except (TypeError, ValueError, OverflowError, RecursionError):
                raise ValueError("supplied processing envelope is not canonical JSON") from None
            if supplied != expected:
                raise ValueError(
                    "supplied processing envelope differs from the stored event")
        envelope = canonical_envelope
        report = {"event_id": event_id, "created": [], "invalidations": [],
                  "conflicts": [], "verifications": [], "commands": []}

        # Events are first-class causal endpoints. Besides making provenance
        # traversable, this prevents event-to-node support edges from being
        # dangling references.
        self.graph.put_node(
            entity_type="event", tenant_id=event["tenant_id"],
            project_id=event["project_id"], node_id=event_id,
            status="recorded", authority=event["authority"],
            data={
                "source_type": event["source_type"],
                "source_id": event.get("source_id"),
                "idempotency_key": event["idempotency_key"],
                "payload_digest": event["payload_digest"],
                "stored_payload_digest": event["stored_payload_digest"],
                "observed_at": event["observed_at"],
            },
            valid_from=event.get("valid_from"),
            valid_to=event.get("valid_to"),
            event_id=event_id,
        )

        flags = envelope.get("flags", {})
        source_type = envelope.get("source_type", event["source_type"])

        # Verifier-authoritative events become verification nodes (EV-003).
        if source_type in ("github:check_run", "github:workflow_run",
                           "github:check_suite"):
            self._process_check(event, flags, report)

        # Push events: dependency/critical-path drift (CI-001, GHI-008).
        if source_type == "github:push":
            self._process_push(event, envelope, report)

        # /cce commands (GHI-005).
        if flags.get("command"):
            self._process_command(event, envelope, report)

        # Text extraction (AD-001..AD-008).
        for block in envelope.get("text_blocks", []):
            self._process_text(event, block, report)

        return report

    def _re_envelope(self, event: dict) -> dict:
        """Rebuild the normalization envelope from a stored event (replay)."""
        source_type = event["source_type"]
        payload = event["payload"] or {}
        if source_type.startswith("github:"):
            name = source_type.split(":", 1)[1]
            try:
                return normalize(name, event["idempotency_key"].split(":", 1)[1],
                                 payload)
            except Exception:
                return {"source_type": source_type, "text_blocks": [], "flags": {}}
        if source_type == "human_decision":
            return {
                "source_type": source_type, "flags": {},
                "text_blocks": [{"text": payload.get("decision", ""),
                                 "authority": "human_decision",
                                 "ref": f"decision:{event['event_id']}"}],
            }
        if source_type == "agent_trace":
            return {
                "source_type": source_type, "flags": {},
                "text_blocks": [{"text": payload.get("message", ""),
                                 "authority": "agent_inference",
                                 "ref": f"trace:{event['source_id']}"}]
                if payload.get("message") else [],
            }
        return {"source_type": source_type, "text_blocks": [], "flags": {}}

    # ------------------------------------------------------- text processing

    def _process_text(self, event: dict, block: dict, report: dict):
        project_id = event["project_id"]
        event_id = event["event_id"]
        text = block.get("text") or ""
        authority = block.get("authority", "untrusted_content")
        ref = block.get("ref", "")
        # A project may declare that prose never mandates; the extractor then
        # records requirements and constraints as claims, exactly as it
        # already does for an untrusted source.
        result = self.extractor.extract(
            text, source_authority=authority, scope={"source_ref": ref},
            prose_may_mandate=bool(
                self.policy.project_config(project_id).get(
                    "prose_may_mandate", True)))
        # Identical statements from different sources converge on one node
        # (AD-004), so a node tracks EVERY source that states it. An edit to
        # one source may only retract that source's claim on the node.
        prior_from_ref = {
            n["node_id"]: n
            for kind in ("requirement", "constraint")
            for n in self.graph.current(
                project_id, kind, tenant_id=self.tenant_id)
            if (ref in _source_refs(n)
                and n["status"] not in ("superseded", "invalidated"))
        }
        seen_ids: set[str] = set()

        for item in result.items:
            if item.suspected_injection:
                node = self.graph.put_node(
                    entity_type="claim", tenant_id=self.tenant_id,
                    project_id=project_id, status="quarantined",
                    criticality="high", authority="untrusted_content",
                    confidence=item.confidence,
                    data={"statement": item.statement, "span": item.span,
                          "source_ref": ref, "suspected_injection": True},
                    event_id=event_id,
                    extractor=result.extractor,
                    extractor_version=result.extractor_version,
                )
                report["created"].append({"node_id": node.id, "kind": "claim",
                                          "quarantined": True})
                self.store.audit(actor="extractor", action="injection.quarantined",
                                 object_id=node.id, detail=item.statement[:200])
                continue

            kind = item.kind
            node_id = stable_node_id(project_id, kind, item.statement)
            seen_ids.add(node_id)
            existing = None
            try:
                existing = self.graph.get(
                    node_id, tenant_id=self.tenant_id,
                    project_id=project_id)
            except KeyError:
                pass
            entity_type = kind if kind in ("assumption", "requirement", "constraint",
                                           "decision", "claim", "task") else "claim"
            status = self._initial_status(entity_type, item, existing)
            # A re-delivery that asserts nothing new is a no-op. Re-writing an
            # unchanged node would re-stamp its transaction time, inflate its
            # version, and re-enter it into conflict ranking, so an idempotent
            # webhook retry could change project state (CCG-001).
            if existing is not None and _restates(existing, item, ref, authority):
                continue
            if existing is not None and authority_rank(authority) < authority_rank(
                    existing.get("authority") or "untrusted_content"):
                # A weaker source cannot downgrade or overwrite; record occurrence.
                self.graph.put_edge(
                    edge_type="supports", src_id=event_id, dst_id=node_id,
                    tenant_id=self.tenant_id, project_id=project_id,
                    strength=0.3, event_id=event_id)
                continue
            node = self.graph.put_node(
                entity_type=entity_type, tenant_id=self.tenant_id,
                project_id=project_id, node_id=node_id, status=status,
                criticality=item.criticality, authority=authority,
                confidence=item.confidence,
                scope=item.scope,
                data={"statement": item.statement, "span": item.span,
                      "source_ref": ref, "stable_key": node_id,
                      "source_refs": sorted(_source_refs(existing) | {ref}),
                      **item.meta},
                event_id=event_id,
                extractor=result.extractor,
                extractor_version=result.extractor_version,
            )
            report["created"].append({"node_id": node.id, "kind": entity_type,
                                      "status": status, "new": existing is None})
            self._detect_near_duplicate_conflict(node, report, event_id)

        # Changed requirement detection (CI-001): a requirement this source
        # used to state and no longer does was edited away. It is invalidated
        # only when NO other source still states it — otherwise the edit just
        # drops this source's claim and the requirement stands on the others.
        for old_id, old in prior_from_ref.items():
            if old_id in seen_ids:
                continue
            remaining = _source_refs(old) - {ref}
            self.graph.put_node(
                entity_type=old["entity_type"], tenant_id=self.tenant_id,
                project_id=project_id, node_id=old_id,
                data={"source_refs": sorted(remaining)}, event_id=event_id,
            )
            if remaining:
                report["conflicts"].append({
                    "a": old_id, "b": None, "winner": old_id,
                    "explanation": f"{ref} no longer states this requirement, but"
                                   f" {sorted(remaining)} still do; not invalidated",
                })
                continue
            inv = self.invalidation.fire(
                tenant_id=self.tenant_id, project_id=project_id,
                target_node_id=old_id, trigger_type="changed_requirement",
                trigger_confidence=0.9,
                reason=f"source {ref} was edited and no longer states this"
                       f" requirement; no other source states it",
                event_id=event_id,
            )
            report["invalidations"].append(inv["node_id"])

    @staticmethod
    def _initial_status(entity_type: str, item, existing) -> str | None:
        if existing is not None:
            return existing["status"]
        if entity_type == "assumption":
            return "proposed" if item.confidence < 0.6 else "active"
        if entity_type in ("requirement", "constraint"):
            return "active"
        if entity_type == "decision":
            return "accepted"
        if entity_type == "task":
            return "done" if item.meta.get("done") else "open"
        return "recorded"

    def _detect_near_duplicate_conflict(self, node, report: dict, event_id: str):
        """Two near-identical statements with a small token difference are a
        potential contradiction (stale doc vs newer decision). Resolve by
        authority + freshness (CCG-005); always preserve and expose the conflict.

        A node that has already lost a conflict takes no further part in one.
        Re-ingesting an unchanged delivery re-stamps every extracted node's
        transaction time, so without this guard the freshness tie-break would
        hand the win back to the superseded loser and retire the survivor —
        a no-op redelivery would silently empty the active requirement set.
        """
        if node["entity_type"] not in ("claim", "decision", "requirement"):
            return
        if node.get("status") in ("superseded", "invalidated", "quarantined"):
            return
        project_id = node["project_id"]
        my_tokens = set(normalize_statement(node["data"]["statement"]).split())
        if len(my_tokens) < 3:
            return
        for other in self.graph.current(
                project_id, tenant_id=self.tenant_id):
            if other["node_id"] == node["node_id"]:
                continue
            if other["entity_type"] not in ("claim", "decision", "requirement"):
                continue
            if other["status"] in ("superseded", "invalidated", "quarantined"):
                continue
            other_tokens = set(
                normalize_statement(other["data"].get("statement") or "").split())
            if not other_tokens or other_tokens == my_tokens:
                continue
            sym_diff = my_tokens ^ other_tokens
            if 0 < len(sym_diff) <= max(2, len(my_tokens) // 4) and \
                    len(my_tokens & other_tokens) >= 2:
                winner, loser, explanation = self._rank_conflict(node, other)
                # A loser that another live source still states is a genuine
                # open disagreement, not a supersession: one issue being
                # edited does not repeal what a different issue still says.
                # Preserve it for human resolution (CCG-005/ADR-017) instead of picking
                # a winner silently (ADR-008).
                contested = bool(
                    loser is not None
                    and _source_refs(loser) - _source_refs(node)
                    and authority_rank(loser.get("authority") or "")
                    == authority_rank(winner.get("authority") or ""))
                if contested:
                    explanation += ("; both statements are still asserted by"
                                    " different sources — human resolution required")
                self.graph.put_edge(
                    edge_type="contradicts", src_id=node["node_id"],
                    dst_id=other["node_id"], tenant_id=self.tenant_id,
                    project_id=project_id, event_id=event_id,
                    data={"explanation": explanation, "contested": contested})
                if loser is not None:
                    self.graph.put_node(
                        entity_type=loser["entity_type"], tenant_id=self.tenant_id,
                        project_id=project_id, node_id=loser["node_id"],
                        data={"conflict_requires_resolution": True} if contested
                        else {},
                        status="uncertain" if (
                            contested or loser["entity_type"] == "assumption")
                        else "superseded",
                        event_id=event_id)
                    if not contested:
                        self.graph.put_edge(
                            edge_type="supersedes", src_id=winner["node_id"],
                            dst_id=loser["node_id"], tenant_id=self.tenant_id,
                            project_id=project_id, event_id=event_id)
                report["conflicts"].append({
                    "a": node["node_id"], "b": other["node_id"],
                    "winner": None if contested else (
                        winner["node_id"] if winner else None),
                    "requires_resolution": contested,
                    "explanation": explanation,
                })

    @staticmethod
    def _rank_conflict(a: dict, b: dict):
        """CCG-005 conflict ranking: authority, then transaction
        freshness, then confidence. Unresolvable -> both preserved."""
        ra, rb = authority_rank(a.get("authority") or ""), authority_rank(
            b.get("authority") or "")
        if ra != rb:
            winner, loser = (a, b) if ra > rb else (b, a)
            return winner, loser, (
                f"authority {winner.get('authority')} outranks"
                f" {loser.get('authority')}")
        if a["tx_from"] != b["tx_from"]:
            winner, loser = (a, b) if a["tx_from"] > b["tx_from"] else (b, a)
            return winner, loser, "same authority; newer statement wins"
        ca, cb = a.get("confidence") or 0, b.get("confidence") or 0
        if ca != cb:
            winner, loser = (a, b) if ca > cb else (b, a)
            return winner, loser, "higher extraction confidence wins"
        return None, None, "unresolved conflict: equal authority, time, confidence"

    # ------------------------------------------------------- checks & pushes

    def _process_check(self, event: dict, flags: dict, report: dict):
        project_id = event["project_id"]
        name = flags.get("name") or event["source_type"]
        conclusion = flags.get("conclusion")
        head_sha = flags.get("head_sha")
        app = flags.get("app")
        trusted = self.policy.external_verifier_trusted(
            project_id, event["source_type"], flags)
        if flags.get("status") != "completed" and conclusion is None:
            return
        result = {"success": "passed", "failure": "failed", "neutral": "skipped",
                  "cancelled": "inconclusive", "timed_out": "inconclusive",
                  "skipped": "skipped", "action_required": "failed",
                  "stale": "stale"}.get(conclusion, "inconclusive")
        node = self.graph.put_node(
            entity_type="verification", tenant_id=self.tenant_id,
            project_id=project_id, status=result,
            authority=(
                "verifier_authoritative" if trusted
                else "repository_authoritative"),
            data={"verifier": name, "source": event["source_type"],
                  "conclusion": conclusion, "head_sha": head_sha,
                  "source_id": event["source_id"], "app": app,
                  "app_id": flags.get("app_id"),
                  "installation_id": flags.get("installation_id"),
                  "workflow_id": flags.get("workflow_id"),
                  "workflow_path": flags.get("workflow_path"),
                  "trusted_app": trusted,
                  "trusted_producer_at_ingest": trusted},
            event_id=event["event_id"],
        )
        report["verifications"].append(node.id)
        if result == "failed" and trusted:
            # Failed check invalidates prior passing verification of the same
            # verifier and anything that relied on it (CI-001 failed_check).
            for prior in self.graph.current(
                    project_id, "verification", status=["passed"],
                    tenant_id=self.tenant_id):
                prior_source = prior["data"].get("source") or ""
                if (prior.get("authority") != "verifier_authoritative"
                        or not prior_source.startswith("github:")):
                    continue
                if prior["data"].get("verifier") == name and \
                        prior["node_id"] != node.id:
                    inv = self.invalidation.fire(
                        tenant_id=self.tenant_id, project_id=project_id,
                        target_node_id=prior["node_id"],
                        trigger_type="failed_check",
                        trigger_confidence=0.95,
                        reason=f"check {name!r} now fails at {head_sha}",
                        event_id=event["event_id"],
                    )
                    report["invalidations"].append(inv["node_id"])

    _MANIFESTS = re.compile(
        r"(^|/)(requirements[^/]*\.txt|pyproject\.toml|package(-lock)?\.json|"
        r"poetry\.lock|Pipfile(\.lock)?|go\.(mod|sum)|Cargo\.(toml|lock)|"
        r"Gemfile(\.lock)?|pom\.xml|build\.gradle[^/]*)$")

    def _process_push(self, event: dict, envelope: dict, report: dict):
        project_id = event["project_id"]
        payload = event["payload"] or {}
        flags = envelope.get("flags", {})
        after = flags.get("after")
        before = flags.get("before")
        ref = flags.get("ref")
        project = self.graph.get(
            project_id, tenant_id=self.tenant_id,
            project_id=project_id, entity_type="project")
        tracked_basis = self.policy.tracked_ref_basis(project_id)
        tracked_ref = tracked_basis["tracked_ref"]
        is_tracked = bool(ref and ref == tracked_ref)
        frontier_matches_policy = (
            project["data"].get("tracked_ref") == tracked_ref
            and project["data"].get("tracked_ref_revision")
            == tracked_basis["revision"]
        )
        current_head = project["data"].get("current_head_sha") \
            if frontier_matches_policy else None
        out_of_order = bool(
            is_tracked and current_head and before != current_head
            and after != current_head and not flags.get("forced"))
        tracked_push = is_tracked and not out_of_order

        if ref and not is_tracked:
            self.store.audit(
                actor="connector", action="push.untracked_ref",
                object_id=ref,
                detail=f"tracked ref is {tracked_ref}; revision frontier unchanged")
        elif out_of_order:
            self.graph.put_node(
                entity_type="project", tenant_id=self.tenant_id,
                project_id=project_id, node_id=project_id,
                status=project.get("status"),
                data={
                    "revision_frontier_uncertain": True,
                    "rejected_head_sha": after,
                    "rejected_before_sha": before,
                },
                event_id=event["event_id"],
            )
            self.store.audit(
                actor="connector", action="push.out_of_order",
                object_id=ref,
                detail=(
                    f"current {current_head}; delivery claimed "
                    f"{before} -> {after}; frontier left unchanged"))
        elif is_tracked and after:
            deleted = bool(flags.get("deleted"))
            effective_head = None if deleted else after
            self.graph.put_node(
                entity_type="project", tenant_id=self.tenant_id,
                project_id=project_id, node_id=project_id,
                status=project.get("status"),
                data={
                    "current_head_sha": effective_head,
                    "tracked_ref": tracked_ref,
                    "tracked_ref_revision": tracked_basis["revision"],
                    "previous_head_sha": before,
                    "revision_frontier_uncertain": deleted,
                },
                event_id=event["event_id"],
            )
            # A passing external result describes exactly one revision.
            # Moving the tracked ref stales every result for another SHA even
            # when GitHub sends an empty commit list.
            for prior in self.graph.current(
                    project_id, "verification", status=["passed"],
                    tenant_id=self.tenant_id):
                source = prior["data"].get("source") or ""
                if (source.startswith("github:")
                        and prior["data"].get("head_sha") != effective_head):
                    self.graph.put_node(
                        entity_type="verification",
                        tenant_id=self.tenant_id, project_id=project_id,
                        node_id=prior["node_id"], status="stale",
                        data={
                            "stale_because": {
                                "recorded_head": prior["data"].get("head_sha"),
                                "current_head": effective_head,
                            },
                        },
                        event_id=event["event_id"],
                    )
        changed: set[str] = set()
        for commit in payload.get("commits", []) or []:
            for key in ("added", "modified", "removed"):
                changed.update(commit.get(key, []) or [])
        if flags.get("forced"):
            self.store.audit(actor="connector", action="push.forced",
                             object_id=flags.get("ref"),
                             detail=f"{flags.get('before')} -> {flags.get('after')}")
        manifest_changed = sorted(
            p for p in changed
            if tracked_push and self._MANIFESTS.search(p))
        if manifest_changed:
            # Tokens the push is "about": changed-path stems + commit messages.
            push_terms: set[str] = set()
            for p in changed:
                stem = p.split("/")[-1].rsplit(".", 1)[0]
                push_terms.update(t for t in re.split(r"[_\-.]", stem.lower())
                                  if len(t) > 3)
            for commit in payload.get("commits", []) or []:
                push_terms.update(
                    t for t in re.findall(r"[a-z]{4,}", (commit.get("message")
                                                         or "").lower()))
            push_terms -= {"bump", "update", "upgrade", "chore", "merge"}
            for node in self.graph.current(
                    project_id, "assumption", status=["active", "supported"],
                    tenant_id=self.tenant_id):
                scope_paths = (node.get("scope") or {}).get("paths", [])
                statement = (node["data"].get("statement") or "").lower()
                statement_terms = set(re.findall(r"[a-z]{4,}", statement))
                mentions_dep = any(
                    tok in statement for tok in
                    ("dependency", "version", "pinned", "requires", "library",
                     "package")) or bool(statement_terms & push_terms)
                if mentions_dep or self._scope_hit(scope_paths, manifest_changed):
                    inv = self.invalidation.fire(
                        tenant_id=self.tenant_id, project_id=project_id,
                        target_node_id=node["node_id"],
                        trigger_type="dependency_drift",
                        trigger_confidence=0.8,
                        reason=f"dependency manifest changed: {manifest_changed}",
                        event_id=event["event_id"],
                    )
                    report["invalidations"].append(inv["node_id"])
        # Critical-path changes make prior passing verifications stale (EV-005).
        if changed and tracked_push:
            for prior in self.graph.current(
                    project_id, "verification", status=["passed"],
                    tenant_id=self.tenant_id):
                subject_paths = (prior.get("scope") or {}).get("paths", [])
                if self._scope_hit(subject_paths, changed):
                    self.graph.put_node(
                        entity_type="verification", tenant_id=self.tenant_id,
                        project_id=project_id, node_id=prior["node_id"],
                        data={"stale_because": sorted(changed)[:10]},
                        status="stale", event_id=event["event_id"])

    @staticmethod
    def _scope_hit(scope_paths: list[str], changed) -> bool:
        for sp in scope_paths or []:
            prefix = sp.rstrip("*").rstrip("/")
            for c in changed:
                if c == sp or (prefix and c.startswith(prefix)):
                    return True
        return False

    # ---------------------------------------------------------------- commands

    def _process_command(self, event: dict, envelope: dict, report: dict):
        flags = envelope.get("flags", {})
        command = (flags.get("command") or "").strip()
        association = flags.get("author_association") or "NONE"
        authorized = association in _AUTHORIZED_ASSOCIATIONS
        self.store.audit(actor=f"github:{association}", action="command.received",
                         object_id=event["event_id"], detail=command,
                         authority="human_intent")
        if not authorized:
            report["commands"].append({"command": command, "status": "rejected",
                                       "reason": f"association {association}"})
            return
        report["commands"].append({"command": command, "status": "accepted"})

    # ------------------------------------------------------------------ resume

    @serialized_access
    def resume_packet(self, project_id: str, *, target: dict | None = None,
                      token_budget: int = 4000, fmt: str = "json"):
        if fmt not in ("json", "markdown"):
            raise ValueError("resume format must be 'json' or 'markdown'")
        # Compose and commit its exact state basis under one snapshot.  The
        # before-basis is deliberately persisted: if an internal callback
        # mutates state while composing, the returned packet fails closed as
        # stale instead of being blessed at a later event sequence.
        with self.store.transaction():
            self._require_project(project_id)
            state_basis = self._packet_state_basis(project_id)
            event_seq = state_basis["event_seq"]
            control_basis_digest = state_basis["control_basis_digest"]
            packet = self.composer.compose(
                tenant_id=self.tenant_id, project_id=project_id, target=target,
                token_budget=token_budget, signer=self.signer,
                state_basis=state_basis)
            self._record_watermark(
                project_id, packet, last_event_seq=event_seq,
                control_basis_digest=control_basis_digest)
        if fmt == "markdown":
            return ResumeComposer.render_markdown(packet)
        return packet

    def _packet_state_basis(self, project_id: str) -> dict:
        """The compact commitment embedded in packets and capsules."""
        self._require_project(project_id)
        control_basis = self._packet_control_basis(project_id)
        return {
            "event_seq": self._latest_event_seq(project_id),
            "control_basis_digest": digest_obj(control_basis),
            "artifact_inputs": control_basis["artifact_inputs"],
        }

    def _latest_event_seq(self, project_id: str) -> int:
        row = self.store._conn.execute(
            "SELECT MAX(seq) AS s FROM events WHERE tenant_id = ? "
            "AND project_id = ?",
            (self.tenant_id, project_id)).fetchone()
        return row["s"] or 0

    def _packet_control_basis(self, project_id: str) -> dict:
        """State that can change a resume packet without appending an event.

        This is intentionally broader than the replay fingerprint: packets
        include runtime tasks, invalidations, policy/grant state, verifier
        results, and memory-tier selection.  Any semantic mutation makes the
        prior packet stale; transaction clocks and audit chatter do not.
        """
        self._require_project(project_id)
        node_fields = (
            "node_id", "version", "entity_type", "tenant_id", "project_id",
            "status", "criticality", "authority", "confidence", "scope", "data",
            "valid_from", "valid_to", "event_id", "extractor",
            "extractor_version",
        )
        edge_fields = (
            "edge_id", "version", "edge_type", "src_id", "dst_id", "tenant_id",
            "project_id", "strength", "data", "valid_from", "valid_to",
            "event_id",
        )
        nodes = [
            {key: node.get(key) for key in node_fields}
            for node in self.graph.current(
                project_id, tenant_id=self.tenant_id)
        ]
        edges = [
            {key: edge.get(key) for key in edge_fields}
            for edge in self.graph.current_edges(
                project_id, tenant_id=self.tenant_id)
        ]
        nodes.sort(key=canonical_json)
        edges.sort(key=canonical_json)

        grants = [dict(row) for row in self.store._conn.execute(
            "SELECT * FROM autonomy_grants WHERE project_id = ? "
            "ORDER BY grant_id", (project_id,))]
        active_grant_ids = sorted(
            grant["grant_id"] for grant in self.policy.active_grants(project_id))
        downgrades = [dict(row) for row in self.store._conn.execute(
            "SELECT * FROM autonomy_downgrades WHERE project_id = ? "
            "ORDER BY seq", (project_id,))]
        assignments = [dict(row) for row in self.store._conn.execute(
            "SELECT assignment.project_id, assignment.node_id, "
            "assignment.tier, assignment.op, assignment.actor, "
            "assignment.reason FROM memory_assignments AS assignment "
            "JOIN nodes AS node ON node.node_id = assignment.node_id "
            "AND node.tx_to IS NULL AND node.tenant_id = ? "
            "AND node.project_id = assignment.project_id "
            "WHERE assignment.project_id = ? ORDER BY assignment.seq",
            (self.tenant_id, project_id))]
        return {
            "schema_version": "cce.packet-control-basis.v1",
            "tenant_id": self.tenant_id,
            "project_id": project_id,
            "event_seq": self._latest_event_seq(project_id),
            "nodes": nodes,
            "edges": edges,
            "policy": self.policy.project_config(project_id),
            "grants": grants,
            "active_grant_ids": active_grant_ids,
            "downgrades": downgrades,
            "memory_assignments": assignments,
            # File bytes are external to SQLite but are still control inputs:
            # a packet that calls a verifier current must stale when the
            # verifier's declared deliverable changes under the same graph.
            "artifact_inputs": self._artifact_digests(project_id),
        }

    def _record_watermark(
            self, project_id: str, packet: dict, *, last_event_seq: int,
            control_basis_digest: str):
        commitment = {
            "project_id": project_id,
            "packet_id": packet.get("packet_id"),
            "packet_digest": packet.get("packet_digest"),
            "last_event_seq": last_event_seq,
            "control_basis_digest": control_basis_digest,
        }
        with self.store.transaction():
            self.store._conn.execute(
                "INSERT OR REPLACE INTO packet_watermark "
                "(project_id, last_event_seq, composed_at, packet_id, "
                "packet_digest, control_basis_digest, audit_entry_hash) "
                "VALUES (?,?,?,?,?,?,NULL)",
                (project_id, last_event_seq, utcnow(), packet.get("packet_id"),
                 packet.get("packet_digest"), control_basis_digest))
            self.store.audit(
                actor="resume", action="packet.watermark",
                object_id=project_id, authority="verifier_authoritative",
                detail=canonical_json(commitment))
            audit = self.store._conn.execute(
                "SELECT entry_hash FROM audit_log WHERE action = ? AND "
                "object_id = ? ORDER BY seq DESC LIMIT 1",
                ("packet.watermark", project_id)).fetchone()
            self.store._conn.execute(
                "UPDATE packet_watermark SET audit_entry_hash = ? "
                "WHERE project_id = ?",
                (audit["entry_hash"] if audit else None, project_id))

    @serialized_access
    def packet_is_stale(self, project_id: str) -> bool:
        """True when no packet reflects the current event watermark (CI-006).

        Never composed a packet counts as stale: the check must not claim a
        packet is current for a commit when none exists.
        """
        self._require_project(project_id)
        row = self.store._conn.execute(
            "SELECT * FROM packet_watermark WHERE project_id = ?",
            (project_id,)).fetchone()
        if row is None or any(
                not row[field] for field in (
                    "packet_id", "packet_digest", "control_basis_digest",
                    "audit_entry_hash")):
            return True
        if self._latest_event_seq(project_id) != row["last_event_seq"]:
            return True
        try:
            current_control_digest = digest_obj(
                self._packet_control_basis(project_id))
        except UnsafeArtifactError:
            return True
        if current_control_digest != row["control_basis_digest"]:
            return True
        audit = self.store._conn.execute(
            "SELECT * FROM audit_log WHERE entry_hash = ? AND action = ? "
            "AND object_id = ?",
            (row["audit_entry_hash"], "packet.watermark", project_id),
        ).fetchone()
        latest_audit = self.store._conn.execute(
            "SELECT entry_hash FROM audit_log WHERE action = ? AND "
            "object_id = ? ORDER BY seq DESC LIMIT 1",
            ("packet.watermark", project_id),
        ).fetchone()
        if audit is None or not self.store.verify_chain("audit_log")["intact"]:
            return True
        if (latest_audit is None
                or latest_audit["entry_hash"] != row["audit_entry_hash"]):
            return True
        expected = {
            "project_id": project_id,
            "packet_id": row["packet_id"],
            "packet_digest": row["packet_digest"],
            "last_event_seq": row["last_event_seq"],
            "control_basis_digest": row["control_basis_digest"],
        }
        try:
            committed = strict_json_loads(audit["detail"])
        except (TypeError, ValueError):
            return True
        return committed != expected

    # ------------------------------------------------------------------- trust

    @serialized_access
    def attest_action(
        self,
        project_id: str,
        *,
        intent_type: str,
        intent_statement: str,
        actor: dict,
        action_type: str = "run_verifier",
        subjects: list[tuple[str, str]] | None = None,
        inputs: list[tuple[str, str]] | None = None,
        environment: dict | None = None,
        verifier_specs: list[VerifierSpec] | None = None,
        verification_outcomes: list[dict] | None = None,
        continuity: dict | None = None,
        requirement_ids: list[str] | None = None,
    ) -> dict:
        """Create + finalize a proof envelope: policy decision, verifier runs,
        truthful status (F4). Never infers success from absence."""
        if not isinstance(actor, dict):
            raise AttestationInputError(
                "invalid attestation input: actor must be a typed object")
        try:
            validate_human_text(intent_type, field="intent_type")
        except ValueError as exc:
            raise AttestationInputError(str(exc)) from None
        if not isinstance(intent_statement, str):
            raise AttestationInputError("intent_statement must be a string")
        if not isinstance(action_type, str) or not action_type:
            raise AttestationInputError("action_type must be a non-empty string")

        continuity = {} if continuity is None else continuity
        subjects = [] if subjects is None else subjects
        inputs = [] if inputs is None else inputs
        environment = {} if environment is None else environment
        verifier_specs = [] if verifier_specs is None else verifier_specs
        verification_outcomes = (
            [] if verification_outcomes is None else verification_outcomes)
        requirement_ids = [] if requirement_ids is None else requirement_ids

        if not isinstance(continuity, dict) or any(
                not isinstance(key, str) for key in continuity):
            raise AttestationInputError("continuity links must be a typed object")
        if not isinstance(subjects, list):
            raise AttestationInputError("subjects must be an array")
        for entry in subjects:
            if (not isinstance(entry, (list, tuple)) or len(entry) != 2
                    or not isinstance(entry[0], str) or not entry[0]
                    or not isinstance(entry[1], str)
                    or _SHA256_DIGEST.fullmatch(entry[1]) is None):
                raise AttestationInputError(
                    "subjects must contain [non-empty name, sha256 digest] pairs")
        if not isinstance(inputs, list):
            raise AttestationInputError("inputs must be an array")
        for entry in inputs:
            if (not isinstance(entry, (list, tuple))
                    or len(entry) not in (2, 3)
                    or not isinstance(entry[0], str) or not entry[0]
                    or not isinstance(entry[1], str)
                    or _SHA256_DIGEST.fullmatch(entry[1]) is None
                    or (len(entry) == 3
                        and (not isinstance(entry[2], str) or not entry[2]))):
                raise AttestationInputError(
                    "inputs must contain [non-empty name, sha256 digest, "
                    "optional non-empty kind] entries")
        if (not isinstance(environment, dict)
                or any(not isinstance(key, str) for key in environment)):
            raise AttestationInputError("environment must be a typed object")
        if (not isinstance(verifier_specs, list)
                or any(not isinstance(spec, VerifierSpec)
                       for spec in verifier_specs)):
            raise AttestationInputError(
                "verifier_specs must be an array of VerifierSpec objects")
        for spec in verifier_specs:
            try:
                spec.validate()
            except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                raise AttestationInputError(
                    f"invalid verifier specification: {exc}") from None
        if (not isinstance(verification_outcomes, list)
                or any(not isinstance(outcome, dict)
                       for outcome in verification_outcomes)):
            raise AttestationInputError(
                "verification_outcomes must be an array of objects")
        if (not isinstance(requirement_ids, list)
                or len(requirement_ids) != len(set(
                    value for value in requirement_ids
                    if isinstance(value, str)))):
            raise AttestationInputError(
                "requirement_ids must be an array of distinct identifiers")
        try:
            requirement_ids = [
                validate_public_identifier(value, field="requirement_id")
                for value in requirement_ids
            ]
            canonical_json({
                "actor": actor,
                "intent_statement": intent_statement,
                "environment": environment,
                "verification_outcomes": verification_outcomes,
            })
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise AttestationInputError(
                f"attestation inputs must be finite canonical JSON: {exc}") from None

        self._require_project(project_id)
        initial_control_basis_digest = digest_obj(
            self._packet_control_basis(project_id))
        continuity = dict(continuity)
        if requirement_ids:
            normalized_requirements = sorted(requirement_ids)
            linked_requirements = continuity.get("requirement_ids")
            if (linked_requirements is not None
                    and (not isinstance(linked_requirements, list)
                         or any(not isinstance(value, str)
                                for value in linked_requirements)
                         or sorted(linked_requirements)
                         != normalized_requirements)):
                raise AttestationInputError(
                    "action-intent requirement_ids and continuity "
                    "requirement_ids must name the same targets")
            if normalized_requirements:
                continuity["requirement_ids"] = normalized_requirements
            requirement_ids = normalized_requirements
        unknown_links = sorted(set(continuity) - set(_CONTINUITY_LINK_TYPES))
        if unknown_links:
            raise AttestationInputError(
                f"unknown typed continuity relation(s): {unknown_links}")
        for relation, targets in continuity.items():
            if (not isinstance(targets, list)
                    or any(not isinstance(target, str) for target in targets)):
                raise AttestationInputError(
                    f"{relation} must be an array of node ids")
            if len(targets) != len(set(targets)):
                raise AttestationInputError(
                    f"{relation} must not contain duplicate node ids")
            for target in targets:
                try:
                    self.graph.get(
                        target, tenant_id=self.tenant_id,
                        project_id=project_id,
                        entity_type=_CONTINUITY_LINK_TYPES[relation])
                except KeyError as exc:
                    raise AttestationInputError(
                        f"{relation} target {target!r} is not a same-project "
                        f"{_CONTINUITY_LINK_TYPES[relation]}") from exc

        policy_defs = self.policy.required_verifier_defs(project_id)
        policy_strength = {
            "required": [
                {
                    "name": definition["name"],
                    "pinned": bool(definition.get("pinned")),
                    "command_digest": (
                        VerifierSpec.from_policy(definition).command_digest
                        if definition.get("pinned") else None),
                    "definition_digest": VerifierSpec.from_policy(
                        definition).definition_digest,
                }
                for definition in policy_defs
            ],
            "min_evidence_grade": self.policy.min_evidence_grade(project_id),
        }
        env = ProofEnvelope(
            tenant_id=self.tenant_id, project_id=project_id,
            intent_type=intent_type, intent_statement=intent_statement,
            actor=actor, requirement_ids=requirement_ids,
        )
        for name, digest in subjects:
            env.add_subject(name, digest)
        for entry in inputs:
            # Caller inputs are 'declared' unless the caller names a kind. The
            # engine collects artifact digests itself, below; anything it did
            # not collect it cannot check for freshness, and must not later
            # report as changed (ADR-065). A 3-tuple opts a caller input into
            # artifact tracking deliberately.
            name, digest, kind = (*entry, "declared")[:3]
            if (kind == "continuity"
                    or (isinstance(name, str)
                        and name.startswith("artifact:"))):
                raise AttestationInputError(
                    "continuity inputs and the 'artifact:' name prefix are "
                    "reserved for engine-collected commitments")
            env.add_input(name, digest, kind=kind)
        # Link identifiers alone do not bind what the verifier observed. A
        # signed digest of every typed target makes a later task,
        # requirement, assumption, or evidence revision invalidate the old
        # proof even if its identifier remains stable.
        for name, digest in self._continuity_state_inputs(
                project_id, continuity).items():
            env.add_input(name, digest, kind="continuity")
        env.set_environment(**environment)
        # Outcomes supplied by the caller are claims, never observations.
        # Shape-check them with every other caller-controlled field before a
        # verifier command or graph mutation can occur.
        outcomes = [{**outcome, "source": SELF_ASSERTED}
                    for outcome in verification_outcomes]
        _preflight_proof_body(env.body, outcomes)
        claim_key = digest_obj({
            "intent_type": intent_type,
            "intent_statement": intent_statement,
            "requirements": sorted(requirement_ids),
            "subjects": subjects,
            "continuity": {
                key: sorted(value) for key, value in sorted(continuity.items())},
        })
        # Reserve an unpredictable identity before signing, but persist no
        # attesting node yet. External checks run without a database write
        # transaction; their bounded output is staged, then proof, evidence,
        # verification nodes, supersession and downgrade commit together.
        proof_node_id = new_id("action")
        env.set_continuity(**continuity, proof_node_id=proof_node_id)
        # POLICY owns every pinned verifier operand: an absolute command for
        # subprocess kinds or a closed path/digest map for file-digest. A
        # caller spec that reuses a pinned name is discarded (ADR-024).
        policy_names = {d["name"] for d in policy_defs}
        pinned_names = {d["name"] for d in policy_defs if d["pinned"]}
        specs: list[VerifierSpec] = [
            VerifierSpec.from_policy(d) for d in policy_defs if d["pinned"]]
        displaced = []
        for spec in verifier_specs:
            # Revalidate mutable dataclass instances at the execution
            # boundary; __post_init__ alone cannot protect a later mutation.
            try:
                spec.validate()
            except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                raise AttestationInputError(
                    f"invalid verifier specification: {exc}") from None
            if spec.name in pinned_names:
                displaced.append(spec.name)
                continue
            # An UNPINNED policy name is satisfiable by a caller-supplied
            # command — but the proof records that the claimant chose it and
            # the evidence grade caps at D. Pinning is the supported form.
            specs.append(spec)
        artifact_paths = sorted({
            artifact
            for definition in policy_defs
            for artifact in (definition.get("artifacts") or [])
        } | {
            artifact
            for spec in specs
            for artifact in normalize_artifact_paths(spec.artifacts)
        })
        visibility_error = self.verifier_runner._artifact_visibility_error(
            artifact_paths)
        if visibility_error:
            raise AttestationInputError(
                "invalid verifier artifact declaration: "
                f"{visibility_error}")
        # Record what the checks were run AGAINST, as signed inputs. Caller
        # verifier artifacts are included as well as policy artifacts, so an
        # unpinned-but-permitted check cannot observe an unsigned deliverable.
        artifact_inputs = self._artifact_digests(
            project_id, artifacts=artifact_paths)
        for name, digest in artifact_inputs.items():
            env.add_input(name, digest, kind="artifact")
        # The action's class is what the engine is ABOUT TO DO, not what the
        # caller called it. Executing a verifier is reversible execution
        # (level 2) however it is labelled; honouring the label let an agent
        # under an AUT-005 downgrade declare "observe" and keep running
        # checks, which is the downgrade doing nothing at all (ADR-048).
        effective_action = action_type
        if specs and ACTION_CLASSES.get(action_type, 0) < \
                ACTION_CLASSES["run_verifier"]:
            effective_action = "run_verifier"
        # A scoped grant must authorize every artifact the action touches.
        # Omitting action_scope used to make a scoped grant behave as global.
        operation_scopes = sorted({
            path for spec in specs for path in (spec.artifacts or [])})
        scope_decisions = [
            self.policy.decide(
                project_id=project_id, action_type=effective_action,
                action_scope=scope)
            for scope in (operation_scopes or [None])
        ]
        decision = dict(scope_decisions[0])
        decision["decision"] = (
            "allow"
            if all(item["decision"] == "allow" for item in scope_decisions)
            else "deny")
        decision["action_scopes"] = operation_scopes
        decision["scope_decisions"] = [
            {
                "scope": scope,
                "decision": item["decision"],
                "effective_level": item["effective_level"],
                "required_level": item["required_level"],
            }
            for scope, item in zip(operation_scopes or [None], scope_decisions)
        ]
        decision["reasons"] = [
            reason
            for scope, item in zip(operation_scopes or [None], scope_decisions)
            for reason in [
                f"scope {scope!r}: {detail}" for detail in item["reasons"]]
        ]
        if effective_action != action_type:
            decision["reasons"].append(
                f"action reclassified {action_type!r} -> {effective_action!r}: "
                f"{len(specs)} verifier(s) would execute")
        env.set_policy_decision(decision)
        staged_runner = VerifierRunner(
            self.store, self.verifier_runner.workdir,
            persist_evidence=False)
        executed_outcomes = []
        if decision["decision"] == "allow":
            for spec in specs:
                outcome = staged_runner.run(spec)
                if outcome.subject_mutated:
                    raise RuntimeError(
                        "declared artifacts changed inside a verifier "
                        "snapshot; discarding the refused attestation")
                executed_outcomes.append(outcome)
                outcomes.append(outcome.to_dict())
                env.add_execution(
                    tool=f"verifier:{spec.name}",
                    command_digest=spec.command_digest,
                    exit_code=outcome.exit_code,
                    started_at=outcome.started_at,
                    output_digest=outcome.output_digest)
        elif specs:
            for spec in specs:
                outcomes.append({"verifier": spec.name, "kind": spec.kind,
                                 "result": "skipped",
                                 "details": "policy denied execution"})
        if decision["decision"] == "allow" and artifact_inputs:
            if self._artifact_digests(
                    project_id, artifacts=artifact_paths) != artifact_inputs:
                raise RuntimeError(
                    "declared artifacts changed while verifiers were running; "
                    "discarding the stale attestation")
        for o in outcomes:
            env.add_verification(o)
        # Policy-mandated verifiers are always required; a caller may ADD to
        # the required set but never substitute its own list (ADR-020).
        required = sorted(policy_names
                          | {s.name for s in specs if s.required})
        # A verifier is pinned only if policy owns its complete executable or
        # built-in adapter definition. A caller-added spec remains unpinned
        # however it labels itself.
        pinned_by_policy = {d["name"] for d in policy_defs if d["pinned"]}
        unpinned = sorted(set(self.policy.unpinned_required_verifiers(project_id))
                          | {name for name in required
                             if name not in pinned_by_policy})
        # Binding must be established AT ATTESTATION and signed with the rest
        # of the evidence. Grading a proof later with no probe attached made
        # the binding cap unreachable in practice: the gate could only ever
        # see "unproven", so unbound evidence passed every floor an operator
        # could realistically set (ADR-049).
        mutation_report = None
        determinism_report = {}
        if decision["decision"] == "allow" and any(s.artifacts for s in specs):
            excluded_probe_paths = []
            if self.store.path != ":memory:":
                store_path = Path(self.store.path).resolve()
                workdir = self.verifier_runner.workdir
                if store_path == workdir or workdir in store_path.parents:
                    excluded_probe_paths = [
                        store_path,
                        Path(str(store_path) + "-wal"),
                        Path(str(store_path) + "-shm"),
                    ]
            mutation_report = run_mutation_probe(
                workdir=str(self.verifier_runner.workdir),
                artifacts=sorted({a for s in specs for a in s.artifacts}),
                specs=[s for s in specs if s.required],
                runner_factory=lambda sandbox: VerifierRunner(None, sandbox),
                excluded_paths=tuple(excluded_probe_paths),
            )
        if decision["decision"] == "allow":
            determinism_report = {
                spec.name: run_determinism_probe(spec, staged_runner)
                for spec in specs if spec.required
            }
        if decision["decision"] == "allow" and artifact_inputs:
            if self._artifact_digests(
                    project_id, artifacts=artifact_paths) != artifact_inputs:
                raise RuntimeError(
                    "declared artifacts changed while evidence probes were "
                    "running; discarding the stale attestation")
        env.set_evidence_context(
            unpinned_required=unpinned,
            policy_pinned=sorted(pinned_by_policy),
            mutation=mutation_report.to_dict() if mutation_report else None,
            determinism=determinism_report)
        finalized = env.finalize(self.signer, required_verifiers=required)
        shape_errors = validate_envelope_shape(finalized)
        if shape_errors:
            raise ValueError(
                "attestation produced an invalid proof: "
                + "; ".join(shape_errors))
        with self.store.transaction():
            current_control_basis_digest = digest_obj(
                self._packet_control_basis(project_id))
            if current_control_basis_digest != initial_control_basis_digest:
                raise RuntimeError(
                    "project control state changed while verifiers were running; "
                    "discarding the stale attestation")
            if displaced:
                self.store.audit(
                    actor="trust-service", action="verifier.displaced",
                    object_id=project_id,
                    detail=f"caller specs for policy-mandated verifier(s) "
                           f"{sorted(set(displaced))} were ignored")
            proof_node = self.graph.put_node(
                entity_type="action", tenant_id=self.tenant_id,
                project_id=project_id, node_id=proof_node_id,
                status=finalized["status"],
                data={
                    "kind": "proof", "intent_type": intent_type,
                    "statement": intent_statement, "claim_key": claim_key,
                    "continuity": continuity,
                    "policy_strength": policy_strength,
                    "policy_decision": decision["decision"],
                    "proof_id": finalized["proof_id"],
                    "proof_digest": finalized["proof_digest"],
                },
            )
            for outcome in executed_outcomes:
                if outcome.output is not None:
                    stored_digest = self.store.put_evidence(
                        outcome.output, media_type="text/plain")
                    if stored_digest != outcome.evidence_digest:
                        raise RuntimeError(
                            "verifier evidence changed before proof commit")
                record_verification(
                    self.graph, outcome, tenant_id=self.tenant_id,
                    project_id=project_id)
            if finalized["status"] == "verified":
                for previous in self.graph.current(
                        project_id, "action", tenant_id=self.tenant_id):
                    if (previous["node_id"] == proof_node.id
                            or previous["data"].get("claim_key") != claim_key
                            or previous["status"] not in (
                                "failed", "incomplete", "inconclusive", "stale")):
                        continue
                    if not _policy_strength_covers(
                            policy_strength,
                            previous["data"].get("policy_strength")):
                        continue
                    self.graph.put_node(
                        entity_type="action", tenant_id=self.tenant_id,
                        project_id=project_id, node_id=previous["node_id"],
                        status="superseded",
                        data={
                            "superseded_by": finalized["proof_id"],
                            "superseded_by_node": proof_node.id,
                        },
                    )
                    self.graph.put_edge(
                        edge_type="supersedes", src_id=proof_node.id,
                        dst_id=previous["node_id"], tenant_id=self.tenant_id,
                        project_id=project_id,
                    )
            for targets in continuity.values():
                for target in targets:
                    self.graph.put_edge(
                        edge_type="derived_from", src_id=proof_node.id,
                        dst_id=target, tenant_id=self.tenant_id,
                        project_id=project_id)
            # AUT-005: a failed proof downgrades autonomy until a human clears it.
            # A policy-denied attempt is not a failed proof — it never ran.
            if (finalized["status"] == "failed"
                    and decision["decision"] == "allow"):
                self.policy.downgrade(
                    project_id, "failed_proof", ceiling=1,
                    actor="trust-service")
        return finalized

    @serialized_access
    def complete_task(self, project_id: str, task_id: str, *,
                      proof: dict | None = None, actor: str = "agent") -> dict:
        """Validate and commit a completion against one coherent snapshot.

        Proof currency, task status, current policy, single-use claiming, and
        the final graph mutation share the same BEGIN IMMEDIATE transaction.
        A concurrent quarantine or policy edit can therefore happen either
        before this decision or after it, never in the validation/mutation
        gap.  Rejections are audited after rollback so the audit survives.
        """
        validate_public_identifier(project_id, field="project_id")
        validate_public_identifier(task_id, field="task_id")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("task completion actor must be a non-empty string")
        actor = validate_human_text(actor, field="task completion actor")
        if proof is not None and not isinstance(proof, dict):
            raise ValueError("task completion proof must be an object or null")
        try:
            with self.store.transaction():
                return self._complete_task_locked(
                    project_id, task_id, proof=proof, actor=actor)
        except PermissionError as exc:
            message = str(exc)
            self.store.audit(
                actor="trust-service", action="completion.rejected",
                object_id=task_id, authority="tenant_policy",
                detail=message)
            if "declares no required verifiers" in message:
                self.store.audit(
                    actor="trust-service", action="policy.misconfigured",
                    object_id=project_id, authority="tenant_policy",
                    detail="proof required for task_complete but no required "
                           "verifiers declared")
            raise

    def _complete_task_locked(self, project_id: str, task_id: str, *,
                              proof: dict | None = None,
                              actor: str = "agent") -> dict:
        """False-completion gate: task_complete requires a VERIFIED proof when
        policy demands one (F4, PA-005, launch gate 'Trust').

        An authentic 'verified' envelope is not enough on its own — it must be
        THIS task's proof. A signature only says the record is genuine, not
        what it is evidence for, so the gate also binds scope (same tenant and
        project), subject (the proof names this task), and single use (a proof
        already spent on another task cannot be replayed).
        """
        try:
            task = self.graph.get(
                task_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="task")
        except KeyError:
            raise PermissionError(
                f"completion rejected: target {task_id} is not a task in the "
                f"requested project {self.tenant_id}/{project_id}") from None
        blocking_invalidations = self.invalidation.blocking_invalidations(
            project_id, task_id)
        if blocking_invalidations:
            details = ", ".join(
                f"{item['node_id']} ({item.get('status')}, "
                f"{(item.get('data') or {}).get('severity')})"
                for item in blocking_invalidations)
            raise PermissionError(
                "completion rejected: unresolved invalidation control state "
                f"blocks this task: {details}. Confirm and resolve it before "
                "claiming completion")
        if task.get("status") == "verified":
            existing_proof = (task.get("data") or {}).get(
                "completion_evidence")
            supplied_proof = proof.get("proof_id") \
                if isinstance(proof, dict) else None
            if ((proof is None and existing_proof is None)
                    or (existing_proof is not None
                        and supplied_proof == existing_proof)):
                return task
            raise PermissionError(
                f"completion rejected: task {task_id} is already verified by "
                "a different completion claim; explicitly reopen or "
                "invalidate it before replacing completion evidence")
        if task.get("status") == "quarantined":
            # Completion would overwrite the flag and silently promote
            # quarantined work to verified. Quarantine is resolved by a human
            # decision, never by claiming success on top of it (ADR-050).
            raise PermissionError(
                f"completion rejected: {task_id} is quarantined "
                f"({(task['data'] or {}).get('quarantine_reason', 'no reason recorded')}). "
                f"Resolve the quarantine before claiming completion.")
        proof_required = self.policy.proof_required(
            project_id, "task_complete")
        if proof_required and proof is None:
            raise PermissionError(
                "completion rejected: policy requires proof for task_complete"
                " and none was provided")
        if proof is not None:
            shape_errors = validate_envelope_shape(proof)
            if shape_errors:
                raise PermissionError(
                    "completion rejected: malformed proof envelope — "
                    + "; ".join(shape_errors))
            check = verify_envelope(proof, self.signer)
            if not check["valid"]:
                raise PermissionError("completion rejected: proof envelope invalid"
                                      " or tampered")
            if proof.get("status") != "verified":
                raise PermissionError(
                    f"completion rejected: proof status is {proof.get('status')!r},"
                    " not 'verified'")
            if proof.get("project_id") != project_id or \
                    proof.get("tenant_id") != self.tenant_id:
                raise PermissionError(
                    "completion rejected: proof was issued for"
                    f" {proof.get('tenant_id')}/{proof.get('project_id')},"
                    f" not {self.tenant_id}/{project_id}")
            if (proof.get("action_intent") or {}).get("type") != "task_complete":
                raise PermissionError(
                    "completion rejected: proof intent is "
                    f"{(proof.get('action_intent') or {}).get('type')!r}, "
                    "not 'task_complete'")
            if not _proof_covers(proof, task_id):
                raise PermissionError(
                    f"completion rejected: proof {proof.get('proof_id')} does not"
                    f" name task {task_id}; attest the task you are completing")
            prior_spend = self.store._conn.execute(
                "SELECT task_id FROM spent_proofs WHERE tenant_id = ? "
                "AND project_id = ? AND proof_id = ?",
                (self.tenant_id, project_id, proof.get("proof_id")),
            ).fetchone()
            if prior_spend is not None and prior_spend["task_id"] != task_id:
                raise PermissionError(
                    f"completion rejected: proof {proof.get('proof_id')} was "
                    f"already used to complete {prior_spend['task_id']}")
            declared = self.policy.required_verifier_defs(project_id)
            if proof_required and not declared:
                # Demanding proof without saying what must be proven leaves
                # the claimant to define its own pass mark, which is the same
                # defect as an unpinned command wearing different clothes. It
                # is a configuration error, and refusing names the fix
                # (ADR-045).
                raise PermissionError(
                    f"completion rejected: project {project_id} requires proof "
                    f"for task_complete but declares no required verifiers, so "
                    f"nothing states what would count as proof. Add a policy-"
                    f"pinned verifier definition, or remove task_complete "
                    f"from require_proof_for.")
            if (proof.get("policy_decision") or {}).get("decision") != "allow":
                raise PermissionError(
                    "completion rejected: proof policy decision is not 'allow'")
            # The required set is re-read at completion time. A proof minted
            # under a laxer policy is not evidence for the current one: it
            # simply never tested what the project now requires (ADR-054).
            # Currency is judged only once the configuration is coherent: a
            # policy with nothing declared has no artifact surface, so a
            # staleness verdict derived from it would describe the config
            # error rather than the world (ADR-056).
            currency = self.proof_currency(project_id, task_id, proof)
            if not currency["current"]:
                raise PermissionError(
                    "completion rejected: the proof no longer describes the "
                    "current state — " + "; ".join(currency["reasons"])
                    + ". Re-attest against the world as it is now.")
            # Compare complete normalized DEFINITIONS, not names or commands.
            # Kind, oracle expectations, timeout, negative control, artifacts
            # and isolation all change what a pass means.  Command-only
            # comparison left those policy changes invisible (ADR-074).
            passed_digests: dict[str, set[str | None]] = {}
            for verification in proof.get("verifications", []):
                if (verification.get("result") == "passed"
                        and verification.get("source")
                        in AUTHORITATIVE_SOURCES):
                    passed_digests.setdefault(
                        verification.get("verifier"), set()).add(
                            verification.get("definition_digest"))
            unmet = []
            for definition in self.policy.required_verifier_defs(project_id):
                name = definition["name"]
                if name not in passed_digests:
                    unmet.append(name)
                elif definition["pinned"]:
                    want = VerifierSpec.from_policy(definition).definition_digest
                    recorded = passed_digests[name]
                    if not any(recorded):
                        unmet.append(
                            f"{name} (this proof records no verifier definition "
                            f"identity, so there is nothing to compare against "
                            f"the pinned policy definition)")
                    elif want not in recorded:
                        unmet.append(
                            f"{name} (the policy's verifier definition changed "
                            f"since this proof was minted)")
            if unmet:
                raise PermissionError(
                    f"completion rejected: the policy now requires {sorted(unmet)}, "
                    f"which this proof does not cover. It was minted under an "
                    f"earlier policy; re-attest against the current one.")
            minimum = self.policy.min_evidence_grade(project_id)
            if minimum:
                grade = self.grade_proof(project_id, proof)
                if not grade.at_least(minimum):
                    raise PermissionError(
                        f"completion rejected: evidence grade {grade.grade} is"
                        f" below the required {minimum} — "
                        + "; ".join(grade.caps or grade.reasons))
        if task.get("status") not in (None, "open", "in_progress"):
            raise PermissionError(
                f"completion rejected: task {task_id} is not completable while "
                f"its status is {task.get('status')!r}; resolve or explicitly "
                "reopen that state before claiming completion")
        current_task = self.graph.get(
            task_id, tenant_id=self.tenant_id, project_id=project_id,
            entity_type="task")
        if current_task.get("version") != task.get("version"):
            raise PermissionError(
                "completion rejected: task state changed while its proof was "
                "being validated; retry against the current task version")
        with self.store.transaction():
            if proof:
                spent_on = self._claim_proof(
                    project_id, proof.get("proof_id"), task_id)
                if spent_on is not None:
                    raise PermissionError(
                        f"completion rejected: proof {proof.get('proof_id')} was "
                        f"already used to complete {spent_on}")
            node = self.graph.put_node(
                entity_type="task", tenant_id=self.tenant_id,
                project_id=project_id, node_id=task_id, status="verified",
                data={
                    "completion_evidence": (proof or {}).get("proof_id"),
                    "completed_by": actor,
                    "completed_at": utcnow(),
                },
                authority=(
                    "verifier_authoritative"
                    if proof else "agent_inference"),
            )
            if proof:
                for action in self.graph.current(
                        project_id, "action", tenant_id=self.tenant_id):
                    if action["data"].get("proof_id") == proof.get("proof_id"):
                        self.graph.put_edge(
                            edge_type="verifies",
                            src_id=action["node_id"], dst_id=task_id,
                            tenant_id=self.tenant_id,
                            project_id=project_id)
                        break
        return node

    @serialized_access
    def bind_github_repository(
            self, project_id: str, *, repository_id: int,
            repository: str | None = None,
            github_installation_id: int | None = None,
            actor: str = "operator") -> dict:
        """Migrate an existing project to immutable GitHub webhook routing."""
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("repository binding actor must be a non-empty string")
        actor = validate_human_text(actor, field="repository binding actor")
        project = self._require_project(project_id)
        repository_id = self._github_numeric_id(
            repository_id, "repository_id")
        repository = validate_repository_name(
            repository, field="repository", optional=True)
        if github_installation_id is not None:
            github_installation_id = self._github_numeric_id(
                github_installation_id, "github_installation_id")
        data = dict(project["data"])
        if repository is not None:
            data["repository"] = repository
        data["repository_id"] = repository_id
        data["github_installation_id"] = github_installation_id
        with self.store.transaction():
            updated = self.graph.put_node(
                entity_type="project", tenant_id=self.tenant_id,
                project_id=project_id, node_id=project_id,
                status=project.get("status"), authority=project.get("authority"),
                data=data)
            self.store.audit(
                actor=actor, action="project.github_binding",
                object_id=project_id, authority="human_decision",
                detail=canonical_json({
                    "repository_id": repository_id,
                    "github_installation_id": github_installation_id,
                    "repository": data.get("repository"),
                }))
        return updated

    def _artifact_digests(
            self, project_id: str,
            artifacts: list[str] | None = None) -> dict[str, str]:
        """Stable content snapshots for canonical declared deliverables.

        POSIX hosts traverse from a held workdir descriptor and open each
        component with O_NOFOLLOW. Other hosts reject links/reparse points at
        every observed route and bracket file reads and recursive inventory
        with physical metadata checks. No invalid declaration is omitted.
        """
        self._require_project(project_id)
        if artifacts is None:
            artifacts = [
                artifact
                for definition in self.policy.required_verifier_defs(project_id)
                for artifact in (definition.get("artifacts") or [])
            ]
        declared = sorted(normalize_artifact_paths(list(artifacts)))
        root = Path(os.path.abspath(self.verifier_runner.workdir))
        digests: dict[str, str] = {}
        for rel in declared:
            try:
                digests[f"artifact:{rel}"] = _snapshot_artifact(root, rel)
            except UnsafeArtifactError:
                raise
            except OSError as exc:
                # Unreadable is not unchanged. Dropping it would erase the
                # artifact from the comparison and silently make the proof
                # look current (ADR-047).
                digests[f"artifact:{rel}"] = sha256_hex(f"<unreadable:{exc}>")
        return digests

    def _continuity_state_inputs(
            self, project_id: str, continuity: dict,
            *, allow_missing: bool = False) -> dict[str, str]:
        """Canonical signed commitments for typed proof targets.

        Node ids are stable across graph versions, so signing only an id lets
        a proof for version 1 authorize version 2. These digests deliberately
        include the node revision and every semantic field but exclude
        transaction clocks. During a later currency check, an unavailable or
        wrong-scope target receives a deterministic tombstone digest rather
        than disappearing from the comparison.
        """
        if not isinstance(continuity, dict):
            raise ValueError("continuity links must be a typed object")
        unknown = sorted(set(continuity) - set(_CONTINUITY_LINK_TYPES))
        if unknown:
            raise ValueError(f"unknown typed continuity relation(s): {unknown}")

        committed: dict[str, str] = {}
        for relation in sorted(continuity):
            targets = continuity[relation]
            if (not isinstance(targets, list)
                    or any(not isinstance(target, str) or not target
                           for target in targets)
                    or len(targets) != len(set(targets))):
                raise ValueError(
                    f"{relation} must be an array of distinct non-empty node ids")
            expected_type = _CONTINUITY_LINK_TYPES[relation]
            for target in sorted(targets):
                name = f"continuity:{relation}:{target}"
                try:
                    node = self.graph.get(
                        target, tenant_id=self.tenant_id,
                        project_id=project_id, entity_type=expected_type)
                except KeyError:
                    if not allow_missing:
                        raise ValueError(
                            f"{relation} target {target!r} is not a same-project "
                            f"{expected_type}") from None
                    basis = {
                        "schema_version": "cce.continuity-state.v1",
                        "relation": relation,
                        "node_id": target,
                        "expected_type": expected_type,
                        "state": "unavailable",
                    }
                else:
                    basis = {
                        "schema_version": "cce.continuity-state.v1",
                        "relation": relation,
                        "node": {
                            field: node.get(field)
                            for field in _CONTINUITY_STATE_FIELDS
                        },
                    }
                committed[name] = digest_obj(basis)
        return committed

    @serialized_access
    def proof_currency(self, project_id: str, task_id: str, proof: dict) -> dict:
        """Does this proof still describe the world it was taken in?

        A proof is a statement about a moment. Three things can make it stop
        being true without anything tampering with it: the deliverables it
        was checked against change, the assumptions the task rests on are
        invalidated, or the task itself is put under review. EV-005 shipped
        `detect_stale` as a library call that nothing invoked — a mechanism
        that exists but is not in the path that decides is not a control
        (ADR-043).
        """
        self._require_project(project_id)
        try:
            task = self.graph.get(
                task_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="task")
        except KeyError:
            raise PermissionError(
                "proof currency target is outside the requested tenant/project") \
                from None
        if not isinstance(proof, dict):
            raise ValueError("proof currency requires a proof object")
        shape_errors = validate_envelope_shape(proof)
        if shape_errors:
            return {
                "current": False,
                "reasons": ["malformed proof envelope: " + "; ".join(shape_errors)],
                "changed_inputs": [], "untracked_inputs": [],
            }

        reasons: list[str] = []
        continuity = proof.get("continuity_links") or {}
        try:
            continuity_inputs = self._continuity_state_inputs(
                project_id, {
                    key: value for key, value in continuity.items()
                    if key != "proof_node_id"
                }, allow_missing=True)
        except ValueError as exc:
            continuity_inputs = {}
            reasons.append(f"invalid continuity links: {exc}")

        recorded_artifacts: list[str] = []
        try:
            for item in proof.get("inputs", []):
                name = item.get("name")
                if (item.get("kind") == "artifact"
                        and isinstance(name, str)
                        and name.startswith("artifact:")):
                    recorded_artifacts.append(
                        normalize_artifact_path(name.removeprefix("artifact:")))
            if len(recorded_artifacts) != len(set(recorded_artifacts)):
                raise ValueError(
                    "proof repeats an engine-collected artifact commitment")
            current_inputs = self._artifact_digests(
                project_id, artifacts=recorded_artifacts)
        except (UnsafeArtifactError, ValueError) as exc:
            return {
                "current": False,
                "reasons": [f"unsafe artifact boundary: {exc}"],
                "changed_inputs": [], "untracked_inputs": [],
            }
        current_inputs.update(continuity_inputs)
        stale = detect_stale(proof, current_inputs)
        if stale["stale"]:
            by_name = {
                item["name"]: item.get("kind")
                for item in proof.get("inputs", [])
            }
            artifact_changes = [
                change["name"] for change in stale["changed_inputs"]
                if by_name.get(change["name"]) == "artifact"]
            continuity_changes = [
                change["name"] for change in stale["changed_inputs"]
                if by_name.get(change["name"]) == "continuity"]
            other_changes = [
                change["name"] for change in stale["changed_inputs"]
                if by_name.get(change["name"]) not in (
                    "artifact", "continuity")]
            if artifact_changes:
                reasons.append(
                    "deliverables changed since attestation: "
                    + ", ".join(artifact_changes))
            if continuity_changes:
                reasons.append(
                    "linked continuity state changed since attestation: "
                    + ", ".join(continuity_changes))
            if other_changes:
                reasons.append(
                    "tracked proof inputs changed since attestation: "
                    + ", ".join(other_changes))

        expected_names = Counter(continuity_inputs.keys())
        recorded_names = Counter(
            item["name"] for item in proof.get("inputs", [])
            if item.get("kind") == "continuity")
        if expected_names != recorded_names:
            reasons.append(
                "proof does not carry exactly one engine-collected state "
                "commitment for every typed continuity target")
        if not _proof_covers(proof, task_id):
            reasons.append("proof does not name the requested task")
        if task.get("status") in ("blocked", "uncertain"):
            reasons.append(
                f"the task is {task['status']}: something it depends on is "
                f"under review")
        for inv in self.invalidation.blocking_invalidations(
                project_id, task_id):
            data = inv.get("data") or {}
            reasons.append(
                f"unresolved invalidation {inv['node_id']} "
                f"({inv.get('status')}, {data.get('trigger_type')}, "
                f"{data.get('severity')}) blocks this task")
        return {"current": not reasons, "reasons": reasons,
                "changed_inputs": stale["changed_inputs"],
                # Disclosed, not silently dropped: a reader must be able to
                # see which recorded inputs this answer does NOT cover.
                "untracked_inputs": stale["untracked_inputs"]}

    # -------------------------------------------------------- evidence quality

    @serialized_access
    def grade_proof(self, project_id: str, proof: dict,
                    mutation: "MutationReport | None" = None,
                    determinism: dict | None = None) -> EvidenceGrade:
        """How hard would this proof be to fake? Lint, not an oracle (ADR-027)."""
        context = proof.get("evidence_context") or {}
        controls = {v.get("verifier"): (v.get("control") or {})
                    for v in proof.get("verifications", [])}
        if mutation is None and context.get("mutation"):
            mutation = MutationReport(**{
                k: v for k, v in context["mutation"].items()
                if k in ("artifacts", "detected", "undetected", "inconclusive",
                         "baseline", "ran_at", "error")})
        if determinism is None:
            recorded = context.get("determinism")
            determinism = recorded if isinstance(recorded, dict) else None
        return grade_evidence(
            outcomes=proof.get("verifications", []),
            required=(proof.get("verification_summary") or {}).get("required", []),
            controls=controls,
            mutation=mutation,
            determinism=determinism,
            unpinned_required=context.get("unpinned_required", []),
        )

    @serialized_access
    def probe_evidence(self, project_id: str, *, artifacts: list[str] | None = None,
                       workdir: str | None = None) -> MutationReport:
        """Destroy each declared deliverable in a sandbox copy and confirm a
        required check notices (EV-007). The real tree is never touched."""
        declared = (
            [] if artifacts is None else normalize_artifact_paths(artifacts))
        defs = [d for d in self.policy.required_verifier_defs(project_id)
                if d["pinned"]]
        specs = [VerifierSpec.from_policy(d) for d in defs]
        for spec in specs:
            declared.extend(spec.artifacts)
        root = workdir or str(self.verifier_runner.workdir)
        report = run_mutation_probe(
            workdir=root,
            artifacts=sorted(set(declared)),
            specs=specs,
            runner_factory=lambda sandbox: VerifierRunner(None, sandbox),
            excluded_paths=tuple(
                self.verifier_runner._snapshot_exclusions(root)),
        )
        self.store.audit(
            actor="trust-service", action="evidence.mutation_probe",
            object_id=project_id,
            detail=f"bound={report.bound} detected={len(report.detected)}"
                   f" undetected={len(report.undetected)}")
        return report

    @serialized_access
    def probe_determinism(self, project_id: str) -> dict:
        """Run each pinned required check twice; disagreement means flaky."""
        out = {}
        for d in self.policy.required_verifier_defs(project_id):
            if not d["pinned"]:
                continue
            spec = VerifierSpec.from_policy(d)
            out[spec.name] = run_determinism_probe(spec, self.verifier_runner)
        return out

    def _claim_proof(self, project_id: str, proof_id: str | None,
                     task_id: str) -> str | None:
        """Atomically claim this proof for this task.

        Returns None when the claim succeeds (or is a benign re-claim by the
        same task), otherwise the task that already holds it. The uniqueness
        is the database's, so two concurrent completions cannot both win
        (ADR-059).
        """
        if not proof_id:
            return None
        with self.store.write_scope():
            try:
                self.store._conn.execute(
                    "INSERT INTO spent_proofs (tenant_id, project_id, proof_id,"
                    " task_id, spent_at) VALUES (?,?,?,?,?)",
                    (self.tenant_id, project_id, proof_id, task_id, utcnow()))
                return None
            except sqlite3.IntegrityError:
                row = self.store._conn.execute(
                    "SELECT task_id FROM spent_proofs WHERE tenant_id = ? "
                    "AND project_id = ? AND proof_id = ?",
                    (self.tenant_id, project_id, proof_id)).fetchone()
                holder = row["task_id"] if row else "another task"
                return None if holder == task_id else holder

    # ----------------------------------------------------------------- checks

    @serialized_access
    def continuity_check(self, project_id: str, *,
                         _sign_receipt: bool = True) -> dict:
        """Evaluate and authenticate one coherent continuity frontier.

        The returned counterfactual witness records both why the verdict holds
        and the exact conjunction that must change to reach success. Reads and
        signing occur under one Store transaction, so policy, graph, packet,
        and log anchors describe a state that actually coexisted.
        """
        with self.store.transaction():
            project = self.graph.get(
                project_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="project")
            project_data = project["data"]
            frontier = self.policy.tracked_ref_frontier(
                project_id, project_data)
            tracked_ref = frontier["tracked_ref"]
            current_head = frontier["current_head_sha"]
            trusted_external_head = frontier["trusted_external_head_sha"]
            frontier_uncertain = frontier["uncertain"]

            open_inv = self.invalidation.open_invalidations(project_id)
            critical = [
                item for item in open_inv
                if item["data"].get("severity") in ("high", "critical")
            ]
            pending = [
                item for item in open_inv
                if item["status"] == "pending_confirmation"
            ]
            failed_proofs = [
                node for node in self.graph.current(
                    project_id, "action", tenant_id=self.tenant_id)
                if node["data"].get("kind") == "proof"
                and node["data"].get("policy_decision") != "deny"
                and node["status"] in (
                    "failed", "incomplete", "inconclusive", "stale")
            ]
            authority_conflicts = [
                node for node in self.graph.current(
                    project_id, tenant_id=self.tenant_id)
                if node["data"].get("conflict_requires_resolution")
                and node["status"] not in (
                    "resolved", "superseded", "invalidated", "rejected")
            ]

            policy_config = self.policy.project_config(project_id)
            definitions = self.policy.required_verifier_defs(project_id)
            passing_nodes = [
                node for node in self.graph.current(
                    project_id, "verification", status=["passed"],
                    tenant_id=self.tenant_id)
            ]
            trusted_passes = []
            verifier_gaps = proof_policy_verifier_gaps(
                policy_config, definitions)
            external_without_frontier = bool(
                project_data.get("repository_id")
                and not trusted_external_head)
            required_identities = []
            for definition in definitions:
                name = definition["name"]
                spec = VerifierSpec.from_policy(definition)
                wanted_digest = spec.command_digest \
                    if definition.get("pinned") else None
                wanted_definition_digest = spec.definition_digest
                identity = {
                    "name": name,
                    "pinned": bool(definition.get("pinned")),
                    "command_digest": wanted_digest,
                    "definition_digest": wanted_definition_digest,
                }
                required_identities.append(identity)
                matches = []
                for node in passing_nodes:
                    data = node["data"]
                    if data.get("verifier") != name:
                        continue
                    source = data.get("source") or ""
                    if source == "executed":
                        if (definition.get("pinned")
                                and data.get("pinned")
                                and data.get("definition_digest")
                                == wanted_definition_digest):
                            matches.append(node)
                    elif source.startswith("github:"):
                        if not trusted_external_head:
                            external_without_frontier = True
                        if (not definition.get("pinned")
                                and self.policy.external_verifier_trusted(
                                    project_id, source, data)
                                and trusted_external_head
                                and data.get("head_sha")
                                == trusted_external_head):
                            matches.append(node)
                if not matches:
                    verifier_gaps.append(name)
                    continue
                chosen = matches[-1]
                data = chosen["data"]
                trusted_passes.append({
                    "node_id": chosen["node_id"],
                    "verifier": name,
                    "source": data.get("source"),
                    "command_digest": data.get("command_digest"),
                    "definition_digest": data.get("definition_digest"),
                    "head_sha": data.get("head_sha"),
                    "app": data.get("app"),
                    "app_id": data.get("app_id"),
                    "workflow_id": data.get("workflow_id"),
                    "workflow_path": data.get("workflow_path"),
                    "installation_id": data.get("installation_id"),
                })

            packet_row = self.store._conn.execute(
                "SELECT * FROM packet_watermark WHERE project_id = ?",
                (project_id,)).fetchone()
            packet_current = not self.packet_is_stale(project_id)
            packet_state = {
                "packet_id": packet_row["packet_id"] if packet_row else None,
                "last_event_seq": (
                    packet_row["last_event_seq"] if packet_row else None),
                "packet_digest": (
                    packet_row["packet_digest"] if packet_row else None),
                "control_basis_digest": (
                    packet_row["control_basis_digest"] if packet_row else None),
                "audit_entry_hash": (
                    packet_row["audit_entry_hash"] if packet_row else None),
                "current": packet_current,
            }
            invalidation_state = [
                {
                    "node_id": item["node_id"],
                    "status": item["status"],
                    "severity": item["data"].get("severity"),
                    "trigger_type": item["data"].get("trigger_type"),
                    "target_node_id": item["data"].get("target_node_id"),
                    "affected": item["data"].get("affected", []),
                }
                for item in open_inv
            ]
            proof_state = [
                {
                    "node_id": node["node_id"],
                    "status": node["status"],
                    "proof_id": node["data"].get("proof_id"),
                    "claim_key": node["data"].get("claim_key"),
                    "intent_type": node["data"].get("intent_type"),
                }
                for node in failed_proofs
            ]
            conflict_state = [
                {
                    "node_id": node["node_id"],
                    "entity_type": node["entity_type"],
                    "status": node["status"],
                    "authority": node.get("authority"),
                    "statement_digest": digest_obj(
                        node["data"].get("statement") or ""),
                }
                for node in authority_conflicts
            ]
            project_events = self.store.events(
                project_id, tenant_id=self.tenant_id)
            project_frontier = {
                "count": len(project_events),
                "max_seq": (
                    max((event["seq"] for event in project_events), default=0)),
                "entries_digest": digest_obj([
                    {
                        "seq": event["seq"],
                        "event_id": event["event_id"],
                        "payload_digest": event["payload_digest"],
                        "entry_hash": event.get("entry_hash"),
                    }
                    for event in project_events
                ]),
            }
            event_chain = self.store.verify_chain("events")
            audit_chain = self.store.verify_chain("audit_log")
            event_checkpoint = {
                "count": self.store._conn.execute(
                    "SELECT COUNT(*) AS n FROM events").fetchone()["n"],
                "tip": self.store._chain_tip("events"),
                "intact": event_chain.get("intact"),
            }
            audit_checkpoint = {
                "count": self.store._conn.execute(
                    "SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"],
                "tip": self.store._chain_tip("audit_log"),
                "intact": audit_chain.get("intact"),
            }
            policy_digest = digest_obj(policy_config)
            projection_digest = self.projection_fingerprint(project_id)
            decision_state = {
                "invalidations": invalidation_state,
                "proofs": proof_state,
                "verifier_requirements": required_identities,
                "trusted_passes": trusted_passes,
                "verifier_gaps": sorted(verifier_gaps),
                "conflicts": conflict_state,
                "packet": packet_state,
                "revision": {
                    "tracked_ref": tracked_ref,
                    "current_head_sha": current_head,
                    "uncertain": frontier_uncertain,
                    "external_without_frontier": external_without_frontier,
                },
                # Counts and tips live in basis as prefix checkpoints. Only
                # integrity truth belongs in decision state, so an unrelated
                # project append does not stale this project's decision.
                "integrity": {
                    "event_log_intact": bool(event_chain.get("intact")),
                    "audit_log_intact": bool(audit_chain.get("intact")),
                },
            }
            predicates = _continuity_predicates(project_id, decision_state)
            decision_state["predicates"] = predicates
            satisfied = [item for item in predicates if item["satisfied"]]
            blockers = [item for item in predicates if not item["satisfied"]]
            conclusion = _continuity_decision(predicates)
            trust_unavailable = (
                not next(item for item in predicates if item["predicate"] ==
                         "revision_frontier_decidable")["satisfied"]
                or not next(item for item in predicates if item["predicate"] ==
                            "integrity_chains_intact")["satisfied"])
            decision_state_digest = digest_obj(decision_state)
            generated_at = utcnow()
            algorithm = getattr(self.signer, "algorithm", "unknown")
            self_authenticating = bool(
                getattr(self.signer, "self_authenticating", False))
            registry_capable = bool(
                not self_authenticating
                and callable(getattr(self.signer, "derive_fingerprint", None))
                and hasattr(self.signer, "registered_fingerprints"))
            if algorithm == "hmac-sha256" and self_authenticating:
                verification_mode = "locally_authenticated_mac"
            elif registry_capable:
                verification_mode = "registered_public_key"
            elif self_authenticating:
                verification_mode = "configured_authenticator"
            else:
                verification_mode = "unestablished_authenticity"
            receipt = {
                "schema_version": "cce.continuity-receipt.v1",
                "payload_type": _CONTINUITY_PAYLOAD_TYPE,
                "receipt_id": new_id("proof"),
                "generated_at": generated_at,
                "decision": conclusion,
                "audience": "operator",
                "privacy_notice": (
                    "Detailed receipts contain stable project, proof, "
                    "invalidation, verifier, and log identifiers. Publish "
                    "only a separately designed selective-disclosure view."),
                "issuer": {
                    "configured_key_id": getattr(
                        self.signer, "key_id", None),
                    "algorithm": algorithm,
                    "verification_mode": verification_mode,
                    "independently_verifiable": registry_capable,
                },
                "basis": {
                    "tenant_id": self.tenant_id,
                    "project_id": project_id,
                    "tracked_ref": tracked_ref,
                    "current_head_sha": current_head,
                    "policy_digest": policy_digest,
                    "projection_digest": projection_digest,
                    "decision_state_digest": decision_state_digest,
                    "project_event_frontier": project_frontier,
                    "event_log": event_checkpoint,
                    "audit_log": audit_checkpoint,
                },
                "satisfied": satisfied,
                "blockers": blockers,
                "flip_conditions": {
                    "semantics": "ceteris_paribus_boolean_frontier",
                    "to_success": {
                        "operator": "all",
                        "predicates": [
                            item["predicate"] for item in blockers
                        ],
                    },
                    "from_success": {
                        "operator": "any",
                        "predicates": [
                            item["predicate"] for item in satisfied
                        ],
                    },
                },
                "decision_state": decision_state,
                "trust_limit": (
                    "HMAC receipts are locally authenticated: a verifier "
                    "holding the shared key can also forge them. Public "
                    "non-repudiation requires a registered asymmetric signer "
                    "and an external transparency anchor. Flip conditions "
                    "are a frozen-state Boolean frontier, not a guarantee "
                    "that remediation will leave every other predicate fixed."),
            }
            receipt["receipt_digest"] = digest_obj({
                key: value for key, value in receipt.items()
                if key not in ("signature", "receipt_digest")
            })
            if _sign_receipt:
                receipt["signature"] = self.signer.sign(receipt)

            return {
                "name": "CCE Continuity",
                "conclusion": conclusion,
                "open_invalidations": [
                    item["node_id"] for item in open_inv],
                "critical": [item["node_id"] for item in critical],
                "pending_confirmation": [
                    item["node_id"] for item in pending],
                "failed_proofs": [
                    node["node_id"] for node in failed_proofs],
                "verifier_gaps": sorted(verifier_gaps),
                "authority_conflicts": [
                    node["node_id"] for node in authority_conflicts],
                "trust_unavailable": trust_unavailable,
                "generated_at": generated_at,
                "continuity_receipt": receipt,
            }

    @staticmethod
    def _invalid_receipt(reason: str) -> dict:
        return {"verdict": "INVALID", "current": False, "reason": reason}

    def _receipt_authenticator_valid(self, receipt: dict) -> tuple[bool, str]:
        """Verify integrity *and* out-of-band signer authenticity."""
        issuer = receipt.get("issuer")
        signature = receipt.get("signature")
        if not isinstance(issuer, dict) or not isinstance(signature, dict):
            return False, "receipt issuer and signature must be objects"
        algorithm = getattr(self.signer, "algorithm", None)
        key_id = getattr(self.signer, "key_id", None)
        if (not isinstance(algorithm, str)
                or issuer.get("algorithm") != algorithm
                or signature.get("algorithm") != algorithm):
            return False, "issuer, signature, and configured algorithms differ"
        if (issuer.get("configured_key_id") != key_id
                or signature.get("key_id") != key_id):
            return False, "issuer and signature key ids do not match the verifier"

        self_authenticating = bool(
            getattr(self.signer, "self_authenticating", False))
        registry_capable = bool(
            not self_authenticating
            and callable(getattr(self.signer, "derive_fingerprint", None))
            and hasattr(self.signer, "registered_fingerprints"))
        if algorithm == "hmac-sha256" and self_authenticating:
            expected_mode = "locally_authenticated_mac"
        elif registry_capable:
            expected_mode = "registered_public_key"
        elif self_authenticating:
            expected_mode = "configured_authenticator"
        else:
            expected_mode = "unestablished_authenticity"
        if (issuer.get("verification_mode") != expected_mode
                or issuer.get("independently_verifiable") is not
                registry_capable):
            return False, "issuer verification claims do not match signer capabilities"
        try:
            signature_ok = bool(self.signer.verify(receipt))
        except (KeyError, TypeError, ValueError):
            signature_ok = False
        if not signature_ok:
            return False, "receipt signature does not cover this content"
        if self_authenticating:
            return True, "configured authenticator verified"
        if not registry_capable:
            return False, "signer cannot establish authenticity out of band"

        actual = self.signer.derive_fingerprint(signature)
        claimed = signature.get("fingerprint")
        registry = set(getattr(self.signer, "registered_fingerprints", set()))
        if not actual or claimed != actual:
            return False, "declared fingerprint does not match the attached key"
        if actual not in registry:
            return False, "signature key is not present in the verifier registry"
        return True, "registered signer verified"

    def _chain_checkpoint_is_prefix(self, table: str, checkpoint: dict) -> bool:
        """Whether a signed global-chain checkpoint is a stored prefix."""
        if (table not in {"events", "audit_log"}
                or not isinstance(checkpoint, dict)
                or set(checkpoint) != {"count", "tip", "intact"}):
            return False
        count = checkpoint.get("count")
        tip = checkpoint.get("tip")
        intact = checkpoint.get("intact")
        if (isinstance(count, bool) or not isinstance(count, int) or count < 0
                or not isinstance(tip, str) or not isinstance(intact, bool)):
            return False
        if count == 0:
            from .store import GENESIS
            return tip == GENESIS
        row = self.store._conn.execute(
            f"SELECT entry_hash FROM {table} ORDER BY seq LIMIT 1 OFFSET ?",
            (count - 1,)).fetchone()
        return bool(row and row["entry_hash"] == tip)

    def _receipt_semantics_valid(
            self, project_id: str, receipt: dict) -> tuple[bool, str]:
        """Recompute v1 predicates, partition, flips, and conclusion."""
        basis = receipt.get("basis")
        state = receipt.get("decision_state")
        if not isinstance(basis, dict) or not isinstance(state, dict):
            return False, "receipt basis and decision_state must be objects"
        required_basis = {
            "tenant_id", "project_id", "tracked_ref", "current_head_sha",
            "policy_digest", "projection_digest", "decision_state_digest",
            "project_event_frontier", "event_log", "audit_log",
        }
        required_state = {
            "invalidations", "proofs", "verifier_requirements",
            "trusted_passes", "verifier_gaps", "conflicts", "packet",
            "revision", "integrity", "predicates",
        }
        if set(basis) != required_basis or set(state) != required_state:
            return False, "receipt decision basis has missing or unknown fields"
        if (basis.get("tenant_id") != self.tenant_id
                or basis.get("project_id") != project_id):
            return False, "receipt tenant/project scope does not match"
        if (not isinstance(state.get("packet"), dict)
                or not isinstance(state.get("revision"), dict)
                or not isinstance(state.get("integrity"), dict)
                or any(not isinstance(state.get(name), list) for name in (
                    "invalidations", "proofs", "verifier_requirements",
                    "trusted_passes", "verifier_gaps", "conflicts",
                    "predicates"))):
            return False, "receipt decision_state field types are invalid"
        nested_shapes = {
            "packet": {
                "packet_id", "last_event_seq", "packet_digest",
                "control_basis_digest", "audit_entry_hash", "current",
            },
            "revision": {
                "tracked_ref", "current_head_sha", "uncertain",
                "external_without_frontier",
            },
            "integrity": {"event_log_intact", "audit_log_intact"},
        }
        for name, fields in nested_shapes.items():
            if set(state[name]) != fields:
                return False, (
                    f"receipt decision_state.{name} has missing or unknown fields")
        record_shapes = {
            "invalidations": {
                "node_id", "status", "severity", "trigger_type",
                "target_node_id", "affected",
            },
            "proofs": {
                "node_id", "status", "proof_id", "claim_key", "intent_type",
            },
            "verifier_requirements": {
                "name", "pinned", "command_digest", "definition_digest",
            },
            "trusted_passes": {
                "node_id", "verifier", "source", "command_digest",
                "definition_digest",
                "head_sha", "app", "app_id", "workflow_id",
                "workflow_path", "installation_id",
            },
            "conflicts": {
                "node_id", "entity_type", "status", "authority",
                "statement_digest",
            },
        }
        for name, fields in record_shapes.items():
            if any(not isinstance(item, dict) or set(item) != fields
                   for item in state[name]):
                return False, (
                    f"receipt decision_state.{name} contains a malformed record")
        gaps = state["verifier_gaps"]
        if (any(not isinstance(name, str) for name in gaps)
                or gaps != sorted(set(gaps))):
            return False, "receipt verifier_gaps must be sorted unique names"
        project_frontier = basis.get("project_event_frontier")
        if (not isinstance(project_frontier, dict)
                or set(project_frontier) != {
                    "count", "max_seq", "entries_digest"}
                or isinstance(project_frontier.get("count"), bool)
                or not isinstance(project_frontier.get("count"), int)
                or project_frontier["count"] < 0
                or isinstance(project_frontier.get("max_seq"), bool)
                or not isinstance(project_frontier.get("max_seq"), int)
                or project_frontier["max_seq"] < 0
                or not isinstance(
                    project_frontier.get("entries_digest"), str)
                or _SHA256_DIGEST.fullmatch(
                    project_frontier["entries_digest"]) is None):
            return False, "receipt project event frontier is malformed"
        for field in (
                "policy_digest", "projection_digest",
                "decision_state_digest"):
            value = basis.get(field)
            if (not isinstance(value, str)
                    or _SHA256_DIGEST.fullmatch(value) is None):
                return False, f"receipt basis {field} is not a canonical digest"
        if basis.get("decision_state_digest") != digest_obj(state):
            return False, "decision_state digest does not match its contents"
        revision = state["revision"]
        if (basis.get("tracked_ref") != revision.get("tracked_ref")
                or basis.get("current_head_sha") !=
                revision.get("current_head_sha")):
            return False, "revision basis contradicts decision_state"
        event_checkpoint = basis.get("event_log")
        audit_checkpoint = basis.get("audit_log")
        if (not isinstance(event_checkpoint, dict)
                or not isinstance(audit_checkpoint, dict)
                or event_checkpoint.get("intact") is not
                state["integrity"].get("event_log_intact")
                or audit_checkpoint.get("intact") is not
                state["integrity"].get("audit_log_intact")):
            return False, "log basis contradicts integrity decision state"
        if (not self._chain_checkpoint_is_prefix("events", event_checkpoint)
                or not self._chain_checkpoint_is_prefix(
                    "audit_log", audit_checkpoint)):
            return False, "receipt log checkpoint is not a stored chain prefix"

        actual_predicates = state["predicates"]
        predicate_fields = {
            "predicate", "subject", "observed", "required", "satisfied",
            "evidence_digest", "remediation",
        }
        if any(not isinstance(item, dict) or set(item) != predicate_fields
               for item in actual_predicates):
            return False, "every decision predicate must be an object"
        actual_names = [item.get("predicate") for item in actual_predicates]
        if (len(actual_names) != len(set(actual_names))
                or set(actual_names) != _CONTINUITY_PREDICATE_NAMES):
            return False, "receipt predicate set is missing, unknown, or duplicated"
        expected_predicates = _continuity_predicates(project_id, state)
        actual_map = {item["predicate"]: item for item in actual_predicates}
        expected_map = {item["predicate"]: item for item in expected_predicates}
        if actual_map != expected_map:
            return False, "receipt predicate truth or evidence is contradictory"

        def partition(name: str) -> tuple[dict[str, dict] | None, str | None]:
            items = receipt.get(name)
            if not isinstance(items, list) or any(
                    not isinstance(item, dict) for item in items):
                return None, f"receipt {name} must be an array of predicates"
            names = [item.get("predicate") for item in items]
            if len(names) != len(set(names)):
                return None, f"receipt {name} contains duplicate predicates"
            return {item["predicate"]: item for item in items}, None

        satisfied_map, error = partition("satisfied")
        if error:
            return False, error
        blocker_map, error = partition("blockers")
        if error:
            return False, error
        expected_satisfied = {
            name: item for name, item in expected_map.items()
            if item["satisfied"]}
        expected_blockers = {
            name: item for name, item in expected_map.items()
            if not item["satisfied"]}
        if (satisfied_map != expected_satisfied
                or blocker_map != expected_blockers):
            return False, "satisfied and blockers are not the exact predicate partition"

        flips = receipt.get("flip_conditions")
        if (not isinstance(flips, dict)
                or set(flips) != {"semantics", "to_success", "from_success"}
                or flips.get("semantics") !=
                "ceteris_paribus_boolean_frontier"):
            return False, "flip conditions omit their ceteris-paribus semantics"
        to_success = flips.get("to_success")
        from_success = flips.get("from_success")
        if not isinstance(to_success, dict) or not isinstance(from_success, dict):
            return False, "flip condition branches must be objects"

        def names_are(branch: dict, operator: str, expected_names: set[str]) -> bool:
            names = branch.get("predicates")
            return bool(
                set(branch) == {"operator", "predicates"}
                and branch.get("operator") == operator
                and isinstance(names, list)
                and all(isinstance(name, str) for name in names)
                and len(names) == len(set(names))
                and set(names) == expected_names)

        if (not names_are(to_success, "all", set(expected_blockers))
                or not names_are(
                    from_success, "any", set(expected_satisfied))):
            return False, "flip sets do not match the predicate partition"
        expected_decision = _continuity_decision(expected_predicates)
        if receipt.get("decision") != expected_decision:
            return False, "receipt decision contradicts its predicates"
        return True, "receipt semantics are internally consistent"

    @serialized_access
    def verify_continuity_receipt(
            self, project_id: str, receipt: dict) -> dict:
        """Classify a receipt as invalid, authentic historical, or current."""
        required = {
            "schema_version", "payload_type", "receipt_id", "generated_at",
            "decision", "audience", "privacy_notice", "issuer", "basis",
            "satisfied", "blockers", "flip_conditions", "decision_state",
            "trust_limit", "receipt_digest", "signature",
        }
        if not isinstance(receipt, dict) or set(receipt) != required:
            return self._invalid_receipt(
                "continuity receipt has missing or unknown top-level fields")
        issuer = receipt.get("issuer")
        signature = receipt.get("signature")
        if (not isinstance(issuer, dict)
                or set(issuer) != {
                    "configured_key_id", "algorithm", "verification_mode",
                    "independently_verifiable"}
                or not isinstance(signature, dict)
                or not {"key_id", "algorithm", "value"} <= set(signature)
                or not set(signature) <= {
                    "key_id", "algorithm", "value", "fingerprint",
                    "public_key"}):
            return self._invalid_receipt(
                "receipt issuer or signature has missing or unknown fields")
        if (receipt.get("schema_version") != "cce.continuity-receipt.v1"
                or receipt.get("payload_type") != _CONTINUITY_PAYLOAD_TYPE
                or receipt.get("audience") != "operator"
                or not isinstance(receipt.get("receipt_id"), str)
                or not receipt["receipt_id"].startswith("prf_")
                or not is_canonical_utc_timestamp(
                    receipt.get("generated_at"))
                or not isinstance(receipt.get("privacy_notice"), str)
                or not receipt["privacy_notice"]
                or not isinstance(receipt.get("trust_limit"), str)
                or not receipt["trust_limit"]):
            return self._invalid_receipt(
                "unsupported schema, payload domain, or audience")
        try:
            expected = digest_obj({
                key: value for key, value in receipt.items()
                if key not in ("signature", "receipt_digest")
            })
        except (TypeError, ValueError, OverflowError, RecursionError):
            return self._invalid_receipt(
                "receipt is not finite canonical JSON")
        if receipt.get("receipt_digest") != expected:
            return self._invalid_receipt(
                "receipt digest does not cover its body")
        authentic, reason = self._receipt_authenticator_valid(receipt)
        if not authentic:
            return self._invalid_receipt(reason)
        try:
            semantic, reason = self._receipt_semantics_valid(project_id, receipt)
        except (KeyError, TypeError, ValueError, OverflowError):
            return self._invalid_receipt(
                "receipt semantic structure cannot be evaluated")
        if not semantic:
            return self._invalid_receipt(reason)

        basis = receipt["basis"]
        live = self.continuity_check(
            project_id, _sign_receipt=False)["continuity_receipt"]
        live_basis = live["basis"]
        frontier_fields = {
            "tracked_ref", "current_head_sha", "policy_digest",
            "projection_digest", "decision_state_digest",
            "project_event_frontier",
        }
        changed = sorted(
            field for field in frontier_fields
            if basis.get(field) != live_basis.get(field))
        if receipt.get("decision") != live.get("decision"):
            changed.append("decision")
        if changed:
            return {
                "verdict": "AUTHENTIC_HISTORICAL",
                "current": False,
                "changed": changed,
                "reason": (
                    "receipt is authentic but no longer describes the live "
                    "semantic continuity frontier"),
            }
        return {
            "verdict": "CURRENT",
            "current": True,
            "changed": [],
            "reason": (
                "receipt authenticity, semantics, and live frontier match"),
        }

    # ---------------------------------------------------------------- rebuild

    @staticmethod
    def _projection_value(value, aliases: dict[str, str], *,
                          anonymize_unknown_ids: bool = True):
        """Canonicalize semantic values while removing processor wall clocks."""
        if isinstance(value, dict):
            return {
                key: Engine._projection_value(
                    item, aliases,
                    anonymize_unknown_ids=anonymize_unknown_ids)
                for key, item in sorted(value.items())
                if key not in _VOLATILE_PROJECTION_KEYS
            }
        if isinstance(value, (list, tuple)):
            return [
                Engine._projection_value(
                    item, aliases,
                    anonymize_unknown_ids=anonymize_unknown_ids)
                for item in value
            ]
        if isinstance(value, str):
            if value in aliases:
                return aliases[value]
            if anonymize_unknown_ids and _INTERNAL_RANDOM_ID.fullmatch(value):
                return f"<{value.split('_', 1)[0]}-id>"
        return value

    def _semantic_projection(
            self, project_id: str, *, _with_origins: bool = False) -> dict:
        """Canonical event-derived graph state, including edge semantics.

        Random row ids, transaction clocks, and processor-generated wall
        clocks cannot survive a clean replay and are excluded. Typed state,
        authority, criticality, confidence, scope, causal edges, strengths,
        provenance events, and extractor identities are committed.
        """
        self._require_project(project_id)
        selected = []
        histories: dict[str, list[dict]] = {}
        for node in self.graph.current(
                project_id, tenant_id=self.tenant_id):
            history = self.graph.history(
                node["node_id"], tenant_id=self.tenant_id,
                project_id=project_id)
            if any(version.get("event_id") for version in history):
                selected.append(node)
                histories[node["node_id"]] = history

        aliases: dict[str, str] = {}
        for node in selected:
            stable_key = node["data"].get("stable_key")
            if stable_key:
                aliases[node["node_id"]] = (
                    f"stable:{node['entity_type']}:{stable_key}")
            elif node["entity_type"] == "event":
                aliases[node["node_id"]] = f"event:{node['node_id']}"
            elif node["entity_type"] == "project":
                aliases[node["node_id"]] = f"project:{project_id}"

        for node in selected:
            if node["node_id"] in aliases:
                continue
            event_ids = sorted({
                version["event_id"]
                for version in histories[node["node_id"]]
                if version.get("event_id")
            })
            hint = {
                "entity_type": node["entity_type"],
                "events": event_ids,
                "data": self._projection_value(node["data"], aliases),
            }
            aliases[node["node_id"]] = (
                f"derived:{node['entity_type']}:{digest_obj(hint)}")

        nodes = []
        node_origins = {}
        for node in selected:
            history = histories[node["node_id"]]
            event_ids = sorted({
                version["event_id"] for version in history
                if version.get("event_id")
            })
            nodes.append({
                "id": aliases[node["node_id"]],
                "entity_type": node["entity_type"],
                "status": node.get("status"),
                "criticality": node.get("criticality"),
                "authority": node.get("authority"),
                "confidence": node.get("confidence"),
                "scope": self._projection_value(node.get("scope"), aliases),
                "data": self._projection_value(node["data"], aliases),
                "event_ids": event_ids,
                "processors": sorted({
                    (
                        str(version.get("extractor") or ""),
                        str(version.get("extractor_version") or ""),
                    )
                    for version in history
                    if version.get("extractor")
                }),
            })
            if _with_origins:
                node_origins[aliases[node["node_id"]]] = {
                    "event_ids": event_ids,
                    # A runtime-created identity later touched by an event is
                    # a hybrid projection.  Retention-aware replay cannot
                    # prove how its runtime prefix should have been rebuilt.
                    "event_only": bool(history) and all(
                        version.get("event_id") for version in history),
                }

        edges = []
        edge_origins: dict[str, list[dict]] = {}
        for edge in self.graph.current_edges(
                project_id, event_derived_only=True,
                tenant_id=self.tenant_id):
            if edge["src_id"] not in aliases or edge["dst_id"] not in aliases:
                continue
            rendered = {
                "edge_type": edge["edge_type"],
                "src": aliases[edge["src_id"]],
                "dst": aliases[edge["dst_id"]],
                "strength": edge["strength"],
                "data": self._projection_value(edge.get("data"), aliases),
                "event_id": edge.get("event_id"),
            }
            edges.append(rendered)
            if _with_origins:
                history = self.store._conn.execute(
                    "SELECT event_id FROM edges WHERE edge_id = ? "
                    "ORDER BY version", (edge["edge_id"],)).fetchall()
                edge_origins.setdefault(
                    canonical_json(rendered), []).append({
                        "event_ids": sorted({
                            row["event_id"] for row in history
                            if row["event_id"]}),
                        "event_only": bool(history) and all(
                            row["event_id"] for row in history),
                    })
        nodes.sort(key=canonical_json)
        edges.sort(key=canonical_json)
        projection = {
            "schema_version": "cce.semantic-projection.v1",
            "project_id": project_id,
            "nodes": nodes,
            "edges": edges,
        }
        if _with_origins:
            projection["_origins"] = {
                "nodes": node_origins, "edges": edge_origins}
        return projection

    @serialized_access
    def projection_fingerprint(self, project_id: str) -> str:
        """Digest the complete event-derived semantic projection (CCG-006)."""
        return digest_obj(self._semantic_projection(project_id))

    @serialized_access
    def replay_completeness(self, project_id: str) -> dict:
        """Whether the log still holds what a rebuild would need (CCG-006).

        Retention (SEC-006) nulls raw payloads past the window while keeping
        every digest, id and timestamp. That is deliberate, and it means the
        projection can no longer be rebuilt from the log alone: replay of a
        cleared event extracts nothing. Before this existed, the first
        retention sweep turned `cce-engine rebuild` into a permanent DIVERGES with
        no indication why — reporting a designed trade-off as if it were
        corruption or a processor bug, which are the opposite diagnosis
        (ADR-063).

        An event that never carried a payload is not redacted; its digest is
        the digest of the empty string, which is how the two are told apart.
        """
        empty = sha256_hex("")
        self._require_project(project_id)
        total = redacted = 0
        for row in self.store.events(
                project_id, tenant_id=self.tenant_id):
            total += 1
            if row["payload"] is None and row["payload_digest"] != empty:
                redacted += 1
        return {
            "events": total,
            "redacted_payloads": redacted,
            "replayable": redacted == 0,
            "note": None if redacted == 0 else
                    f"{redacted} of {total} event payloads were cleared by the"
                    f" retention policy; the projection cannot be rebuilt from"
                    f" the log alone, and this is permanent by design",
        }

    @serialized_access
    def replay_agrees_where_replayable(self, project_id: str,
                                       fresh: "Engine") -> dict:
        """Compare every semantic node and edge a retained suffix produced.

        A rebuild that lost its prefix cannot match a full fingerprint, but
        every node and causal edge it DID produce must still agree with the
        live projection, including authority, status, criticality, confidence,
        scope, extractor identity, edge type, strength, and edge data.
        That distinguishes 'retention removed the inputs' from 'retention
        removed the inputs AND something else is also wrong'.
        """
        live = self._semantic_projection(project_id, _with_origins=True)
        origins = live.pop("_origins")
        replayed = fresh._semantic_projection(project_id)
        live_nodes = {node["id"]: node for node in live["nodes"]}
        replayed_nodes = {
            node["id"]: node for node in replayed["nodes"]}
        empty = sha256_hex("")
        replayable_event_ids = {
            event["event_id"] for event in self.store.events(
                project_id, tenant_id=self.tenant_id)
            if event["payload"] is not None
            or event["payload_digest"] == empty
        }
        disagreements = []
        checked_nodes = 0
        for node in replayed["nodes"]:
            semantic_id = node["id"]
            expected = live_nodes.get(semantic_id)
            if expected is None:
                disagreements.append({
                    "kind": "node", "semantic_id": semantic_id,
                    "issue": "replayed but not live"})
                continue
            checked_nodes += 1
            if node != expected:
                disagreements.append({
                    "kind": "node", "semantic_id": semantic_id,
                    "issue": "replayed differently",
                    "live": expected, "replayed": node})

        # The reverse direction matters whenever retention has removed an
        # unrelated prefix: otherwise an extra live projection row sourced by
        # a fully retained event disappears from the comparison.  Restrict
        # this claim to event-only identities whose entire source set remains
        # replayable; runtime/event hybrids are outside the rebuild contract.
        for semantic_id, node in live_nodes.items():
            if semantic_id in replayed_nodes:
                continue
            origin = origins["nodes"].get(semantic_id) or {}
            event_ids = set(origin.get("event_ids") or [])
            if (not origin.get("event_only") or not event_ids
                    or not event_ids <= replayable_event_ids):
                continue
            checked_nodes += 1
            disagreements.append({
                "kind": "node", "semantic_id": semantic_id,
                "issue": "live but not replayed from retained events",
                "live": node,
            })

        live_edges = Counter(canonical_json(edge) for edge in live["edges"])
        replayed_edges = Counter(
            canonical_json(edge) for edge in replayed["edges"])
        checked_edges = sum(replayed_edges.values())
        for encoded, count in (replayed_edges - live_edges).items():
            disagreements.append({
                "kind": "edge", "issue": "replayed but not live or differs",
                "count": count, "replayed": strict_json_loads(encoded)})
        for encoded, count in (live_edges - replayed_edges).items():
            eligible = [
                origin for origin in origins["edges"].get(encoded, [])
                if origin.get("event_only")
                and set(origin.get("event_ids") or [])
                and set(origin.get("event_ids") or []) <= replayable_event_ids
            ]
            eligible_count = min(count, len(eligible))
            if not eligible_count:
                continue
            checked_edges += eligible_count
            disagreements.append({
                "kind": "edge",
                "issue": "live but not replayed from retained events",
                "count": eligible_count, "live": strict_json_loads(encoded)})
        return {
            "compared": checked_nodes + checked_edges,
            "compared_nodes": checked_nodes,
            "compared_edges": checked_edges,
            "disagreements": disagreements,
            "agrees": not disagreements,
        }

    @serialized_access
    def rebuild_projection(self, project_id: str) -> "Engine":
        """Replay the canonical event log into a fresh in-memory engine."""
        fresh = Engine(":memory:", tenant_id=self.tenant_id, signer=self.signer)
        project = self._require_project(project_id)
        fresh.create_project(
            project["data"].get("name", project_id),
            repository=project["data"].get("repository"),
            repository_id=project["data"].get("repository_id"),
            github_installation_id=project["data"].get(
                "github_installation_id"),
            capture_mode=project["data"].get("capture_mode", "redacted"),
            config=self.policy.project_config(project_id),
            project_id=project_id)
        for event in self.store.events(
                project_id, tenant_id=self.tenant_id):
            with fresh.store.write_scope():
                fresh.store._conn.execute(
                    "INSERT OR IGNORE INTO events (event_id, tenant_id, project_id,"
                    " source_type, source_id, idempotency_key, observed_at,"
                    " recorded_at, valid_from, valid_to, actor_type, actor_id,"
                    " authority, sensitivity, capture_mode, payload_digest,"
                    " stored_payload_digest, payload, schema_version, seq)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (event["event_id"], event["tenant_id"], event["project_id"],
                     event["source_type"], event["source_id"],
                     event["idempotency_key"], event["observed_at"],
                     event["recorded_at"], event["valid_from"], event["valid_to"],
                     event["actor_type"], event["actor_id"], event["authority"],
                      event["sensitivity"], event["capture_mode"],
                      event["payload_digest"], event["stored_payload_digest"],
                      canonical_json(event["payload"])
                      if event["payload"] is not None else None,
                     event["schema_version"], event["seq"]))
            # Replay must be at least as tolerant as live ingestion. Live
            # processing quarantines an event whose extraction raises and
            # carries on (ADR-036); if replay instead aborted, a single
            # quarantined event would make the projection permanently
            # unrebuildable and CCG-006 unverifiable from then on.
            try:
                with fresh.store.transaction():
                    # The replay store has its own chain metadata. Process
                    # the exact row canonical to that store rather than the
                    # source store's otherwise-identical row.
                    fresh.process_event(fresh.store.get_event(
                        event["event_id"], tenant_id=self.tenant_id,
                        project_id=project_id))
                    fresh.store.mark_processed(
                        event["event_id"], PROCESSOR_VERSION, "ok")
            except Exception as exc:
                fresh.store.mark_processed(
                    event["event_id"], PROCESSOR_VERSION,
                    "quarantined", repr(exc))
        return fresh
