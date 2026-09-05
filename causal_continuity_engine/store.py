"""Immutable event/evidence store (ADR-001) on SQLite (ADR-011).

Canonical truth is the append-only event log plus content-addressed evidence
blobs. Graph rows (graph.py) are rebuildable projections. Canonical events and
evidence are never updated in place; corrections are new events. Retention may
clear stored event payloads, and processing metadata is updated as event
handling advances. Those mutable operational fields are authenticated by the
stored-payload commitment, event chain, and audit records.

CCG-001: redelivery of the same source event (idempotency key) creates no
duplicate semantic event; a payload digest mismatch on redelivery is flagged,
never silently merged.
"""

from __future__ import annotations

import re
import sqlite3
import threading
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from .core import (
    canonical_json,
    is_canonical_utc_timestamp,
    is_public_identifier,
    is_rfc3339_datetime,
    new_id,
    sha256_hex,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
)


def serialized_access(method):
    """Serialize same-connection reads with transactions in other threads.

    SQLite isolates separate connections, but one shared connection exposes
    its own uncommitted writes to every thread using it. Every storage-backed
    reader therefore shares the Store's re-entrant lock.
    """
    @wraps(method)
    def locked(instance, *args, **kwargs):
        store = getattr(instance, "store", instance)
        with store._lock:
            return method(instance, *args, **kwargs)
    return locked


#: Chain genesis. A chain whose first link declares any other predecessor
#: has had entries removed from its head.
GENESIS = "sha256:" + "0" * 64

_ANCHOR_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ANCHOR_REQUIRED_FIELDS = frozenset({
    "schema_version", "table", "count", "tip", "intact_at_export",
    "exported_at",
})
_ANCHOR_BINDING_FIELDS = frozenset({"tenant_id", "project_id"})


class AnchorExportError(RuntimeError):
    """A broken chain cannot be represented as a publishable v1 anchor."""


#: Every event column the chain covers. Mutable `payload` bytes are represented
#: by `stored_payload_digest`, so retention redaction cannot break the chain;
#: everything else that
#: describes the event — including who it came from, its validity window and
#: its sensitivity classification — is bound.
_EVENT_CHAINED_COLUMNS = (
    "event_id", "tenant_id", "project_id", "source_type", "source_id",
    "idempotency_key", "observed_at", "recorded_at", "valid_from", "valid_to",
    "actor_type", "actor_id", "authority", "sensitivity", "capture_mode",
    "payload_digest", "stored_payload_digest", "schema_version", "seq",
)

_EVENT_AUTHORITIES = frozenset({
    "untrusted_content", "agent_inference", "agent_observed",
    "human_intent", "repository_authoritative", "verifier_authoritative",
    "human_decision", "tenant_policy",
})
_EVENT_ACTOR_TYPES = frozenset({"human", "agent", "service", None})
_EVENT_CAPTURE_MODES = frozenset({"metadata_only", "redacted", "full"})
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID_RE = re.compile(r"^evt_[0-9a-f]{24}$")
def _require_nonempty_string(name: str, value) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")


def _validate_log_text(
        name: str, value, *, nullable: bool = False,
        max_length: int = 262_144) -> str | None:
    """Validate text before SQLite affinity can change its chained identity."""
    if value is None and nullable:
        return None
    return validate_human_text(value, field=name, max_length=max_length)


def _validate_datetime(name: str, value, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not is_rfc3339_datetime(value):
        raise ValueError(f"{name} must be an RFC 3339 date-time") from None


def _validate_digest(name: str, value) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 digest URI")


def _validate_stored_event(event: dict) -> None:
    """Enforce cce.event.v1 at the write boundary without jsonschema."""
    expected = {
        "event_id", "tenant_id", "project_id", "source_type", "source_id",
        "idempotency_key", "observed_at", "recorded_at", "valid_from",
        "valid_to", "actor_type", "actor_id", "authority", "sensitivity",
        "capture_mode", "payload_digest", "stored_payload_digest", "payload",
        "schema_version", "seq", "prev_hash", "entry_hash",
    }
    if set(event) != expected:
        raise ValueError("stored event fields do not match cce.event.v1")
    if _EVENT_ID_RE.fullmatch(event["event_id"]) is None:
        raise ValueError("event_id does not match cce.event.v1")
    validate_public_identifier(event["tenant_id"], field="tenant_id")
    validate_public_identifier(event["project_id"], field="project_id")
    for field in (
            "tenant_id", "project_id", "source_type", "idempotency_key",
            "sensitivity"):
        _require_nonempty_string(field, event[field])
    for field in ("source_id", "actor_id"):
        if event[field] is not None and not isinstance(event[field], str):
            raise ValueError(f"{field} must be a string or null")
    for field in ("observed_at", "recorded_at"):
        _validate_datetime(field, event[field])
    for field in ("valid_from", "valid_to"):
        _validate_datetime(field, event[field], nullable=True)
    if (event["actor_type"] is not None
            and not isinstance(event["actor_type"], str)):
        raise ValueError("actor_type is not allowed by cce.event.v1")
    if event["actor_type"] not in _EVENT_ACTOR_TYPES:
        raise ValueError("actor_type is not allowed by cce.event.v1")
    if (not isinstance(event["authority"], str)
            or event["authority"] not in _EVENT_AUTHORITIES):
        raise ValueError("authority is not allowed by cce.event.v1")
    if (not isinstance(event["capture_mode"], str)
            or event["capture_mode"] not in _EVENT_CAPTURE_MODES):
        raise ValueError("capture_mode is not allowed by cce.event.v1")
    if event["schema_version"] != "cce.event.v1":
        raise ValueError("schema_version must be cce.event.v1")
    if (isinstance(event["seq"], bool) or not isinstance(event["seq"], int)
            or event["seq"] < 1):
        raise ValueError("seq must be a positive integer")
    for field in (
            "payload_digest", "stored_payload_digest", "prev_hash",
            "entry_hash"):
        _validate_digest(field, event[field])
    payload = event["payload"]
    if payload is not None and not isinstance(payload, dict):
        raise ValueError("event payload must be an object or null")
    try:
        persisted = "" if payload is None else canonical_json(payload)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("event payload must be canonical JSON") from None
    if sha256_hex(persisted) != event["stored_payload_digest"]:
        raise ValueError(
            "stored_payload_digest does not authenticate the stored payload")


def _event_entry(data) -> dict:
    # Rows created before the persisted-payload commitment existed have a
    # NULL added by migration and retain their original chain identity. They
    # are readable only after redaction; non-null legacy payloads fail closed
    # in _event_dict because their bytes were never committed.
    return {
        key: data[key] for key in _EVENT_CHAINED_COLUMNS
        if key != "stored_payload_digest"
        or data.get("stored_payload_digest") is not None
    }


def _link(prev_hash: str, entry: dict) -> str:
    """Hash-chain link: SHA-256 over the predecessor and this entry.

    Deliberately excludes raw payloads and covers both the source-body digest
    used for idempotency and the exact persisted-payload digest. Retention can
    null the bytes without rewriting either commitment.
    """
    return sha256_hex(f"{prev_hash}\n{canonical_json(entry)}")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_id       TEXT,
    idempotency_key TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    recorded_at     TEXT NOT NULL,
    valid_from      TEXT,
    valid_to        TEXT,
    actor_type      TEXT,
    actor_id        TEXT,
    authority       TEXT NOT NULL,
    sensitivity     TEXT NOT NULL DEFAULT 'internal',
    capture_mode    TEXT NOT NULL DEFAULT 'full',
    payload_digest  TEXT NOT NULL,
    stored_payload_digest TEXT NOT NULL,
    payload         TEXT,
    schema_version  TEXT NOT NULL,
    seq             INTEGER,
    prev_hash       TEXT,
    entry_hash      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id, observed_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_idempotency_scope
ON events(tenant_id, project_id, idempotency_key);

CREATE TABLE IF NOT EXISTS event_seq (n INTEGER);

-- Serialises hash-chain appends across processes (ADR-046). Reading the
-- chain tip and writing the next link must be one atomic step; a plain
-- SELECT takes only a read lock, so two connections can read the same tip
-- and both append from it, forking the chain. Bumping this row first takes
-- SQLite's write lock and makes the pair atomic. `events` already had this
-- property by accident, because it bumps event_seq before reading the tip.
CREATE TABLE IF NOT EXISTS chain_lock (
    table_name TEXT PRIMARY KEY,
    n          INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO chain_lock (table_name, n) VALUES ('audit_log', 0);
INSERT OR IGNORE INTO chain_lock (table_name, n) VALUES ('events', 0);

CREATE TABLE IF NOT EXISTS payload_mismatches (
    idempotency_key TEXT NOT NULL,
    existing_digest TEXT NOT NULL,
    new_digest      TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_blobs (
    digest      TEXT PRIMARY KEY,
    content     BLOB,
    media_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
    size        INTEGER NOT NULL,
    sensitivity TEXT NOT NULL DEFAULT 'internal',
    captured_at TEXT NOT NULL,
    deleted_at  TEXT
);

CREATE TABLE IF NOT EXISTS processed_events (
    event_id          TEXT NOT NULL,
    processor_version TEXT NOT NULL,
    processed_at      TEXT NOT NULL,
    status            TEXT NOT NULL,      -- ok | quarantined
    error             TEXT,
    PRIMARY KEY (event_id, processor_version)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    object_id  TEXT,
    before_ref TEXT,
    after_ref  TEXT,
    authority  TEXT,
    detail     TEXT,
    prev_hash  TEXT,
    entry_hash TEXT
);

-- Tamper evidence (SEC-007, ADR-028). "Append-only" was an API convention:
-- anyone holding the SQLite file could UPDATE a row and nothing would show.
-- These triggers make rewriting canonical history an error rather than a
-- silent success. Event payloads remain updatable in one direction only,
-- so retention deletion can null them. The chain covers both the raw-source
-- payload_digest and the exact persisted-byte stored_payload_digest, so
-- redaction cannot break integrity and pre-redaction identity stays distinct.
CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only: delete is not permitted'); END;

CREATE TRIGGER IF NOT EXISTS events_no_rewrite
BEFORE UPDATE OF event_id, tenant_id, project_id, source_type, source_id,
                 idempotency_key, observed_at, recorded_at, authority,
                 payload_digest, stored_payload_digest, schema_version, seq,
                 prev_hash, entry_hash,
                 valid_from, valid_to, actor_type, actor_id, sensitivity,
                 capture_mode
ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only: this column is immutable'); END;

CREATE TRIGGER IF NOT EXISTS events_payload_redaction_only
BEFORE UPDATE OF payload ON events
WHEN NEW.payload IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'event payloads may only be redacted, never rewritten'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;

-- Evidence is immutable except for the one-way content redaction required by
-- retention. The digest and metadata remain as a tombstone so references and
-- deletion audit records keep resolving without retaining the private bytes.
CREATE TRIGGER IF NOT EXISTS evidence_no_delete
BEFORE DELETE ON evidence_blobs
BEGIN SELECT RAISE(ABORT, 'evidence rows are immutable tombstones'); END;

CREATE TRIGGER IF NOT EXISTS evidence_metadata_no_rewrite
BEFORE UPDATE OF digest, media_type, size, sensitivity, captured_at ON evidence_blobs
BEGIN SELECT RAISE(ABORT, 'evidence metadata is immutable'); END;

CREATE TRIGGER IF NOT EXISTS evidence_content_redaction_only
BEFORE UPDATE OF content ON evidence_blobs
WHEN NOT (OLD.content IS NOT NULL AND NEW.content IS NULL
          AND OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'evidence content may only be redacted with a tombstone'); END;

CREATE TRIGGER IF NOT EXISTS evidence_deleted_at_redaction_only
BEFORE UPDATE OF deleted_at ON evidence_blobs
WHEN NOT (OLD.content IS NOT NULL AND NEW.content IS NULL
          AND OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'evidence deletion time may only accompany redaction'); END;
"""


class DuplicateEventError(Exception):
    """Same idempotency key, same payload digest: benign redelivery."""

    def __init__(self, event_id: str):
        super().__init__(f"duplicate delivery of {event_id}")
        self.event_id = event_id


class PayloadMismatchError(Exception):
    """Same idempotency key, different payload digest: flagged, rejected."""


class EvidenceIntegrityError(Exception):
    """Stored evidence bytes no longer match their content address."""


class EventPayloadIntegrityError(Exception):
    """Persisted event payload bytes lack or contradict their commitment."""


class Store:
    def __init__(self, path: str | Path = ":memory:", *, _pre_schema_check=None):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        try:
            self._conn.row_factory = sqlite3.Row
            # Compatibility refusal must see the connection Store will use,
            # but must run before WAL selection or any schema installation can
            # change an existing database (ADR-106).
            if _pre_schema_check is not None:
                _pre_schema_check(self._conn)
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            # A second writer waits rather than failing outright; chain appends
            # are short, so contention resolves quickly (ADR-046).
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._lock = threading.RLock()
        except BaseException as initialization_error:
            try:
                self._conn.close()
            except Exception as cleanup_error:
                initialization_error.add_note(
                    "additionally failed to close SQLite connection: "
                    f"{cleanup_error!r}")
            raise
        # Explicit outer transactions hold _lock for their whole lifetime,
        # so this depth is only observed by the owning thread. Participating
        # write methods use write_scope() and cannot accidentally commit the
        # outer unit halfway through projection.
        self._transaction_depth = 0
        with self._lock:
            # Install the current schema first. executescript() commits
            # implicitly, so every migration-sensitive operation below uses
            # single-statement execute() calls inside one owned writer lock.
            try:
                self._conn.executescript(_SCHEMA)
                # Serialize schema inspection and replacement across processes;
                # the losing opener re-inspects only after the winner commits.
                self._conn.execute("BEGIN IMMEDIATE")
                event_columns = {
                    row["name"] for row in self._conn.execute(
                        "PRAGMA table_info(events)")}
                if "stored_payload_digest" not in event_columns:
                    self._conn.execute(
                        "ALTER TABLE events "
                        "ADD COLUMN stored_payload_digest TEXT")
                self._migrate_global_event_idempotency()

                # A table rebuild removes its indexes and triggers. Repair
                # these while the same writer transaction still excludes a
                # concurrent initializer.
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_project "
                    "ON events(project_id, observed_at)")
                self._conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "idx_events_idempotency_scope "
                    "ON events(tenant_id, project_id, idempotency_key)")
                self._conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS events_no_delete
                    BEFORE DELETE ON events
                    BEGIN SELECT RAISE(
                        ABORT, 'events are append-only: delete is not permitted');
                    END
                """)
                self._conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS events_payload_redaction_only
                    BEFORE UPDATE OF payload ON events
                    WHEN NEW.payload IS NOT NULL
                    BEGIN SELECT RAISE(
                        ABORT, 'event payloads may only be redacted, never rewritten');
                    END
                """)
                # CREATE TRIGGER IF NOT EXISTS cannot upgrade an older
                # definition. Compare the installed SQL and replace only a
                # stale definition: dropping/recreating this trigger on every
                # open turned read-only CLI commands into database writes.
                desired_no_rewrite = """
                    CREATE TRIGGER events_no_rewrite
                    BEFORE UPDATE OF event_id, tenant_id, project_id,
                        source_type, source_id, idempotency_key, observed_at,
                        recorded_at, authority, payload_digest,
                        stored_payload_digest, schema_version, seq, prev_hash,
                        entry_hash, valid_from, valid_to, actor_type, actor_id,
                        sensitivity, capture_mode
                    ON events
                    BEGIN SELECT RAISE(
                        ABORT, 'events are append-only: this column is immutable');
                    END
                """
                installed = self._conn.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type = 'trigger' AND name = 'events_no_rewrite'"
                ).fetchone()

                def normalized_sql(value: str | None) -> str:
                    return re.sub(r"\s+", " ", value or "").strip().rstrip(
                        ";").casefold()

                if (installed is None
                        or normalized_sql(installed["sql"])
                        != normalized_sql(desired_no_rewrite)):
                    self._conn.execute(
                        "DROP TRIGGER IF EXISTS events_no_rewrite")
                    self._conn.execute(desired_no_rewrite)
                cur = self._conn.execute("SELECT COUNT(*) FROM event_seq")
                if cur.fetchone()[0] == 0:
                    self._conn.execute("INSERT INTO event_seq (n) VALUES (0)")
                self._conn.commit()
            except BaseException as initialization_error:
                try:
                    if self._conn.in_transaction:
                        self._conn.rollback()
                except Exception as cleanup_error:
                    initialization_error.add_note(
                        "additionally failed to roll back SQLite initialization: "
                        f"{cleanup_error!r}")
                try:
                    self._conn.close()
                except Exception as cleanup_error:
                    initialization_error.add_note(
                        "additionally failed to close SQLite connection: "
                        f"{cleanup_error!r}")
                raise

    def _migrate_global_event_idempotency(self) -> bool:
        """Replace the legacy globally-unique delivery key in place.

        Provider delivery ids are project-local namespaces. A global UNIQUE
        constraint lets one tenant suppress another tenant's event. SQLite
        cannot drop that inline constraint, so existing stores need a
        lossless table rebuild. Hash-chain values are copied byte-for-byte.
        """
        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'events'"
        ).fetchone()
        compact = "".join(((row["sql"] if row else "") or "").upper().split())
        if "IDEMPOTENCY_KEYTEXTNOTNULLUNIQUE" not in compact:
            return False

        columns = (
            "event_id, tenant_id, project_id, source_type, source_id, "
            "idempotency_key, observed_at, recorded_at, valid_from, valid_to, "
            "actor_type, actor_id, authority, sensitivity, capture_mode, "
            "payload_digest, stored_payload_digest, payload, schema_version, "
            "seq, prev_hash, entry_hash"
        )
        self._conn.execute("ALTER TABLE events RENAME TO events_global_idempotency")
        self._conn.execute("""
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_id TEXT,
                idempotency_key TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                valid_from TEXT,
                valid_to TEXT,
                actor_type TEXT,
                actor_id TEXT,
                authority TEXT NOT NULL,
                sensitivity TEXT NOT NULL DEFAULT 'internal',
                capture_mode TEXT NOT NULL DEFAULT 'full',
                payload_digest TEXT NOT NULL,
                stored_payload_digest TEXT,
                payload TEXT,
                schema_version TEXT NOT NULL,
                seq INTEGER,
                prev_hash TEXT,
                entry_hash TEXT
            )
        """)
        self._conn.execute(
            f"INSERT INTO events ({columns}) "
            f"SELECT {columns} FROM events_global_idempotency")
        self._conn.execute("DROP TABLE events_global_idempotency")
        return True

    @serialized_access
    def close(self):
        self._conn.close()

    # ------------------------------------------------------------ transactions

    @contextmanager
    def transaction(self):
        """One atomic Store/Graph write unit, with safe nested savepoints.

        Methods that use :meth:`write_scope` join this transaction instead of
        committing independently. ``append_event`` deliberately remains a
        standalone canonical-log append; callers start a transaction only for
        the projection performed after that append succeeds.
        """
        with self._lock:
            nested = self._transaction_depth > 0
            savepoint = f"cce_store_tx_{self._transaction_depth}"
            if nested:
                self._conn.execute(f"SAVEPOINT {savepoint}")
            else:
                if self._conn.in_transaction:
                    raise RuntimeError(
                        "cannot start Store.transaction() inside an unmanaged transaction")
                self._conn.execute("BEGIN IMMEDIATE")
            self._transaction_depth += 1
            try:
                yield self
            except BaseException:
                self._transaction_depth -= 1
                if nested:
                    self._conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                else:
                    self._conn.rollback()
                raise
            else:
                self._transaction_depth -= 1
                if nested:
                    self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                else:
                    try:
                        self._conn.commit()
                    except BaseException:
                        # Deferred constraints can fail only at COMMIT and
                        # leave SQLite's transaction open. Never return a
                        # depth-zero Store with a poisoned unmanaged tx.
                        if self._conn.in_transaction:
                            self._conn.rollback()
                        raise

    @contextmanager
    def write_scope(self):
        """Join an outer transaction, or commit this write standalone."""
        with self._lock:
            if self._transaction_depth:
                yield self._conn
            else:
                with self._conn:
                    yield self._conn

    @contextmanager
    def read_snapshot(self):
        """Hold one coherent SQLite view across a multi-query decision."""
        with self._lock:
            if self._transaction_depth:
                yield self._conn
                return
            if self._conn.in_transaction:
                raise RuntimeError(
                    "cannot start a read snapshot inside an unmanaged transaction")
            self._conn.execute("BEGIN")
            try:
                yield self._conn
            finally:
                if self._conn.in_transaction:
                    self._conn.rollback()

    # ------------------------------------------------------------------ events

    def append_event(
        self,
        *,
        tenant_id: str,
        project_id: str,
        source_type: str,
        idempotency_key: str,
        payload: dict | None,
        authority: str,
        observed_at: str | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        actor_type: str = "service",
        actor_id: str = "cce",
        source_id: str | None = None,
        sensitivity: str = "internal",
        capture_mode: str = "full",
        schema_version: str = "cce.event.v1",
        payload_digest: str | None = None,
    ) -> dict:
        """Append an immutable event. Returns the stored event row as a dict.

        Raises DuplicateEventError on benign redelivery and
        PayloadMismatchError when the same key arrives with different content.
        """
        for field, value in (
                ("tenant_id", tenant_id), ("project_id", project_id),
                ("source_type", source_type),
                ("idempotency_key", idempotency_key),
                ("sensitivity", sensitivity)):
            _require_nonempty_string(field, value)
        tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        project_id = validate_public_identifier(project_id, field="project_id")
        if payload is not None and not isinstance(payload, dict):
            raise ValueError("event payload must be an object or null")
        if source_id is not None and not isinstance(source_id, str):
            raise ValueError("source_id must be a string or null")
        if actor_id is not None and not isinstance(actor_id, str):
            raise ValueError("actor_id must be a string or null")
        if actor_type is not None and not isinstance(actor_type, str):
            raise ValueError("actor_type is not allowed by cce.event.v1")
        if actor_type not in _EVENT_ACTOR_TYPES:
            raise ValueError("actor_type is not allowed by cce.event.v1")
        if (not isinstance(authority, str)
                or authority not in _EVENT_AUTHORITIES):
            raise ValueError("authority is not allowed by cce.event.v1")
        if (not isinstance(capture_mode, str)
                or capture_mode not in _EVENT_CAPTURE_MODES):
            raise ValueError("capture_mode is not allowed by cce.event.v1")
        if schema_version != "cce.event.v1":
            raise ValueError("schema_version must be cce.event.v1")
        for field, value in (
                ("observed_at", observed_at), ("valid_from", valid_from),
                ("valid_to", valid_to)):
            _validate_datetime(field, value, nullable=True)
        if payload_digest is not None:
            _validate_digest("payload_digest", payload_digest)
        try:
            payload_text = None if payload is None else canonical_json(payload)
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise ValueError("event payload must be canonical JSON") from None
        digest = payload_digest or sha256_hex(payload_text or "")
        stored_digest = sha256_hex(payload_text or "")
        now = utcnow()
        with self._lock:
            if self._transaction_depth:
                raise RuntimeError(
                    "append_event is a standalone canonical-log commit; append it before "
                    "opening the projection transaction")
            # Acquire SQLite's cross-process writer lock before looking up
            # the key. A SELECT-first sequence lets two processes both see
            # absence and race the insert.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT event_id, payload_digest FROM events "
                    "WHERE tenant_id = ? AND project_id = ? AND idempotency_key = ?",
                    (tenant_id, project_id, idempotency_key),
                ).fetchone()
                if row is not None and row["payload_digest"] == digest:
                    self._conn.commit()
                    raise DuplicateEventError(row["event_id"])
                if row is not None:
                    self._conn.execute(
                        "INSERT INTO payload_mismatches VALUES (?,?,?,?)",
                        (idempotency_key, row["payload_digest"], digest, now),
                    )
                    # CCG-001 requires the mismatch flag to survive the
                    # rejection raised to the caller.
                    self._conn.commit()
                    raise PayloadMismatchError(
                        f"idempotency key {idempotency_key!r} redelivered with"
                        " different payload"
                    )
                self._conn.execute("UPDATE event_seq SET n = n + 1")
                seq = self._conn.execute("SELECT n FROM event_seq").fetchone()[0]
                event_id = new_id("event")
                prev_hash = self._chain_tip("events")
                observed = observed_at or now
                valid_start = valid_from or observed
                entry = {
                    "event_id": event_id, "tenant_id": tenant_id,
                    "project_id": project_id, "source_type": source_type,
                    "source_id": source_id, "idempotency_key": idempotency_key,
                    "observed_at": observed, "recorded_at": now,
                    "valid_from": valid_start,
                    "valid_to": valid_to, "actor_type": actor_type,
                    "actor_id": actor_id, "authority": authority,
                    "sensitivity": sensitivity, "capture_mode": capture_mode,
                    "payload_digest": digest,
                    "stored_payload_digest": stored_digest,
                    "schema_version": schema_version, "seq": seq,
                }
                entry_hash = _link(prev_hash, _event_entry(entry))
                stored_event = entry | {
                    "payload": payload, "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                }
                _validate_stored_event(stored_event)
                self._conn.execute(
                    "INSERT INTO events (event_id, tenant_id, project_id, source_type,"
                    " source_id, idempotency_key, observed_at, recorded_at, valid_from,"
                    " valid_to, actor_type, actor_id, authority, sensitivity,"
                    " capture_mode, payload_digest, stored_payload_digest, payload,"
                    " schema_version, seq, prev_hash, entry_hash)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event_id, tenant_id, project_id, source_type, source_id,
                        idempotency_key, observed, now,
                        valid_start, valid_to, actor_type,
                        actor_id, authority, sensitivity, capture_mode,
                        digest, stored_digest, payload_text, schema_version, seq,
                        prev_hash, entry_hash,
                    ),
                )
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.rollback()
                raise
            else:
                self._conn.commit()
        return self.get_event(event_id)

    @serialized_access
    def get_event(
            self, event_id: str, *, tenant_id: str | None = None,
            project_id: str | None = None) -> dict:
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None \
                or (tenant_id is not None and row["tenant_id"] != tenant_id) \
                or (project_id is not None and row["project_id"] != project_id):
            raise KeyError(event_id)
        return self._event_dict(row)

    @serialized_access
    def events(
            self, project_id: str | None = None, since_seq: int = 0, *,
            tenant_id: str | None = None) -> list[dict]:
        if isinstance(since_seq, bool) or not isinstance(since_seq, int) \
                or since_seq < 0:
            raise ValueError("since_seq must be a non-negative integer")
        if tenant_id is not None:
            tenant_id = validate_public_identifier(
                tenant_id, field="tenant_id")
        if project_id is not None:
            project_id = validate_public_identifier(
                project_id, field="project_id")
        q = "SELECT * FROM events WHERE seq > ?"
        args: list = [since_seq]
        if tenant_id is not None:
            q += " AND tenant_id = ?"
            args.append(tenant_id)
        if project_id is not None:
            q += " AND project_id = ?"
            args.append(project_id)
        q += " ORDER BY seq"
        return [self._event_dict(r) for r in self._conn.execute(q, args)]

    @staticmethod
    def _event_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        payload_text = d["payload"]
        if payload_text is not None:
            commitment = d.get("stored_payload_digest")
            if commitment is None:
                raise EventPayloadIntegrityError(
                    f"event {d['event_id']} predates persisted-payload commitments; "
                    "its retained payload cannot be trusted")
            if sha256_hex(payload_text) != commitment:
                raise EventPayloadIntegrityError(
                    f"event {d['event_id']} persisted payload failed its commitment")
            d["payload"] = strict_json_loads(payload_text)
        else:
            d["payload"] = None
        return d

    @serialized_access
    def payload_mismatches(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM payload_mismatches")]

    # ---------------------------------------------------------------- evidence

    def put_evidence(
        self,
        content: bytes | str,
        media_type: str = "text/plain",
        sensitivity: str = "internal",
    ) -> str:
        """Store content-addressed evidence; returns its digest URI."""
        if not isinstance(content, (bytes, str)):
            raise ValueError("evidence content must be bytes or a string")
        media_type = _validate_log_text(
            "evidence media_type", media_type, max_length=256)
        sensitivity = _validate_log_text(
            "evidence sensitivity", sensitivity, max_length=256)
        data = content.encode("utf-8") if isinstance(content, str) else content
        digest = sha256_hex(data)
        with self.write_scope():
            exists = self._conn.execute(
                "SELECT media_type, sensitivity, size FROM evidence_blobs "
                "WHERE digest = ?", (digest,)
            ).fetchone()
            if exists:
                # The digest identifies bytes, not caller-selected metadata.
                # Silently returning an older row with a different sensitivity
                # or media type makes the return value describe state that was
                # never written and can under-classify retained evidence.
                if (exists["media_type"] != media_type
                        or exists["sensitivity"] != sensitivity
                        or exists["size"] != len(data)):
                    raise ValueError(
                        "evidence digest already exists with different metadata")
            else:
                self._conn.execute(
                    "INSERT INTO evidence_blobs (digest, content, media_type, size,"
                    " sensitivity, captured_at) VALUES (?,?,?,?,?,?)",
                    (digest, data, media_type, len(data), sensitivity, utcnow()),
                )
        return digest

    @serialized_access
    def get_evidence(self, digest: str) -> bytes | None:
        row = self._conn.execute(
            "SELECT content, size, deleted_at FROM evidence_blobs WHERE digest = ?", (digest,)
        ).fetchone()
        if row is None or row["deleted_at"] is not None:
            return None
        content = row["content"]
        if content is None or len(content) != row["size"] or sha256_hex(content) != digest:
            raise EvidenceIntegrityError(
                f"evidence {digest} failed content-address verification")
        return content

    def delete_evidence(self, digest: str, actor: str, reason: str) -> bool:
        """Retention/privacy deletion (SEC-006): content removed, non-content
        audit proof retained."""
        _validate_digest("evidence digest", digest)
        actor = _validate_log_text("evidence deletion actor", actor, max_length=1024)
        reason = _validate_log_text("evidence deletion reason", reason)
        with self.transaction():
            row = self._conn.execute(
                "SELECT 1 FROM evidence_blobs WHERE digest = ? AND deleted_at IS NULL",
                (digest,),
            ).fetchone()
            if not row:
                return False
            self._conn.execute(
                "UPDATE evidence_blobs SET content = NULL, deleted_at = ? WHERE digest = ?",
                (utcnow(), digest),
            )
            self.audit(actor=actor, action="evidence.delete", object_id=digest, detail=reason)
        return True

    # ------------------------------------------------------------- processing

    def mark_processed(
        self, event_id: str, processor_version: str, status: str = "ok", error: str | None = None
    ):
        event_id = validate_public_identifier(event_id, field="processed event_id")
        processor_version = _validate_log_text(
            "processor_version", processor_version, max_length=256)
        if not isinstance(status, str) or status not in {"ok", "quarantined"}:
            raise ValueError("processing status must be 'ok' or 'quarantined'")
        if error is not None:
            error = _validate_log_text("processing error", error)
        with self.write_scope():
            self._conn.execute(
                "INSERT OR REPLACE INTO processed_events VALUES (?,?,?,?,?)",
                (event_id, processor_version, utcnow(), status, error),
            )

    @serialized_access
    def quarantined(self, processor_version: str) -> list[dict]:
        return [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM processed_events WHERE status = 'quarantined'"
                " AND processor_version = ?",
                (processor_version,),
            )
        ]

    # ------------------------------------------------------------------ audit

    def audit(
        self,
        *,
        actor: str,
        action: str,
        object_id: str | None = None,
        before_ref: str | None = None,
        after_ref: str | None = None,
        authority: str | None = None,
        detail: str | None = None,
    ):
        actor = _validate_log_text("audit actor", actor, max_length=1024)
        action = _validate_log_text("audit action", action, max_length=256)
        object_id = _validate_log_text(
            "audit object_id", object_id, nullable=True, max_length=4096)
        before_ref = _validate_log_text(
            "audit before_ref", before_ref, nullable=True, max_length=4096)
        after_ref = _validate_log_text(
            "audit after_ref", after_ref, nullable=True, max_length=4096)
        authority = _validate_log_text(
            "audit authority", authority, nullable=True, max_length=256)
        # Empty optional detail is a long-standing public call pattern (for
        # example, revoking a grant without a reason). Persist one canonical
        # representation for "no detail" instead of rejecting or chaining a
        # semantically duplicate empty string.
        detail = _validate_log_text(
            "audit detail", None if detail == "" else detail, nullable=True)
        at = utcnow()
        entry = {
            "at": at, "actor": actor, "action": action,
            "object_id": object_id, "before_ref": before_ref,
            "after_ref": after_ref, "authority": authority,
            "detail": detail,
        }
        # Validate the exact chained value before taking the writer lock. This
        # also documents that every stored scalar will retain its Python type
        # across SQLite's TEXT affinity boundary.
        canonical_json(entry)
        with self.write_scope():
            # Take the write lock BEFORE reading the tip, so the read and the
            # append are one atomic step even across processes (ADR-046).
            self._conn.execute(
                "UPDATE chain_lock SET n = n + 1 WHERE table_name = 'audit_log'")
            prev_hash = self._chain_tip("audit_log")
            entry_hash = _link(prev_hash, entry)
            self._conn.execute(
                "INSERT INTO audit_log (at, actor, action, object_id, before_ref,"
                " after_ref, authority, detail, prev_hash, entry_hash)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (at, actor, action, object_id, before_ref, after_ref, authority,
                 detail, prev_hash, entry_hash),
            )

    @serialized_access
    def audit_entries(self, action_prefix: str = "") -> list[dict]:
        return [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM audit_log WHERE action LIKE ? ORDER BY seq",
                (action_prefix + "%",),
            )
        ]

    # -------------------------------------------------------- tamper evidence

    @serialized_access
    def _chain_tip(self, table: str) -> str:
        row = self._conn.execute(
            f"SELECT entry_hash FROM {table} ORDER BY seq DESC LIMIT 1").fetchone()
        return (row["entry_hash"] if row and row["entry_hash"] else GENESIS)

    @serialized_access
    def verify_chain(self, table: str = "events") -> dict:
        """Recompute the chain and report the first link that does not hold.

        Detects in-place rewrites and removals from the middle. It cannot on
        its own detect truncation of the TAIL — dropping the last N entries
        leaves a shorter but internally consistent chain — which is what the
        external anchor is for (ADR-028).
        """
        if table not in ("events", "audit_log"):
            raise ValueError(f"no chain on {table!r}")
        rows = self._conn.execute(
            f"SELECT * FROM {table} ORDER BY seq").fetchall()
        prev = GENESIS
        payloads_unavailable = 0
        for row in rows:
            data = dict(row)
            if table == "events":
                entry = _event_entry(data)
                ident = data["event_id"]
                payload_text = data.get("payload")
                stored_digest = data.get("stored_payload_digest")
                if payload_text is None:
                    payloads_unavailable += 1
                elif stored_digest is None:
                    return {
                        "intact": False, "table": table, "broken_at": ident,
                        "reason": "retained payload has no immutable commitment",
                        "checked": data["seq"],
                    }
                elif sha256_hex(payload_text) != stored_digest:
                    return {
                        "intact": False, "table": table, "broken_at": ident,
                        "reason": "persisted payload differs from its commitment",
                        "checked": data["seq"],
                    }
            else:
                entry = {k: data[k] for k in
                         ("at", "actor", "action", "object_id", "before_ref",
                          "after_ref", "authority", "detail")}
                ident = f"audit:{data['seq']}"
            expected = _link(prev, entry)
            if data["prev_hash"] != prev:
                return {"intact": False, "table": table, "broken_at": ident,
                        "reason": "predecessor link does not match",
                        "checked": data["seq"]}
            if data["entry_hash"] != expected:
                return {"intact": False, "table": table, "broken_at": ident,
                        "reason": "entry content does not match its hash",
                        "checked": data["seq"]}
            prev = expected
        result = {
            "intact": True, "table": table, "entries": len(rows), "tip": prev}
        if table == "events":
            result["payload_integrity"] = (
                "unavailable" if payloads_unavailable else "verified")
            result["payloads_unavailable"] = payloads_unavailable
        return result

    @serialized_access
    def export_anchor(
            self, table: str = "events", *, tenant_id: str | None = None,
            project_id: str | None = None) -> dict:
        """A content-free commitment to publish somewhere you do not control.

        Publishing {count, tip} out of band is what makes tail truncation and
        wholesale re-chaining detectable. Held only by the operator it proves
        nothing: an anchor produced at verification time from the same store
        agrees with whatever that store currently says.
        """
        if (tenant_id is None) != (project_id is None):
            raise ValueError(
                "anchor tenant_id and project_id must be supplied together")
        if tenant_id is not None and (
                not is_public_identifier(tenant_id)
                or not is_public_identifier(project_id)):
            raise ValueError("anchor project binding has malformed identifiers")
        with self.read_snapshot():
            result = self.verify_chain(table)
            if not result["intact"]:
                raise AnchorExportError(
                    f"cannot export {table} anchor: chain is not intact "
                    f"({result.get('reason', 'integrity verification failed')})")
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            tip = self._chain_tip(table)
        anchor = {
            "schema_version": "cce.anchor.v1", "table": table,
            "count": row["n"], "tip": tip,
            "intact_at_export": result["intact"], "exported_at": utcnow(),
        }
        if tenant_id is not None:
            anchor.update({"tenant_id": tenant_id, "project_id": project_id})
        return anchor

    @serialized_access
    def verify_against_anchor(
            self, anchor: dict, *, expected_tenant_id: str | None = None,
            expected_project_id: str | None = None) -> dict:
        """Prove the live chain still carries the anchored prefix."""
        def invalid(reason: str) -> dict:
            return {"ok": False,
                    "reason": f"invalid anchor document: {reason}"}

        if not isinstance(anchor, dict):
            return invalid("anchor must be an object")
        fields = set(anchor)
        missing = _ANCHOR_REQUIRED_FIELDS - fields
        unknown = fields - _ANCHOR_REQUIRED_FIELDS - _ANCHOR_BINDING_FIELDS
        binding = fields & _ANCHOR_BINDING_FIELDS
        if missing or unknown or binding not in (
                frozenset(), _ANCHOR_BINDING_FIELDS):
            return invalid(
                f"missing={sorted(missing)}, unknown={sorted(unknown)}, "
                f"binding={sorted(binding)}")
        if (expected_tenant_id is None) != (expected_project_id is None):
            return invalid(
                "expected tenant_id and project_id must be supplied together")
        if expected_tenant_id is not None and not binding:
            return invalid(
                "anchor is unbound and cannot satisfy a project-scoped check")
        if anchor.get("schema_version") != "cce.anchor.v1":
            return invalid("unsupported schema")
        table = anchor.get("table")
        if table not in ("events", "audit_log"):
            return invalid("table must be 'events' or 'audit_log'")
        count = anchor.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return invalid("count must be a non-negative integer")
        tip = anchor.get("tip")
        if not isinstance(tip, str) or _ANCHOR_DIGEST.fullmatch(tip) is None:
            return invalid("tip must be a canonical sha256 digest")
        if (count == 0 and tip != GENESIS) or (count > 0 and tip == GENESIS):
            return invalid("count and tip are inconsistent")
        exported_at = anchor.get("exported_at")
        if not is_canonical_utc_timestamp(exported_at):
            return invalid(
                "exported_at must be a canonical real-calendar UTC timestamp")
        if anchor.get("intact_at_export") is not True:
            return invalid("intact_at_export must be true")
        if binding:
            tenant_id = anchor.get("tenant_id")
            project_id = anchor.get("project_id")
            if (not is_public_identifier(tenant_id)
                    or not is_public_identifier(project_id)):
                return invalid("project binding has malformed identifiers")
            if (expected_tenant_id is not None
                    and tenant_id != expected_tenant_id):
                return invalid("anchor belongs to another tenant")
            if (expected_project_id is not None
                    and project_id != expected_project_id):
                return invalid("anchor belongs to another project")
        with self.read_snapshot():
            chain = self.verify_chain(table)
            if not chain["intact"]:
                return {"ok": False, "reason": "chain is broken", "chain": chain}
            live_count = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            if live_count < count:
                return {"ok": False, "reason": (
                    f"log has {live_count} entries but {count} were "
                    f"anchored: entries were removed from the tail"),
                    "anchored": count, "live": live_count}
            if count == 0:
                # An empty anchor commits to GENESIS and no entries.
                prefix_tip = GENESIS
            else:
                row = self._conn.execute(
                    f"SELECT entry_hash FROM {table} "
                    "ORDER BY seq LIMIT 1 OFFSET ?",
                    (count - 1,)).fetchone()
                prefix_tip = row["entry_hash"] if row else GENESIS
        if prefix_tip != tip:
            return {"ok": False, "reason": (
                "the anchored prefix no longer hashes to the published tip: "
                "history before the anchor was rewritten"),
                "anchored_tip": tip, "live_tip": prefix_tip}
        return {
            "ok": True,
            "bound": bool(binding),
            "anchored": count,
            "live": live_count,
            "appended_since": live_count - count,
        }
