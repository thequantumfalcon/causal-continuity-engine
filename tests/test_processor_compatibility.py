"""Processor/projection compatibility boundary (ADR-114).

A durable projection must not be opened by a processor whose semantics did not
produce it. These regressions pin the admission contract, the canonical
producer, and the mutation ordering.

Two different kinds of test live here and they fail on older code for
different reasons. A rejection pin fails because an older boundary ADMITS a
database it should refuse. A lifecycle compatibility positive fails the other
way round: an older, blunter boundary REFUSES a state that is actually
supported. Neither depends on a new symbol existing.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.core import canonical_json, sha256_hex
from causal_continuity_engine.engine import PROCESSOR_VERSION, Engine
from causal_continuity_engine.github import WebhookError, WebhookPayloadError
from causal_continuity_engine.store import GENESIS, Store

COMPAT_ERROR = getattr(
    engine_module, "ProcessorProjectionCompatibilityError", None)
TENANT = "ten_local"
PROJECT = "prj_compat"
REPOSITORY_ID = 4242


# --------------------------------------------------------------- helpers
def _private_dir(tmp_path, name):
    path = tmp_path / name
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _issue(number, body):
    return {
        "action": "opened",
        "issue": {"number": number, "title": "T", "body": body,
                  "state": "open", "labels": [],
                  "author_association": "OWNER",
                  "created_at": "2026-07-29T10:00:00Z"},
        "repository": {"id": REPOSITORY_ID, "full_name": "o/r"},
    }


def _malformed_issue():
    return {
        "action": "opened",
        "repository": {"id": REPOSITORY_ID, "full_name": "o/r"},
    }


def _ingested(directory, body="The exporter must write CSV output."):
    """A normal exact-S ingest history."""
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    engine.ingest_github(PROJECT, "issues", "d1", _issue(1, body))
    engine.close()
    return database


EDGE_BODY = ("The exporter must write CSV output.\n"
             "The exporter must write JSON output.")


def _ingested_with_edges(directory):
    """A history that really produces event-attributed edge rows."""
    database = _ingested(directory)
    engine = Engine(database, workdir=str(directory))
    try:
        engine.ingest_github(
            PROJECT, "issues", "d2", _issue(2, "The exporter must write JSON output."))
    finally:
        engine.close()
    return database


def _sql(database, *statements):
    connection = sqlite3.connect(database)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()


def _scalar(database, query):
    connection = sqlite3.connect(database)
    try:
        return connection.execute(query).fetchone()[0]
    finally:
        connection.close()


def _rows(database, query, parameters=()):
    connection = sqlite3.connect(database)
    try:
        return connection.execute(query, parameters).fetchall()
    finally:
        connection.close()


def _quarantine_tamper_trigger(tamper):
    if tamper == "suppress":
        return (
            "CREATE TRIGGER tamper_quarantine BEFORE INSERT ON processed_events"
            " WHEN NEW.status='quarantined' BEGIN SELECT RAISE(IGNORE); END"
        )
    if tamper == "rewrite":
        return (
            "CREATE TRIGGER tamper_quarantine AFTER INSERT ON processed_events"
            " WHEN NEW.status='quarantined' BEGIN UPDATE processed_events"
            " SET error='rewritten' WHERE event_id=NEW.event_id"
            " AND processor_version=NEW.processor_version; END"
        )
    if tamper == "inject-node":
        return (
            "CREATE TRIGGER tamper_quarantine AFTER INSERT ON processed_events"
            " WHEN NEW.status='quarantined' BEGIN INSERT INTO nodes"
            " (node_id,version,entity_type,tenant_id,project_id,status,authority,"
            "data,tx_from,event_id) VALUES"
            " ('nod_tamper000000000000000000',1,'claim','ten_local','prj_compat',"
            "'active','agent_observed','{}','2026-01-01T00:00:00Z',NEW.event_id); END"
        )
    if tamper == "inject-edge":
        return (
            "CREATE TRIGGER tamper_quarantine AFTER INSERT ON processed_events"
            " WHEN NEW.status='quarantined' BEGIN INSERT INTO edges"
            " (edge_id,version,edge_type,src_id,dst_id,tenant_id,project_id,"
            "strength,data,tx_from,event_id) VALUES"
            " ('edg_tamper000000000000000000',1,'supports','src_tamper',"
            "'dst_tamper','ten_local','prj_compat',1.0,'{}',"
            "'2026-01-01T00:00:00Z',NEW.event_id); END"
        )
    raise AssertionError(f"unknown quarantine tamper {tamper}")


def _clone_row(database, table, **overrides):
    """Clone a row, overriding named columns, so every NOT NULL column is set
    without this test hard-coding the producer's column list."""
    connection = sqlite3.connect(database)
    try:
        connection.row_factory = sqlite3.Row
        source = connection.execute(
            f"SELECT * FROM {table} WHERE event_id IS NOT NULL LIMIT 1"
        ).fetchone()
        assert source is not None, f"no attributed {table} row to clone"
        columns = [key for key in source.keys() if key != "row_id"]
        values = [overrides.get(key, source[key]) for key in columns]
        connection.execute(
            f"INSERT INTO {table} ({','.join(columns)}) "
            f"VALUES ({','.join('?' * len(columns))})", values)
        connection.commit()
    finally:
        connection.close()


def _drop_event_triggers(database):
    connection = sqlite3.connect(database)
    try:
        names = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' "
            "AND tbl_name='events'")]
        for name in names:
            connection.execute(f"DROP TRIGGER {name}")
        connection.commit()
    finally:
        connection.close()


def _assert_refused(database, workdir):
    """Pre-fix this fails with 'admitted', which is the intended reason."""
    try:
        engine = Engine(database, workdir=str(workdir))
        engine.close()
    except Exception as exc:  # noqa: BLE001 - the verdict is the assertion
        if COMPAT_ERROR is not None and isinstance(exc, COMPAT_ERROR):
            assert "re-ingest" in str(exc)
            return
        pytest.fail(f"refused for the wrong reason: {type(exc).__name__}: {exc}")
    pytest.fail("database was admitted but must be refused")


def _assert_admitted(database, workdir):
    engine = Engine(database, workdir=str(workdir))
    engine.close()


# ------------------------------------------------------ admissible shapes
def test_absent_zero_byte_and_memory_paths_remain_initializable(tmp_path):
    directory = _private_dir(tmp_path, "init")
    _assert_admitted(directory / "absent.sqlite3", directory)
    zero = directory / "zero.sqlite3"
    zero.write_bytes(b"")
    _assert_admitted(zero, directory)
    _assert_admitted(":memory:", directory)
    _assert_admitted(Path(":memory:"), directory)


def test_eventless_and_project_only_databases_admit(tmp_path):
    directory = _private_dir(tmp_path, "eventless")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.close()
    _assert_admitted(database, directory)
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    engine.close()
    _assert_admitted(database, directory)


def test_normal_ingest_history_admits(tmp_path):
    directory = _private_dir(tmp_path, "normal")
    database = _ingested(directory)
    _assert_admitted(database, directory)


def test_relative_string_and_path_inputs_admit(tmp_path, monkeypatch):
    directory = _private_dir(tmp_path, "relative")
    database = _ingested(directory)
    _assert_admitted(Path(database), directory)
    monkeypatch.chdir(directory)
    _assert_admitted("cce.sqlite3", directory)


def test_store_only_append_only_history_admits_and_stays_usable(tmp_path):
    """A bare Store has no graph tables; its events were never projected."""
    directory = _private_dir(tmp_path, "store-only")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    record = store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-store-only",
        payload={"text_blocks": [
            {"text": "The exporter must write CSV output.",
             "authority": "human_intent", "ref": "direct:1"}]},
        authority="human_intent")
    store.close()
    assert _scalar(database,
                   "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                   "AND name IN ('nodes','edges')") == 0

    engine = Engine(database, workdir=str(directory))
    try:
        engine.create_project("p", project_id=PROJECT,
                              repository_id=REPOSITORY_ID)
        engine.process_event(engine.store.get_event(
            record["event_id"], tenant_id=TENANT, project_id=PROJECT))
        assert _scalar(database, "SELECT COUNT(*) FROM processed_events") == 1
    finally:
        engine.close()
    _assert_admitted(database, directory)


# ------------------------------------------------------------ producer
def test_direct_process_event_writes_projection_and_marker(tmp_path):
    directory = _private_dir(tmp_path, "direct")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    record = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-direct",
        payload={"text_blocks": [
            {"text": "The exporter must write CSV output.",
             "authority": "human_intent", "ref": "direct:1"}]},
        authority="human_intent")
    engine.process_event(engine.store.get_event(
        record["event_id"], tenant_id=TENANT, project_id=PROJECT))
    engine.close()

    assert _scalar(database,
                   "SELECT COUNT(*) FROM processed_events WHERE "
                   f"processor_version='{PROCESSOR_VERSION}' "
                   "AND status='ok'") == 1
    _assert_admitted(database, directory)


def test_malformed_github_ingest_rejects_before_append(tmp_path):
    directory = _private_dir(tmp_path, "malformed-github-ingest")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    try:
        with pytest.raises(WebhookPayloadError, match="payload.issue"):
            engine.ingest_github(
                PROJECT, "issues", "malformed-ingest", _malformed_issue())
        assert engine.store.events(PROJECT, tenant_id=TENANT) == []
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events").fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL"
        ).fetchone()[0] == 0
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("case", "source_type", "idempotency_key", "payload", "error_type", "match"),
    [
        (
            "malformed-shape", "github:issues", "github:malformed-direct",
            _malformed_issue(), WebhookPayloadError, "payload.issue",
        ),
        (
            "unknown-suffix", "github:not_subscribed", "github:unknown-direct",
            _issue(7, "ordinary text"), WebhookError, "unsubscribed event",
        ),
        (
            "missing-delimiter", "github:issues", "missing-delimiter",
            _issue(8, "ordinary text"), WebhookPayloadError,
            "idempotency_key.*delimiter",
        ),
        (
            "wrong-prefix", "github:issues", "evil:delivery",
            _issue(8, "ordinary text"), WebhookPayloadError,
            "GitHub event identity",
        ),
        (
            "extra-delimiter", "github:issues", "github:a:b",
            _issue(8, "ordinary text"), WebhookPayloadError,
            "GitHub event identity",
        ),
        (
            "empty-delivery", "github:issues", "github:",
            _issue(8, "ordinary text"), WebhookPayloadError,
            "GitHub event identity",
        ),
    ],
)
def test_direct_process_event_requires_github_normalization(
        tmp_path, case, source_type, idempotency_key, payload,
        error_type, match):
    directory = _private_dir(tmp_path, f"github-direct-{case}")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type=source_type,
        idempotency_key=idempotency_key, payload=payload,
        authority="repository_authoritative")
    before = canonical_json(event)
    try:
        with pytest.raises(error_type, match=match):
            engine.process_event(event)
        assert canonical_json(engine.store.get_event(
            event["event_id"], tenant_id=TENANT, project_id=PROJECT)) == before
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
    finally:
        engine.close()
    _assert_admitted(database, directory)


def test_direct_process_event_preserves_valid_github_normalization(tmp_path):
    directory = _private_dir(tmp_path, "valid-github-direct")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="github:issues",
        idempotency_key="github:valid-direct",
        payload=_issue(9, "The exporter must write CSV output."),
        authority="human_intent")
    fresh = None
    try:
        report = engine.process_event(event)
        assert report["created"]
        assert _rows(
            database,
            "SELECT processor_version, status FROM processed_events"
            " WHERE event_id = ?", (event["event_id"],)) == [
                (PROCESSOR_VERSION, "ok")]
        before = engine.projection_fingerprint(PROJECT)
        fresh = engine.rebuild_projection(PROJECT)
        assert fresh.projection_fingerprint(PROJECT) == before
    finally:
        if fresh is not None:
            fresh.close()
        engine.close()


@pytest.mark.parametrize("failure_type", [WebhookPayloadError, MemoryError],
                         ids=("payload-error", "memory-error"))
def test_live_github_reconstruction_failure_quarantines_after_capture(
        tmp_path, monkeypatch, failure_type):
    directory = _private_dir(
        tmp_path, f"github-live-{failure_type.__name__}")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    calls = 0
    original_normalize = engine_module.normalize

    def fail_reconstruction(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise failure_type("forced canonical reconstruction failure")
        return original_normalize(*args, **kwargs)

    monkeypatch.setattr(engine_module, "normalize", fail_reconstruction)
    try:
        with pytest.raises(failure_type, match="reconstruction failure"):
            engine.ingest_github(
                PROJECT, "issues", "live-reconstruction",
                _issue(10, "The exporter must write CSV output."))
        assert calls == 2
        event = engine.store.events(PROJECT, tenant_id=TENANT)[0]
        assert _rows(
            database,
            "SELECT processor_version, status, error FROM processed_events"
            " WHERE event_id = ?", (event["event_id"],)) == [
                (PROCESSOR_VERSION, "quarantined",
                 "event processing failed")]
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
    finally:
        engine.close()
    _assert_admitted(database, directory)


def test_direct_oversized_github_suffix_propagates_without_projection(tmp_path):
    directory = _private_dir(tmp_path, "github-direct-oversized-suffix")
    database = directory / "cce.sqlite3"
    suffix = "x" * 270_000
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type=f"github:{suffix}",
        idempotency_key="github:oversized-direct",
        payload=_issue(11, "ordinary text"),
        authority="repository_authoritative")
    before = canonical_json(event)
    try:
        with pytest.raises(WebhookError) as caught:
            engine.process_event(event)
        assert suffix in str(caught.value)
        assert canonical_json(engine.store.get_event(
            event["event_id"], tenant_id=TENANT, project_id=PROJECT)) == before
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
    finally:
        engine.close()
    _assert_admitted(database, directory)


def test_rebuild_quarantines_malformed_github_and_continues(tmp_path):
    directory = _private_dir(tmp_path, "github-rebuild-normalization")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    malformed = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="github:issues",
        idempotency_key="github:malformed-rebuild",
        payload=_malformed_issue(), authority="repository_authoritative")
    oversized_suffix = "x" * 270_000
    oversized = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT,
        source_type=f"github:{oversized_suffix}",
        idempotency_key="github:oversized-rebuild",
        payload=_issue(11, "ordinary text"),
        authority="repository_authoritative")
    wrong_prefix = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="github:issues",
        idempotency_key="evil:delivery",
        payload=_issue(12, "ordinary text"),
        authority="repository_authoritative")
    valid = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="github:issues",
        idempotency_key="github:valid-rebuild",
        payload=_issue(13, "The exporter must write JSON output."),
        authority="human_intent")
    source_before = canonical_json(
        engine.store.events(PROJECT, tenant_id=TENANT))
    fresh = engine.rebuild_projection(PROJECT)
    try:
        markers = {
            row[0]: (row[1], row[2])
            for row in fresh.store._conn.execute(
                "SELECT event_id, status, error FROM processed_events")
        }
        assert markers == {
            malformed["event_id"]: (
                "quarantined", "event processing failed"),
            oversized["event_id"]: (
                "quarantined", "event processing failed"),
            wrong_prefix["event_id"]: (
                "quarantined", "event processing failed"),
            valid["event_id"]: ("ok", None),
        }
        assert oversized_suffix not in markers[oversized["event_id"]][1]
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (malformed["event_id"],)).fetchone()[0] == 0
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (malformed["event_id"],)).fetchone()[0] == 0
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (oversized["event_id"],)).fetchone()[0] == 0
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (oversized["event_id"],)).fetchone()[0] == 0
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (wrong_prefix["event_id"],)).fetchone()[0] == 0
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (wrong_prefix["event_id"],)).fetchone()[0] == 0
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE node_id = ? AND event_id = ?",
            (valid["event_id"], valid["event_id"])).fetchone()[0] == 1
        assert canonical_json(
            engine.store.events(PROJECT, tenant_id=TENANT)) == source_before
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events").fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL"
        ).fetchone()[0] == 0
    finally:
        fresh.close()
        engine.close()


def test_rebuild_quarantine_diagnostic_is_total_and_continues(
        tmp_path, monkeypatch):
    directory = _private_dir(tmp_path, "github-rebuild-hostile-error-name")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    hostile = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="github:issues",
        idempotency_key="github:hostile-error-name",
        payload=_issue(13, "ordinary text"),
        authority="repository_authoritative")
    valid = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="github:issues",
        idempotency_key="github:after-hostile-error",
        payload=_issue(14, "The exporter must write YAML output."),
        authority="human_intent")
    hostile_error = type("Bad\nName", (Exception,), {})
    original_normalize = engine_module.normalize

    def fail_first(event_name, delivery_id, payload):
        if delivery_id == "hostile-error-name":
            raise hostile_error("source-shaped detail")
        return original_normalize(event_name, delivery_id, payload)

    monkeypatch.setattr(engine_module, "normalize", fail_first)
    fresh = engine.rebuild_projection(PROJECT)
    try:
        marker = fresh.store._conn.execute(
            "SELECT processor_version, status, error FROM processed_events"
            " WHERE event_id = ?", (hostile["event_id"],)).fetchone()
        assert tuple(marker) == (
            PROCESSOR_VERSION, "quarantined", "event processing failed")
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (hostile["event_id"],)).fetchone()[0] == 0
        marker = fresh.store._conn.execute(
            "SELECT processor_version, status, error FROM processed_events"
            " WHERE event_id = ?", (valid["event_id"],)).fetchone()
        assert tuple(marker) == (PROCESSOR_VERSION, "ok", None)
        assert fresh.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE node_id = ? AND event_id = ?",
            (valid["event_id"], valid["event_id"])).fetchone()[0] == 1
    finally:
        fresh.close()
        engine.close()


@pytest.mark.parametrize(
    "tamper", ["suppress", "rewrite", "inject-node", "inject-edge"])
def test_live_quarantine_requires_exact_terminal_state(
        tmp_path, monkeypatch, tamper):
    directory = _private_dir(tmp_path, f"live-quarantine-{tamper}")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    engine.close()
    _sql(database, _quarantine_tamper_trigger(tamper))

    engine = Engine(database, workdir=str(directory))
    attempts = []
    original_process_text = engine._process_text
    original_mark_processed = Store.mark_processed

    def fail_after_witness(event, block, report):
        original_process_text(event, block, report)
        raise RuntimeError("forced post-witness projection failure")

    def observed_mark(store, event_id, processor_version, status="ok", error=None):
        if store is engine.store and status == "quarantined":
            attempts.append((event_id, processor_version, status, error))
        return original_mark_processed(
            store, event_id, processor_version, status, error)

    monkeypatch.setattr(engine, "_process_text", fail_after_witness)
    monkeypatch.setattr(Store, "mark_processed", observed_mark)
    try:
        with pytest.raises(
                engine_module.ProcessorProjectionCompatibilityError,
                match="re-ingest") as refusal:
            engine.ingest_agent_trace(
                PROJECT, session_id=None, span_id=f"live-{tamper}",
                payload={"message": "The exporter must write CSV output."})
        assert refusal.value.__suppress_context__ is True
        event = engine.store.events(PROJECT, tenant_id=TENANT)[0]
        assert attempts == [(
            event["event_id"], PROCESSOR_VERSION, "quarantined",
            "event processing failed")]
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
    finally:
        engine.close()
    _assert_admitted(database, directory)


@pytest.mark.parametrize(
    "tamper", ["suppress", "rewrite", "inject-node", "inject-edge"])
def test_rebuild_quarantine_requires_exact_terminal_state(
        tmp_path, monkeypatch, tamper):
    directory = _private_dir(tmp_path, f"rebuild-quarantine-{tamper}")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    failed = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        source_id=f"failed-{tamper}", idempotency_key=f"trace:failed-{tamper}",
        payload={"message": "The exporter must write CSV output."},
        authority="agent_observed")
    later = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        source_id=f"later-{tamper}", idempotency_key=f"trace:later-{tamper}",
        payload={"message": "The exporter must write JSON output."},
        authority="agent_observed")
    attempts = []
    fresh_stores = []
    original_process_text = Engine._process_text
    original_mark_processed = Store.mark_processed

    def fail_first(instance, event, block, report):
        if event["event_id"] == failed["event_id"]:
            original_process_text(instance, event, block, report)
            raise RuntimeError("forced post-witness projection failure")
        return original_process_text(instance, event, block, report)

    def observed_mark(store, event_id, processor_version, status="ok", error=None):
        if store is not engine.store and status == "quarantined":
            attempts.append((event_id, processor_version, status, error))
            if not fresh_stores:
                fresh_stores.append(store)
                store._conn.execute(_quarantine_tamper_trigger(tamper))
        return original_mark_processed(
            store, event_id, processor_version, status, error)

    monkeypatch.setattr(Engine, "_process_text", fail_first)
    monkeypatch.setattr(Store, "mark_processed", observed_mark)
    rebuilt = None
    caught = None
    try:
        try:
            rebuilt = engine.rebuild_projection(PROJECT)
        except Exception as exc:  # the concrete verdict is asserted below
            caught = exc
        assert isinstance(
            caught, engine_module.ProcessorProjectionCompatibilityError)
        assert attempts == [(
            failed["event_id"], PROCESSOR_VERSION, "quarantined",
            "event processing failed")]
        assert fresh_stores
        with pytest.raises(sqlite3.ProgrammingError):
            fresh_stores[0]._conn.execute("SELECT 1")
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events").fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id IN (?, ?)",
            (failed["event_id"], later["event_id"])).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id IN (?, ?)",
            (failed["event_id"], later["event_id"])).fetchone()[0] == 0
    finally:
        if rebuilt is not None:
            rebuilt.close()
        engine.close()


def test_rebuild_preserves_quarantine_baseexception_when_cleanup_fails(
        tmp_path, monkeypatch):
    directory = _private_dir(tmp_path, "rebuild-quarantine-baseexception")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        source_id="baseexception", idempotency_key="trace:baseexception",
        payload={"message": "The exporter must write CSV output."},
        authority="agent_observed")
    original_close = Engine.close

    def fail_processing(_instance, _event, _block, _report):
        raise RuntimeError("forced post-witness projection failure")

    def interrupt_quarantine(_store, _event_id, _exc):
        raise KeyboardInterrupt("forced process-control interruption")

    def close_with_failure(instance):
        result = original_close(instance)
        if instance is not engine:
            raise SystemExit("forced close failure")
        return result

    monkeypatch.setattr(Engine, "_process_text", fail_processing)
    monkeypatch.setattr(
        engine_module, "_mark_event_quarantined", interrupt_quarantine)
    monkeypatch.setattr(Engine, "close", close_with_failure)
    try:
        with pytest.raises(
                KeyboardInterrupt,
                match="process-control interruption") as interruption:
            engine.rebuild_projection(PROJECT)
        assert interruption.value.__notes__ == [
            "additionally failed to close rebuilt projection"]
    finally:
        engine.close()


@pytest.mark.parametrize("concurrent_state", ["success", "graph-only"])
def test_quarantine_cannot_overwrite_concurrent_terminal_state(
        tmp_path, monkeypatch, concurrent_state):
    directory = _private_dir(
        tmp_path, f"quarantine-concurrent-{concurrent_state}")
    database = directory / "cce.sqlite3"
    failing = Engine(database, workdir=str(directory))
    failing.create_project("p", project_id=PROJECT,
                           repository_id=REPOSITORY_ID)
    succeeding = Engine(database, workdir=str(directory))
    before_quarantine = threading.Event()
    resume_quarantine = threading.Event()
    worker_errors = []
    original_diagnostic = engine_module._quarantine_diagnostic

    def attributed_projection(event_id):
        return {
            table: [tuple(row) for row in succeeding.store._conn.execute(
                f"SELECT * FROM {table} WHERE event_id=? ORDER BY row_id", (event_id,))]
            for table in ("nodes", "edges")
        }

    def fail_after_witness(_event, _block, _report):
        raise RuntimeError("forced post-witness projection failure")

    def pause_before_quarantine(exc):
        before_quarantine.set()
        if not resume_quarantine.wait(10):
            raise RuntimeError("timed out waiting for concurrent success")
        return original_diagnostic(exc)

    def run_failing_ingest():
        try:
            failing.ingest_agent_trace(
                PROJECT, session_id=None,
                span_id=f"concurrent-{concurrent_state}",
                payload={"message": "The exporter must write CSV output."})
        except BaseException as exc:  # captured for the main test thread
            worker_errors.append(exc)

    monkeypatch.setattr(failing, "_process_text", fail_after_witness)
    monkeypatch.setattr(
        engine_module, "_quarantine_diagnostic", pause_before_quarantine)
    worker = threading.Thread(target=run_failing_ingest)
    worker.start()
    try:
        try:
            assert before_quarantine.wait(10), \
                "failing ingest did not reach quarantine"
            events = succeeding.store.events(PROJECT, tenant_id=TENANT)
            assert len(events) == 1
            event = events[0]
            if concurrent_state == "success":
                succeeding.process_event(event)
            else:
                succeeding.graph.put_node(
                    entity_type="claim", tenant_id=TENANT,
                    project_id=PROJECT,
                    node_id="clm_concurrent0000000000000000",
                    status="active", authority="agent_observed",
                    data={"statement": "concurrent attributed state"},
                    event_id=event["event_id"])
            winning_projection = attributed_projection(event["event_id"])
            assert winning_projection["nodes"]
            if concurrent_state == "success":
                assert winning_projection["edges"]
            else:
                assert winning_projection["edges"] == []
        finally:
            resume_quarantine.set()
            worker.join(10)
        assert not worker.is_alive(), "failing ingest did not finish"
        assert len(worker_errors) == 1
        assert isinstance(
            worker_errors[0], engine_module.ProcessorProjectionCompatibilityError)
        marker_rows = succeeding.store._conn.execute(
            "SELECT processor_version, status, error FROM processed_events"
            " WHERE event_id = ?", (event["event_id"],)).fetchall()
        if concurrent_state == "success":
            assert [tuple(row) for row in marker_rows] == [
                (PROCESSOR_VERSION, "ok", None)]
        else:
            assert marker_rows == []
        assert succeeding.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] > 0
        assert attributed_projection(event["event_id"]) == winning_projection
    finally:
        resume_quarantine.set()
        if worker.is_alive():
            worker.join(10)
        failing.close()
        succeeding.close()
    if concurrent_state == "success":
        _assert_admitted(database, directory)
    else:
        _assert_refused(database, directory)


@pytest.mark.parametrize("secret", [
    "sk-proj-" + "A" * 40,
    ("-----BEGIN RSA PRIVATE KEY-----\n"
     "MIIE AABB\n"
     "REVG"),
], ids=("token", "spaced-truncated-pem"))
def test_direct_process_event_refuses_unredacted_canonical_payload_atomically(
        tmp_path, secret):
    """A Store caller cannot stamp current semantics over secret-bearing bytes."""
    directory = _private_dir(tmp_path, "direct-unredacted")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    record = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-direct-unredacted",
        payload={"message": f"Requirement: deploy with {secret}"},
        authority="agent_observed")
    stored = engine.store.get_event(
        record["event_id"], tenant_id=TENANT, project_id=PROJECT)
    before = canonical_json(stored)

    try:
        with pytest.raises(
                engine_module.ProcessorProjectionCompatibilityError,
                match="re-ingest"):
            engine.process_event(stored)

        assert canonical_json(engine.store.get_event(
            record["event_id"], tenant_id=TENANT, project_id=PROJECT)) == before
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (record["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (record["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE event_id = ?",
            (record["event_id"],)).fetchone()[0] == 0
        assert secret not in "\n".join(
            row[0] for row in engine.store._conn.execute("SELECT data FROM nodes"))
    finally:
        engine.close()

    frozen = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == frozen


@pytest.mark.parametrize("mode", ["metadata_only", "redacted", "full"])
def test_current_capture_boundary_preserves_normal_ingest_and_rebuild(
        tmp_path, mode):
    directory = _private_dir(tmp_path, f"ingest-{mode}-rebuild")
    database = directory / "cce.sqlite3"
    token = "sk-proj-" + "B" * 40
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID,
                          capture_mode=mode)
    payload = _issue(2, f"Requirement: deploy with {token}")
    payload["changes"] = {"secret": "x" * 40}
    engine.ingest_github(
        PROJECT, "issues", "redacted-rebuild", payload)

    event = engine.store.events(PROJECT, tenant_id=TENANT)[0]
    assert token not in canonical_json(event["payload"])
    if mode == "metadata_only":
        assert (event["payload"]["changes"]["secret"]
                == "[DROPPED:secret:40chars]")
    else:
        assert event["payload"]["changes"]["secret"] == "x" * 40
    assert _rows(
        database,
        "SELECT processor_version, status FROM processed_events"
        " WHERE event_id = ?",
        (event["event_id"],)) == [(PROCESSOR_VERSION, "ok")]
    before = engine.projection_fingerprint(PROJECT)
    fresh = engine.rebuild_projection(PROJECT)
    try:
        assert fresh.projection_fingerprint(PROJECT) == before
        assert token not in canonical_json(
            fresh.store.events(PROJECT, tenant_id=TENANT)[0]["payload"])
    finally:
        fresh.close()
        engine.close()


def test_metadata_ingest_recaptures_sentinel_source_and_rebuilds(tmp_path):
    directory = _private_dir(tmp_path, "metadata-sentinel-rebuild")
    database = directory / "cce.sqlite3"
    source = "[DROPPED:body:4111111111111111chars]"
    engine = Engine(database, workdir=str(directory))
    engine.create_project(
        "p", project_id=PROJECT, repository_id=REPOSITORY_ID,
        capture_mode="metadata_only")
    engine.ingest_github(
        PROJECT, "issues", "metadata-sentinel", _issue(3, source))

    event = engine.store.events(PROJECT, tenant_id=TENANT)[0]
    assert event["payload"]["issue"]["body"] == (
        f"[DROPPED:body:{len(source)}chars]")
    assert event["payload"]["issue"]["body"] != source
    before = engine.projection_fingerprint(PROJECT)
    fresh = engine.rebuild_projection(PROJECT)
    try:
        assert fresh.projection_fingerprint(PROJECT) == before
    finally:
        fresh.close()
        engine.close()


def test_ingest_does_not_turn_a_redaction_refusal_into_quarantine(
        tmp_path, monkeypatch):
    directory = _private_dir(tmp_path, "ingest-redaction-refusal")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)

    def refuse(_payload, _mode):
        engine_module._refuse_projection()

    monkeypatch.setattr(
        engine_module, "_assert_payload_uses_current_capture", refuse)
    try:
        with pytest.raises(
                engine_module.ProcessorProjectionCompatibilityError,
                match="re-ingest"):
            engine.ingest_agent_trace(
                PROJECT, session_id=None, span_id="compat-refusal",
                payload={"message": "ordinary text"})
        event_id = engine.store.events(PROJECT, tenant_id=TENANT)[0]["event_id"]
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event_id,)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event_id,)).fetchone()[0] == 0
    finally:
        engine.close()


@pytest.mark.parametrize("failure_type", [MemoryError, RuntimeError],
                         ids=("memory-error", "unexpected-error"))
def test_ingest_validator_failure_never_mints_current_quarantine(
        tmp_path, monkeypatch, failure_type):
    directory = _private_dir(tmp_path, f"ingest-{failure_type.__name__}")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)

    def fail_validation(_payload, _mode):
        raise failure_type("capture validation failed")

    monkeypatch.setattr(
        engine_module, "_capture_payload_is_current", fail_validation)
    caught = None
    try:
        try:
            engine.ingest_agent_trace(
                PROJECT, session_id=None, span_id="validator-failure",
                payload={"message": "ordinary text"})
        except Exception as exc:
            caught = exc
        event_id = engine.store.events(
            PROJECT, tenant_id=TENANT)[0]["event_id"]
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event_id,)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event_id,)).fetchone()[0] == 0
        assert isinstance(
            caught, engine_module.ProcessorProjectionCompatibilityError)
    finally:
        engine.close()


def test_ingest_reload_failure_cannot_quarantine_unvalidated_payload(
        tmp_path, monkeypatch):
    directory = _private_dir(tmp_path, "ingest-reload-failure")
    database = directory / "cce.sqlite3"
    token = "sk-proj-" + "F" * 40
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    get_event_calls = 0
    original_get_event = Store.get_event

    def bypass_capture(payload, mode):
        return payload, {
            "mode": mode, "redactions": [], "dropped_fields": 0}

    def fail_second_reload(store, *args, **kwargs):
        nonlocal get_event_calls
        if store is engine.store:
            get_event_calls += 1
            if get_event_calls == 2:
                raise MemoryError("canonical event reload failed")
        return original_get_event(store, *args, **kwargs)

    monkeypatch.setattr(engine_module, "apply_capture_mode", bypass_capture)
    monkeypatch.setattr(Store, "get_event", fail_second_reload)
    caught = None
    try:
        try:
            engine.ingest_agent_trace(
                PROJECT, session_id=None, span_id="reload-failure",
                payload={"message": f"Requirement: deploy with {token}"})
        except Exception as exc:
            caught = exc
        event = engine.store.events(PROJECT, tenant_id=TENANT)[0]
        assert get_event_calls == 2
        assert token in canonical_json(event["payload"])
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert isinstance(
            caught, engine_module.ProcessorProjectionCompatibilityError)
    finally:
        engine.close()


def test_rebuild_does_not_turn_a_redaction_refusal_into_quarantine(
        tmp_path, monkeypatch):
    directory = _private_dir(tmp_path, "rebuild-redaction-refusal")
    database = directory / "cce.sqlite3"
    token = "sk-proj-" + "C" * 40
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="rebuild-unredacted",
        payload={"message": f"Requirement: deploy with {token}"},
        authority="agent_observed")
    marker_calls = []
    original = Store.mark_processed

    def observed(store, *args, **kwargs):
        marker_calls.append((args, kwargs))
        return original(store, *args, **kwargs)

    monkeypatch.setattr(Store, "mark_processed", observed)
    try:
        with pytest.raises(
                engine_module.ProcessorProjectionCompatibilityError,
                match="re-ingest"):
            engine.rebuild_projection(PROJECT)
        assert marker_calls == []
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
    finally:
        engine.close()


@pytest.mark.parametrize("failure_type", [MemoryError, RuntimeError],
                         ids=("memory-error", "unexpected-error"))
def test_rebuild_validator_failure_never_mints_current_quarantine(
        tmp_path, monkeypatch, failure_type):
    directory = _private_dir(tmp_path, f"rebuild-{failure_type.__name__}")
    database = directory / "cce.sqlite3"
    token = "sk-proj-" + "D" * 40
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="rebuild-validator-failure",
        payload={"message": f"Requirement: deploy with {token}"},
        authority="agent_observed")
    marker_calls = []
    original_mark_processed = Store.mark_processed

    def fail_validation(_payload, _mode):
        raise failure_type("capture validation failed")

    def observed_mark(store, *args, **kwargs):
        marker_calls.append((args, kwargs))
        return original_mark_processed(store, *args, **kwargs)

    monkeypatch.setattr(
        engine_module, "_capture_payload_is_current", fail_validation)
    monkeypatch.setattr(Store, "mark_processed", observed_mark)
    caught = None
    fresh = None
    try:
        try:
            fresh = engine.rebuild_projection(PROJECT)
        except Exception as exc:
            caught = exc
        finally:
            if fresh is not None:
                fresh.close()
        assert marker_calls == []
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert isinstance(
            caught, engine_module.ProcessorProjectionCompatibilityError)
    finally:
        engine.close()


def test_rebuild_reload_failure_cannot_quarantine_unvalidated_payload(
        tmp_path, monkeypatch):
    directory = _private_dir(tmp_path, "rebuild-reload-failure")
    database = directory / "cce.sqlite3"
    token = "sk-proj-" + "E" * 40
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="rebuild-reload-failure",
        payload={"message": f"Requirement: deploy with {token}"},
        authority="agent_observed")
    marker_calls = []
    reload_failed = False
    original_get_event = Store.get_event
    original_mark_processed = Store.mark_processed

    def fail_first_fresh_reload(store, *args, **kwargs):
        nonlocal reload_failed
        if store is not engine.store and not reload_failed:
            reload_failed = True
            raise MemoryError("canonical event reload failed")
        return original_get_event(store, *args, **kwargs)

    def observed_mark(store, *args, **kwargs):
        marker_calls.append((args, kwargs))
        return original_mark_processed(store, *args, **kwargs)

    monkeypatch.setattr(Store, "get_event", fail_first_fresh_reload)
    monkeypatch.setattr(Store, "mark_processed", observed_mark)
    caught = None
    fresh = None
    try:
        try:
            fresh = engine.rebuild_projection(PROJECT)
        except Exception as exc:
            caught = exc
        finally:
            if fresh is not None:
                fresh.close()
        assert reload_failed is True
        assert marker_calls == []
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert isinstance(
            caught, engine_module.ProcessorProjectionCompatibilityError)
    finally:
        engine.close()


def test_direct_process_event_uses_project_capture_mode_not_event_claim(
        tmp_path):
    directory = _private_dir(tmp_path, "direct-metadata-policy")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project(
        "p", project_id=PROJECT, repository_id=REPOSITORY_ID,
        capture_mode="metadata_only")
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="direct-metadata-policy",
        payload={"message": "private ordinary deployment detail"},
        authority="agent_observed")
    before = canonical_json(event)
    try:
        with pytest.raises(
                engine_module.ProcessorProjectionCompatibilityError,
                match="re-ingest"):
            engine.process_event(event)
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert canonical_json(engine.store.get_event(
            event["event_id"], tenant_id=TENANT, project_id=PROJECT)) == before
    finally:
        engine.close()


def test_direct_process_event_also_binds_recorded_metadata_mode(tmp_path):
    directory = _private_dir(tmp_path, "direct-recorded-metadata-policy")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID,
                          capture_mode="redacted")
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="direct-recorded-metadata-policy",
        payload={"message": "private ordinary deployment detail"},
        authority="agent_observed", capture_mode="metadata_only")
    before = canonical_json(event)
    try:
        with pytest.raises(
                engine_module.ProcessorProjectionCompatibilityError,
                match="re-ingest"):
            engine.process_event(event)
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert canonical_json(engine.store.get_event(
            event["event_id"], tenant_id=TENANT, project_id=PROJECT)) == before
    finally:
        engine.close()


def test_recorded_full_sentinel_cannot_claim_current_metadata_output(tmp_path):
    directory = _private_dir(tmp_path, "direct-full-sentinel-metadata-policy")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID,
                          capture_mode="metadata_only")
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="direct-full-sentinel-metadata-policy",
        payload={"description": {
            "password": "[DROPPED:password:16chars]"}},
        authority="agent_observed", capture_mode="full")
    try:
        with pytest.raises(
                engine_module.ProcessorProjectionCompatibilityError,
                match="re-ingest"):
            engine.process_event(event)
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM processed_events WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE event_id = ?",
            (event["event_id"],)).fetchone()[0] == 0
    finally:
        engine.close()


def test_recorded_metadata_output_survives_relaxed_project_mode(tmp_path):
    directory = _private_dir(tmp_path, "metadata-output-redacted-project")
    database = directory / "cce.sqlite3"
    payload, _ = engine_module.apply_capture_mode(
        {"description": {"password": "abcdefghijklmnop"}},
        "metadata_only")
    assert payload["description"]["password"] == (
        "[DROPPED:password:16chars]")
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID,
                          capture_mode="redacted")
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="metadata-output-redacted-project",
        payload=payload, authority="agent_observed",
        capture_mode="metadata_only")
    fresh = None
    try:
        engine.process_event(event)
        before = engine.projection_fingerprint(PROJECT)
        fresh = engine.rebuild_projection(PROJECT)
        assert fresh.projection_fingerprint(PROJECT) == before
        assert _rows(
            database,
            "SELECT processor_version, status FROM processed_events"
            " WHERE event_id = ?", (event["event_id"],)) == [
                (PROCESSOR_VERSION, "ok")]
    finally:
        if fresh is not None:
            fresh.close()
        engine.close()
    _assert_admitted(database, directory)


def test_markerless_admission_uses_recorded_metadata_capture_mode(tmp_path):
    raw_directory = _private_dir(tmp_path, "markerless-metadata-raw")
    raw_database = raw_directory / "cce.sqlite3"
    store = Store(str(raw_database))
    try:
        store.append_event(
            tenant_id=TENANT, project_id=PROJECT,
            source_type="agent_trace", idempotency_key="metadata-raw",
            payload={"message": "private ordinary deployment detail"},
            authority="agent_observed", capture_mode="metadata_only")
    finally:
        store.close()
    before = _frozen_state(raw_database)
    _assert_refused(raw_database, raw_directory)
    assert _frozen_state(raw_database) == before

    captured_directory = _private_dir(tmp_path, "markerless-metadata-captured")
    captured_database = captured_directory / "cce.sqlite3"
    payload, _ = engine_module.apply_capture_mode(
        {"message": "private ordinary deployment detail"}, "metadata_only")
    store = Store(str(captured_database))
    try:
        store.append_event(
            tenant_id=TENANT, project_id=PROJECT,
            source_type="agent_trace", idempotency_key="metadata-captured",
            payload=payload, authority="agent_observed",
            capture_mode="metadata_only")
    finally:
        store.close()
    _assert_admitted(captured_database, captured_directory)


def test_projection_failure_leaves_neither_projection_nor_marker(tmp_path,
                                                                 monkeypatch):
    directory = _private_dir(tmp_path, "rollback")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    record = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-fail",
        payload={"text_blocks": [
            {"text": "The exporter must write CSV output.",
             "authority": "human_intent", "ref": "direct:1"}]},
        authority="human_intent")
    stored = engine.store.get_event(record["event_id"], tenant_id=TENANT,
                                    project_id=PROJECT)

    def explode(*args, **kwargs):
        raise RuntimeError("marker write failure")

    monkeypatch.setattr(engine.store, "mark_processed", explode)
    with pytest.raises(RuntimeError):
        engine.process_event(stored)
    engine.close()

    assert _scalar(database, "SELECT COUNT(*) FROM processed_events") == 0
    assert _scalar(database,
                   "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL") == 0
    _assert_admitted(database, directory)


def test_rebuild_returns_a_distinct_engine_with_current_markers(tmp_path):
    directory = _private_dir(tmp_path, "rebuild")
    database = _ingested(directory)
    live = Engine(database, workdir=str(directory))
    fresh = live.rebuild_projection(PROJECT)
    try:
        assert fresh is not live
        assert fresh.store._conn is not live.store._conn
        assert (live.projection_fingerprint(PROJECT)
                == fresh.projection_fingerprint(PROJECT))
        assert (live._semantic_projection(PROJECT)
                == fresh._semantic_projection(PROJECT))
        versions = {row[0] for row in fresh.store._conn.execute(
            "SELECT DISTINCT processor_version FROM processed_events")}
        assert versions == {PROCESSOR_VERSION}
    finally:
        fresh.close()
        live.close()


# --------------------------------------------------------- refused shapes
def test_released_processor_one_zero_store_refuses(tmp_path):
    """0.1.0-0.1.3 marker state, constructed here rather than replayed.

    The markers of a store this producer wrote are rewritten to
    cce-processor/1.0.0; no released binary runs in this test.
    """
    directory = _private_dir(tmp_path, "released")
    database = _ingested(directory)
    _sql(database,
         "UPDATE processed_events SET processor_version='cce-processor/1.0.0'")
    _assert_refused(database, directory)


def test_store_processed_before_the_checkbox_fix_refuses(tmp_path):
    """cce-processor/1.2.0 marker state, constructed here rather than replayed.

    Extraction stopped recording a task-list checkbox as statement text after
    1.2.0 stores were written, so such a store can hold "[ ] ..." statements
    that this processor no longer produces.
    """
    directory = _private_dir(tmp_path, "pre-checkbox")
    database = _ingested(directory)
    _sql(database,
         "UPDATE processed_events SET processor_version='cce-processor/1.2.0'")
    _assert_refused(database, directory)


def test_store_processed_before_current_redaction_semantics_refuses(
        tmp_path, monkeypatch):
    """1.3.0 projection can retain credentials 1.4.0 recognizes.

    The old producer is represented by its version marker and persisted
    output, not by importing a second implementation into this test.  The
    selected ``sk-proj-`` form is one the exact 1.3.0 source retained and the
    current redactor replaces. Retention then clears the canonical payload so
    only the version boundary can protect the credential left in graph state.
    """
    directory = _private_dir(tmp_path, "pre-redaction-semantics")
    database = directory / "cce.sqlite3"
    token = "sk-proj-" + "A" * 40

    monkeypatch.setattr(
        engine_module, "PROCESSOR_VERSION", "cce-processor/1.3.0")
    monkeypatch.setattr(
        engine_module, "apply_capture_mode",
        lambda payload, mode: (
            payload,
            {"mode": mode, "redactions": [], "dropped_fields": 0},
        ),
    )
    monkeypatch.setattr(
        engine_module, "_capture_payload_is_current",
        lambda payload, mode: True)
    engine = Engine(database, workdir=str(directory))
    try:
        engine.create_project(
            "p", project_id=PROJECT, repository_id=REPOSITORY_ID)
        engine.ingest_github(
            PROJECT, "issues", "pre-redaction-semantics-1",
            _issue(1, f"We assume deployment uses {token}."))
    finally:
        engine.close()
    monkeypatch.undo()

    assert token in _scalar(database, "SELECT payload FROM events")
    assert any(token in row[0] for row in _rows(
        database, "SELECT data FROM nodes"))
    _sql(database, "UPDATE events SET payload = NULL")
    assert _scalar(database, "SELECT payload FROM events") is None
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


def test_synthetic_processor_one_four_projection_refuses_unchanged(tmp_path):
    """A 1.4 marker-bearing projection cannot be opened by processor 1.5.

    This is synthetic producer state: the current test producer creates a
    valid projection, then only its marker is rewritten to the literal 1.4
    identity. No released 1.4 artifact is invoked or claimed here.
    """
    directory = _private_dir(tmp_path, "pre-normalization-semantics")
    database = _ingested(directory)
    _sql(database,
         "UPDATE processed_events SET processor_version='cce-processor/1.4.0'")
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


def test_current_marker_payload_skips_admission_redaction(tmp_path,
                                                           monkeypatch):
    """The marker already binds a current projection to current semantics."""
    directory = _private_dir(tmp_path, "current-marker-scan")
    database = _ingested(directory)
    assert _scalar(database, "SELECT payload FROM events") is not None
    calls = []
    original = engine_module._capture_payload_is_current

    def observed(payload, mode):
        calls.append((payload, mode))
        return original(payload, mode)

    monkeypatch.setattr(engine_module, "_capture_payload_is_current", observed)
    _assert_admitted(database, directory)

    assert calls == []


def test_old_marker_payload_skips_redaction_then_refuses_unchanged(
        tmp_path, monkeypatch):
    """An old marker is already a deciding incompatibility."""
    directory = _private_dir(tmp_path, "old-marker-scan")
    database = _ingested(directory)
    _sql(database,
         "UPDATE processed_events SET processor_version='cce-processor/1.3.0'")
    assert _scalar(database, "SELECT payload FROM events") is not None
    before = _frozen_state(database)
    calls = []
    original = engine_module._capture_payload_is_current

    def observed(payload, mode):
        calls.append((payload, mode))
        return original(payload, mode)

    monkeypatch.setattr(engine_module, "_capture_payload_is_current", observed)
    _assert_refused(database, directory)

    assert calls == []
    assert _frozen_state(database) == before


def test_markerless_clean_payload_is_still_checked(tmp_path, monkeypatch):
    """The optimization must not bypass the only semantic witness."""
    directory = _private_dir(tmp_path, "markerless-clean-scan")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    try:
        store.append_event(
            tenant_id=TENANT, project_id=PROJECT,
            source_type="agent_trace", idempotency_key="markerless-clean",
            payload={"note": "ordinary text"}, authority="agent_observed")
    finally:
        store.close()
    calls = []
    original = engine_module._capture_payload_is_current

    def observed(payload, mode):
        calls.append((payload, mode))
        return original(payload, mode)

    monkeypatch.setattr(engine_module, "_capture_payload_is_current", observed)
    _assert_admitted(database, directory)

    # Engine checks once through the immutable path and once on Store's exact
    # connection before schema installation.
    assert calls == [({"note": "ordinary text"}, "full")] * 2


@pytest.mark.parametrize("payload", [
    {"note": "sk-proj-" + "A" * 40},
    {"sk-proj-" + "A" * 40: "value"},
])
def test_markerless_retained_secret_refuses_before_projection(tmp_path, payload):
    """A version marker cannot protect an event that has no projection yet."""
    directory = _private_dir(tmp_path, "markerless-retained-secret")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    try:
        store.append_event(
            tenant_id=TENANT, project_id=PROJECT,
            source_type="agent_trace", idempotency_key="legacy-secret",
            payload=payload, authority="agent_observed")
    finally:
        store.close()

    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


def test_redaction_recursion_is_a_fixed_compatibility_refusal(
        tmp_path, monkeypatch):
    """A nested retained payload must not escape the admission boundary."""
    directory = _private_dir(tmp_path, "recursive-retained-payload")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    try:
        store.append_event(
            tenant_id=TENANT, project_id=PROJECT,
            source_type="agent_trace", idempotency_key="recursive-payload",
            payload={"note": "nested"}, authority="agent_observed")
    finally:
        store.close()

    def recursion_at_redaction(_payload, _mode):
        raise RecursionError("retained payload exceeds the redaction walk")

    monkeypatch.setattr(
        engine_module, "_capture_payload_is_current", recursion_at_redaction)
    before = _frozen_state(database)
    with pytest.raises(
            engine_module.ProcessorProjectionCompatibilityError,
            match="re-ingest"):
        Engine(database, workdir=str(directory))
    assert _frozen_state(database) == before


def test_markerless_projection_refuses(tmp_path):
    directory = _private_dir(tmp_path, "markerless")
    database = _ingested(directory)
    _sql(database, "DELETE FROM processed_events")
    assert _scalar(database,
                   "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL") > 0
    _assert_refused(database, directory)


def test_old_and_current_markers_refuse(tmp_path):
    directory = _private_dir(tmp_path, "mixture")
    database = _ingested(directory)
    event_id = _scalar(database, "SELECT event_id FROM events")
    _sql(database,
         "INSERT OR REPLACE INTO processed_events VALUES "
         f"('{event_id}','cce-processor/1.0.0','2026-01-01T00:00:00Z','ok',NULL)")
    _assert_refused(database, directory)


def test_malformed_marker_status_refuses(tmp_path):
    directory = _private_dir(tmp_path, "status")
    database = _ingested(directory)
    _sql(database, "UPDATE processed_events SET status='weird'")
    _assert_refused(database, directory)


def test_orphan_marker_refuses(tmp_path):
    directory = _private_dir(tmp_path, "orphan-marker")
    database = _ingested(directory)
    _sql(database,
         "INSERT OR REPLACE INTO processed_events VALUES "
         "('evt_orphan000000000000000000','" + PROCESSOR_VERSION +
         "','2026-01-01T00:00:00Z','ok',NULL)")
    _assert_refused(database, directory)


def test_missing_canonical_event_node_refuses(tmp_path):
    directory = _private_dir(tmp_path, "no-event-node")
    database = _ingested(directory)
    event_id = _scalar(database, "SELECT event_id FROM events")
    _sql(database,
         f"DELETE FROM nodes WHERE node_id='{event_id}' "
         "AND entity_type='event'")
    assert _scalar(database,
                   "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL") > 0
    _assert_refused(database, directory)


def test_historical_only_canonical_event_node_refuses(tmp_path):
    directory = _private_dir(tmp_path, "historical")
    database = _ingested(directory)
    _sql(database,
         "UPDATE nodes SET tx_to='2026-01-01T00:00:00Z' "
         "WHERE event_id IS NOT NULL")
    _assert_refused(database, directory)


def test_ok_marker_without_any_projection_refuses(tmp_path):
    directory = _private_dir(tmp_path, "ok-empty")
    database = _ingested(directory)
    _sql(database, "DELETE FROM nodes WHERE event_id IS NOT NULL",
         "DELETE FROM edges WHERE event_id IS NOT NULL")
    _assert_refused(database, directory)


@pytest.mark.parametrize("table", ["nodes", "edges"])
def test_quarantine_marker_with_retained_projection_refuses(tmp_path, table):
    directory = _private_dir(tmp_path, f"quarantine-{table}")
    database = _ingested_with_edges(directory)
    if table == "edges":
        # Leave ONLY an attributed edge behind, so the refusal must come from
        # the edge witness rather than a retained node.
        _sql(database, "DELETE FROM nodes WHERE event_id IS NOT NULL")
    else:
        _sql(database, "DELETE FROM edges WHERE event_id IS NOT NULL")
    assert _scalar(
        database, f"SELECT COUNT(*) FROM {table} WHERE event_id IS NOT NULL") > 0
    _sql(database,
         "UPDATE processed_events SET status='quarantined' "
         f"WHERE processor_version='{PROCESSOR_VERSION}'")
    _assert_refused(database, directory)


@pytest.mark.parametrize("table", ["nodes", "edges"])
def test_orphan_attributed_graph_row_refuses(tmp_path, table):
    directory = _private_dir(tmp_path, f"orphan-{table}")
    database = _ingested_with_edges(directory)
    assert _scalar(
        database, f"SELECT COUNT(*) FROM {table} WHERE event_id IS NOT NULL") > 0
    key = "node_id" if table == "nodes" else "edge_id"
    _clone_row(database, table,
               **{key: f"{'nod' if table == 'nodes' else 'edg'}_ghost000000000000",
                  "event_id": "evt_ghost000000000000000000"})
    _assert_refused(database, directory)


@pytest.mark.parametrize("column", ["tenant_id", "project_id"])
@pytest.mark.parametrize("table", ["nodes", "edges"])
def test_cross_scope_attributed_graph_row_refuses(tmp_path, table, column):
    directory = _private_dir(tmp_path, f"cross-{table}-{column}")
    database = _ingested_with_edges(directory)
    assert _scalar(
        database, f"SELECT COUNT(*) FROM {table} WHERE event_id IS NOT NULL") > 0
    key = "node_id" if table == "nodes" else "edge_id"
    _clone_row(database, table,
               **{key: f"{'nod' if table == 'nodes' else 'edg'}_cross000000000000",
                  column: "other_scope_value"})
    _assert_refused(database, directory)


def test_attributed_graph_rows_without_any_events_refuse(tmp_path):
    directory = _private_dir(tmp_path, "no-events")
    database = _ingested(directory)
    _drop_event_triggers(database)
    _sql(database, "DELETE FROM processed_events", "DELETE FROM events")
    assert _scalar(database,
                   "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL") > 0
    _assert_refused(database, directory)


def test_multi_project_one_incompatible_event_refuses_globally(tmp_path):
    directory = _private_dir(tmp_path, "multi")
    database = _ingested(directory)
    engine = Engine(database, workdir=str(directory))
    engine.create_project("q", project_id="prj_other",
                          repository_id=REPOSITORY_ID)
    engine.ingest_github("prj_other", "issues", "d2",
                         _issue(2, "The service must support Python 3.12."))
    engine.close()
    event_id = _scalar(database, "SELECT event_id FROM events LIMIT 1")
    _sql(database,
         f"DELETE FROM processed_events WHERE event_id='{event_id}'",
         "INSERT OR REPLACE INTO processed_events VALUES "
         f"('{event_id}','cce-processor/1.0.0','2026-01-01T00:00:00Z','ok',NULL)")
    _assert_refused(database, directory)


def test_retention_cleared_incompatible_history_refuses(tmp_path):
    directory = _private_dir(tmp_path, "retention")
    database = _ingested(directory)
    _sql(database,
         "UPDATE processed_events SET processor_version='cce-processor/1.0.0'",
         "UPDATE events SET payload=NULL")
    _assert_refused(database, directory)


# -------------------------------------------------------- schema shapes
@pytest.mark.parametrize("ddl", [
    "CREATE TABLE processed_events (event_id TEXT, processor_version TEXT,"
    " status TEXT, PRIMARY KEY (event_id, processor_version))",
    "CREATE TABLE processed_events (status TEXT, event_id TEXT,"
    " processor_version TEXT, error TEXT, processed_at TEXT,"
    " PRIMARY KEY (event_id, processor_version))",
    "CREATE TABLE processed_events (event_id TEXT, processor_version TEXT,"
    " processed_at TEXT, status TEXT, error TEXT, extra TEXT,"
    " PRIMARY KEY (event_id, processor_version))",
    "CREATE TABLE processed_events (event_id TEXT, processor_version TEXT,"
    " processed_at TEXT, status TEXT, error TEXT)",
    "CREATE TABLE processed_events (event_id TEXT, processor_version TEXT,"
    " processed_at TEXT, status TEXT, error TEXT,"
    " PRIMARY KEY (processor_version, event_id))",
])
def test_incompatible_marker_schema_refuses(tmp_path, ddl):
    directory = _private_dir(tmp_path, "marker-schema")
    database = _ingested(directory)
    _sql(database, "ALTER TABLE processed_events RENAME TO pe_old", ddl)
    _assert_refused(database, directory)


def test_missing_marker_table_refuses(tmp_path):
    directory = _private_dir(tmp_path, "marker-absent")
    database = _ingested(directory)
    _sql(database, "DROP TABLE processed_events")
    _assert_refused(database, directory)


@pytest.mark.parametrize("present", ["nodes", "edges"])
def test_exactly_one_graph_table_refuses(tmp_path, present):
    directory = _private_dir(tmp_path, f"partial-graph-{present}")
    database = _ingested(directory)
    missing = "edges" if present == "nodes" else "nodes"
    _sql(database, f"DROP TABLE {missing}")
    _assert_refused(database, directory)


def test_marker_without_graph_tables_refuses(tmp_path):
    directory = _private_dir(tmp_path, "store-only-marked")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    record = store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-marked", payload={"note": "x"},
        authority="agent_observed")
    store.mark_processed(record["event_id"], PROCESSOR_VERSION, "ok")
    store.close()
    _assert_refused(database, directory)


def test_malformed_empty_schema_refuses_before_store_installation(tmp_path):
    directory = _private_dir(tmp_path, "malformed-empty")
    database = directory / "cce.sqlite3"
    _sql(database, "CREATE TABLE events (event_id TEXT)")
    before = database.read_bytes()
    _assert_refused(database, directory)
    assert database.read_bytes() == before, \
        "refusal must not mutate the database"


# ------------------------------------------------------ ordering / TOCTOU
def test_exact_connection_check_catches_path_substitution(tmp_path,
                                                          monkeypatch):
    """Interpose between the path preflight and Store's own connection."""
    directory = _private_dir(tmp_path, "toctou")
    good = directory / "cce.sqlite3"
    engine = Engine(good, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    engine.close()

    incompatible_dir = _private_dir(tmp_path, "toctou-src")
    incompatible = _ingested(incompatible_dir)
    _sql(incompatible,
         "UPDATE processed_events SET processor_version='cce-processor/1.0.0'")

    path_check = getattr(
        engine_module, "_assert_processor_projection_compatible_path", None)
    if path_check is None:
        pytest.skip("boundary symbol absent: not an independent pre-fix pin")

    swapped = {"done": False}

    def swap_after_preflight(path):
        path_check(path)
        if not swapped["done"]:
            swapped["done"] = True
            good.write_bytes(incompatible.read_bytes())

    monkeypatch.setattr(
        engine_module, "_assert_processor_projection_compatible_path",
        swap_after_preflight)

    before = good.read_bytes()
    _assert_refused(good, directory)
    assert swapped["done"], "substitution never ran"
    assert good.read_bytes() != before
    assert _scalar(good, "SELECT COUNT(*) FROM processed_events") == 1


def test_admission_uses_a_constant_number_of_statements(tmp_path):
    """Statement count must not grow with the event count."""
    counts = {}
    for label, events in (("small", 1), ("large", 12)):
        directory = _private_dir(tmp_path, f"scale-{label}")
        database = directory / "cce.sqlite3"
        engine = Engine(database, workdir=str(directory))
        engine.create_project("p", project_id=PROJECT,
                              repository_id=REPOSITORY_ID)
        for number in range(events):
            engine.ingest_github(
                PROJECT, "issues", f"d{number}",
                _issue(number + 1,
                       f"Requirement number {number} must hold."))
        engine.close()

        checker = getattr(
            engine_module, "_assert_processor_projection_compatible", None)
        if checker is None:
            pytest.skip("boundary symbol absent: not an independent pre-fix pin")
        connection = sqlite3.connect(database)
        statements = []
        connection.set_trace_callback(statements.append)
        try:
            checker(connection)
        finally:
            connection.set_trace_callback(None)
            connection.close()
        counts[label] = len(statements)
        assert not any("FROM nodes" in s and "WHERE event_id =" in s
                       for s in statements), \
            "per-event correlated scan of nodes"
    assert counts["small"] == counts["large"], counts


def test_cli_refuses_with_a_bounded_sanitized_error(tmp_path):
    directory = _private_dir(tmp_path, "cli")
    repo_root = Path(engine_module.__file__).resolve().parents[1]
    init = subprocess.run(
        [sys.executable, "-m", "causal_continuity_engine.cli",
         "--dir", str(directory), "init", "--repo-id", str(REPOSITORY_ID)],
        capture_output=True, text=True, cwd=str(repo_root),
        env={**os.environ, "PYTHONPATH": str(repo_root)})
    assert init.returncode == 0, init.stderr

    cce = directory / ".cce"
    meta_before = (cce / "meta.json").read_bytes()
    entries_before = sorted(p.name for p in cce.iterdir())

    engine = Engine(cce / "cce.db", workdir=str(directory))
    project_id = engine.projects()[0]["node_id"] if hasattr(
        engine, "projects") else None
    engine.close()
    if project_id is None:
        connection = sqlite3.connect(cce / "cce.db")
        project_id = connection.execute(
            "SELECT node_id FROM nodes WHERE entity_type='project' "
            "LIMIT 1").fetchone()[0]
        connection.close()

    engine = Engine(cce / "cce.db", workdir=str(directory))
    engine.ingest_github(project_id, "issues", "d1",
                         _issue(1, "The exporter must write CSV output."))
    engine.close()
    _sql(cce / "cce.db",
         "UPDATE processed_events SET processor_version='cce-processor/1.0.0'")

    result = subprocess.run(
        [sys.executable, "-m", "causal_continuity_engine.cli",
         "--dir", str(directory), "resume"],
        capture_output=True, text=True, cwd=str(repo_root),
        env={**os.environ, "PYTHONPATH": str(repo_root)})

    assert result.returncode == 2, (result.returncode, result.stderr)
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert len([line for line in result.stderr.splitlines() if line.strip()]) == 1
    for secret in ("exporter", "CSV", "evt_", "req_", str(cce)):
        assert secret not in result.stderr
    assert (cce / "meta.json").read_bytes() == meta_before
    assert sorted(p.name for p in cce.iterdir()) == entries_before


def test_committed_wal_refusal_preserves_main_wal_and_logical_state(tmp_path):
    directory = _private_dir(tmp_path, "wal")
    database = _ingested(directory)
    _sql(database,
         "UPDATE processed_events SET processor_version='cce-processor/1.0.0'")
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE IF NOT EXISTS _probe (x INTEGER)")
    connection.execute("INSERT INTO _probe VALUES (1)")
    connection.commit()

    target = _private_dir(tmp_path, "wal-copy")
    copied = target / "cce.sqlite3"
    for suffix in ("", "-wal", "-shm"):
        source = Path(str(database) + suffix)
        if source.exists():
            Path(str(copied) + suffix).write_bytes(source.read_bytes())
    connection.close()

    def snapshot():
        # Read logical state FIRST: opening a committed-WAL database
        # checkpoints it, so reading bytes first would attribute this
        # harness's own checkpoint to the refusal under test.
        state = {}
        state["logical"] = (
            _scalar(copied, "SELECT COUNT(*) FROM events"),
            _scalar(copied, "SELECT COUNT(*) FROM processed_events"),
            _scalar(copied, "SELECT COUNT(*) FROM nodes"),
            _scalar(copied, "SELECT COUNT(*) FROM sqlite_master"),
        )
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(copied) + suffix)
            state[suffix] = path.read_bytes() if path.exists() else None
        return state

    before = snapshot()
    assert Path(str(copied) + "-wal").exists() or before["-wal"] is None
    _assert_refused(copied, target)
    after = snapshot()

    assert after[""] == before[""], "main database changed on refusal"
    assert after["-wal"] == before["-wal"], "WAL changed on refusal"
    assert after["logical"] == before["logical"], "logical state changed"
    # ADR-106's exact limit: read-only inspection of a committed WAL may create
    # or update transient shared-memory sidecar state. That is recorded, not
    # claimed away.
    assert before["-shm"] is None or after["-shm"] is not None


# =====================================================================
# P0-v6 review-gap regressions
# =====================================================================
def _engine_ddl():
    """Exact CREATE statements the producer installs, read from a real store."""
    directory = tempfile.mkdtemp(prefix="cce-ddl-")
    os.chmod(directory, 0o700)
    database = os.path.join(directory, "cce.sqlite3")
    Engine(database, workdir=directory).close()
    connection = sqlite3.connect(database)
    try:
        return {
            row[0]: row[1] for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table'")
            if row[1]
        }
    finally:
        connection.close()


def _build(directory, statements):
    """An isolated fixture: only the statements given, no ALTER residue."""
    database = directory / "cce.sqlite3"
    connection = sqlite3.connect(database)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    return database


def _frozen_state(database):
    """Bytes, schema, directory entries and logical serialization, captured
    after the fixture is complete and immediately before admission."""
    directory = Path(database).parent
    connection = sqlite3.connect(database)
    try:
        schema = sorted(
            (row[0], row[1], row[2]) for row in connection.execute(
                "SELECT type, name, sql FROM sqlite_master"))
        dump = "\n".join(connection.iterdump())
    finally:
        connection.close()
    return {
        "bytes": Path(database).read_bytes(),
        "entries": sorted(p.name for p in directory.iterdir()),
        "schema": schema,
        "dump": dump,
    }


# ---------------------------------------------------------------- G2
@pytest.mark.parametrize("keep", [
    ("processed_events", "nodes", "edges"),
    ("processed_events",),
    ("nodes", "edges"),
])
def test_events_absent_with_projection_residue_refuses(tmp_path, keep):
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, "no-events-" + "-".join(keep))
    database = _build(directory, [ddl[name] for name in keep])
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before, "refusal mutated the database"


def test_events_renamed_away_with_projection_residue_refuses(tmp_path):
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, "events-renamed")
    statements = [ddl["processed_events"], ddl["nodes"], ddl["edges"],
                  ddl["events"].replace("CREATE TABLE events",
                                        "CREATE TABLE events_residue", 1)]
    database = _build(directory, statements)
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


@pytest.mark.parametrize("spelling", ["EVENTS", "Events"])
def test_case_variant_canonical_tables_refuse(tmp_path, spelling):
    """SQLite resolves names case-insensitively; the census must too, while
    still requiring the canonical spelling the producer wrote."""
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, f"case-{spelling}")
    statements = [
        ddl["events"].replace("CREATE TABLE events",
                              f"CREATE TABLE {spelling}", 1),
        ddl["processed_events"], ddl["nodes"], ddl["edges"],
    ]
    database = _build(directory, statements)
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


# ---------------------------------------------------------------- G3
def test_events_without_uniqueness_and_duplicate_ids_refuses(tmp_path):
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, "events-dup")
    declaration = ddl["events"].replace("event_id        TEXT PRIMARY KEY",
                                        "event_id        TEXT", 1)
    assert "PRIMARY KEY" not in declaration.split("\n")[1]
    database = _build(directory, [declaration, ddl["processed_events"],
                                  ddl["nodes"], ddl["edges"]])
    _sql(database,
         "INSERT INTO events (event_id, tenant_id, project_id, source_type,"
         " idempotency_key, observed_at, recorded_at, authority,"
         " payload_digest, stored_payload_digest, schema_version)"
         " VALUES ('evt_dup00000000000000000','t','p','s','k','1','1','a',"
         "'d','d','v')",
         "INSERT INTO events (event_id, tenant_id, project_id, source_type,"
         " idempotency_key, observed_at, recorded_at, authority,"
         " payload_digest, stored_payload_digest, schema_version)"
         " VALUES ('evt_dup00000000000000000','t','p','s','k2','1','1','a',"
         "'d','d','v')")
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


@pytest.mark.parametrize("table", ["nodes", "edges"])
def test_graph_subset_declaration_refuses(tmp_path, table):
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, f"{table}-subset")
    # A layout that still satisfies the earlier statement-identity boundary:
    # every producer column is present, with one extra column appended. Only
    # the complete-declaration check can tell this from the real table.
    database = _build(directory, [
        ddl["events"], ddl["processed_events"], ddl["nodes"], ddl["edges"],
        f"ALTER TABLE {table} ADD COLUMN extra_column TEXT"])
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


def test_marker_declaration_with_wrong_default_refuses(tmp_path):
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, "marker-default")
    database = _build(directory, [
        ddl["events"],
        "CREATE TABLE processed_events (event_id TEXT NOT NULL,"
        " processor_version TEXT NOT NULL, processed_at TEXT NOT NULL,"
        " status TEXT NOT NULL DEFAULT 'ok', error TEXT,"
        " PRIMARY KEY (event_id, processor_version))",
        ddl["nodes"], ddl["edges"]])
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


def test_canonical_name_as_a_view_refuses(tmp_path):
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, "view-alias")
    database = _build(directory, [
        ddl["events"], ddl["nodes"], ddl["edges"],
        "CREATE TABLE marker_backing (event_id TEXT, processor_version TEXT,"
        " processed_at TEXT, status TEXT, error TEXT)",
        "CREATE VIEW processed_events AS SELECT * FROM marker_backing"])
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


# ---------------------------------------------------------------- G4
def test_classification_leaves_no_open_transaction(tmp_path):
    directory = _private_dir(tmp_path, "snapshot")
    database = _ingested(directory)
    checker = getattr(
        engine_module, "_assert_processor_projection_compatible", None)
    if checker is None:
        pytest.fail("database was admitted but must be refused")
    connection = sqlite3.connect(database)
    try:
        checker(connection)
        assert connection.in_transaction is False, \
            "classification left a transaction open"
    finally:
        connection.close()


@pytest.mark.parametrize("state", ["ok-marker-without-node",
                                   "old-marker-with-node"])
def test_each_complete_state_refuses_independently(tmp_path, state):
    directory = _private_dir(tmp_path, f"state-{state}")
    database = _ingested(directory)
    event_id = _scalar(database, "SELECT event_id FROM events")
    if state == "ok-marker-without-node":
        _sql(database, f"DELETE FROM nodes WHERE node_id='{event_id}'"
                       " AND entity_type='event'")
    else:
        _sql(database, "UPDATE processed_events SET"
                       " processor_version='cce-processor/1.0.0'")
    _assert_refused(database, directory)


# ---------------------------------------------------------------- G6
@pytest.mark.parametrize("trigger", [
    "CREATE TRIGGER suppress BEFORE INSERT ON processed_events"
    " BEGIN SELECT RAISE(IGNORE); END",
    "CREATE TRIGGER wipe AFTER INSERT ON processed_events"
    " BEGIN DELETE FROM processed_events WHERE event_id = NEW.event_id; END",
    "CREATE TRIGGER alter_status AFTER INSERT ON processed_events"
    " BEGIN UPDATE processed_events SET status='quarantined'"
    " WHERE event_id = NEW.event_id; END",
])
def test_marker_write_is_verified_inside_the_owning_transaction(tmp_path,
                                                                trigger):
    directory = _private_dir(tmp_path, "marker-postcondition")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    engine.close()
    _sql(database, trigger)

    engine = Engine(database, workdir=str(directory))
    record = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-post",
        payload={"text_blocks": [
            {"text": "The exporter must write CSV output.",
             "authority": "human_intent", "ref": "direct:1"}]},
        authority="human_intent")
    stored = engine.store.get_event(record["event_id"], tenant_id=TENANT,
                                    project_id=PROJECT)
    with pytest.raises(Exception) as captured:
        engine.process_event(stored)
    assert not isinstance(captured.value, AssertionError)
    engine.close()

    assert _scalar(
        database,
        "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL") == 0, \
        "projection survived a marker postcondition failure"


def test_quarantine_then_successful_retry_is_consistent(tmp_path):
    directory = _private_dir(tmp_path, "retry")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    record = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-retry",
        payload={"text_blocks": [
            {"text": "The exporter must write CSV output.",
             "authority": "human_intent", "ref": "direct:1"}]},
        authority="human_intent")
    engine.store.mark_processed(record["event_id"], PROCESSOR_VERSION,
                                "quarantined", "boom")
    engine.close()
    _assert_admitted(database, directory)

    engine = Engine(database, workdir=str(directory))
    engine.process_event(engine.store.get_event(
        record["event_id"], tenant_id=TENANT, project_id=PROJECT))
    engine.close()
    rows = _rows(
        database, "SELECT processor_version, status FROM processed_events")
    assert rows == [(PROCESSOR_VERSION, "ok")]
    _assert_admitted(database, directory)


# ---------------------------------------------------------------- G8
def test_simulated_processor_bump_refuses_each_other(tmp_path, monkeypatch):
    """Version-separation control in both directions, not an older-bug pin."""
    directory = _private_dir(tmp_path, "bump")
    database = _ingested(directory)
    _assert_admitted(database, directory)

    # Derived, not a literal: a real bump must never collide with the
    # simulated one.
    monkeypatch.setattr(engine_module, "PROCESSOR_VERSION",
                        f"{PROCESSOR_VERSION}+simulated-bump")
    _assert_refused(database, directory)
    future_directory = _private_dir(tmp_path, "bump-new")
    future_database = _ingested(future_directory)
    _assert_admitted(future_database, future_directory)

    monkeypatch.undo()
    _assert_admitted(database, directory)
    _assert_refused(future_database, future_directory)


@pytest.mark.parametrize("version", ["1.5.0", "1.6.0", "1.7.0"])
def test_pre_source_lifecycle_processor_marker_refuses(tmp_path, version):
    """Structural version control; this is not a released-producer fixture."""
    directory = _private_dir(tmp_path, "pre-co-assertion")
    database = _ingested(directory)
    _assert_admitted(database, directory)
    _sql(database,
         f"UPDATE processed_events SET processor_version='cce-processor/{version}'")
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


def test_append_only_history_admits_under_a_simulated_bump(tmp_path,
                                                           monkeypatch):
    directory = _private_dir(tmp_path, "bump-append")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="k-bump", payload={"note": "x"},
        authority="agent_observed")
    store.close()
    # Derived, not a literal: a real bump must never collide with the
    # simulated one.
    monkeypatch.setattr(engine_module, "PROCESSOR_VERSION",
                        f"{PROCESSOR_VERSION}+simulated-bump")
    _assert_admitted(database, directory)


# =====================================================================
# P0-v8: finite events-declaration migration lifecycle
#
# Declarations below are frozen literals captured from the real Store. They are
# deliberately NOT imported from the candidate: a test that reuses the
# implementation's own constant cannot detect the implementation being wrong.
# =====================================================================
_LEGACY_EVENTS_BODY = """
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT,
    idempotency_key TEXT NOT NULL{uniq},
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
    payload TEXT,
    schema_version TEXT NOT NULL,
    seq INTEGER,
    prev_hash TEXT,
    entry_hash TEXT
"""

# (name, declared type, notnull, default, pk ordinal, hidden)
_FRESH_CURRENT_EVENTS = (
    ("event_id", "TEXT", 0, None, 1, 0), ("tenant_id", "TEXT", 1, None, 0, 0),
    ("project_id", "TEXT", 1, None, 0, 0),
    ("source_type", "TEXT", 1, None, 0, 0),
    ("source_id", "TEXT", 0, None, 0, 0),
    ("idempotency_key", "TEXT", 1, None, 0, 0),
    ("observed_at", "TEXT", 1, None, 0, 0),
    ("recorded_at", "TEXT", 1, None, 0, 0),
    ("valid_from", "TEXT", 0, None, 0, 0),
    ("valid_to", "TEXT", 0, None, 0, 0),
    ("actor_type", "TEXT", 0, None, 0, 0),
    ("actor_id", "TEXT", 0, None, 0, 0),
    ("authority", "TEXT", 1, None, 0, 0),
    ("sensitivity", "TEXT", 1, "'internal'", 0, 0),
    ("capture_mode", "TEXT", 1, "'full'", 0, 0),
    ("payload_digest", "TEXT", 1, None, 0, 0),
    ("stored_payload_digest", "TEXT", 1, None, 0, 0),
    ("payload", "TEXT", 0, None, 0, 0),
    ("schema_version", "TEXT", 1, None, 0, 0),
    ("seq", "INTEGER", 0, None, 0, 0),
    ("prev_hash", "TEXT", 0, None, 0, 0),
    ("entry_hash", "TEXT", 0, None, 0, 0),
)
# Rebuild path: canonical order, digest NULLABLE at slot 16.
_REBUILT_EVENTS = tuple(
    ("stored_payload_digest", "TEXT", 0, None, 0, 0) if c[0] ==
    "stored_payload_digest" else c for c in _FRESH_CURRENT_EVENTS)
# Add-column path: legacy order, nullable digest appended after entry_hash.
_ADDCOL_EVENTS = tuple(
    c for c in _FRESH_CURRENT_EVENTS if c[0] != "stored_payload_digest"
) + (("stored_payload_digest", "TEXT", 0, None, 0, 0),)

_SCOPED_INDEX = ("idx_events_idempotency_scope", 1, "c",
                 ("tenant_id", "project_id", "idempotency_key"))


def _xdecl(database, table="events"):
    connection = sqlite3.connect(database)
    try:
        return tuple(
            (row[1], (row[2] or "").upper(), row[3], row[4], row[5], row[6])
            for row in connection.execute(f"PRAGMA table_xinfo({table})"))
    finally:
        connection.close()


def _indexes(database, table="events"):
    connection = sqlite3.connect(database)
    try:
        out = []
        for row in connection.execute(f"PRAGMA index_list({table})"):
            cols = tuple(x[2] for x in connection.execute(
                f'PRAGMA index_info("{row[1]}")'))
            out.append((row[1], row[2], row[3], cols))
        return sorted(out)
    finally:
        connection.close()


def _index_xinfo(database, index):
    connection = sqlite3.connect(database)
    try:
        return tuple(connection.execute(
            f'PRAGMA index_xinfo("{index}")'))
    finally:
        connection.close()


_SCOPED_INDEX_XINFO = (
    (0, 1, "tenant_id", 0, "BINARY", 1),
    (1, 2, "project_id", 0, "BINARY", 1),
    (2, 5, "idempotency_key", 0, "BINARY", 1),
    (3, -1, None, 0, "BINARY", 0),
)


def _duplicate_scoped_key(database):
    _clone_row(
        database, "events", event_id="evt_ffffffffffffffffffffffff")


def _legacy_events_database(directory, inline_unique):
    """A full Engine-shaped database whose events table is raw legacy."""
    database = directory / "cce.sqlite3"
    Engine(database, workdir=str(directory)).close()
    body = _LEGACY_EVENTS_BODY.format(uniq=" UNIQUE" if inline_unique else "")
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            "DROP TABLE events; CREATE TABLE events (" + body + ");")
        connection.commit()
    finally:
        connection.close()
    return database


@pytest.mark.parametrize("inline_unique", [True, False])
def test_raw_legacy_events_migrates_and_stays_admitted(tmp_path,
                                                       inline_unique):
    """Defect pin: P0-v6 refuses both raw legacy variants at _EVENTS_DECL."""
    directory = _private_dir(tmp_path, f"legacy-{inline_unique}")
    database = _legacy_events_database(directory, inline_unique)
    assert len(_xdecl(database)) == 21

    # 1-2. open through Engine; Store migrates
    Engine(database, workdir=str(directory)).close()
    expected = _REBUILT_EVENTS if inline_unique else _ADDCOL_EVENTS
    assert _xdecl(database) == expected
    assert _SCOPED_INDEX in _indexes(database)
    assert not any(index[0].startswith("sqlite_autoindex_events_2")
                   for index in _indexes(database)), \
        "global idempotency uniqueness survived migration"

    # 3-5. reopen: declaration unchanged and still admitted
    after_first = _xdecl(database)
    Engine(database, workdir=str(directory)).close()
    assert _xdecl(database) == after_first

    # 6. process one normal current event
    engine = Engine(database, workdir=str(directory))
    engine.create_project("p", project_id=PROJECT,
                          repository_id=REPOSITORY_ID)
    engine.ingest_github(PROJECT, "issues", "d1",
                         _issue(1, "The exporter must write CSV output."))
    engine.close()

    # 7-8. reopen; admitted with a non-null persisted digest
    _assert_admitted(database, directory)
    assert _scalar(database,
                   "SELECT COUNT(*) FROM events"
                   " WHERE stored_payload_digest IS NULL") == 0
    assert _scalar(database, "SELECT COUNT(*) FROM events") >= 1


def test_fresh_current_events_layout_is_admitted(tmp_path):
    directory = _private_dir(tmp_path, "fresh-current")
    database = directory / "cce.sqlite3"
    Engine(database, workdir=str(directory)).close()
    assert _xdecl(database) == _FRESH_CURRENT_EVENTS
    _assert_admitted(database, directory)


def test_duplicate_scoped_idempotency_without_index_refuses_unchanged(
        tmp_path):
    """Refuse before Store can add one index and fail on the next."""
    directory = _private_dir(tmp_path, "duplicate-scope-no-index")
    database = _ingested(directory)
    _sql(database, "DROP INDEX idx_events_idempotency_scope",
         "DROP INDEX idx_events_project")
    _duplicate_scoped_key(database)
    before = _frozen_state(database)

    _assert_refused(database, directory)

    assert _frozen_state(database) == before


def test_duplicate_scoped_idempotency_with_counterfeit_index_refuses(
        tmp_path):
    """A correctly named index on the wrong column cannot certify scope."""
    directory = _private_dir(tmp_path, "duplicate-scope-fake-index")
    database = _ingested(directory)
    _sql(database, "DROP INDEX idx_events_idempotency_scope",
         "CREATE UNIQUE INDEX idx_events_idempotency_scope"
         " ON events(event_id)")
    _duplicate_scoped_key(database)
    before = _frozen_state(database)

    _assert_refused(database, directory)

    assert _frozen_state(database) == before


def test_counterfeit_scoped_index_refuses_without_duplicate_rows(tmp_path):
    """Bind index identity independently of the duplicate-row guard."""
    directory = _private_dir(tmp_path, "fake-index-identity")
    database = _ingested(directory)
    _sql(database, "DROP INDEX idx_events_idempotency_scope",
         "CREATE UNIQUE INDEX idx_events_idempotency_scope"
         " ON events(event_id)")
    before = _frozen_state(database)

    _assert_refused(database, directory)

    assert _frozen_state(database) == before


@pytest.mark.parametrize("definition", [
    "CREATE INDEX idx_events_idempotency_scope"
    " ON events(tenant_id, project_id, idempotency_key)",
    "CREATE UNIQUE INDEX idx_events_idempotency_scope"
    " ON events(project_id, tenant_id, idempotency_key)",
    "CREATE UNIQUE INDEX idx_events_idempotency_scope"
    " ON events(tenant_id COLLATE NOCASE, project_id, idempotency_key)",
    "CREATE UNIQUE INDEX idx_events_idempotency_scope"
    " ON events(tenant_id, project_id, idempotency_key)"
    " WHERE idempotency_key <> ''",
    "CREATE UNIQUE INDEX IDX_EVENTS_IDEMPOTENCY_SCOPE"
    " ON events(tenant_id, project_id, idempotency_key)",
])
def test_scoped_index_definition_is_bound(tmp_path, definition):
    directory = _private_dir(tmp_path, "fake-index-definition")
    database = _ingested(directory)
    _sql(database, "DROP INDEX idx_events_idempotency_scope", definition)
    before = _frozen_state(database)

    _assert_refused(database, directory)

    assert _frozen_state(database) == before


def test_missing_scoped_index_with_unique_rows_is_repaired(tmp_path):
    """An interrupted index installation remains a supported repair path."""
    directory = _private_dir(tmp_path, "missing-index-repair")
    database = _ingested(directory)
    _sql(database, "DROP INDEX idx_events_idempotency_scope")

    _assert_admitted(database, directory)

    assert _SCOPED_INDEX in _indexes(database)
    assert _index_xinfo(
        database, "idx_events_idempotency_scope") == _SCOPED_INDEX_XINFO
    _assert_admitted(database, directory)
    assert _index_xinfo(
        database, "idx_events_idempotency_scope") == _SCOPED_INDEX_XINFO


@pytest.mark.parametrize("column", [
    "tenant_id",
    "project_id",
    "idempotency_key",
])
def test_missing_scoped_index_with_nonbinary_column_refuses_unchanged(
        tmp_path, column):
    """Index repair must not inherit a non-producer column collation."""
    directory = _private_dir(tmp_path, f"missing-index-{column}-nocase")
    declaration = _engine_ddl()["events"]
    canonical = {
        "tenant_id": "tenant_id       TEXT NOT NULL,",
        "project_id": "project_id      TEXT NOT NULL,",
        "idempotency_key": "idempotency_key TEXT NOT NULL,",
    }[column]
    altered = declaration.replace(
        canonical, canonical[:-1] + " COLLATE NOCASE,", 1)
    assert altered != declaration, "fixture did not alter the declaration"
    database = _build(directory, [altered])
    before = _frozen_state(database)

    _assert_refused(database, directory)

    assert _frozen_state(database) == before, "refusal mutated the database"


def test_binary_scoped_index_cannot_mask_nonbinary_column(tmp_path):
    """The producer's table declaration is bound, not only its index."""
    directory = _private_dir(tmp_path, "binary-index-nocase-column")
    declaration = _engine_ddl()["events"]
    canonical = "tenant_id       TEXT NOT NULL,"
    altered = declaration.replace(
        canonical, canonical[:-1] + " COLLATE NOCASE,", 1)
    database = _build(directory, [
        altered,
        "CREATE UNIQUE INDEX idx_events_idempotency_scope ON events("
        "tenant_id COLLATE BINARY, project_id COLLATE BINARY, "
        "idempotency_key COLLATE BINARY)",
    ])
    assert _index_xinfo(
        database, "idx_events_idempotency_scope") == _SCOPED_INDEX_XINFO
    before = _frozen_state(database)

    _assert_refused(database, directory)

    assert _frozen_state(database) == before, "refusal mutated the database"


@pytest.mark.parametrize("inline_unique", [True, False])
def test_populated_raw_legacy_events_refuses_before_migration(tmp_path,
                                                              inline_unique):
    directory = _private_dir(tmp_path, f"legacy-populated-{inline_unique}")
    database = _legacy_events_database(directory, inline_unique)
    _sql(database,
         "INSERT INTO events (event_id, tenant_id, project_id, source_type,"
         " idempotency_key, observed_at, recorded_at, authority,"
         " payload_digest, schema_version, payload)"
         " VALUES ('evt_legacy00000000000000','t','p','s','k','1','1','a',"
         "'d','v','{}')")
    before = _xdecl(database)
    _assert_refused(database, directory)
    assert _xdecl(database) == before, "refusal migrated the schema"


def test_migrated_layout_with_null_digest_refuses(tmp_path):
    directory = _private_dir(tmp_path, "null-digest")
    database = _legacy_events_database(directory, False)
    Engine(database, workdir=str(directory)).close()
    assert _xdecl(database) == _ADDCOL_EVENTS
    _sql(database,
         "INSERT INTO events (event_id, tenant_id, project_id, source_type,"
         " idempotency_key, observed_at, recorded_at, authority,"
         " payload_digest, schema_version, stored_payload_digest, payload)"
         " VALUES ('evt_nulldigest0000000000','t','p','s','k','1','1','a',"
         "'d','v',NULL,'{}')")
    # Corrected in P0-v9: a NULL digest only refuses while the payload is
    # still retained. A cleared payload legitimately carries neither.
    _assert_refused(database, directory)


def test_adjacent_unsupported_events_variant_refuses(tmp_path):
    """Corrected deciding pin: a full, Store-usable near-miss declaration.

    Replaces the P0-v6 three-column subset fixture, which refused later with
    OperationalError: no such column: observed_at rather than for the intended
    compatibility reason.
    """
    ddl = _engine_ddl()
    directory = _private_dir(tmp_path, "near-miss")
    near_miss = ddl["events"].replace("source_id       TEXT,",
                                      "source_id       TEXT NOT NULL,", 1)
    assert near_miss != ddl["events"], "fixture did not alter the declaration"
    database = _build(directory, [near_miss, ddl["processed_events"],
                                  ddl["nodes"], ddl["edges"]])
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


def test_checker_transaction_closes_on_success_and_refusal(tmp_path):
    checker = getattr(
        engine_module, "_assert_processor_projection_compatible", None)
    if checker is None:
        pytest.fail("database was admitted but must be refused")

    directory = _private_dir(tmp_path, "txn-success")
    database = _ingested(directory)
    connection = sqlite3.connect(database)
    try:
        checker(connection)
        assert connection.in_transaction is False
    finally:
        connection.close()

    directory = _private_dir(tmp_path, "txn-refusal")
    database = _ingested(directory)
    _sql(database, "UPDATE processed_events SET"
                   " processor_version='cce-processor/1.0.0'")
    connection = sqlite3.connect(database)
    try:
        with pytest.raises(engine_module.ProcessorProjectionCompatibilityError):
            checker(connection)
        assert connection.in_transaction is False
    finally:
        connection.close()


def test_caller_owned_transaction_remains_caller_owned(tmp_path):
    checker = getattr(
        engine_module, "_assert_processor_projection_compatible", None)
    if checker is None:
        pytest.fail("database was admitted but must be refused")
    directory = _private_dir(tmp_path, "caller-txn")
    database = _ingested(directory)
    connection = sqlite3.connect(database)
    try:
        connection.execute("BEGIN")
        assert connection.in_transaction is True
        checker(connection)
        assert connection.in_transaction is True, \
            "checker closed a caller-owned transaction"
    finally:
        connection.rollback()
        connection.close()


# =====================================================================
# P0-v10: synthetic, chain-valid, producer-SHAPED redacted legacy
# lifecycle. These fixtures are constructed here; they are not bound to
# any released producer binary.
#
# The P0-v9 fixture was NOT producer-valid: its event ids did not match
# evt_[0-9a-f]{24}, its first prev_hash was NULL rather than GENESIS, its
# entry_hash was a synthetic label rather than the canonical link, event_seq
# stayed 0, and Store.verify_chain reported intact=False
# ("predecessor link does not match"). Every "chain survives" claim made from
# it is withdrawn. verify_chain is the deciding oracle here.
#
# canonical_json/sha256_hex/GENESIS are stable core primitives. The private
# _link and _event_entry helpers are deliberately NOT imported: the entry is
# rebuilt from a literal column list so a change in either would be caught.
# =====================================================================
_CHAINED_COLUMNS = (
    "event_id", "tenant_id", "project_id", "source_type", "source_id",
    "idempotency_key", "observed_at", "recorded_at", "valid_from", "valid_to",
    "actor_type", "actor_id", "authority", "sensitivity", "capture_mode",
    "payload_digest", "stored_payload_digest", "schema_version", "seq",
)
_ORIGINAL_PAYLOAD = '{"original": true}'
_ORIGINAL_DIGEST = sha256_hex(_ORIGINAL_PAYLOAD)


def _legacy_row(seq, payload=None):
    """One producer-shaped legacy row. payload=None models retention."""
    return {
        "event_id": "evt_" + f"{seq:024x}",
        "tenant_id": TENANT,
        "project_id": PROJECT,
        "source_type": "github.issues",
        "source_id": None,
        "idempotency_key": f"legacy-key-{seq}",
        "observed_at": "2026-07-29T10:00:00Z",
        "recorded_at": "2026-07-29T10:00:00Z",
        "valid_from": None,
        "valid_to": None,
        "actor_type": None,
        "actor_id": None,
        "authority": "human_intent",
        "sensitivity": "internal",
        "capture_mode": "full",
        "payload_digest": _ORIGINAL_DIGEST,
        "schema_version": "cce.event.v1",
        "seq": seq,
        "payload": payload,
    }


def _legacy_entry_hash(row, prev_hash):
    """Canonical link over the legacy chained entry.

    A legacy row has no stored_payload_digest, and the producer omits that key
    from the entry when it is absent or NULL, so the chain identity survives
    migration unchanged.
    """
    entry = {key: row.get(key) for key in _CHAINED_COLUMNS
             if key != "stored_payload_digest"}
    return sha256_hex(f"{prev_hash}\n{canonical_json(entry)}")


def _seed_legacy_chain(database, rows):
    """Insert a producer-valid chain and set event_seq to MAX(seq)."""
    columns = [c for c in _CHAINED_COLUMNS if c != "stored_payload_digest"]
    columns += ["payload", "prev_hash", "entry_hash"]
    prev = GENESIS
    connection = sqlite3.connect(database)
    try:
        for row in rows:
            entry_hash = _legacy_entry_hash(row, prev)
            values = [row.get(c) for c in columns[:-2]] + [prev, entry_hash]
            connection.execute(
                f"INSERT INTO events ({','.join(columns)})"
                f" VALUES ({','.join('?' * len(columns))})", values)
            prev = entry_hash
        connection.execute("UPDATE event_seq SET n = ?",
                           (max(r["seq"] for r in rows),))
        connection.commit()
    finally:
        connection.close()
    return prev


def _producer_valid_legacy(directory, inline_unique, payloads=(None, None)):
    database = _legacy_events_database(directory, inline_unique)
    rows = [_legacy_row(index + 1, payload)
            for index, payload in enumerate(payloads)]
    tip = _seed_legacy_chain(database, rows)
    return database, tip


def _verify(database):
    """Verify in place. Only safe once the database is already migrated:
    Store() performs supported migration when it opens."""
    store = Store(str(database))
    try:
        return store.verify_chain("events")
    finally:
        store.close()


def _verify_copy(database, holder):
    """Verify a pre-migration fixture without migrating the original.

    `holder` is a caller-owned pytest temporary directory: Store() migrates on
    open, so the copy is disposable, but it must not be an unmanaged
    process-global temp directory.
    """
    target = Path(holder) / "verify-copy.sqlite3"
    target.write_bytes(Path(database).read_bytes())
    store = Store(str(target))
    try:
        return store.verify_chain("events")
    finally:
        store.close()


def _copy_database(source, directory):
    target = directory / "cce.sqlite3"
    target.write_bytes(Path(source).read_bytes())
    return target


def _event_seq(database):
    return _scalar(database, "SELECT n FROM event_seq")


# ------------------------------------------------ fixture self-validation
@pytest.mark.parametrize("inline_unique", [True, False])
def test_producer_valid_legacy_fixture_is_intact_before_migration(
        tmp_path, inline_unique):
    directory = _private_dir(tmp_path, f"valid-{inline_unique}")
    database, tip = _producer_valid_legacy(directory, inline_unique)
    assert len(_xdecl(database)) == 21
    result = _verify_copy(database, directory)
    assert result["intact"] is True, result
    assert result["entries"] == 2
    assert result["tip"] == tip
    assert result["payloads_unavailable"] == 2
    assert result["payload_integrity"] == "unavailable"
    assert _event_seq(database) == 2


# ------------------------------------------------- P0-v8 branch isolation
@pytest.mark.parametrize("inline_unique", [True, False])
def test_raw_branch_admits_and_store_migration_agrees(tmp_path,
                                                      inline_unique):
    """Candidate admits the raw branch; exact P0-v8 refuses it. Store itself
    accepts an identical copy either way."""
    directory = _private_dir(tmp_path, f"raw-branch-{inline_unique}")
    database, _ = _producer_valid_legacy(directory, inline_unique)
    before = _xdecl(database)

    sibling = _private_dir(tmp_path, f"raw-branch-copy-{inline_unique}")
    copy = _copy_database(database, sibling)

    # Candidate: the raw branch admits and migrates. Exact P0-v8 refuses here
    # at the raw-layout gate; that A/B is the isolation.
    Engine(database, workdir=str(directory)).close()
    assert _xdecl(database) != before, "admission did not migrate"

    # Store migration accepts the identical copy independently.
    Store(str(copy)).close()
    expected = _REBUILT_EVENTS if inline_unique else _ADDCOL_EVENTS
    assert _xdecl(copy) == expected
    assert _verify(copy)["intact"] is True


@pytest.mark.parametrize("inline_unique", [True, False])
def test_migrated_null_digest_branch_admits_independently(tmp_path,
                                                          inline_unique):
    """Already migrated by Store, so the raw-layout gate cannot be the cause."""
    directory = _private_dir(tmp_path, f"migrated-branch-{inline_unique}")
    database, tip = _producer_valid_legacy(directory, inline_unique)
    Store(str(database)).close()
    expected = _REBUILT_EVENTS if inline_unique else _ADDCOL_EVENTS
    assert _xdecl(database) == expected
    result = _verify(database)
    assert result["intact"] is True and result["tip"] == tip
    assert _scalar(database, "SELECT COUNT(*) FROM events"
                             " WHERE stored_payload_digest IS NULL") == 2
    # Already migrated by Store, so the raw-layout gate cannot apply: exact
    # P0-v8 still refuses here from its unconditional NULL-digest policy,
    # while the candidate admits.
    _assert_admitted(database, directory)


# ----------------------------------------------------- lifecycle proof
@pytest.mark.parametrize("inline_unique", [True, False])
def test_redacted_legacy_full_lifecycle(tmp_path, inline_unique):
    directory = _private_dir(tmp_path, f"lifecycle-{inline_unique}")
    database, tip = _producer_valid_legacy(directory, inline_unique)
    assert _verify_copy(database, directory)["intact"] is True

    Engine(database, workdir=str(directory)).close()
    expected = _REBUILT_EVENTS if inline_unique else _ADDCOL_EVENTS
    assert _xdecl(database) == expected
    after = _verify(database)
    assert after["intact"] is True and after["tip"] == tip
    assert after["payload_integrity"] == "unavailable"

    engine = Engine(database, workdir=str(directory))
    try:
        for seq in (1, 2):
            stored = engine.store.get_event(
                "evt_" + f"{seq:024x}", tenant_id=TENANT, project_id=PROJECT)
            assert stored["payload"] is None
    finally:
        engine.close()

    for _ in range(2):
        Engine(database, workdir=str(directory)).close()
    assert _verify(database)["tip"] == tip

    engine = Engine(database, workdir=str(directory))
    try:
        engine.create_project("p", project_id=PROJECT,
                              repository_id=REPOSITORY_ID)
        engine.process_event(engine.store.get_event(
            "evt_" + f"{1:024x}", tenant_id=TENANT, project_id=PROJECT))
    finally:
        engine.close()
    first_id = "evt_" + f"{1:024x}"
    assert _rows(
        database, "SELECT processor_version, status FROM processed_events"
        " WHERE event_id = ?", (first_id,)) == [(PROCESSOR_VERSION, "ok")]
    assert _scalar(database,
                   "SELECT COUNT(*) FROM nodes WHERE node_id = '" + first_id
                   + "' AND entity_type = 'event' AND tx_to IS NULL") == 1

    previous_max = _scalar(database, "SELECT MAX(seq) FROM events")
    previous_tip = _verify(database)["tip"]
    engine = Engine(database, workdir=str(directory))
    try:
        engine.ingest_github(PROJECT, "issues", "d-new",
                             _issue(7, "The exporter must write CSV output."))
    finally:
        engine.close()
    new = _rows(
        database,
        "SELECT seq, prev_hash FROM events ORDER BY seq DESC LIMIT 1")[0]
    assert new[0] == previous_max + 1
    assert new[1] == previous_tip
    assert _event_seq(database) == new[0]
    assert _verify(database)["intact"] is True

    for _ in range(2):
        Engine(database, workdir=str(directory)).close()
    final = _verify(database)
    assert final["intact"] is True
    assert _event_seq(database) == new[0]
    assert _rows(
        database, "SELECT processor_version, status FROM processed_events"
        " WHERE event_id = ?", (first_id,)) == [(PROCESSOR_VERSION, "ok")]
    assert _scalar(database,
                   "SELECT COUNT(*) FROM nodes WHERE node_id = '" + first_id
                   + "' AND entity_type = 'event' AND tx_to IS NULL") == 1


# ------------------------------------------------- repaired negatives
@pytest.mark.parametrize("inline_unique", [True, False])
def test_retained_payload_raw_legacy_refuses(tmp_path, inline_unique):
    directory = _private_dir(tmp_path, f"retained-{inline_unique}")
    database, _ = _producer_valid_legacy(
        directory, inline_unique, payloads=(_ORIGINAL_PAYLOAD, None))
    # The links are correctly computed; a migrated copy still cannot
    # authenticate a retained payload that has no commitment, which is exactly
    # why this state must be refused rather than migrated.
    first = _legacy_row(1, _ORIGINAL_PAYLOAD)
    assert _scalar(database,
                   "SELECT entry_hash FROM events WHERE seq = 1") == \
        _legacy_entry_hash(first, GENESIS)
    assert _verify_copy(database, directory)["reason"] == \
        "retained payload has no immutable commitment"
    before = _frozen_state(database)
    _assert_refused(database, directory)
    assert _frozen_state(database) == before


@pytest.mark.parametrize("inline_unique", [True, False])
def test_raw_legacy_marker_rule_is_isolated(tmp_path, inline_unique):
    """One current quarantined marker, zero attributed graph rows.

    Ordinary per-event classification would admit that state, so the refusal
    can only come from the raw-layout rule.
    """
    directory = _private_dir(tmp_path, f"raw-marker-{inline_unique}")
    database, _ = _producer_valid_legacy(directory, inline_unique)
    _sql(database,
         "INSERT INTO processed_events VALUES ('evt_"
         + f"{1:024x}" + "','" + PROCESSOR_VERSION
         + "','2026-01-01T00:00:00Z','quarantined',NULL)")
    assert _scalar(database, "SELECT COUNT(*) FROM nodes"
                             " WHERE event_id IS NOT NULL") == 0
    assert _scalar(database, "SELECT COUNT(*) FROM edges"
                             " WHERE event_id IS NOT NULL") == 0
    before = _xdecl(database)
    _assert_refused(database, directory)
    assert _xdecl(database) == before


@pytest.mark.parametrize("inline_unique", [True, False])
def test_raw_legacy_with_attributed_graph_row_is_preserved_control(
        tmp_path, inline_unique):
    """Preservation control, not a deciding raw-rule pin: an orphan-scoped
    attributed row is refused by more than one rule."""
    directory = _private_dir(tmp_path, f"raw-graph-{inline_unique}")
    database, _ = _producer_valid_legacy(directory, inline_unique)
    _sql(database,
         "INSERT INTO nodes (node_id, version, entity_type, tenant_id,"
         " project_id, data, tx_from, event_id)"
         " VALUES ('nod_legacy0000000000000', 1, 'requirement', '" + TENANT
         + "', '" + PROJECT + "', '{}', '2026-01-01T00:00:00Z', 'evt_"
         + f"{1:024x}" + "')")
    before = _xdecl(database)
    _assert_refused(database, directory)
    assert _xdecl(database) == before


# =====================================================================
# P0-v11 / G2: virgin-database census
#
# When canonical lowercase `events` is absent, the database may be treated as
# virgin only when main.sqlite_schema holds zero non-SQLite-owned objects.
# SQLite-owned means a name whose first seven characters are exactly `sqlite_`
# compared case-insensitively; everything else -- table, view, index or
# trigger -- is user state. There is deliberately no allowlist for
# CCE-looking residue: installing a fresh canonical schema beside abandoned
# history produces a database holding both, which is what this refuses.
#
# This phase classifies schema OBJECTS only. It establishes nothing about
# header pragmas, application_id/user_version, WAL or rollback-journal state,
# declarations, row identities, collations, constraints, triggers on an
# otherwise canonical schema, or concurrent change. Those remain G3/G4/G7.
# =====================================================================
def _closed_database(directory, statements, name="cce.sqlite3"):
    """A closed database whose only content is exactly `statements`."""
    database = Path(directory) / name
    connection = sqlite3.connect(database)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    return database


def _full_state(database):
    """Bytes, logical dump, schema and directory inventory."""
    directory = Path(database).parent
    connection = sqlite3.connect(database)
    try:
        schema = sorted((r[0], r[1], r[2]) for r in connection.execute(
            "SELECT type, name, sql FROM main.sqlite_schema"))
        dump = "\n".join(connection.iterdump())
    finally:
        connection.close()
    return {
        "bytes": Path(database).read_bytes(),
        "dump": dump,
        "schema": schema,
        "entries": sorted(p.name for p in directory.iterdir()),
    }


def _residue_events_sql(new_name):
    ddl = _engine_ddl()["events"]
    return ddl.replace("CREATE TABLE events", f"CREATE TABLE {new_name}", 1)


# ------------------------------------------------------- deciding cases
def test_renamed_canonical_history_refuses_virgin_initialization(tmp_path):
    """Exact P0-v10 admits this and installs a fresh schema beside it."""
    source_dir = _private_dir(tmp_path, "g2-source")
    source = source_dir / "cce.sqlite3"
    store = Store(str(source))
    store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="g2-key", payload={"note": "x"},
        authority="agent_observed")
    store.close()
    connection = sqlite3.connect(source)
    connection.row_factory = sqlite3.Row
    row = dict(connection.execute("SELECT * FROM events").fetchone())
    connection.close()

    directory = _private_dir(tmp_path, "g2-residue")
    database = _closed_database(directory, [_residue_events_sql("events_residue")])
    columns = list(row)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            f"INSERT INTO events_residue ({','.join(columns)})"
            f" VALUES ({','.join('?' * len(columns))})",
            [row[key] for key in columns])
        connection.commit()
    finally:
        connection.close()

    before = _full_state(database)
    _assert_refused(database, directory)
    assert _full_state(database) == before


@pytest.mark.parametrize("case", [
    "empty-residue", "legacy-residue", "empty-user-table",
    "populated-user-table", "user-view",
])
def test_any_user_object_without_canonical_events_refuses(tmp_path, case):
    directory = _private_dir(tmp_path, f"g2-{case}")
    if case == "empty-residue":
        statements = [_residue_events_sql("events_residue")]
    elif case == "legacy-residue":
        statements = [
            "CREATE TABLE events_residue ("
            + _LEGACY_EVENTS_BODY.format(uniq="") + ")"]
    elif case == "empty-user-table":
        statements = ["CREATE TABLE unrelated (x INTEGER)"]
    elif case == "populated-user-table":
        statements = ["CREATE TABLE unrelated (x INTEGER)",
                      "INSERT INTO unrelated VALUES (1)"]
    else:
        statements = ["CREATE VIEW residue AS SELECT 1"]
    database = _closed_database(directory, statements)

    if case == "legacy-residue":
        # A chain-valid raw-legacy row living under the renamed table.
        rows = [_legacy_row(1)]
        columns = [c for c in _CHAINED_COLUMNS
                   if c != "stored_payload_digest"] + [
            "payload", "prev_hash", "entry_hash"]
        entry_hash = _legacy_entry_hash(rows[0], GENESIS)
        values = [rows[0].get(c) for c in columns[:-2]] + [GENESIS, entry_hash]
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                f"INSERT INTO events_residue ({','.join(columns)})"
                f" VALUES ({','.join('?' * len(columns))})", values)
            connection.commit()
        finally:
            connection.close()

    before = _full_state(database)
    _assert_refused(database, directory)
    assert _full_state(database) == before


# ---------------------------------------------------- positive controls
def test_absent_zero_byte_and_memory_remain_initializable_g2(tmp_path):
    directory = _private_dir(tmp_path, "g2-virgin")
    _assert_admitted(directory / "absent.sqlite3", directory)
    zero = directory / "zero.sqlite3"
    zero.write_bytes(b"")
    _assert_admitted(zero, directory)
    _assert_admitted(":memory:", directory)
    _assert_admitted(Path(":memory:"), directory)


def test_existing_database_with_no_schema_objects_admits(tmp_path):
    directory = _private_dir(tmp_path, "g2-empty-schema")
    database = _closed_database(directory, [])
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE seed (x INTEGER)")
        connection.execute("DROP TABLE seed")
        connection.commit()
        assert connection.execute(
            "SELECT COUNT(*) FROM main.sqlite_schema").fetchone()[0] == 0
    finally:
        connection.close()
    _assert_admitted(database, directory)


def test_retained_sqlite_sequence_is_not_schema_virgin(tmp_path):
    """Policy correction, not a positive control.

    A `sqlite_` prefix is a namespace property, not proof that SQLite created
    the object. P0-v11 filtered on that prefix and so admitted this database;
    a retained sqlite_sequence still means the file is not schema-virgin.
    """
    directory = _private_dir(tmp_path, "g2-sqlite-sequence")
    database = _closed_database(directory, [
        "CREATE TABLE counted (id INTEGER PRIMARY KEY AUTOINCREMENT)",
        "INSERT INTO counted DEFAULT VALUES",
        "DROP TABLE counted"])
    connection = sqlite3.connect(database)
    try:
        names = [r[0] for r in connection.execute(
            "SELECT name FROM main.sqlite_schema")]
    finally:
        connection.close()
    assert names == ["sqlite_sequence"], names
    before = _full_state(database)
    _assert_refused(database, directory)
    assert _full_state(database) == before


def test_forged_reserved_prefix_object_refuses(tmp_path):
    """A parseable, queryable table forged under the reserved prefix.

    P0-v11 counted this as SQLite-owned and installed a fresh CCE schema
    beside a retained row that stayed readable afterwards.
    """
    directory = _private_dir(tmp_path, "g2-forged-prefix")
    database = directory / "cce.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE residue(value TEXT)")
        connection.execute("INSERT INTO residue VALUES ('retained-secret')")
        connection.commit()
        version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE main.sqlite_schema SET name='sqlite_evil',"
            " tbl_name='sqlite_evil',"
            " sql='CREATE TABLE sqlite_evil(value TEXT)'"
            " WHERE type='table' AND name='residue'")
        connection.execute(f"PRAGMA schema_version={version + 1}")
        connection.commit()
        connection.execute("PRAGMA writable_schema=OFF")
    finally:
        connection.close()

    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT name FROM main.sqlite_schema WHERE type='table'"
        ).fetchall() == [("sqlite_evil",)]
        assert connection.execute(
            "SELECT value FROM sqlite_evil").fetchall() == [
                ("retained-secret",)]
    finally:
        connection.close()

    before = _full_state(database)
    _assert_refused(database, directory)
    assert _full_state(database) == before


def test_eventless_current_store_takes_the_canonical_path(tmp_path):
    directory = _private_dir(tmp_path, "g2-eventless")
    database = directory / "cce.sqlite3"
    Engine(database, workdir=str(directory)).close()
    assert _scalar(database, "SELECT COUNT(*) FROM events") == 0
    _assert_admitted(database, directory)


def test_append_only_canonical_store_takes_the_canonical_path(tmp_path):
    directory = _private_dir(tmp_path, "g2-append-only")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="g2-append", payload={"note": "x"},
        authority="agent_observed")
    store.close()
    assert _scalar(database, "SELECT COUNT(*) FROM events") == 1
    assert _scalar(database, "SELECT COUNT(*) FROM processed_events") == 0
    _assert_admitted(database, directory)


# =====================================================================
# Review round: false refusals of states the current code produces, and a
# refusal that changed the database it refused.
# =====================================================================
@pytest.mark.parametrize("change", ["correct", "quarantine", "invalidate"])
def test_reversioned_event_node_stays_admitted(tmp_path, change):
    """A library call that versions an event node writes its new row without
    an event attribution. Counting the canonical node only among rows
    attributed to its own event refused every later open of the database.
    """
    from causal_continuity_engine.invalidation import TRIGGER_TYPES

    directory = _private_dir(tmp_path, f"reversion-{change}")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    try:
        engine.create_project("p", project_id=PROJECT,
                              repository_id=REPOSITORY_ID)
        event_id = engine.ingest_human_decision(
            PROJECT, actor="alice", decision="Use Postgres for storage")["event_id"]
        if change == "correct":
            engine.memory.correct(PROJECT, event_id, {"note": "typo"}, "alice")
        elif change == "quarantine":
            engine.partial.quarantine(event_id, "alice", "spam event")
        else:
            engine.invalidation.fire(
                tenant_id=TENANT, project_id=PROJECT, target_node_id=event_id,
                trigger_type=sorted(TRIGGER_TYPES)[0], reason="bad")
    finally:
        engine.close()
    # The state under test: the live canonical row carries no attribution.
    assert _rows(
        database, "SELECT event_id FROM nodes WHERE node_id = ?"
        " AND entity_type = 'event' AND tx_to IS NULL", (event_id,)) == [(None,)]
    _assert_admitted(database, directory)
    _assert_admitted(database, directory)


_OPENER = r"""
import os, pathlib, sqlite3, sys, time
root, database, needle, mode, flag = sys.argv[1:6]
sys.path.insert(0, root)
real_connect = sqlite3.connect


def connect(*args, **kwargs):
    connection = real_connect(*args, **kwargs)
    if not kwargs.get("uri"):
        state = {"hit": False}

        def trace(statement):
            if state["hit"] or needle not in statement:
                return
            state["hit"] = True
            if mode == "crash":
                os._exit(9)
            pathlib.Path(flag).write_text("paused")
            time.sleep(2)

        connection.set_trace_callback(trace)
    return connection


sqlite3.connect = connect
from causal_continuity_engine.engine import Engine
Engine(database, workdir=os.path.dirname(database)).close()
"""


def _opener(database, needle, mode, flag=""):
    root = Path(engine_module.__file__).resolve().parents[1]
    return [sys.executable, "-c", _OPENER, str(root), str(database), needle,
            mode, str(flag)]


def _tables(database):
    return {row[0] for row in _rows(
        database, "SELECT name FROM sqlite_master WHERE type = 'table'")}


@pytest.mark.parametrize("table", ["processed_events", "edges"])
def test_interrupted_first_open_is_completed_not_refused(tmp_path, table):
    """Store and Graph install these tables one statement at a time. A first
    open killed part way used to leave a file every later open refused."""
    directory = _private_dir(tmp_path, f"crash-{table}")
    database = directory / "cce.sqlite3"
    crash = subprocess.run(
        _opener(database, f"CREATE TABLE IF NOT EXISTS {table}", "crash"),
        capture_output=True, text=True)
    assert crash.returncode == 9, (crash.returncode, crash.stderr)
    assert table not in _tables(database)

    _assert_admitted(database, directory)
    _assert_admitted(database, directory)
    assert {"events", "processed_events", "nodes", "edges"} <= _tables(database)


def test_interrupted_open_of_unprocessed_history_is_completed(tmp_path):
    directory = _private_dir(tmp_path, "crash-history")
    database = directory / "cce.sqlite3"
    store = Store(str(database))
    try:
        for index in range(3):
            store.append_event(
                tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
                idempotency_key=f"k-crash-{index}", payload={"note": index},
                authority="agent_observed")
    finally:
        store.close()
    crash = subprocess.run(
        _opener(database, "CREATE TABLE IF NOT EXISTS edges", "crash"),
        capture_output=True, text=True)
    assert crash.returncode == 9, (crash.returncode, crash.stderr)
    assert "nodes" in _tables(database) and "edges" not in _tables(database)
    assert _scalar(database, "SELECT COUNT(*) FROM events") == 3

    _assert_admitted(database, directory)
    assert _scalar(database, "SELECT COUNT(*) FROM events") == 3


def test_concurrent_first_open_is_admitted(tmp_path):
    directory = _private_dir(tmp_path, "concurrent")
    database = directory / "cce.sqlite3"
    flag = directory / "paused"
    first = subprocess.Popen(
        _opener(database, "CREATE TABLE IF NOT EXISTS processed_events",
                "pause", flag),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(3000):
            if flag.exists() or first.poll() is not None:
                break
            __import__("time").sleep(0.01)
        assert flag.exists(), first.communicate(timeout=60)
        _assert_admitted(database, directory)
    finally:
        _, stderr = first.communicate(timeout=60)
    assert first.returncode == 0, stderr


def test_partial_graph_with_projected_rows_still_refuses(tmp_path):
    """Negative control: only an unprocessed partial schema is admitted."""
    directory = _private_dir(tmp_path, "partial-projected")
    database = _ingested(directory)
    _sql(database, "DELETE FROM processed_events", "DROP TABLE edges")
    assert _scalar(database,
                   "SELECT COUNT(*) FROM nodes WHERE event_id IS NOT NULL") > 0
    _assert_refused(database, directory)


def test_cli_refuses_before_provisioning_legacy_runtime_secrets(tmp_path):
    """Metadata written before runtime secrets existed makes the CLI provision
    them while opening a project. The path preflight must refuse first."""
    directory = _private_dir(tmp_path, "cli-legacy")
    repo_root = Path(engine_module.__file__).resolve().parents[1]
    environment = {**os.environ, "PYTHONPATH": str(repo_root)}
    init = subprocess.run(
        [sys.executable, "-m", "causal_continuity_engine.cli",
         "--dir", str(directory), "init", "--repo-id", str(REPOSITORY_ID)],
        capture_output=True, text=True, cwd=str(repo_root), env=environment)
    assert init.returncode == 0, init.stderr

    cce = directory / ".cce"
    meta = json.loads((cce / "meta.json").read_text())
    engine = Engine(cce / "cce.db", workdir=str(directory))
    try:
        engine.ingest_github(meta["project_id"], "issues", "d1",
                             _issue(1, "The exporter must write CSV output."))
    finally:
        engine.close()
    _sql(cce / "cce.db",
         "UPDATE processed_events SET processor_version='cce-processor/1.0.0'")
    for field in ("api_token_file", "webhook_secret_file"):
        (cce / meta.pop(field)).unlink()
    (cce / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    def tree():
        return sorted((str(path.relative_to(cce)), path.read_bytes())
                      for path in cce.rglob("*") if path.is_file())

    before = tree()
    result = subprocess.run(
        [sys.executable, "-m", "causal_continuity_engine.cli",
         "--dir", str(directory), "resume"],
        capture_output=True, text=True, cwd=str(repo_root), env=environment)
    assert result.returncode == 2, (result.returncode, result.stderr)
    assert tree() == before


def test_mcp_reports_a_refused_project_as_a_tool_error_and_keeps_serving(
        tmp_path, capsys):
    """The MCP server opens a project through the CLI's opener. Turning a
    refusal into SystemExit inside that opener killed the server on its first
    tool call, so the client's later requests were never answered."""
    import io

    from causal_continuity_engine.mcp import serve

    directory = _private_dir(tmp_path, "mcp-refused")
    repo_root = Path(engine_module.__file__).resolve().parents[1]
    init = subprocess.run(
        [sys.executable, "-m", "causal_continuity_engine.cli",
         "--dir", str(directory), "init", "--repo-id", str(REPOSITORY_ID)],
        capture_output=True, text=True, cwd=str(repo_root),
        env={**os.environ, "PYTHONPATH": str(repo_root)})
    assert init.returncode == 0, init.stderr
    cce = directory / ".cce"
    meta = json.loads((cce / "meta.json").read_text())
    engine = Engine(cce / "cce.db", workdir=str(directory))
    try:
        engine.ingest_github(meta["project_id"], "issues", "d1",
                             _issue(1, "The exporter must write CSV output."))
    finally:
        engine.close()
    _sql(cce / "cce.db",
         "UPDATE processed_events SET processor_version='cce-processor/1.0.0'")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "resume_packet", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
    ]
    stdout = io.StringIO()
    status = serve(
        str(directory),
        stdin=io.StringIO("".join(json.dumps(r) + "\n" for r in requests)),
        stdout=stdout)
    responses = {r["id"]: r for r in map(json.loads, stdout.getvalue().splitlines())}

    assert status == 0
    assert responses[2]["result"]["isError"] is True
    text = responses[2]["result"]["content"][0]["text"]
    diagnostics = capsys.readouterr().err
    assert text == "tool execution failed"
    assert "ProcessorProjectionCompatibilityError" in diagnostics
    disclosed = text + diagnostics
    assert str(directory) not in disclosed
    assert "exporter" not in disclosed and "CSV" not in disclosed
    assert responses[3]["result"] == {}

@pytest.mark.skipif(
    not hasattr(sqlite3.Connection, "setconfig")
    or not hasattr(sqlite3, "SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE"),
    reason="disabling checkpoint-on-close needs Python 3.12 (ADR-114 limit)")
def test_connection_check_refusal_leaves_committed_wal_in_place(tmp_path):
    """The second check runs on Store's own connection. Closing that
    connection after a refusal checkpointed the WAL into the main database."""
    directory = _private_dir(tmp_path, "wal-refusal")
    database = _ingested(directory)
    copy_dir = _private_dir(tmp_path, "wal-refusal-copy")
    copy = copy_dir / "cce.sqlite3"
    writer = sqlite3.connect(database)
    try:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "UPDATE processed_events SET processor_version='cce-processor/1.0.0'")
        writer.commit()
        for suffix in ("", "-wal", "-shm"):
            source = Path(str(database) + suffix)
            if source.exists():
                Path(str(copy) + suffix).write_bytes(source.read_bytes())
    finally:
        writer.close()
    main_before = copy.read_bytes()
    wal_before = Path(str(copy) + "-wal").read_bytes()
    assert wal_before, "fixture must carry a committed WAL"

    with pytest.raises(COMPAT_ERROR):
        Store(str(copy),
              _pre_schema_check=engine_module._assert_processor_projection_compatible)
    assert copy.read_bytes() == main_before
    assert Path(str(copy) + "-wal").read_bytes() == wal_before


def _corrected_event_store(directory):
    """A store whose live canonical event node carries no event attribution,
    as a correction writes it. Returns the database and the event id."""
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    try:
        engine.create_project("p", project_id=PROJECT,
                              repository_id=REPOSITORY_ID)
        engine.create_project("q", project_id="prj_other",
                              repository_id=REPOSITORY_ID + 1)
        event_id = engine.ingest_human_decision(
            PROJECT, actor="alice", decision="Use Postgres for storage")["event_id"]
        engine.memory.correct(PROJECT, event_id, {"note": "typo"}, "alice")
    finally:
        engine.close()
    assert _rows(
        database, "SELECT event_id FROM nodes WHERE node_id = ?"
        " AND entity_type = 'event' AND tx_to IS NULL", (event_id,)) == [(None,)]
    return database, event_id


@pytest.mark.parametrize("tamper", [
    "moved-to-other-project", "moved-to-other-tenant", "retyped", "duplicated"])
def test_live_canonical_event_node_must_match_its_event(tmp_path, tamper):
    """Counting the canonical node by identity must still require the event's
    tenant and project, the event entity type, and exactly one live row."""
    directory = _private_dir(tmp_path, f"canonical-{tamper}")
    database, event_id = _corrected_event_store(directory)
    _assert_admitted(database, directory)
    live = f"node_id = '{event_id}' AND tx_to IS NULL"
    if tamper == "moved-to-other-project":
        _sql(database, f"UPDATE nodes SET project_id = 'prj_other' WHERE {live}")
    elif tamper == "moved-to-other-tenant":
        _sql(database, f"UPDATE nodes SET tenant_id = 'ten_other' WHERE {live}")
    elif tamper == "retyped":
        _sql(database, f"UPDATE nodes SET entity_type = 'claim' WHERE {live}")
    else:
        columns = [row[1] for row in _rows(database, "PRAGMA table_info(nodes)")
                   if row[1] not in ("row_id", "version")]
        _sql(database,
             f"INSERT INTO nodes ({', '.join(columns)}, version)"
             f" SELECT {', '.join(columns)}, version + 100 FROM nodes WHERE {live}")
        assert _scalar(database, f"SELECT COUNT(*) FROM nodes WHERE {live}") == 2
    _assert_refused(database, directory)


@pytest.mark.parametrize("table", ["processed_events", "nodes", "edges"])
def test_generated_column_on_a_bound_table_refuses(tmp_path, table):
    """`PRAGMA table_info` omits generated columns, so binding these tables
    through it accepted a table the producer never wrote."""
    directory = _private_dir(tmp_path, f"generated-{table}")
    database = _ingested(directory)
    _sql(database, f"ALTER TABLE {table} ADD COLUMN shadow TEXT"
                   " GENERATED ALWAYS AS ('forged') VIRTUAL")
    assert "shadow" not in [row[1] for row in _rows(
        database, f"PRAGMA table_info({table})")]
    _assert_refused(database, directory)


# ------------------------------------------------- crash between the commits
def _strand_issue_after_log_commit(engine, payload, delivery_id):
    original = engine._process_prepared_event

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("power loss between the two commits")

    engine._process_prepared_event = interrupted
    try:
        with pytest.raises(KeyboardInterrupt):
            engine.ingest_github(PROJECT, "issues", delivery_id, payload)
    finally:
        engine._process_prepared_event = original
    return engine.store.events(PROJECT, tenant_id=TENANT)[-1]["event_id"]


def test_a_crash_between_the_log_and_the_projection_is_visible_and_healable(
        tmp_path):
    """The log commits first, so a crash in between strands an event.

    ingest() quarantines on Exception, but a real interruption is not an
    Exception: the event stays committed, the projection transaction rolls
    back, and no marker is written. Before the continuity frontier was bound
    to packet completeness, that state reported clean; and re-delivering the
    event did nothing at all.
    """
    directory = _private_dir(tmp_path, "crash")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    try:
        engine.create_project(
            "p", project_id=PROJECT, repository_id=REPOSITORY_ID)
        payload = _issue(1, "The exporter must write CSV output.")

        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt("power loss between the two commits")

        engine._process_prepared_event = interrupted
        with pytest.raises(KeyboardInterrupt):
            engine.ingest_github(PROJECT, "issues", "d1", payload)
        del engine._process_prepared_event

        completeness = engine.replay_completeness(PROJECT)
        assert completeness["unprojected_events"] == 1
        assert "no processing marker" in (completeness["note"] or "")
        assert _rows(database, "SELECT COUNT(*) FROM events")[0][0] == 1
        assert _rows(
            database, "SELECT COUNT(*) FROM processed_events")[0][0] == 0

        healed = engine.ingest_github(PROJECT, "issues", "d1", payload)
        assert healed is not None
        assert healed["healed_unprojected_event"] is True
        assert engine.replay_completeness(PROJECT)["unprojected_events"] == 0
        assert _rows(
            database, "SELECT COUNT(*) FROM processed_events")[0][0] == 1

        # A genuine duplicate is still a no-op, and healing does not repeat.
        assert engine.ingest_github(PROJECT, "issues", "d1", payload) is None
        assert engine.replay_completeness(PROJECT)["unprojected_events"] == 0
    finally:
        engine.close()


def test_two_reconcilers_project_an_unprocessed_event_exactly_once(tmp_path):
    directory = _private_dir(tmp_path, "concurrent-reconcilers")
    database = directory / "cce.sqlite3"
    builder = Engine(database, workdir=str(directory))
    payload = _issue(1, "The exporter must write CSV output.")
    builder.create_project(
        "p", project_id=PROJECT, repository_id=REPOSITORY_ID)
    event_id = _strand_issue_after_log_commit(
        builder, payload, "concurrent-reconciliation")
    builder.close()

    first = Engine(database, workdir=str(directory))
    second = Engine(database, workdir=str(directory))
    barrier = threading.Barrier(2)
    observed = {}
    reports = {}
    errors = {}
    try:
        for label, engine in (("first", first), ("second", second)):
            original = engine.store.unprocessed_event_ids

            def synchronized(*args, _label=label, _engine=engine,
                             _original=original, **kwargs):
                result = _original(*args, **kwargs)
                if not _engine.store._conn.in_transaction:
                    observed[_label] = list(result)
                    barrier.wait(timeout=10)
                return result

            engine.store.unprocessed_event_ids = synchronized

        def reconcile(label, engine):
            try:
                reports[label] = engine.ingest_github(
                    PROJECT, "issues", "concurrent-reconciliation", payload)
            except BaseException as exc:
                errors[label] = exc

        threads = [
            threading.Thread(target=reconcile, args=("first", first)),
            threading.Thread(target=reconcile, args=("second", second)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        assert not any(thread.is_alive() for thread in threads)
        assert errors == {}
        assert all(event_id in observed[label] for label in ("first", "second"))
        healed = [report for report in reports.values()
                  if report is not None and report.get("healed_unprojected_event")]
        assert len(healed) == 1
        assert list(reports.values()).count(None) == 1
        assert _rows(
            database, "SELECT COUNT(*) FROM nodes WHERE node_id = ?", (event_id,)
        ) == [(1,)]
        assert _rows(
            database, "SELECT COUNT(*) FROM nodes WHERE event_id = ?", (event_id,)
        ) == [(2,)]
        assert _rows(
            database,
            "SELECT processor_version, status, error FROM processed_events "
            "WHERE event_id = ?",
            (event_id,),
        ) == [(PROCESSOR_VERSION, "ok", None)]
    finally:
        first.close()
        second.close()


def test_reconciliation_does_not_overwrite_a_competing_quarantine(tmp_path):
    directory = _private_dir(tmp_path, "quarantine-interposition")
    database = directory / "cce.sqlite3"
    marker_writer = Engine(database, workdir=str(directory))
    payload = _issue(1, "The exporter must write CSV output.")
    marker_writer.create_project(
        "p", project_id=PROJECT, repository_id=REPOSITORY_ID)
    event_id = _strand_issue_after_log_commit(
        marker_writer, payload, "quarantine-interposition")
    reconciler = Engine(database, workdir=str(directory))
    original = reconciler.store.unprocessed_event_ids
    observations = 0

    def quarantine_after_initial_observation(*args, **kwargs):
        nonlocal observations
        result = original(*args, **kwargs)
        observations += 1
        if observations == 1:
            assert event_id in result
            marker_writer.store.mark_processed(
                event_id, PROCESSOR_VERSION, "quarantined",
                "competing processor failure")
        return result

    reconciler.store.unprocessed_event_ids = quarantine_after_initial_observation
    try:
        report = reconciler.ingest_github(
            PROJECT, "issues", "quarantine-interposition", payload)
        assert report is None
        assert observations == 2
        assert _rows(
            database,
            "SELECT processor_version, status, error FROM processed_events "
            "WHERE event_id = ?",
            (event_id,),
        ) == [(PROCESSOR_VERSION, "quarantined", "competing processor failure")]
        assert _rows(
            database, "SELECT COUNT(*) FROM nodes WHERE event_id = ?", (event_id,)
        ) == [(0,)]
        assert _rows(
            database, "SELECT COUNT(*) FROM edges WHERE event_id = ?", (event_id,)
        ) == [(0,)]
    finally:
        reconciler.close()
        marker_writer.close()


@pytest.mark.parametrize(
    ("stored_mode", "current_mode"),
    [("full", "metadata_only"), ("metadata_only", "full")],
)
def test_healing_reports_the_capture_mode_of_the_stored_event(
        tmp_path, stored_mode, current_mode):
    directory = _private_dir(tmp_path, f"stored-capture-report-{stored_mode}")
    database = directory / "cce.sqlite3"
    engine = Engine(database, workdir=str(directory))
    try:
        engine.create_project(
            "p", project_id=PROJECT, repository_id=REPOSITORY_ID,
            capture_mode=stored_mode)
        payload = _issue(1, "The exporter must preserve every row in order.")

        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt("power loss between the two commits")

        engine._process_prepared_event = interrupted
        with pytest.raises(KeyboardInterrupt):
            engine.ingest_github(PROJECT, "issues", "capture-d1", payload)
        del engine._process_prepared_event
        event = engine.store.events(
            PROJECT, tenant_id=engine.tenant_id)[-1]
        assert event["capture_mode"] == stored_mode

        project = engine.graph.get(
            PROJECT, tenant_id=engine.tenant_id, project_id=PROJECT)
        project_data = dict(project["data"])
        project_data["capture_mode"] = current_mode
        engine.graph.put_node(
            entity_type="project", tenant_id=engine.tenant_id,
            project_id=PROJECT, node_id=PROJECT, status="active",
            data=project_data)
        assert engine.project_capture_mode(PROJECT) == current_mode
        if stored_mode == "full":
            # A retry is not permission to reinterpret retained full-capture
            # bytes under a stricter policy. Refusal must leave the gap visible.
            before = _frozen_state(database)
            with pytest.raises(COMPAT_ERROR):
                engine.ingest_github(PROJECT, "issues", "capture-d1", payload)
            assert _frozen_state(database) == before
            assert engine.store.unprocessed_event_ids(
                PROJECT, tenant_id=engine.tenant_id) == [event["event_id"]]
            project_data["capture_mode"] = stored_mode
            engine.graph.put_node(
                entity_type="project", tenant_id=engine.tenant_id,
                project_id=PROJECT, node_id=PROJECT, status="active",
                data=project_data)
        healed = engine.ingest_github(
            PROJECT, "issues", "capture-d1", payload)

        assert healed is not None
        assert healed["healed_unprojected_event"] is True
        assert healed["capture"] == {
            "mode": stored_mode, "redactions": [], "dropped_fields": 0}
        stored_body = engine.store.get_event(
            event["event_id"], tenant_id=engine.tenant_id,
            project_id=PROJECT)["payload"]["issue"]["body"]
        if stored_mode == "full":
            assert stored_body == "The exporter must preserve every row in order."
        else:
            assert stored_body.startswith("[DROPPED:body:")
    finally:
        engine.close()
