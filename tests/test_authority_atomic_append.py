"""The private append primitive joins one owner-controlled Store write unit.

This is a storage prerequisite, not operator authentication or a confirmation
producer. Public connector appends retain their standalone commit contract.
"""

import sqlite3
import threading
from contextlib import closing

import pytest

from causal_continuity_engine.core import canonical_json, sha256_hex
from causal_continuity_engine.engine import PROCESSOR_VERSION, Engine
from causal_continuity_engine.store import DuplicateEventError, PayloadMismatchError, Store

TENANT, PROJECT = "ten_atomic", "prj_atomic"


@pytest.fixture
def store(tmp_path):
    instance = Store(tmp_path / "atomic.sqlite3")
    yield instance
    instance.close()


def _fields(key="request-1", **overrides):
    return {
        "tenant_id": TENANT, "project_id": PROJECT,
        "source_type": "human_decision", "idempotency_key": key,
        "payload": {"text": "The retained proposal must remain exact."},
        "authority": "human_decision",
        **overrides,
    }


def _state(store):
    return {
        "events": store.events(),
        "sequence": store._conn.execute("SELECT n FROM event_seq").fetchone()[0],
        "audit": store.audit_entries(),
        "locks": [tuple(row) for row in store._conn.execute(
            "SELECT * FROM chain_lock ORDER BY table_name")],
        "mismatches": store.payload_mismatches(),
    }


def test_public_append_still_refuses_an_owned_transaction(store):
    before = _state(store)
    with store.transaction():
        with pytest.raises(RuntimeError, match="standalone canonical-log commit"):
            store.append_event(**_fields())
        assert _state(store) == before
    assert _state(store) == before


def test_public_duplicate_and_mismatch_keep_standalone_semantics(store):
    first = store.append_event(**_fields())
    with pytest.raises(DuplicateEventError) as duplicate:
        store.append_event(**_fields())
    assert duplicate.value.event_id == first["event_id"]
    with pytest.raises(PayloadMismatchError):
        store.append_event(**_fields(payload={"text": "Different operands"}))
    with closing(sqlite3.connect(store.path)) as reader:
        assert reader.execute("SELECT count(*) FROM payload_mismatches").fetchone()[0] == 1
        assert reader.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert reader.execute("SELECT n FROM event_seq").fetchone()[0] == 1
    assert not store._conn.in_transaction
    assert store.verify_chain()["intact"] is True


def _defer_append_failure(store):
    with store.write_scope():
        store._conn.execute("CREATE TABLE append_parent (id INTEGER PRIMARY KEY)")
        store._conn.execute(
            "CREATE TABLE append_child (parent_id INTEGER REFERENCES append_parent(id) "
            "DEFERRABLE INITIALLY DEFERRED)")
        store._conn.execute(
            "CREATE TRIGGER defer_append AFTER INSERT ON events "
            "BEGIN INSERT INTO append_child VALUES (999); END")


def test_public_deferred_commit_failure_rolls_back_and_allows_retry(store):
    _defer_append_failure(store)
    before = _state(store)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        store.append_event(**_fields())
    assert not store._conn.in_transaction
    assert store._transaction_depth == 0
    assert _state(store) == before
    assert store._conn.execute("SELECT count(*) FROM append_child").fetchone()[0] == 0
    with store.write_scope():
        store._conn.execute("DROP TRIGGER defer_append")
    event = store.append_event(**_fields())
    assert event["seq"] == 1
    assert store.verify_chain()["intact"] is True


def test_private_deferred_commit_failure_rolls_back_with_owner(store):
    _defer_append_failure(store)
    before = _state(store)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
        with store.transaction():
            event = store._append_event_in_transaction(**_fields())
            store.audit(actor="owner-local", action="authority.test", object_id=event["event_id"])
    assert not store._conn.in_transaction
    assert store._transaction_depth == 0
    assert _state(store) == before
    assert store._conn.execute("SELECT count(*) FROM append_child").fetchone()[0] == 0
    with store.write_scope():
        store._conn.execute("DROP TRIGGER defer_append")
    with store.transaction():
        event = store._append_event_in_transaction(**_fields())
    assert event["seq"] == 1
    assert store.verify_chain()["intact"] is True


def test_atomic_append_commits_only_with_its_owner(store):
    with closing(sqlite3.connect(store.path)) as reader:
        with store.transaction():
            first = store._append_event_in_transaction(**_fields())
            second = store._append_event_in_transaction(**_fields("request-2"))
            store.audit(actor="owner-local", action="authority.test", object_id=first["event_id"])
            assert first["seq"] == 1
            assert second["seq"] == 2
            assert second["prev_hash"] == first["entry_hash"]
            assert first["stored_payload_digest"] == sha256_hex(canonical_json(first["payload"]))
            assert store._conn.in_transaction
            assert reader.execute("SELECT count(*) FROM events").fetchone()[0] == 0
            assert reader.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0
        assert reader.execute("SELECT count(*) FROM events").fetchone()[0] == 2
        assert reader.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 1
    assert store.verify_chain()["intact"] is True
    assert store.verify_chain("audit_log")["intact"] is True


def test_outer_failure_rolls_back_event_sequence_and_audit(store):
    first = store.append_event(**_fields("previous"))
    before = _state(store)
    with pytest.raises(RuntimeError, match="abort decision"):
        with store.transaction():
            event = store._append_event_in_transaction(**_fields())
            store.audit(actor="owner-local", action="authority.test", object_id=event["event_id"])
            raise RuntimeError("abort decision")
    assert _state(store) == before
    assert not store._conn.in_transaction
    assert store._transaction_depth == 0
    following = store.append_event(**_fields("following"))
    assert following["seq"] == 2
    assert following["prev_hash"] == first["entry_hash"]


def test_nested_failure_preserves_prior_owner_writes(store):
    with store.transaction():
        first = store._append_event_in_transaction(**_fields("first"))
        with pytest.raises(RuntimeError, match="abort nested"):
            with store.transaction():
                store._append_event_in_transaction(**_fields("nested"))
                store.audit(actor="owner-local", action="authority.nested")
                raise RuntimeError("abort nested")
        second = store._append_event_in_transaction(**_fields("second"))
        assert [row["event_id"] for row in store.events()] == [
            first["event_id"], second["event_id"]]
        assert second["seq"] == 2
        assert store.audit_entries() == []
    assert store.verify_chain()["intact"] is True


def test_atomic_duplicate_is_a_benign_noop_inside_owner(store):
    first = store.append_event(**_fields())
    before = _state(store)
    with store.transaction():
        with pytest.raises(DuplicateEventError) as duplicate:
            store._append_event_in_transaction(**_fields())
        assert duplicate.value.event_id == first["event_id"]
        assert _state(store) == before
        assert store._transaction_depth == 1
        store.audit(actor="owner-local", action="authority.duplicate-observed")
    assert store.events() == before["events"]
    assert len(store.audit_entries()) == 1


def test_atomic_conflicting_retry_does_not_commit_or_discard_owner_state(store):
    store.append_event(**_fields())
    with store.transaction():
        store.audit(actor="owner-local", action="authority.before-conflict")
        before = _state(store)
        with pytest.raises(PayloadMismatchError):
            store._append_event_in_transaction(**_fields(payload={"text": "Changed operands"}))
        assert _state(store) == before
        assert store._transaction_depth == 1
        second = store._append_event_in_transaction(**_fields("following"))
        assert second["seq"] == 2
    assert len(store.audit_entries()) == 1
    assert store.payload_mismatches() == []
    assert store.verify_chain()["intact"] is True


@pytest.mark.parametrize("mode", ["no_transaction", "read_snapshot", "unmanaged_writer"])
def test_atomic_append_requires_owned_writer_transaction(store, mode):
    before = _state(store)

    def refuse():
        with pytest.raises(RuntimeError, match="owned Store writer transaction"):
            store._append_event_in_transaction(**_fields())
        assert _state(store) == before

    if mode == "read_snapshot":
        with store.read_snapshot():
            refuse()
            assert store._conn.in_transaction
    elif mode == "unmanaged_writer":
        store._conn.execute("BEGIN IMMEDIATE")
        try:
            refuse()
            assert store._conn.in_transaction
        finally:
            store._conn.rollback()
    else:
        refuse()
    assert _state(store) == before


def test_atomic_append_refuses_owned_read_only_transaction(tmp_path):
    path = tmp_path / "readonly.sqlite3"
    original = Store(path)
    original.close()
    before = path.read_bytes()
    reader = Store(path, _read_only=True)
    try:
        with reader.transaction():
            with pytest.raises(RuntimeError, match="owned Store writer transaction"):
                reader._append_event_in_transaction(**_fields())
            assert reader._transaction_depth == 1
            assert reader._conn.in_transaction
    finally:
        reader.close()
    assert path.read_bytes() == before


@pytest.mark.parametrize("overrides, message", [
    ({"tenant_id": "../foreign"}, "tenant_id"),
    ({"project_id": False}, "project_id"),
    ({"payload": []}, "payload"),
    ({"payload": {"value": float("nan")}}, "canonical JSON"),
    ({"authority": "operator"}, "authority"),
    ({"capture_mode": "unknown"}, "capture_mode"),
    ({"schema_version": "cce.event.v2"}, "schema_version"),
    ({"observed_at": "not-a-time"}, "observed_at"),
    ({"payload_digest": "not-a-digest"}, "payload_digest"),
])
def test_atomic_append_preserves_event_validation(store, overrides, message):
    before = _state(store)
    with store.transaction():
        with pytest.raises(ValueError, match=message):
            store._append_event_in_transaction(**_fields(**overrides))
        assert _state(store) == before
        assert store._transaction_depth == 1
    assert _state(store) == before


def test_caught_insert_failure_rolls_back_only_the_append_savepoint(store):
    with store.write_scope():
        store._conn.execute(
            "CREATE TRIGGER fail_atomic_event BEFORE INSERT ON events "
            "WHEN NEW.idempotency_key = 'broken' "
            "BEGIN SELECT RAISE(ABORT, 'planted event insertion failure'); END")
    with store.transaction():
        store.audit(actor="owner-local", action="authority.before-insert")
        before = _state(store)
        with pytest.raises(sqlite3.IntegrityError, match="planted event insertion failure"):
            store._append_event_in_transaction(**_fields("broken"))
        assert _state(store) == before
        event = store._append_event_in_transaction(**_fields("valid"))
        assert event["seq"] == 1
    assert len(store.audit_entries()) == 1
    assert store.verify_chain()["intact"] is True


def _projection_state(engine):
    return _state(engine.store) | {
        "nodes": [tuple(row) for row in engine.store._conn.execute(
            "SELECT * FROM nodes ORDER BY row_id")],
        "edges": [tuple(row) for row in engine.store._conn.execute(
            "SELECT * FROM edges ORDER BY row_id")],
        "markers": [tuple(row) for row in engine.store._conn.execute(
            "SELECT * FROM processed_events ORDER BY event_id, processor_version")],
    }


def _process_atomic_event(engine):
    # Use ordinary canonical prose, not a pretend structured authority event.
    # The opposed pair stays nonauthoritative; its source-support edges still
    # exercise real processor-created relationships inside the owned transaction.
    event = engine.store._append_event_in_transaction(**_fields(payload={
        "decision": ("The exporter must retain every row.\n"
                     "The exporter must not retain every row."),
        "actor": "owner-local", "scope": None,
    }, capture_mode="redacted"))
    report = engine.process_event(event)
    engine.store.audit(
        actor="owner-local", action="authority.atomic-test", object_id=event["event_id"])
    assert report["created"]
    assert report["conflicts"] == []
    proposals = [engine.graph.get(item["node_id"], tenant_id=TENANT, project_id=PROJECT)
                 for item in report["created"]]
    assert len(proposals) == 2
    assert all(node["entity_type"] == "claim" for node in proposals)
    assert {node["data"]["proposed_kind"] for node in proposals} == {
        "requirement", "constraint"}
    assert all(not engine.graph.may_mandate(node) for node in proposals)
    marker = engine.store._conn.execute(
        "SELECT processor_version, status FROM processed_events WHERE event_id=?",
        (event["event_id"],)).fetchall()
    assert [tuple(row) for row in marker] == [(PROCESSOR_VERSION, "ok")]
    assert engine.store._conn.execute(
        "SELECT count(*) FROM edges WHERE event_id=?", (event["event_id"],)).fetchone()[0] > 0
    supports = engine.store._conn.execute(
        "SELECT src_id, dst_id FROM edges WHERE event_id=? AND edge_type='supports'",
        (event["event_id"],)).fetchall()
    assert {tuple(row) for row in supports} == {
        (event["event_id"], node["node_id"]) for node in proposals}
    return event


def test_owned_append_processing_and_audit_commit_reopen_and_replay(tmp_path):
    path = tmp_path / "engine-atomic.sqlite3"
    engine = Engine(path, tenant_id=TENANT)
    try:
        engine.create_project("Atomic processor fixture", project_id=PROJECT)
        with engine.store.transaction():
            event = _process_atomic_event(engine)
        fingerprint = engine.projection_fingerprint(PROJECT)
        assert engine.store.verify_chain()["intact"] is True
        assert engine.store.verify_chain("audit_log")["intact"] is True
    finally:
        engine.close()
    reopened = Engine(path, tenant_id=TENANT)
    try:
        assert reopened.store.get_event(event["event_id"]) == event
        assert reopened.projection_fingerprint(PROJECT) == fingerprint
        assert reopened.store.verify_chain()["intact"] is True
        assert reopened.store.verify_chain("audit_log")["intact"] is True
        assert reopened.replay_completeness(PROJECT)["replayable"] is True
        rebuilt = reopened.rebuild_projection(PROJECT)
        try:
            assert rebuilt.projection_fingerprint(PROJECT) == fingerprint
        finally:
            rebuilt.close()
    finally:
        reopened.close()


def test_failure_after_real_processing_rolls_back_the_entire_owned_decision(tmp_path):
    engine = Engine(tmp_path / "engine-rollback.sqlite3", tenant_id=TENANT)
    try:
        engine.create_project("Atomic processor fixture", project_id=PROJECT)
        before = _projection_state(engine)
        with pytest.raises(RuntimeError, match="abort after processing"):
            with engine.store.transaction():
                _process_atomic_event(engine)
                assert _projection_state(engine) != before
                raise RuntimeError("abort after processing")
        assert _projection_state(engine) == before
        assert not engine.store._conn.in_transaction
        assert engine.store._transaction_depth == 0
        # The rejected request identity and sequence remain reusable.
        with engine.store.transaction():
            event = _process_atomic_event(engine)
        assert event["seq"] == 1
        assert engine.store.verify_chain()["intact"] is True
        assert engine.store.verify_chain("audit_log")["intact"] is True
    finally:
        engine.close()


def test_two_connections_serialize_before_private_append(store):
    second = Store(store.path)
    attempted = threading.Event()
    entered = threading.Event()
    observed = []
    errors = []

    def trace(sql):
        if sql == "BEGIN IMMEDIATE":
            attempted.set()

    def append_second():
        try:
            with second.transaction():
                entered.set()
                observed.append(second.events())
                observed.append(second._append_event_in_transaction(**_fields("second")))
        except BaseException as exc:
            errors.append(exc)

    second._conn.set_trace_callback(trace)
    thread = threading.Thread(target=append_second)
    try:
        with store.transaction():
            first = store._append_event_in_transaction(**_fields("first"))
            thread.start()
            # The second BEGIN has reached SQLite while this connection still
            # owns its writer; no sleep-based scheduling assumption is needed.
            assert attempted.wait(5)
            assert not entered.is_set()
        thread.join(5)
        assert not thread.is_alive()
        assert errors == []
        assert entered.is_set()
        assert observed[0] == [first]
        assert observed[1]["seq"] == 2
        assert observed[1]["prev_hash"] == first["entry_hash"]
        assert store.verify_chain()["intact"] is True
    finally:
        if thread.ident is not None:
            thread.join(5)
        second.close()
