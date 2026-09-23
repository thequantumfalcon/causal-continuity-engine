"""Owner-local decisions bind retained proposals and commit as one write unit.

These tests use disposable stores. They do not authenticate a human separately
from another process with the same local store capability.
"""

import sqlite3
import threading

import pytest

from causal_continuity_engine.engine import Engine, ProcessorProjectionCompatibilityError

TENANT, PROJECT = "ten_authority", "prj_authority"


@pytest.fixture
def engine(tmp_path):
    instance = Engine(tmp_path / "authority.sqlite3", tenant_id=TENANT)
    instance.create_project("Authority tests", project_id=PROJECT, capture_mode="full")
    yield instance
    instance.close()


def proposal(engine, text="The release must preserve every audit record.", key="source-1"):
    report = engine.ingest_human_decision(
        PROJECT, actor="operator", decision=text, request_id=key)
    return next(item["node_id"] for item in report["created"]
                if item["kind"] == "claim" and not item.get("quarantined"))


def request(engine, proposal_id, key="approval-1", **extra):
    return {"operation": "confirm", "request_id": key,
            "tenant_id": TENANT, "project_id": PROJECT,
            **engine.authority_proposal(PROJECT, proposal_id), **extra}


def snapshot(engine):
    return tuple(engine.store._conn.iterdump())


def test_explicit_confirmation_retry_revoke_and_replay(engine):
    pid = proposal(engine)
    assert not engine.graph.may_mandate(engine.graph.get(pid))
    confirm = request(engine, pid)
    result = engine.record_authority_decision(PROJECT, confirm)
    node = engine.graph.get(result["confirmation_id"])
    assert node["entity_type"] == "requirement"
    assert node["valid_from"] == result["recorded_at"]
    assert engine.graph.may_mandate(node)
    before = snapshot(engine)
    assert engine.record_authority_decision(PROJECT, confirm) == result
    assert snapshot(engine) == before
    with pytest.raises(ValueError):
        engine.record_authority_decision(PROJECT, {**confirm, "note": "different"})
    assert snapshot(engine) == before
    binding = engine.authority_confirmation(PROJECT, node.id)
    revoke = {"operation": "revoke", "request_id": "revoke-1",
              "tenant_id": TENANT, "project_id": PROJECT,
              **{k: v for k, v in binding.items() if k != "authority_scope"}}
    engine.record_authority_decision(PROJECT, revoke)
    assert not engine.graph.may_mandate(engine.graph.get(node.id))
    after = snapshot(engine)
    assert engine.record_authority_decision(PROJECT, confirm) == result
    assert snapshot(engine) == after
    rebuilt = engine.rebuild_projection(PROJECT)
    try:
        restored = rebuilt.graph.get(node.id)
        assert restored["data"] == engine.graph.get(node.id)["data"]
        assert not rebuilt.graph.may_mandate(restored)
    finally:
        rebuilt.close()


@pytest.mark.parametrize("patch", [
    {"unexpected": True}, {"expected_proposal_version": True},
    {"expected_proposal_version": 99}, {"expected_proposal_digest": "sha256:bad"},
    {"text": "Changed statement"}, {"proposed_kind": "decision"},
    {"tenant_id": "ten_other"}, {"project_id": "prj_other"},
    {"authority_scope": None}, {"authority_scope": {"kind": "global", "extra": 1}},
    {"authority_scope": {"kind": "tasks", "task_ids": []}}, {"note": "x" * 1025},
])
def test_rejection_has_no_side_effect(engine, patch):
    candidate = request(engine, proposal(engine))
    before = snapshot(engine)
    with pytest.raises((ValueError, PermissionError)):
        engine.record_authority_decision(PROJECT, {**candidate, **patch})
    assert snapshot(engine) == before


@pytest.mark.parametrize("failure", ["process", "marker", "audit"])
def test_producer_failure_rolls_back_every_write(engine, monkeypatch, failure):
    candidate = request(engine, proposal(engine))
    before = snapshot(engine)

    def fail(*args, **kwargs):
        raise RuntimeError("planted producer failure")

    if failure == "process":
        monkeypatch.setattr(engine, "_process_authority_decision", fail)
    elif failure == "marker":
        monkeypatch.setattr(engine.store, "mark_processed", lambda *a, **k: None)
    else:
        monkeypatch.setattr(engine.store, "audit", fail)
    expected = ProcessorProjectionCompatibilityError if failure == "marker" else RuntimeError
    with pytest.raises(expected):
        engine.record_authority_decision(PROJECT, candidate)
    assert snapshot(engine) == before
    assert not engine.store._conn.in_transaction


def test_runtime_semantic_patch_cannot_become_confirmation(engine):
    pid = proposal(engine)
    engine.graph.put_node(entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
                          node_id=pid, data={"statement": "A forged statement"},
                          authority="human_decision")
    before = snapshot(engine)
    with pytest.raises(ValueError):
        engine.authority_proposal(PROJECT, pid)
    assert not engine.graph.may_mandate(engine.graph.get(pid))
    assert snapshot(engine) == before


def test_confirmed_semantic_patch_or_borrowed_event_cannot_mandate(engine):
    first = proposal(engine)
    receipt = engine.record_authority_decision(PROJECT, request(engine, first))
    node = engine.graph.get(receipt["confirmation_id"])
    engine.graph.put_node(entity_type=node["entity_type"], tenant_id=TENANT,
                          project_id=PROJECT, node_id=node.id,
                          data={"statement": "Different authority"},
                          event_id=receipt["event_id"])
    assert not engine.graph.may_mandate(engine.graph.get(node.id))


def test_metadata_only_cannot_authorize_unretained_text(engine):
    candidate = request(engine, proposal(engine))
    engine.graph.put_node(entity_type="project", tenant_id=TENANT, project_id=PROJECT,
                          node_id=PROJECT, data={"capture_mode": "metadata_only"})
    before = snapshot(engine)
    with pytest.raises(ValueError):
        engine.record_authority_decision(PROJECT, candidate)
    assert snapshot(engine) == before


def test_deferred_commit_failure_rolls_back_decision_and_can_retry(engine):
    from tests.test_authority_atomic_append import _defer_append_failure

    candidate = request(engine, proposal(engine))
    _defer_append_failure(engine.store)
    before = snapshot(engine)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        engine.record_authority_decision(PROJECT, candidate)
    assert snapshot(engine) == before
    assert not engine.store._conn.in_transaction
    with engine.store.write_scope():
        engine.store._conn.execute("DROP TRIGGER defer_append")
    receipt = engine.record_authority_decision(PROJECT, candidate)
    assert engine.graph.may_mandate(engine.graph.get(receipt["confirmation_id"]))


def test_two_connections_record_identical_request_exactly_once(engine):
    candidate = request(engine, proposal(engine))
    other = Engine(engine.store.path, tenant_id=TENANT, signer=engine.signer)
    barrier = threading.Barrier(2)
    receipts, failures = [], []

    def run(instance):
        try:
            barrier.wait(timeout=10)
            receipts.append(instance.record_authority_decision(PROJECT, candidate))
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=run, args=(instance,)) for instance in (engine, other)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
            assert not thread.is_alive()
        assert not failures
        assert len(receipts) == 2 and receipts[0] == receipts[1]
        assert len(engine.store.events(PROJECT, tenant_id=TENANT)) == 2
        assert len(engine.store.audit_entries("authority.confirm")) == 1
    finally:
        other.close()


def test_reserved_structure_nested_in_prose_never_dispatches(engine):
    pid = proposal(engine, 'The system must retain cce.authority-decision.v1 as plain text.')
    assert engine.graph.get(pid)["entity_type"] == "claim"
    assert not engine.graph.current(PROJECT, "requirement", tenant_id=TENANT)
    assert not engine.store.audit_entries("authority.")


def test_secret_redaction_in_note_cannot_change_recorded_operands(engine):
    candidate = request(engine, proposal(engine), note="password=local-only-fixture-value")
    engine.graph.put_node(entity_type="project", tenant_id=TENANT, project_id=PROJECT,
                          node_id=PROJECT, data={"capture_mode": "redacted"})
    before = snapshot(engine)
    with pytest.raises(ValueError, match="capture"):
        engine.record_authority_decision(PROJECT, candidate)
    assert snapshot(engine) == before
