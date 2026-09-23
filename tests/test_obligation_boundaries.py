"""Adversarial scope, time and transaction checks for complete task obligations."""

from datetime import timedelta

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.core import digest_obj, parse_ts, utcnow
from causal_continuity_engine.engine import Engine
from tests.test_obligation_completeness import (
    OBLIGATIONS,
    PROJECT,
    _attest,
    _confirm,
    _spent,
    _task,
    engine,
)

__all__ = ["engine"]  # pytest imports the same real-producer fixture explicitly.


@pytest.mark.parametrize("operation", ["revoke", "replace_scope"])
def test_canonical_scope_or_revocation_change_stales_existing_proof(engine, operation):
    target = _task(engine)
    sibling = _task(engine, "sibling")
    member = _confirm(engine, *OBLIGATIONS[0], "moving-requirement")
    proof = _attest(engine, target)
    request = {
        "operation": operation, "request_id": "change-authority",
        "tenant_id": engine.tenant_id, "project_id": PROJECT,
        **engine.authority_confirmation(PROJECT, member),
    }
    # Revocation has no new scope operand; replace_scope does.
    request.pop("authority_scope")
    if operation == "replace_scope":
        request["authority_scope"] = {"kind": "tasks", "task_ids": [sibling]}
    engine.record_authority_decision(PROJECT, request)
    before = engine.graph.get(target), _spent(engine)
    assert not engine.proof_currency(PROJECT, target, proof)["current"]
    with pytest.raises(PermissionError):
        engine.complete_task(PROJECT, target, proof=proof)
    assert (engine.graph.get(target), _spent(engine)) == before


@pytest.mark.parametrize("field", ["proof_id", "completion_evidence", "last_verified_at"])
def test_runtime_semantic_fields_are_not_dropped_as_bookkeeping(engine, field):
    target = _task(engine)
    member = engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        data={"statement": "Clock calibration is unchanged", field: "first"}, status="active")
    proof = _attest(engine, target)
    engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        node_id=member.id, data={field: "second"})
    assert not engine.proof_currency(PROJECT, target, proof)["current"]
    with pytest.raises(PermissionError, match="no longer describes"):
        engine.complete_task(PROJECT, target, proof=proof)


@pytest.mark.parametrize("scope", [
    {}, {"kind": "tasks", "task_ids": []}, {"kind": "global", "extra": True},
    {"kind": "tasks", "task_ids": ["tsk_not_confirmed"]},
])
def test_malformed_runtime_scope_cannot_mean_empty_authority(engine, scope):
    target = _task(engine)
    engine.graph.put_node(
        entity_type="constraint", tenant_id=engine.tenant_id, project_id=PROJECT,
        data={"statement": "Retain export commitments", "authority_scope": scope},
        status="active")
    before = engine.graph.current(PROJECT), _spent(engine)
    with pytest.raises(ValueError, match="invalid proof obligation target"):
        _attest(engine, target)
    assert (engine.graph.current(PROJECT), _spent(engine)) == before


def test_validity_is_parsed_and_half_open(engine):
    target = _task(engine)
    member = engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        data={"statement": "Calibration valid for this interval"}, status="active",
        valid_from="2027-01-01T01:00:00+02:00", valid_to="2027-01-01T03:00:00+02:00")
    basis = engine._obligation_basis(PROJECT, target, instant=parse_ts("2027-01-01T00:00:00Z"))
    assert [item["node_id"] for item in basis["obligations"]] == [member.id]
    at_end = engine._obligation_basis(PROJECT, target, instant=parse_ts("2027-01-01T01:00:00Z"))
    assert at_end["obligations"] == []


def test_clock_crossing_alone_stales_a_previously_future_obligation(engine, monkeypatch):
    target = _task(engine)
    now = parse_ts(utcnow())
    start = now + timedelta(hours=1)
    engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        data={"statement": "The next calibration must be honored"}, status="active",
        valid_from=start.isoformat())
    proof = _attest(engine, target)
    monkeypatch.setattr(engine_module, "utcnow", lambda: (start + timedelta(hours=1)).isoformat())
    before = engine.graph.get(target), _spent(engine)
    assert not engine.proof_currency(PROJECT, target, proof)["current"]
    with pytest.raises(PermissionError, match="no longer describes"):
        engine.complete_task(PROJECT, target, proof=proof)
    assert (engine.graph.get(target), _spent(engine)) == before


def test_caller_cannot_use_reserved_name_under_declared_kind(engine):
    target = _task(engine)
    before = engine.graph.current(PROJECT), _spent(engine)
    with pytest.raises(ValueError, match="reserved"):
        engine.attest_action(
            PROJECT, intent_type="task_complete", intent_statement="done", actor={"agent": "test"},
            continuity={"task_ids": [target]},
            inputs=[(f"continuity:obligations:{target}", digest_obj({}), "declared")])
    assert (engine.graph.current(PROJECT), _spent(engine)) == before


def test_peer_write_between_target_reads_cannot_publish_mixed_obligations(engine, monkeypatch):
    target = _task(engine)
    sibling = _task(engine, "sibling")
    peer = Engine(engine.store.path, workdir=engine.verifier_runner.workdir)
    original = engine._obligation_basis
    interposed = False
    seen = []

    def interleave(project_id, task_id, **kwargs):
        nonlocal interposed
        basis = original(project_id, task_id, **kwargs)
        seen.append((task_id, [item["node_id"] for item in basis["obligations"]]))
        if not interposed:
            interposed = True
            _confirm(peer, *OBLIGATIONS[0], "peer-requirement",
                     scope={"kind": "tasks", "task_ids": [sibling]})
        return basis

    monkeypatch.setattr(engine, "_obligation_basis", interleave)
    before_actions = engine.graph.current(PROJECT, "action")
    try:
        with pytest.raises(RuntimeError, match="obligations changed"):
            engine.attest_action(
                PROJECT, intent_type="task_complete", intent_statement="done",
                actor={"agent": "test"}, continuity={"task_ids": [target, sibling]})
        assert interposed
        # First pair belongs to the pre-write SQLite snapshot, not mixed reads.
        assert seen[:2] == [(target, []), (sibling, [])]
        assert engine.graph.current(PROJECT, "action") == before_actions
        assert _spent(engine) == []
        assert len(peer.graph.current(PROJECT, "requirement")) == 1
    finally:
        peer.close()
