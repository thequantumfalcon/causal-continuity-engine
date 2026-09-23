"""Confirmation preserves source-calibrated criticality, never mutable labels.

These disposable-store checks preserve the extractor's existing calibration;
they do not establish that its pattern-based risk classification is semantic.
"""

import pytest

from causal_continuity_engine.engine import Engine

TENANT, PROJECT = "ten_criticality", "prj_criticality"
ASSUMPTION = "We assume the cluster credentials never rotate mid-run."


@pytest.fixture
def engine(tmp_path):
    instance = Engine(tmp_path / "criticality.sqlite3", tenant_id=TENANT)
    instance.create_project("Criticality", project_id=PROJECT, capture_mode="full")
    yield instance
    instance.close()


def _proposal(engine, text=ASSUMPTION, kind="assumption", key="source"):
    report = engine.ingest_human_decision(
        PROJECT, actor="operator", decision=text, request_id=key)
    proposals = [engine.graph.get(item["node_id"]) for item in report["created"]
                 if item["kind"] == "claim" and not item.get("quarantined")]
    proposal, = [node for node in proposals if node["data"].get("proposed_kind") == kind]
    assert proposal["data"]["needs_confirmation"] is True
    return proposal


def _request(engine, proposal, key="approve"):
    return {"operation": "confirm", "request_id": key, "tenant_id": TENANT,
            "project_id": PROJECT, **engine.authority_proposal(PROJECT, proposal.id)}


def _confirm(engine, proposal, key="approve"):
    return engine.record_authority_decision(PROJECT, _request(engine, proposal, key))


def _replace_scope(engine, confirmation_id, scope):
    return engine.record_authority_decision(PROJECT, {
        "operation": "replace_scope", "request_id": "rescope", "tenant_id": TENANT,
        "project_id": PROJECT, **engine.authority_confirmation(PROJECT, confirmation_id),
        "authority_scope": scope})


@pytest.mark.parametrize("text,kind,criticality", [
    (ASSUMPTION, "assumption", "high"),
    ("The pipeline must preserve production records.", "requirement", "high"),
    ("The importer must not log credentials.", "constraint", "high"),
    ("We decided to protect production data.", "decision", "high"),
    ("The exporter must avoid data loss.", "requirement", "critical"),
    ("The importer must validate schemas.", "requirement", "medium"),
    ("- [ ] implement the parser", "task", "medium"),
])
def test_confirmation_retains_calibrated_source_criticality(engine, text, kind, criticality):
    proposal = _proposal(engine, text, kind)
    assert proposal["criticality"] == criticality
    receipt = _confirm(engine, proposal)
    confirmed = engine.graph.get(receipt["confirmation_id"])
    assert confirmed["criticality"] == criticality
    assert engine.graph.may_mandate(confirmed)


@pytest.mark.parametrize("mutate_current_proposal", [False, True])
def test_rescope_and_replay_retain_original_criticality(engine, mutate_current_proposal):
    proposal = _proposal(engine)
    assert proposal["criticality"] == "high"
    receipt = _confirm(engine, proposal)
    task = _proposal(engine, "- [ ] implement the parser", "task", "task-source")
    task_id = _confirm(engine, task, "task-approval")["confirmation_id"]
    if mutate_current_proposal:
        engine.graph.put_node(
            entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
            node_id=proposal.id, data={}, criticality="low")
        assert engine.graph.get(proposal.id)["criticality"] == "low"
        assert engine.graph.history(proposal.id)[0]["criticality"] == "high"
    scope = {"kind": "tasks", "task_ids": [task_id]}
    _replace_scope(engine, receipt["confirmation_id"], scope)
    confirmed = engine.graph.get(receipt["confirmation_id"])
    assert confirmed["scope"] == scope
    assert confirmed["criticality"] == "high"
    assert all(row["criticality"] == "high"
               for row in engine.graph.history(confirmed.id))
    fresh = engine.rebuild_projection(PROJECT)
    try:
        restored = fresh.graph.get(confirmed.id)
        assert restored["criticality"] == "high"
        assert restored["scope"] == scope
        assert fresh.graph.may_mandate(restored)
    finally:
        fresh.close()


def test_editing_current_proposal_before_confirmation_refuses_without_writes(engine):
    proposal = _proposal(engine)
    request = _request(engine, proposal)
    engine.graph.put_node(entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
                          node_id=proposal.id, data={}, criticality="low")
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises(ValueError, match="stale, edited or withdrawn"):
        engine.record_authority_decision(PROJECT, request)
    assert tuple(engine.store._conn.iterdump()) == before


def test_original_projection_criticality_must_match_retained_extraction(engine):
    proposal = _proposal(engine)
    assert proposal["criticality"] == "high"
    with engine.store.write_scope():
        engine.store._conn.execute(
            "UPDATE nodes SET criticality='low' WHERE node_id=? AND version=1", (proposal.id,))
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises(ValueError):
        engine.authority_proposal(PROJECT, proposal.id)
    assert tuple(engine.store._conn.iterdump()) == before


def test_mutable_confirmed_criticality_cannot_change_binding_authority(engine):
    receipt = _confirm(engine, _proposal(engine))
    confirmed = engine.graph.get(receipt["confirmation_id"])
    engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        node_id=confirmed.id, data={}, criticality="low")
    changed = engine.graph.get(confirmed.id)
    assert changed["criticality"] == "low"
    assert not engine.graph.may_mandate(changed)
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises(ValueError, match="withdrawn or altered authority"):
        _replace_scope(engine, confirmed.id, {"kind": "global"})
    assert tuple(engine.store._conn.iterdump()) == before


@pytest.mark.parametrize("confidence,status", [(0.2, "pending_confirmation"), (0.95, "open")])
def test_confirmed_high_criticality_controls_real_invalidation(engine, confidence, status):
    receipt = _confirm(engine, _proposal(engine))
    invalidation = engine.invalidation.fire(
        tenant_id=TENANT, project_id=PROJECT, target_node_id=receipt["confirmation_id"],
        trigger_type="contradictory_evidence", trigger_confidence=confidence,
        reason="rotation observed")
    assert invalidation["status"] == status
    assert invalidation["data"]["severity"] == "high"
    assert engine.continuity_check(PROJECT)["conclusion"] == "action_required"


def test_unavailable_source_withholds_authority_and_refuses_new_revocation(engine):
    proposal = _proposal(engine)
    receipt = _confirm(engine, proposal)
    operands = engine.authority_confirmation(PROJECT, receipt["confirmation_id"])
    with engine.store.write_scope():
        engine.store._conn.execute("UPDATE events SET payload=NULL WHERE event_id=?",
                                   (proposal["event_id"],))
    assert not engine.graph.may_mandate(engine.graph.get(receipt["confirmation_id"]))
    before = tuple(engine.store._conn.iterdump())
    # The canonical state reader requires retained source content even for a
    # reduction of authority. This is an availability limit, not renewed trust.
    with pytest.raises(ValueError, match="proposal source binding is unavailable"):
        engine.record_authority_decision(PROJECT, {
            "operation": "revoke", "request_id": "revoke", "tenant_id": TENANT,
            "project_id": PROJECT,
            **{key: value for key, value in operands.items() if key != "authority_scope"}})
    assert tuple(engine.store._conn.iterdump()) == before
    assert not engine.graph.may_mandate(engine.graph.get(receipt["confirmation_id"]))
