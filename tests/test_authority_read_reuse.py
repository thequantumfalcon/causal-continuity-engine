"""Collector-local reuse bounds canonical reads without extending their lifetime.

Counts pin repeated work, not elapsed-time performance. Real proposals and local
confirmations establish every positive control; privileged disposable-store
damage probes do not claim protection against the store's owner.
"""

from collections import Counter
from datetime import timedelta

import pytest

from causal_continuity_engine.core import canonical_json, parse_ts, utcnow
from tests.authority_helpers import confirm_proposal
from tests.test_engine_e2e import _issue
from tests.test_obligation_completeness import (
    OBLIGATIONS,
    PROJECT,
    _attest,
    _confirm,
    _task,
    engine,
)

__all__ = ["engine"]


def _collect(engine, target=None, *, instant=None):
    with engine.store.transaction():
        return engine._applicable_obligations(
            PROJECT, target, instant=parse_ts(utcnow()) if instant is None else instant)


def _change(engine, member, operation, *, scope=None):
    binding = engine.authority_confirmation(PROJECT, member)
    binding.pop("authority_scope")
    request = {"operation": operation, "request_id": operation + "-" + member,
               "tenant_id": engine.tenant_id, "project_id": PROJECT, **binding}
    if scope is not None:
        request["authority_scope"] = scope
    return engine.record_authority_decision(PROJECT, request)


@pytest.mark.parametrize("targeted", [False, True])
@pytest.mark.parametrize("counted", ["control_witnesses", "scope_identities"])
def test_one_collector_reads_each_canonical_identity_once(engine, monkeypatch, targeted, counted):
    tasks = [_task(engine, key) for key in ("target", "sibling")]
    scope = {"kind": "tasks", "task_ids": sorted(tasks)}
    controls = [_confirm(engine, kind, text, kind, scope=scope) for kind, text in OBLIGATIONS]
    states, task_reads = Counter(), Counter()
    original_state, original_get = engine._authority_state, engine.graph.get

    def state(project_id, confirmation_id):
        states[confirmation_id] += 1
        return original_state(project_id, confirmation_id)

    def get(node_id, **kwargs):
        if node_id in tasks and kwargs.get("entity_type") == "task":
            task_reads[node_id] += 1
        return original_get(node_id, **kwargs)

    monkeypatch.setattr(engine, "_authority_state", state)
    monkeypatch.setattr(engine.graph, "get", get)
    members = _collect(engine, tasks[0] if targeted else None)
    assert {member["node_id"] for member in members} == set(controls)
    if counted == "control_witnesses":
        assert {control: states[control] for control in controls} == dict.fromkeys(controls, 1)
    else:
        assert {task: states[task] for task in tasks} == dict.fromkeys(tasks, 1)
        assert task_reads == Counter(dict.fromkeys(tasks, 1))


def test_healthy_shared_controls_preserve_public_packet_and_proof_semantics(engine):
    target, sibling = _task(engine), _task(engine, "sibling")
    scope = {"kind": "tasks", "task_ids": sorted([target, sibling])}
    controls = [_confirm(engine, kind, text, kind, scope=scope) for kind, text in OBLIGATIONS]
    members = _collect(engine, target)
    assert {member["node_id"] for member in members} == set(controls)
    for member in members:
        node = engine.graph.get(member["node_id"])
        assert member["origin"] == "confirmed"
        assert member["authority_scope"] == scope
        assert member["content"] == {
            key: value for key, value in node["data"].items() if key != "decided_at"}
        assert member["confirmation"] == {key: node["data"][key] for key in (
            "proposal_id", "confirmation_event_id", "decision_event_id", "authority_version")}
    proof = _attest(engine, target)
    packet = engine.resume_packet(PROJECT, task_id=target)
    assert packet["complete"] is True
    assert packet["mandatory_control"] == members
    assert engine._obligation_basis(PROJECT, target)["obligations"] == members
    assert engine.proof_currency(PROJECT, target, proof)["current"] is True
    assert engine.complete_task(PROJECT, target, proof=proof)["status"] == "verified"


@pytest.mark.parametrize("damage", ["statement", "criticality", "quarantine", "blocked"])
def test_each_collector_checks_actual_node_semantics_and_status(engine, damage):
    target = _task(engine)
    member = _confirm(engine, *OBLIGATIONS[0], "actual-node")
    with engine.store.transaction():
        assert [item["node_id"] for item in _collect(engine, target)] == [member]
        changes = {"statement": {"data": {"statement": "Unapproved replacement"}},
                   "criticality": {"criticality": "low", "data": {}},
                   "quarantine": {"status": "quarantined", "data": {}},
                   "blocked": {"status": "blocked", "data": {}}}[damage]
        engine.graph.put_node(entity_type="requirement", tenant_id=engine.tenant_id,
                              project_id=PROJECT, node_id=member, **changes)
        actual = engine.graph.get(member)
        members = _collect(engine, target)
        if damage == "blocked":
            assert [item["node_id"] for item in members] == [member]
            assert members[0]["status"] == "blocked"
            assert engine.authority_is_current(actual)
        else:
            assert members == []
            assert not engine.authority_is_current(actual)


@pytest.mark.parametrize("operation", ["revoke", "replace_scope"])
def test_repeated_collectors_in_one_writer_observe_new_canonical_decisions(engine, operation):
    target, sibling = _task(engine), _task(engine, "sibling")
    member = _confirm(engine, *OBLIGATIONS[0], "moving")
    with engine.store.transaction():
        assert [item["node_id"] for item in _collect(engine, target)] == [member]
        scope = {"kind": "tasks", "task_ids": [sibling]} if operation == "replace_scope" else None
        _change(engine, member, operation, scope=scope)
        assert _collect(engine, target) == []
        siblings = _collect(engine, sibling)
        if operation == "replace_scope":
            assert [item["node_id"] for item in siblings] == [member]
            assert siblings[0]["authority_scope"] == scope
            assert siblings[0]["confirmation"]["authority_version"] == 2
        else:
            assert siblings == []


def test_repeated_collector_checks_source_support_not_just_canonical_approval(engine):
    target = _task(engine)
    engine.bind_github_repository(PROJECT, repository_id=1001)
    report = engine.ingest_github(PROJECT, "issues", "source", _issue(1, OBLIGATIONS[0][1]))
    proposal, = [item["node_id"] for item in report["created"] if item["kind"] == "claim"]
    member = confirm_proposal(engine, PROJECT, proposal).id
    assert [item["node_id"] for item in _collect(engine, target)] == [member]
    # Source ingress owns its canonical append; unlike authority decisions it
    # deliberately cannot join an existing writer.
    engine.ingest_github(PROJECT, "issues", "withdraw", _issue(1, "No obligations remain."))
    # Keep a superficially eligible projection so the deciding check is
    # retained source support, not merely the terminal-status/validity filter.
    engine.graph.put_node(entity_type="requirement", tenant_id=engine.tenant_id,
                          project_id=PROJECT, node_id=member, status="active", data={},
                          reopen_validity=True, valid_from=utcnow())
    assert not engine.authority_is_current(engine.graph.get(member))
    assert _collect(engine, target) == []


def test_agreeing_but_noncanonical_scope_damage_never_becomes_empty_membership(engine):
    target, sibling = _task(engine), _task(engine, "sibling")
    member = _confirm(engine, *OBLIGATIONS[0], "damaged-scope")
    with engine.store.transaction():
        assert [item["node_id"] for item in _collect(engine, target)] == [member]
        data = dict(engine.graph.get(member)["data"])
        scope = {"kind": "tasks", "task_ids": [sibling]}
        data["authority_scope"] = scope
        engine.store._conn.execute(
            "UPDATE nodes SET data=?,scope=? WHERE node_id=? AND tx_to IS NULL",
            (canonical_json(data), canonical_json(scope), member))
        with pytest.raises(ValueError, match="scope disagrees with canonical authority"):
            _collect(engine, target)
        with pytest.raises(ValueError, match="scope disagrees with canonical authority"):
            engine.resume_packet(PROJECT, task_id=target)


@pytest.mark.parametrize("lost", ["source", "later_decision"])
def test_retention_after_origin_withholds_warm_collector_authority(engine, lost):
    target = _task(engine)
    member = _confirm(engine, *OBLIGATIONS[0], "retained")
    later = _confirm(engine, *OBLIGATIONS[3], "later")
    _change(engine, later, "revoke")
    node = engine.graph.get(member if lost == "source" else later)
    if lost == "source":
        event_id = engine.graph.history(node["data"]["proposal_id"])[0]["event_id"]
    else:
        event_id = node["data"]["confirmation_event_id"]
    with engine.store.transaction():
        assert [item["node_id"] for item in _collect(engine, target)] == [member]
        engine.store._conn.execute("UPDATE events SET payload=NULL WHERE event_id=?", (event_id,))
        assert not engine.authority_is_current(engine.graph.get(member))
        with pytest.raises(ValueError):
            _collect(engine, target)
        with pytest.raises(ValueError):
            engine.resume_packet(PROJECT, task_id=target)
        assert engine.store.verify_chain("events")["intact"] is True


def test_retention_before_new_origins_does_not_poison_new_collector_authority(engine):
    old = _confirm(engine, *OBLIGATIONS[0], "old")
    _change(engine, old, "revoke")
    assert engine.memory.sweep_retention(raw_days=0) == 3
    target = _task(engine)
    member = _confirm(engine, *OBLIGATIONS[3], "fresh")
    assert [item["node_id"] for item in _collect(engine, target)] == [member]
    packet = engine.resume_packet(PROJECT, task_id=target)
    assert [item["node_id"] for item in packet["mandatory_control"]] == [member]
    assert engine.store.verify_chain("events")["intact"] is True


def test_same_writer_rechecks_half_open_validity_without_database_change(engine):
    target = _task(engine)
    member = _confirm(engine, *OBLIGATIONS[0], "expiring")
    end = parse_ts(utcnow()) + timedelta(hours=1)
    engine.graph.put_node(entity_type="requirement", tenant_id=engine.tenant_id,
                          project_id=PROJECT, node_id=member, data={}, valid_to=end.isoformat())
    with engine.store.transaction():
        before = tuple(engine.store._conn.iterdump())
        assert [item["node_id"] for item in _collect(
            engine, target, instant=end - timedelta(microseconds=1))] == [member]
        assert _collect(engine, target, instant=end) == []
        assert tuple(engine.store._conn.iterdump()) == before


def test_unconfirmed_extracted_control_still_validates_persisted_scope(engine):
    target = _task(engine)
    # A planted non-authority extraction cannot mandate, but its malformed
    # persisted scope must still refuse before the authority check skips it.
    node = engine.graph.put_node(
        entity_type="requirement", tenant_id=engine.tenant_id, project_id=PROJECT,
        data={"statement": "Unconfirmed control", "authority_scope": {}},
        status="active", extractor="cce-deterministic")
    assert not engine.authority_is_current(node)
    with pytest.raises(ValueError, match="invalid persisted obligation scope"):
        _collect(engine, target)


def test_unavailable_withdrawal_history_refuses_instead_of_silently_omitting(engine):
    target = _task(engine)
    member = _confirm(engine, *OBLIGATIONS[0], "missing-withdrawal")
    proposal = engine.graph.get(member)["data"]["proposal_id"]
    assert [item["node_id"] for item in _collect(engine, target)] == [member]
    # Model unavailable referenced history without removing canonical events.
    # Canonical confirmation reconstruction succeeds; source-support lookup
    # raises, and that refusal must not turn into an empty complete packet.
    engine.graph.put_node(entity_type="claim", tenant_id=engine.tenant_id,
                          project_id=PROJECT, node_id=proposal,
                          data={"source_withdrawn": True})
    with engine.store.transaction():
        engine.store._conn.execute(
            "UPDATE nodes SET event_id=? WHERE node_id=? AND tx_to IS NULL",
            ("evt_unavailable_withdrawal", proposal))
        with pytest.raises(KeyError, match="evt_unavailable_withdrawal"):
            _collect(engine, target)
        with pytest.raises(KeyError, match="evt_unavailable_withdrawal"):
            engine.resume_packet(PROJECT, task_id=target)
