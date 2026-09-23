"""Frozen task-packet contract; unsupported old APIs are not defect evidence.

Scope is explicit applicability, not semantic relevance. Real retained proposals
and owner-local confirmations provide all positive task/control authority here.
These tests do not establish a serialized-byte bound or remote delivery.
"""

from pathlib import Path

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.core import canonical_json, digest_obj
from causal_continuity_engine.engine import Engine

PROJECT = "prj_task_packets"
MEMBER_FIELDS = {
    "node_id", "entity_type", "origin", "status", "criticality", "confidence",
    "authority", "valid_from", "valid_to", "authority_scope", "content", "confirmation",
}
CONFIRMATION_FIELDS = {
    "proposal_id", "confirmation_event_id", "decision_event_id", "authority_version",
}


@pytest.fixture
def engine(tmp_path):
    assert Path(engine_module.__file__).resolve() == (
        Path(__file__).resolve().parents[1] / "causal_continuity_engine" / "engine.py")
    instance = Engine(tmp_path / "packets.sqlite3", workdir=tmp_path)
    instance.create_project("Packet scopes", project_id=PROJECT, capture_mode="full")
    try:
        yield instance
    finally:
        instance.close()


def _proposal(engine, kind, text, key, *, project_id=PROJECT):
    report = engine.ingest_human_decision(
        project_id, actor="source-" + key, decision=text, request_id="ingest-" + key)
    proposal_id, = [item["node_id"] for item in report["created"]
                    if item["kind"] == "claim" and not item.get("quarantined")]
    proposal = engine.authority_proposal(project_id, proposal_id)
    assert proposal["proposed_kind"] == kind
    return proposal


def _confirm(engine, kind, text, key, *, scope=None, project_id=PROJECT):
    proposal = _proposal(engine, kind, text, key, project_id=project_id)
    receipt = engine.record_authority_decision(project_id, {
        "operation": "confirm", "request_id": "confirm-" + key,
        "tenant_id": engine.tenant_id, "project_id": project_id,
        **proposal, "authority_scope": scope or {"kind": "global"},
    })
    node = engine.graph.get(receipt["confirmation_id"])
    assert engine.graph.may_mandate(node)
    return node


def _task(engine, key, *, project_id=PROJECT):
    return _confirm(engine, "task", "- [ ] Package the " + key + " archive", key,
                    project_id=project_id)


def _controls(engine, key, scope):
    subject = {
        "global": "federated inventory adapter", "alpha": "lunar navigation dashboard",
        "beta": "orchard irrigation monitor", "shared": "oceanographic sample registry",
    }.get(key, key + " exporter")
    declarations = [
        ("requirement", f"The {subject} must retain archive checksums."),
        ("constraint", f"The {subject} must not record passwords."),
        ("decision", f"We decided to use SQLite for the {subject}."),
        ("assumption", f"We assume the {subject} is reachable during validation."),
    ]
    return [_confirm(engine, kind, text, key + "-" + kind, scope=scope)
            for kind, text in declarations]


def _scope(task_id=None):
    return ({"kind": "project"} if task_id is None
            else {"kind": "task", "task_id": task_id})


def _packet(engine, task_id=None, **kwargs):
    if task_id is None:
        return engine.resume_packet(PROJECT, **kwargs)
    return engine.resume_packet(PROJECT, task_id=task_id, **kwargs)


def _assert_contract(engine, packet, task_id, expected):
    assert packet["schema_version"] == "cce.resume.v2"
    assert packet["tenant_id"] == engine.tenant_id
    assert packet["project_id"] == PROJECT
    assert packet["scope"] == _scope(task_id)
    assert packet["complete"] is True
    members = packet["mandatory_control"]
    assert packet["authority_set_digest"] == digest_obj(members)
    assert [(item["entity_type"], item["node_id"]) for item in members] == sorted(
        (node["entity_type"], node["node_id"]) for node in expected)
    by_id = {node["node_id"]: node for node in expected}
    for member in members:
        assert set(member) == MEMBER_FIELDS
        node = by_id[member["node_id"]]
        for field in ("node_id", "entity_type", "status", "criticality", "confidence",
                      "authority", "valid_from", "valid_to"):
            assert member[field] == node[field]
        if node["data"].get("confirmation_event_id"):
            assert member["origin"] == "confirmed"
            assert member["authority_scope"] == node["data"]["authority_scope"]
            assert set(member["confirmation"]) == CONFIRMATION_FIELDS
            assert member["confirmation"] == {
                field: node["data"][field] for field in CONFIRMATION_FIELDS}
            assert member["content"] == {
                key: value for key, value in node["data"].items() if key != "decided_at"}
        else:
            assert member["origin"] == "runtime"
            assert member["authority_scope"] == {"kind": "global"}
            assert member["confirmation"] is None
            assert member["content"] == node["data"]
    assert engine.signer.verify(packet)


def _watermarks(engine):
    return [dict(row) for row in engine.store._conn.execute(
        "SELECT * FROM packet_watermark ORDER BY packet_id")]


def _audit(engine):
    return engine.store.audit_entries("packet.watermark")


@pytest.fixture
def signing_calls(engine, monkeypatch):
    calls = []
    original = type(engine.signer).sign

    def observe(signer, body):
        calls.append(body)
        return original(signer, body)

    # Observe the actual signer; no authentication or outcome is replaced.
    monkeypatch.setattr(type(engine.signer), "sign", observe)
    return calls


@pytest.mark.parametrize("mode", ["project", "alpha", "beta"])
def test_complete_controls_are_global_plus_explicit_task_scope(engine, mode):
    alpha, beta = _task(engine, "alpha"), _task(engine, "beta")
    groups = {
        "global": _controls(engine, "global", {"kind": "global"}),
        "alpha": _controls(engine, "alpha", {"kind": "tasks", "task_ids": [alpha.id]}),
        "beta": _controls(engine, "beta", {"kind": "tasks", "task_ids": [beta.id]}),
        "shared": _controls(engine, "shared", {
            "kind": "tasks", "task_ids": sorted([alpha.id, beta.id])}),
    }
    for nodes in groups.values():
        for node in nodes:
            engine.memory.promote(PROJECT, node.id, "L0", actor="owner")
    selected = None if mode == "project" else {"alpha": alpha.id, "beta": beta.id}[mode]
    expected = [node for name, nodes in groups.items()
                if mode == "project" or name in ("global", mode, "shared") for node in nodes]
    expected = [engine.graph.get(node.id) for node in expected]
    packet = _packet(engine, selected)
    _assert_contract(engine, packet, selected, expected)
    binding = (packet["authority"]["active_requirements"]
               + packet["authority"]["active_constraints"] + packet["accepted_decisions"]
               + packet["assumptions"]["active"]
               + packet["mission"]["pinned_control_state"])
    all_controls = {node.id for nodes in groups.values() for node in nodes}
    assert {item["node_id"] for item in binding} & all_controls == {
        node.id for node in expected}
    if selected:
        excluded = groups["beta" if mode == "alpha" else "alpha"]
        omissions = canonical_json(packet["omissions"])
        assert all(node.id not in omissions for node in excluded)
        assert any(item.get("count", 0) > 0 for item in packet["omissions"])
        assert {item["node_id"] for item in packet["open_work"]["tasks"]} == {selected}


@pytest.mark.parametrize("task_mode", [False, True])
def test_unscoped_runtime_control_remains_global_and_complete(engine, task_mode):
    task = _task(engine, "runtime")
    node = engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        status="active", authority="human_decision",
        data={"statement": "The measured calibration clock remains stable.",
              "decided_at": "runtime semantic content", "nested": {"rate": 1}})
    selected = task.id if task_mode else None
    _assert_contract(engine, _packet(engine, selected), selected, [node])


@pytest.mark.parametrize("task_mode", [False, True])
def test_token_hint_never_trims_mandatory_task_work(engine, task_mode):
    tasks = [_task(engine, key) for key in ("alpha", "beta", "gamma")]
    controls = _controls(engine, "budget", {"kind": "global"})
    selected = tasks[0].id if task_mode else None
    packet = _packet(engine, selected, token_budget=1)
    _assert_contract(engine, packet, selected, controls)
    assert {item["node_id"] for item in packet["open_work"]["tasks"]} == (
        {selected} if selected else {node.id for node in tasks})


def test_target_metadata_cannot_select_authority_scope(engine):
    task = _task(engine, "metadata")
    controls = _controls(engine, "metadata", {"kind": "tasks", "task_ids": [task.id]})
    packet = engine.resume_packet(PROJECT, target={"task_id": "tsk_not_real", "kind": "task"})
    _assert_contract(engine, packet, None, controls)


def test_project_and_two_task_watermarks_coexist_without_freshness_substitution(engine):
    alpha, beta = _task(engine, "alpha"), _task(engine, "beta")
    assert engine.packet_is_stale(PROJECT)
    first = _packet(engine, alpha.id)
    assert not engine.packet_is_stale(PROJECT, task_id=alpha.id)
    assert engine.packet_is_stale(PROJECT, task_id=beta.id)
    assert engine.packet_is_stale(PROJECT)
    second = _packet(engine, beta.id)
    assert engine.packet_is_stale(PROJECT)
    project = _packet(engine)
    rows = _watermarks(engine)
    assert len(rows) == 3
    assert {row["scope_key"]: row["packet_id"] for row in rows} == {
        "project": project["packet_id"], "task:" + alpha.id: first["packet_id"],
        "task:" + beta.id: second["packet_id"],
    }
    for selected in (None, alpha.id, beta.id):
        assert not engine.packet_is_stale(PROJECT, task_id=selected)
    assert {entry["object_id"] for entry in _audit(engine)} == {
        canonical_json({"tenant_id": engine.tenant_id, "project_id": PROJECT,
                        "scope_key": key})
        for key in ("project", "task:" + alpha.id, "task:" + beta.id)
    }
    preserved = [row for row in rows if row["scope_key"] != "task:" + alpha.id]
    _packet(engine, alpha.id)
    assert [row for row in _watermarks(engine)
            if row["scope_key"] != "task:" + alpha.id] == preserved
    for selected in (None, alpha.id, beta.id):
        assert not engine.packet_is_stale(PROJECT, task_id=selected)


def test_cross_task_audit_commitment_cannot_be_substituted(engine):
    alpha, beta = _task(engine, "alpha"), _task(engine, "beta")
    for selected in (None, alpha.id, beta.id):
        _packet(engine, selected)
    rows = {row["scope_key"]: row for row in _watermarks(engine)}
    with engine.store.transaction():
        engine.store._conn.execute(
            "UPDATE packet_watermark SET audit_entry_hash=? WHERE project_id=? AND scope_key=?",
            (rows["task:" + beta.id]["audit_entry_hash"], PROJECT, "task:" + alpha.id))
    assert engine.packet_is_stale(PROJECT, task_id=alpha.id)
    assert not engine.packet_is_stale(PROJECT, task_id=beta.id)
    assert not engine.packet_is_stale(PROJECT)


@pytest.mark.parametrize("mutation", ["sibling_authority_event", "policy"])
def test_project_safety_changes_conservatively_stale_every_scope(engine, mutation):
    alpha, beta = _task(engine, "alpha"), _task(engine, "beta")
    for selected in (None, alpha.id, beta.id):
        _packet(engine, selected)
    if mutation == "sibling_authority_event":
        _controls(engine, "newbeta", {"kind": "tasks", "task_ids": [beta.id]})
    else:
        engine.policy.set_project_config(PROJECT, {"max_autonomy_level": 1})
    for selected in (None, alpha.id, beta.id):
        assert engine.packet_is_stale(PROJECT, task_id=selected)


@pytest.mark.parametrize("invalid_target", ["unknown", "foreign", "runtime", "proposal", "revoked"])
def test_ineligible_target_refuses_before_signing_or_persistence(
        engine, signing_calls, invalid_target):
    if invalid_target == "unknown":
        task_id = "tsk_unknown"
    elif invalid_target == "foreign":
        engine.create_project("Foreign", project_id="prj_other", capture_mode="full")
        task_id = _task(engine, "foreign", project_id="prj_other").id
    elif invalid_target == "runtime":
        task_id = engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PROJECT,
            status="open", authority="human_decision",
            data={"statement": "Package the runtime archive"}).id
    elif invalid_target == "proposal":
        task_id = _proposal(engine, "task", "- [ ] Package the proposed archive", "proposal")[
            "proposal_id"]
    else:
        task_id = _task(engine, "revoked").id
        operands = engine.authority_confirmation(PROJECT, task_id)
        engine.record_authority_decision(PROJECT, {
            "operation": "revoke", "request_id": "revoke-target", "tenant_id": engine.tenant_id,
            "project_id": PROJECT,
            **{key: value for key, value in operands.items() if key != "authority_scope"},
        })
    signing_calls.clear()
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises((ValueError, PermissionError), match="task|scope|authority"):
        _packet(engine, task_id)
    assert signing_calls == []
    assert tuple(engine.store._conn.iterdump()) == before


def test_failed_composition_preserves_existing_watermark_and_audit(engine, signing_calls):
    engine.resume_packet(PROJECT)
    engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        status="active", authority="human_decision", data={"statement": 42})
    before_rows, before_audit = _watermarks(engine), _audit(engine)
    before = tuple(engine.store._conn.iterdump())
    signing_calls.clear()
    with pytest.raises(ValueError):
        engine.resume_packet(PROJECT)
    assert signing_calls == []
    assert _watermarks(engine) == before_rows
    assert _audit(engine) == before_audit
    assert tuple(engine.store._conn.iterdump()) == before


@pytest.mark.parametrize("corruption", ["missing_data_scope", "missing_node_scope", "disagreement"])
def test_damaged_confirmed_scope_refuses_complete_packet(engine, signing_calls, corruption):
    task = _task(engine, "scope")
    node = _controls(engine, "scope", {"kind": "global"})[0]
    data, scope = dict(node["data"]), node["scope"]
    if corruption == "missing_data_scope":
        data.pop("authority_scope")
    elif corruption == "missing_node_scope":
        scope = None
    else:
        data["authority_scope"] = {"kind": "tasks", "task_ids": [task.id]}
    with engine.store.transaction():
        engine.store._conn.execute(
            "UPDATE nodes SET data=?,scope=? WHERE node_id=? AND tx_to IS NULL",
            (canonical_json(data), None if scope is None else canonical_json(scope), node.id))
    before = tuple(engine.store._conn.iterdump())
    signing_calls.clear()
    with pytest.raises(ValueError, match="scope"):
        engine.resume_packet(PROJECT)
    assert signing_calls == []
    assert tuple(engine.store._conn.iterdump()) == before


def test_quarantine_collision_refuses_instead_of_claiming_partial_completeness(
        engine, signing_calls):
    node = _controls(engine, "collision", {"kind": "global"})[0]
    engine.resume_packet(PROJECT)
    engine.graph.put_node(
        entity_type="claim", tenant_id=engine.tenant_id, project_id=PROJECT,
        status="quarantined", authority="untrusted_content",
        data={"statement": node["data"]["statement"], "suspected_injection": True})
    before = tuple(engine.store._conn.iterdump())
    signing_calls.clear()
    with pytest.raises(ValueError, match="quarantin|mandatory"):
        engine.resume_packet(PROJECT)
    assert signing_calls == []
    assert tuple(engine.store._conn.iterdump()) == before


def test_pending_canonical_event_refuses_complete_packet_without_refresh(engine, signing_calls):
    engine.resume_packet(PROJECT)
    engine.store.append_event(
        tenant_id=engine.tenant_id, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="pending-source", payload={"message": "Pending observation"},
        authority="agent_observed")
    assert engine.packet_is_stale(PROJECT)
    before = tuple(engine.store._conn.iterdump())
    signing_calls.clear()
    with pytest.raises(ValueError, match="pending|unprocessed|process"):
        engine.resume_packet(PROJECT)
    assert engine.packet_is_stale(PROJECT)
    assert signing_calls == []
    assert tuple(engine.store._conn.iterdump()) == before
