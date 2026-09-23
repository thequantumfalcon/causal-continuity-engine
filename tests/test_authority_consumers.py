"""Consumer wiring pins; synthetic callbacks do not establish confirmation validity."""

from types import SimpleNamespace

import pytest

from causal_continuity_engine.api import RequestValidationError, make_handler
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.graph import Graph
from causal_continuity_engine.invalidation import ResolutionInputError
from causal_continuity_engine.mcp import _Session
from causal_continuity_engine.store import Store

PROJECT = "prj_consumers"
PROPOSALS = [
    ("requirement", "The importer must validate schemas."),
    ("constraint", "The importer must not log credentials."),
    ("decision", "We decided to use SQLite for storage."),
    ("assumption", "We assume the database is reachable from CI."),
    ("task", "- [x] write the parser"),
]


@pytest.fixture
def consumer(tmp_path, monkeypatch):
    engine = Engine(tmp_path / "consumers.db", tenant_id="ten_consumers", workdir=tmp_path)
    engine.create_project("consumer boundary", project_id=PROJECT)
    denied = set()
    monkeypatch.setattr(engine.graph, "may_mandate",
                        lambda node: node["node_id"] not in denied, raising=False)
    try:
        yield engine, denied
    finally:
        engine.close()


@pytest.fixture
def authority_engine(tmp_path):
    engine = Engine(tmp_path / "authority.db", tenant_id="ten_consumers", workdir=tmp_path)
    engine.create_project("real authority boundary", project_id=PROJECT, capture_mode="full")
    try:
        yield engine
    finally:
        engine.close()


def confirm(engine, text):
    report = engine.ingest_human_decision(
        PROJECT, actor="owner", decision=text, request_id="source")
    proposal_id = next(item["node_id"] for item in report["created"] if item["kind"] == "claim")
    receipt = engine.record_authority_decision(PROJECT, {
        "operation": "confirm", "request_id": "confirm", "tenant_id": engine.tenant_id,
        "project_id": PROJECT, **engine.authority_proposal(PROJECT, proposal_id)})
    return engine.graph.get(receipt["confirmation_id"])


def revoke(engine, confirmation_id):
    operands = engine.authority_confirmation(PROJECT, confirmation_id)
    return engine.record_authority_decision(PROJECT, {
        "operation": "revoke", "request_id": "revoke", "tenant_id": engine.tenant_id,
        "project_id": PROJECT, **{k: v for k, v in operands.items() if k != "authority_scope"}})


def binding_items(packet, kind):
    return {
        "requirement": packet["authority"]["active_requirements"],
        "constraint": packet["authority"]["active_constraints"],
        "decision": packet["accepted_decisions"],
        "assumption": packet["assumptions"]["active"],
        "task": packet["open_work"]["tasks"],
    }[kind]


def node(engine, kind, *, status="active", **data):
    return engine.graph.put_node(
        entity_type=kind, tenant_id=engine.tenant_id, project_id=PROJECT,
        status=status, authority="human_decision", data={"statement": kind, **data})


def handler(engine):
    """Exercise the real handlers without claiming transport/authentication coverage."""
    cls = make_handler(engine, PROJECT, api_token="consumer-test-token-not-a-secret-0000")
    instance = cls.__new__(cls)
    instance._parsed_request_target = SimpleNamespace(query="")
    instance.responses = []
    instance._send = lambda code, body: instance.responses.append((code, body))
    return instance


def test_graph_callback_is_optional_only_for_privileged_standalone_graph():
    store = Store(":memory:")
    try:
        direct = Graph(store)
        candidate = {"node_id": "candidate"}
        assert direct.may_mandate(candidate)
        seen = []

        def check(value):
            seen.append(value)
            return False

        guarded = Graph(store, authority_check=check)
        assert not guarded.may_mandate(candidate)
        assert seen == [candidate]
    finally:
        store.close()


def test_l0_promotion_requires_current_authority(consumer):
    engine, denied = consumer
    candidate = node(engine, "claim")
    denied.add(candidate.id)
    with pytest.raises(ValueError, match="authority"):
        engine.memory.promote(PROJECT, candidate.id, "L0", actor="owner")


@pytest.mark.parametrize("exit_name", ["tier_members", "l0", "packet"])
def test_existing_l0_assignment_is_not_current_authority(consumer, exit_name):
    engine, denied = consumer
    candidate = node(engine, "claim")
    denied.clear()
    engine.memory.promote(PROJECT, candidate.id, "L0", actor="owner")
    denied.add(candidate.id)
    assert engine.memory.tier_of(PROJECT, candidate.id) == "L0"
    if exit_name == "tier_members":
        assert engine.memory.tier_members(PROJECT, "L0") == []
    elif exit_name == "l0":
        assert engine.memory.l0(PROJECT) == []
    else:
        packet = engine.resume_packet(PROJECT)
        assert packet["mission"]["pinned_control_state"] == []
        assert any(item["section"] == "mission control state" and item["count"] == 1
                   for item in packet["omissions"])
        assert candidate.id in {item["node_id"] for item in packet["recent_context"]}


@pytest.mark.parametrize("kind,status,section", [
    ("requirement", "active", "requirements"),
    ("constraint", "active", "constraints"),
    ("decision", "accepted", "decisions"),
    ("assumption", "active", "active_assumptions"),
    ("assumption", "uncertain", "uncertain_assumptions"),
    ("task", "open", "tasks"),
])
def test_packet_binding_sections_share_the_authority_predicate(consumer, kind, status, section):
    engine, denied = consumer
    blocked = node(engine, kind, status=status)
    allowed = node(engine, kind, status=status, statement="explicit allowed control")
    denied.add(blocked.id)
    packet = engine.resume_packet(PROJECT)
    sections = {
        "requirements": packet["authority"]["active_requirements"],
        "constraints": packet["authority"]["active_constraints"],
        "decisions": packet["accepted_decisions"],
        "active_assumptions": packet["assumptions"]["active"],
        "uncertain_assumptions": packet["assumptions"]["uncertain"],
        "tasks": packet["open_work"]["tasks"],
    }
    assert {item["node_id"] for item in sections[section]} == {allowed.id}
    assert any(item["count"] == 1 for item in packet["omissions"])


def test_human_decision_label_is_not_a_memory_provenance_root(consumer):
    engine, denied = consumer
    candidate = node(engine, "claim")
    denied.add(candidate.id)
    with pytest.raises(ValueError, match="provenance"):
        engine.memory.promote(PROJECT, candidate.id, "L3", actor="owner")
    denied.clear()
    engine.memory.promote(PROJECT, candidate.id, "L3", actor="owner")


@pytest.mark.parametrize("exit_name", ["recovery", "capsule"])
def test_recovery_tasks_and_capsule_assumptions_require_current_authority(consumer, exit_name):
    engine, denied = consumer
    task = node(engine, "task", status="open")
    assumption = node(engine, "assumption")
    denied.update((task.id, assumption.id))
    if exit_name == "recovery":
        assert engine.partial.recovery_packet(PROJECT)["remaining_tasks"] == []
    else:
        state = engine.capsules._observable_state(engine.tenant_id, PROJECT)
        assert state["active_assumptions"] == []


def test_superseding_decision_requires_the_shared_authority_predicate(consumer):
    engine, denied = consumer
    target = node(engine, "assumption")
    replacement = node(engine, "decision", status="accepted", supersedes_node_id=target.id)
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=target.id,
        reason="fixture")
    denied.add(replacement.id)
    with pytest.raises(ResolutionInputError, match="authority"):
        engine.invalidation.resolve(
            invalidation.id, mode="superseding_decision", actor="owner",
            replacement_node_id=replacement.id)
    assert engine.graph.get(invalidation.id)["status"] == "open"


def test_resolution_keeps_unavailable_target_held_without_hiding_invalidation(consumer):
    engine, denied = consumer
    target = node(engine, "assumption")
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=target.id,
        reason="fixture")
    denied.add(target.id)
    before = engine.graph.get(target.id)
    packet = engine.resume_packet(PROJECT)
    assert invalidation.id in {item["invalidation_id"] for item in packet["invalidations"]}
    result = engine.invalidation.resolve(
        invalidation.id, mode="narrowed_scope", actor="owner", narrowed_scope={"part": "one"})
    assert engine.graph.get(target.id) == before
    assert target.id not in result["data"]["released_nodes"]
    assert target.id in result["data"]["still_held_nodes"]


@pytest.mark.parametrize("exit_name", ["http", "mcp"])
def test_http_and_mcp_assumptions_filter_authority_but_keep_invalidations(consumer, exit_name):
    engine, denied = consumer
    unavailable = node(engine, "assumption", statement="unavailable belief")
    allowed = node(engine, "assumption", statement="allowed belief")
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=unavailable.id,
        reason="unavailable belief still has a real invalidation")
    # An ordinary status restamp must not substitute for authority at either exit.
    engine.graph.put_node(entity_type="assumption", tenant_id=engine.tenant_id,
                          project_id=PROJECT, node_id=unavailable.id, data={}, status="active")
    denied.add(unavailable.id)
    if exit_name == "http":
        http = handler(engine)
        http.assumptions(PROJECT)
        assert {item["node_id"] for item in http.responses[-1][1]} == {allowed.id}
        http.invalidations(PROJECT)
        assert {item["node_id"] for item in http.responses[-1][1]} == {invalidation.id}
    else:
        session = _Session("unused-test-directory")
        session._engine, session._meta = engine, {"project_id": PROJECT}
        assert session.call("list_assumptions", {}) == "- [active] allowed belief"
        assert "real invalidation" in session.call("list_invalidations", {})


@pytest.mark.parametrize("kind", ["assumption", "claim", "requirement", "constraint", "decision"])
def test_http_resolve_rejects_semantic_patch_even_for_direct_graph_authority(consumer, kind):
    engine, _ = consumer
    candidate = node(engine, kind)
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises(RequestValidationError, match="content"):
        handler(engine).resolve({"action": "narrow", "data": {"statement": "edited"}},
                                candidate.id)
    assert tuple(engine.store._conn.iterdump()) == before


def test_http_status_resolution_preserves_origin_and_withdrawal(consumer):
    engine, denied = consumer
    candidate = engine.graph.put_node(
        entity_type="claim", tenant_id=engine.tenant_id, project_id=PROJECT,
        status="invalidated", authority="untrusted_content",
        data={"statement": "withdrawn proposal", "source_withdrawn": True,
              "revoked": True, "needs_confirmation": True})
    denied.add(candidate.id)
    http = handler(engine)
    http.resolve({"action": "narrow"}, candidate.id)
    current = engine.graph.get(candidate.id)
    assert http.responses[-1][0] == 200
    assert current["status"] == "active"
    assert current["authority"] == "untrusted_content"
    assert current["data"] == candidate["data"]
    assert not engine.graph.may_mandate(current)


def test_http_invalidation_resolution_cannot_rewrite_authority_scope(consumer):
    engine, _ = consumer
    candidate = node(engine, "assumption")
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=candidate.id, reason="fixture")
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises(RequestValidationError, match="scope"):
        handler(engine).resolve({"invalidation_id": invalidation.id, "mode": "narrowed_scope",
                                 "narrowed_scope": {"component": "new"}}, candidate.id)
    assert tuple(engine.store._conn.iterdump()) == before


def test_resolution_restores_eligible_dependents_but_not_unavailable_ones(consumer):
    engine, denied = consumer
    target = node(engine, "assumption")
    blocked = node(engine, "task", status="open")
    allowed = node(engine, "task", status="open")
    for dependent in (blocked, allowed):
        engine.graph.put_edge(
            edge_type="assumes", src_id=dependent.id, dst_id=target.id,
            tenant_id=engine.tenant_id, project_id=PROJECT)
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=target.id, reason="fixture")
    assert engine.graph.get(blocked.id)["status"] == "uncertain"
    assert engine.graph.get(allowed.id)["status"] == "uncertain"
    denied.add(blocked.id)
    before = engine.graph.get(blocked.id)
    result = engine.invalidation.resolve(
        invalidation.id, mode="narrowed_scope", actor="owner", narrowed_scope={"part": "one"})
    assert engine.graph.get(blocked.id) == before
    assert engine.graph.get(allowed.id)["status"] == "open"
    assert engine.graph.get(target.id)["status"] == "active"
    assert blocked.id in result["data"]["still_held_nodes"]
    assert {target.id, allowed.id} == set(result["data"]["released_nodes"])


@pytest.mark.parametrize("status", [
    "invalidated", "superseded", "revoked", "withdrawn", "uncertain", "blocked",
])
@pytest.mark.parametrize("exit_name", ["promotion", "read", "packet"])
def test_l0_current_witness_does_not_override_inactive_control_status(consumer, status, exit_name):
    engine, _ = consumer
    candidate = node(engine, "requirement")
    engine.memory.promote(PROJECT, candidate.id, "L0", actor="owner")
    engine.graph.put_node(entity_type="requirement", tenant_id=engine.tenant_id,
                          project_id=PROJECT, node_id=candidate.id, data={}, status=status)
    assert engine.graph.may_mandate(engine.graph.get(candidate.id))
    if exit_name == "promotion":
        with pytest.raises(ValueError, match="L0"):
            engine.memory.promote(PROJECT, candidate.id, "L0", actor="owner")
    elif exit_name == "read":
        assert engine.memory.l0(PROJECT) == []
    else:
        packet = engine.resume_packet(PROJECT)
        assert packet["mission"]["pinned_control_state"] == []
        assert any(item["section"] == "mission control state" for item in packet["omissions"])


@pytest.mark.parametrize("kind", ["requirement", "constraint"])
def test_uncertain_control_is_not_presented_as_active_authority(consumer, kind):
    engine, _ = consumer
    node(engine, kind, status="uncertain")
    assert binding_items(engine.resume_packet(PROJECT), kind) == []


def test_real_confirmation_restores_without_conflating_witness_and_liveness(authority_engine):
    engine = authority_engine
    candidate = confirm(engine, "We assume the database is reachable from CI.")
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=candidate.id, reason="fixture")
    current = engine.graph.get(candidate.id)
    assert current["status"] == "invalidated" and engine.graph.may_mandate(current)
    result = engine.invalidation.resolve(
        invalidation.id, mode="narrowed_scope", actor="owner", narrowed_scope={"kind": "global"})
    current = engine.graph.get(candidate.id)
    assert current["status"] == "active" and engine.graph.may_mandate(current)
    assert candidate.id in result["data"]["released_nodes"]


@pytest.mark.parametrize("kind,text", PROPOSALS)
@pytest.mark.parametrize("change", ["revoke", "semantic_patch"])
def test_real_confirmation_is_required_at_packet_and_memory_exits(authority_engine, kind, text,
                                                                  change):
    engine = authority_engine
    candidate = confirm(engine, text)
    assert candidate["entity_type"] == kind
    assert engine.graph.may_mandate(candidate)
    engine.memory.promote(PROJECT, candidate.id, "L0", actor="owner")
    packet = engine.resume_packet(PROJECT)
    assert {item["node_id"] for item in binding_items(packet, kind)} == {candidate.id}
    assert {item["node_id"] for item in packet["mission"]["pinned_control_state"]} == {candidate.id}
    if change == "revoke":
        revoke(engine, candidate.id)
        patch = {}
    else:
        patch = {"statement": "Unconfirmed semantic edit"}
    engine.graph.put_node(entity_type=kind, tenant_id=engine.tenant_id, project_id=PROJECT,
                          node_id=candidate.id, data=patch, status=candidate["status"])
    assert not engine.graph.may_mandate(engine.graph.get(candidate.id))
    packet = engine.resume_packet(PROJECT)
    assert binding_items(packet, kind) == []
    assert packet["mission"]["pinned_control_state"] == []
    assert engine.memory.l0(PROJECT) == []
    with pytest.raises(ValueError, match="authority"):
        engine.memory.promote(PROJECT, candidate.id, "L0", actor="owner")


@pytest.mark.parametrize("exit_name", ["http", "mcp", "capsule", "recovery"])
def test_real_revocation_reaches_transport_and_recovery_views(authority_engine, exit_name):
    engine = authority_engine
    text = ("- [x] write the parser" if exit_name == "recovery"
            else "We assume the database is reachable from CI.")
    candidate = confirm(engine, text)

    def current_items():
        if exit_name == "http":
            http = handler(engine)
            http.assumptions(PROJECT)
            return http.responses[-1][1]
        if exit_name == "mcp":
            session = _Session("unused-test-directory")
            session._engine, session._meta = engine, {"project_id": PROJECT}
            return session.call("list_assumptions", {})
        if exit_name == "capsule":
            state = engine.capsules._observable_state(engine.tenant_id, PROJECT)
            return state["active_assumptions"]
        return engine.partial.recovery_packet(PROJECT)["remaining_tasks"]

    before = current_items()
    if exit_name == "mcp":
        assert candidate["data"]["statement"] in before
    else:
        assert {item["node_id"] for item in before} == {candidate.id}
    revoke(engine, candidate.id)
    if exit_name == "recovery":
        engine.graph.put_node(entity_type="task", tenant_id=engine.tenant_id, project_id=PROJECT,
                              node_id=candidate.id, data={}, status="open")
    else:
        handler(engine).resolve({"action": "narrow"}, candidate.id)
    assert not engine.graph.may_mandate(engine.graph.get(candidate.id))
    assert current_items() == ("No active assumptions." if exit_name == "mcp" else [])


def test_real_uncertain_assumption_is_contextual_until_revoked(authority_engine):
    engine = authority_engine
    candidate = confirm(engine, "We assume the database is reachable from CI.")
    engine.graph.put_node(entity_type="assumption", tenant_id=engine.tenant_id,
                          project_id=PROJECT, node_id=candidate.id, data={}, status="uncertain")
    packet = engine.resume_packet(PROJECT)
    assert packet["assumptions"]["active"] == []
    assert {item["node_id"] for item in packet["assumptions"]["uncertain"]} == {candidate.id}
    revoke(engine, candidate.id)
    engine.graph.put_node(entity_type="assumption", tenant_id=engine.tenant_id,
                          project_id=PROJECT, node_id=candidate.id, data={}, status="uncertain")
    assert engine.resume_packet(PROJECT)["assumptions"]["uncertain"] == []


def test_real_revocation_cannot_be_cleared_by_invalidation_restoration(authority_engine):
    engine = authority_engine
    candidate = confirm(engine, "We assume the database is reachable from CI.")
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=candidate.id, reason="fixture")
    revoke(engine, candidate.id)
    before = engine.graph.get(candidate.id)
    result = engine.invalidation.resolve(
        invalidation.id, mode="narrowed_scope", actor="owner", narrowed_scope={"kind": "global"})
    assert engine.graph.get(candidate.id) == before
    assert candidate.id in result["data"]["still_held_nodes"]
    assert candidate.id not in result["data"]["released_nodes"]


def test_critical_invalidation_can_still_be_pinned_when_its_subject_cannot(consumer):
    engine, denied = consumer
    candidate = node(engine, "assumption")
    invalidation = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT,
        trigger_type="dependency_drift", target_node_id=candidate.id, reason="fixture")
    denied.add(candidate.id)
    engine.memory.promote(PROJECT, invalidation.id, "L0", actor="owner")
    packet = engine.resume_packet(PROJECT)
    pinned_ids = {item["node_id"] for item in packet["mission"]["pinned_control_state"]}
    assert pinned_ids == {invalidation.id}
    assert {item["invalidation_id"] for item in packet["invalidations"]} == {invalidation.id}
