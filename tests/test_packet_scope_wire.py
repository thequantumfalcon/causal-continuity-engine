"""Closed packet scope and project-only portable capsule boundaries.

Literal packets below test wire grammar, not live authority. Integration cases
use the real local proposal/confirmation producer; no human identity is claimed.
"""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from referencing import Registry, Resource

from causal_continuity_engine.capsule import CapsuleError, CapsuleManager
from causal_continuity_engine.core import digest_obj
from causal_continuity_engine.engine import Engine
from tests.authority_helpers import confirmed_task
from tests.schema_validation import draft202012_validator

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-22T00:00:00.000000Z"


def _seal_packet(packet):
    packet["authority_set_digest"] = digest_obj(packet["mandatory_control"])
    packet["packet_digest"] = digest_obj({
        key: value for key, value in packet.items()
        if key not in ("signature", "packet_digest")})
    return packet


def _packet(scope=None):
    return _seal_packet({
        "schema_version": "cce.resume.v2", "packet_id": "rsp_" + "a" * 24,
        "generated_at": NOW, "project_state_at": None, "project_state_basis": None,
        "tenant_id": "ten_wire", "project_id": "prj_wire",
        "max_response_bytes": 131_072, "response_format": "engine-json",
        "scope": {"kind": "project"} if scope is None else scope,
        "complete": True, "mandatory_control": [], "target": {},
        "mission": {"project": "Wire", "objective": "", "target": {},
                    "pinned_control_state": [], "retired_control_state": []},
        "authority": {"instruction_precedence": [], "active_requirements": [],
                      "active_constraints": []},
        "accepted_decisions": [], "verified_progress": [], "invalidations": [],
        "assumptions": {"active": [], "uncertain": []},
        "open_work": {"tasks": [], "blockers": [], "next_safe_action": {"summary": ""}},
        "environment": {}, "trust": {
            "policy": {},
            "autonomy_level": None, "required_verifiers": [], "completed_checks": [],
            "failed_or_stale_checks": [], "gaps": []},
        "continuity_lineage": {
            "source_session": None, "checkpoints": [], "packet_generation_time": NOW},
        "evidence_index": [], "evidence_coverage": 1.0, "omissions": [],
        "recent_context": [], "token_estimate": 0,
    })


def _member(node_id="req_wire", scope=None):
    return {
        "node_id": node_id, "entity_type": "requirement", "origin": "runtime",
        "status": "active", "criticality": None, "confidence": 0.75,
        "authority": "human_decision", "valid_from": None, "valid_to": None,
        "authority_scope": {"kind": "global"} if scope is None else scope,
        "content": {"statement": "Retain archive checksums."}, "confirmation": None,
    }


def _validator(name):
    schemas = [json.loads(path.read_text()) for path in (ROOT / "schemas").glob("*.json")]
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    schema = json.loads((ROOT / "schemas" / name).read_text())
    return draft202012_validator(schema, registry=registry)


@pytest.mark.parametrize("scope", [{"kind": "project"}, {"kind": "task", "task_id": "tsk_wire"}])
def test_shared_packet_validator_accepts_both_complete_scope_modes(scope):
    packet = _packet(scope)
    CapsuleManager._validate_resume_packet(packet)


@pytest.mark.parametrize("scope", [
    {}, {"kind": "global"}, {"kind": "project", "task_id": "tsk_wire"},
    {"kind": "task"}, {"kind": "task", "task_id": "tsk_wire", "extra": True},
    {"kind": "task", "task_id": "tsk_wire\n"},
])
def test_closed_packet_scope_refuses_authentically_digestible_aliases(scope):
    with pytest.raises(CapsuleError, match="scope"):
        CapsuleManager._validate_resume_packet(_packet(scope))


@pytest.mark.parametrize("complete", [False, None, 0, 1, "true"])
def test_packet_completeness_requires_literal_true(complete):
    packet = _packet()
    packet["complete"] = complete
    with pytest.raises(CapsuleError, match="complete"):
        CapsuleManager._validate_resume_packet(_seal_packet(packet))


@pytest.mark.parametrize("defect", ["missing", "not_object", "nonfinite"])
def test_complete_trust_requires_finite_policy_object(defect):
    packet = _packet()
    if defect == "missing":
        packet["trust"].pop("policy")
    elif defect == "not_object":
        packet["trust"]["policy"] = []
    else:
        packet["trust"]["policy"] = {"nested": {"limit": float("nan")}}
    if defect != "nonfinite":
        _seal_packet(packet)
    with pytest.raises(CapsuleError, match="trust|finite canonical JSON"):
        CapsuleManager._validate_resume_packet(packet)
    if defect != "nonfinite":
        assert not _validator("cce.resume.v2.json").is_valid(packet)


def test_complete_trust_keeps_opaque_finite_policy_data():
    packet = _packet()
    packet["trust"]["policy"] = {"unknown_future_setting": {"values": [1, True, None]}}
    _seal_packet(packet)
    CapsuleManager._validate_resume_packet(packet)
    assert _validator("cce.resume.v2.json").is_valid(packet)


@pytest.mark.parametrize("defect", [
    "unknown_member_field", "missing_member_field", "duplicate_id", "unsorted",
    "unknown_kind", "unknown_origin", "bad_scope", "duplicate_scope_task",
    "unsorted_scope_tasks", "runtime_confirmation", "confirmed_without_confirmation",
    "float_authority_version", "boolean_authority_version", "bad_validity", "nonfinite",
    "foreign_task", "wrong_digest",
])
def test_mandatory_control_is_closed_canonical_and_task_applicable(defect):
    packet = _packet({"kind": "task", "task_id": "tsk_wire"})
    member = _member()
    packet["mandatory_control"] = [member]
    if defect == "unknown_member_field":
        member["extra"] = True
    elif defect == "missing_member_field":
        member.pop("status")
    elif defect == "duplicate_id":
        packet["mandatory_control"].append(copy.deepcopy(member))
    elif defect == "unsorted":
        packet["mandatory_control"] = [_member("req_z"), member]
    elif defect == "unknown_kind":
        member["entity_type"] = "task"
    elif defect == "unknown_origin":
        member["origin"] = "prose"
    elif defect == "bad_scope":
        member["authority_scope"] = {"kind": "global", "extra": True}
    elif defect in ("duplicate_scope_task", "unsorted_scope_tasks"):
        member["authority_scope"] = {
            "kind": "tasks", "task_ids": (
                ["tsk_wire", "tsk_wire"] if defect == "duplicate_scope_task"
                else ["tsk_z", "tsk_wire"])}
    elif defect == "runtime_confirmation":
        member["confirmation"] = {}
    elif defect == "confirmed_without_confirmation":
        member["origin"] = "confirmed"
    elif defect in ("float_authority_version", "boolean_authority_version"):
        member["origin"] = "confirmed"
        member["confirmation"] = {
            "proposal_id": "clm_wire", "confirmation_event_id": "evt_wire",
            "decision_event_id": "evt_wire", "authority_version": (
                1.0 if defect == "float_authority_version" else True)}
    elif defect == "bad_validity":
        member["valid_from"] = "2026-02-30T00:00:00Z"
    elif defect == "nonfinite":
        member["content"]["value"] = float("nan")
    elif defect == "foreign_task":
        member["authority_scope"] = {"kind": "tasks", "task_ids": ["tsk_other"]}
    if defect != "nonfinite":
        _seal_packet(packet)
    if defect == "wrong_digest":
        packet["authority_set_digest"] = digest_obj([])
        packet["packet_digest"] = digest_obj({
            key: value for key, value in packet.items() if key != "packet_digest"})
    with pytest.raises(CapsuleError, match="mandatory|authority_set"):
        CapsuleManager._validate_resume_packet(packet)


def test_v2_schema_and_runtime_accept_complete_control_data():
    packet = _packet({"kind": "task", "task_id": "tsk_wire"})
    member = _member(scope={"kind": "tasks", "task_ids": ["tsk_wire"]})
    member["content"].update(proof_id="semantic data", nested={"values": [1, None, True]})
    member["valid_from"] = "2026-01-01T01:00:00+01:00"
    packet["mandatory_control"] = [member]
    _seal_packet(packet)
    CapsuleManager._validate_resume_packet(packet)
    _validator("cce.resume.v2.json").validate(packet)
    assert list(_validator("cce.resume.v1.json").iter_errors(packet))


def test_historical_schema_bytes_are_unchanged():
    expected = {
        "cce.resume.v1.json": "d7db2c95fd6913d830497e8890b1f22344d8ddd467c894e76b6d35900e1ea33b",
        "cce.capsule.v1.json": "23d40e9458c2851776ebc58703c0298ae98d074ba8e547bbd1b5e724c75fac26",
        "cce.continuity-receipt.v1.json":
            "cab6719924b223d6ce4506667ca7f5ecc4821e711d794b25cb6ad21ae76abd01",
    }
    for name, wanted in expected.items():
        assert hashlib.sha256((ROOT / "schemas" / name).read_bytes()).hexdigest() == wanted


def test_member_order_is_kind_then_id_and_identity_is_unique_across_kinds():
    packet = _packet()
    first, second = _member("zzz_assumption"), _member("aaa_requirement")
    first["entity_type"] = "assumption"
    packet["mandatory_control"] = [first, second]
    CapsuleManager._validate_resume_packet(_seal_packet(packet))
    second["node_id"] = first["node_id"]
    with pytest.raises(CapsuleError, match="unique"):
        CapsuleManager._validate_resume_packet(_seal_packet(packet))


def test_confirmed_member_and_nullable_runtime_scalars_remain_valid():
    packet = _packet()
    member = _member()
    member.update(status=None, criticality=None, confidence=None, authority=None)
    member["origin"] = "confirmed"
    member["confirmation"] = {
        "proposal_id": "clm_wire", "confirmation_event_id": "evt_original",
        "decision_event_id": "evt_rescope", "authority_version": 2}
    packet["mandatory_control"] = [member]
    CapsuleManager._validate_resume_packet(_seal_packet(packet))
    _validator("cce.resume.v2.json").validate(packet)


@pytest.fixture
def engine(tmp_path):
    import causal_continuity_engine.engine as module

    assert Path(module.__file__).resolve() == ROOT / "causal_continuity_engine" / "engine.py"
    instance = Engine(tenant_id="ten_wire", workdir=tmp_path)
    instance.create_project(
        "Wire", project_id="prj_wire", capture_mode="full",
        config={"require_proof_for": []})
    instance.graph.put_node(
        entity_type="artifact", tenant_id=instance.tenant_id, project_id="prj_wire",
        status="recorded", data={"kind": "environment", "python": "3.11", "os": "test"})
    try:
        yield instance
    finally:
        instance.close()


def _export(engine, signer=None):
    return engine.capsules.export(
        tenant_id=engine.tenant_id, project_id="prj_wire", session_id=None,
        source_model="source", source_runtime="runtime", target_adapter="target",
        signer=engine.signer if signer is None else signer)


def _seal_capsule(engine, capsule):
    capsule["content_digest"] = digest_obj({
        key: value for key, value in capsule.items()
        if key not in ("signature", "content_digest")})
    capsule["signature"] = engine.signer.sign(capsule)
    return capsule


def _database(engine):
    return tuple(engine.store._conn.iterdump())


def test_project_capsule_round_trip_retains_full_control_and_expected_identity(engine):
    confirmed_task(engine, "prj_wire")
    control = engine.graph.put_node(
        entity_type="requirement", tenant_id=engine.tenant_id, project_id="prj_wire",
        status="active", data={"statement": "Preserve all checksums.", "proof_id": "semantic"})
    capsule = _export(engine)
    packet = capsule["resume_packet"]
    assert capsule["schema_version"] == "cce.capsule.v2"
    assert packet["scope"] == {"kind": "project"}
    assert packet["tenant_id"] == capsule["tenant_id"] == engine.tenant_id
    assert packet["project_id"] == capsule["project_id"] == "prj_wire"
    member, = packet["mandatory_control"]
    assert member["node_id"] == control.id
    assert member["content"]["proof_id"] == "semantic"
    _validator("cce.capsule.v2.json").validate(capsule)
    assert list(_validator("cce.capsule.v1.json").iter_errors(capsule))
    assert engine.capsules.validate(
        capsule, engine.signer, expected_tenant_id=engine.tenant_id,
        expected_project_id="prj_wire")["valid"] is True
    result = engine.capsules.import_capsule(
        capsule, signer=engine.signer, target_model="target", target_runtime="runtime",
        expected_tenant_id=engine.tenant_id, expected_project_id="prj_wire")
    assert result["challenge"]["passed"] is True
    assert result["session"]["data"]["migrated_from_capsule"] == capsule["capsule_id"]


@pytest.mark.parametrize("defect", ["task", "tenant_id", "project_id"])
def test_authentic_capsule_scope_substitution_refuses_at_every_consumer(engine, defect):
    task = confirmed_task(engine, "prj_wire")
    capsule = _export(engine)
    if defect == "task":
        capsule["resume_packet"] = engine.resume_packet("prj_wire", task_id=task["node_id"])
        reason = "project-only"
    else:
        capsule["resume_packet"][defect] = "foreign_identity"
        _seal_packet(capsule["resume_packet"])
        reason = "identity differs"
    _seal_capsule(engine, capsule)
    assert engine.signer.verify(capsule)
    before = _database(engine)
    with pytest.raises(CapsuleError, match=reason):
        engine.capsules.validate(capsule, engine.signer)
    with pytest.raises(CapsuleError, match=reason):
        engine.capsules.challenge(capsule)
    with pytest.raises(CapsuleError, match=reason):
        engine.capsules.import_capsule(
            capsule, signer=engine.signer, target_model="target", target_runtime="runtime")
    assert _database(engine) == before
    if defect == "task":
        assert list(_validator("cce.capsule.v2.json").iter_errors(capsule))


@pytest.mark.parametrize("defect", ["task", "tenant_id", "project_id"])
def test_capsule_export_scope_guard_precedes_outer_signing_and_audit(engine, monkeypatch, defect):
    task = confirmed_task(engine, "prj_wire")
    packet = engine.resume_packet("prj_wire", task_id=task["node_id"] if defect == "task" else None)
    if defect != "task":
        packet[defect] = "foreign_identity"
        _seal_packet(packet)
    monkeypatch.setattr(engine.composer, "compose", lambda **kwargs: copy.deepcopy(packet))

    class NeverSign:
        def sign(self, body):
            pytest.fail("scope refusal consumed an outer signature")

    before = _database(engine)
    with pytest.raises(CapsuleError, match="project-only|identity differs"):
        _export(engine, NeverSign())
    assert _database(engine) == before


def test_hidden_looking_mandatory_content_cannot_be_trimmed_during_export(engine):
    engine.graph.put_node(
        entity_type="requirement", tenant_id=engine.tenant_id, project_id="prj_wire",
        status="active", data={"statement": "Retain checksums.",
                               "nested": {"thinking": "a privileged semantic operand"}})

    class NeverSign:
        def sign(self, body):
            pytest.fail("mandatory-content refusal consumed an outer signature")

    before = _database(engine)
    with pytest.raises(CapsuleError, match="mandatory control.*hidden"):
        _export(engine, NeverSign())
    assert _database(engine) == before


def test_mandatory_probability_overflow_is_a_shape_refusal():
    packet = _packet()
    member = _member()
    member["confidence"] = 10 ** 400
    packet["mandatory_control"] = [member]
    with pytest.raises(CapsuleError, match="mandatory_control"):
        CapsuleManager._validate_resume_packet(packet)


def test_new_schema_calendar_assertion_is_active():
    packet = _packet()
    member = _member()
    member["valid_from"] = "2026-02-30T00:00:00Z"
    packet["mandatory_control"] = [member]
    _seal_packet(packet)
    assert list(_validator("cce.resume.v2.json").iter_errors(packet))
