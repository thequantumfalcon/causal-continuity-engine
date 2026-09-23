"""Capsule contents and drift decisions use one control-validity frontier."""

from pathlib import Path

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.engine import Engine
from tests.test_task_packets import _confirm

PROJECT = "prj_capsule_clock"
BEFORE = "2099-01-01T00:00:00Z"
AFTER = "2099-01-01T00:00:02Z"


@pytest.fixture
def engine():
    assert Path(engine_module.__file__).resolve() == (
        Path(__file__).resolve().parents[1] / "causal_continuity_engine" / "engine.py")
    instance = Engine()
    instance.create_project(
        "Capsule clock", project_id=PROJECT, capture_mode="full",
        config={"require_proof_for": []})
    instance.graph.put_node(
        entity_type="artifact", tenant_id=instance.tenant_id, project_id=PROJECT,
        status="recorded", data={"kind": "environment", "python": "3.11", "os": "test"})
    try:
        yield instance
    finally:
        instance.close()


def _frontiers(engine, monkeypatch):
    requirement = _confirm(
        engine, "requirement", "The temporal exporter must preserve archive checksums.",
        "clock", project_id=PROJECT)
    engine.graph.put_node(
        entity_type="requirement", tenant_id=engine.tenant_id, project_id=PROJECT,
        node_id=requirement.id, data={}, valid_from="2099-01-01T00:00:01Z")
    bases = {}
    for instant in (BEFORE, AFTER):
        monkeypatch.setattr(engine_module, "utcnow", lambda instant=instant: instant)
        bases[instant] = engine._packet_state_basis(PROJECT)
    assert bases[BEFORE] != bases[AFTER]
    return requirement.id, bases


def _clock(monkeypatch, mode):
    samples = []

    def advance():
        samples.append(None)
        before = mode == "before" or mode == "crossing" and len(samples) == 1
        return BEFORE if before else AFTER

    monkeypatch.setattr(engine_module, "utcnow", advance)


def _export(engine):
    capsule = engine.capsules.export(
        tenant_id=engine.tenant_id, project_id=PROJECT, session_id=None,
        source_model="source", source_runtime="runtime", target_adapter="target",
        signer=engine.signer)
    assert engine.signer.verify(capsule)
    engine.capsules.validate(
        capsule, engine.signer, expected_tenant_id=engine.tenant_id,
        expected_project_id=PROJECT)
    return capsule


def _assert_frontier(packet, requirement_id, bases, mode):
    included = requirement_id in {member["node_id"] for member in packet["mandatory_control"]}
    if mode != "crossing":
        assert included == (mode == "after")
    assert packet["complete"] is True
    assert packet["project_state_basis"] == bases[AFTER if included else BEFORE], (
        "mandatory authority and its control commitment describe different validity instants")
    return included


@pytest.mark.parametrize("mode", ["before", "after", "crossing"])
def test_capsule_export_commits_the_same_validity_frontier_it_contains(engine, monkeypatch, mode):
    requirement_id, bases = _frontiers(engine, monkeypatch)
    _clock(monkeypatch, mode)
    capsule = _export(engine)
    _assert_frontier(capsule["resume_packet"], requirement_id, bases, mode)


@pytest.mark.parametrize("mode", ["before", "after", "crossing"])
def test_capsule_import_drift_matches_its_actual_live_control_frontier(engine, monkeypatch, mode):
    requirement_id, bases = _frontiers(engine, monkeypatch)
    monkeypatch.setattr(engine_module, "utcnow", lambda: BEFORE)
    capsule = _export(engine)
    assert not _assert_frontier(capsule["resume_packet"], requirement_id, bases, "before")
    original_compose = engine.composer.compose
    live_packets = []

    def observe(**kwargs):
        packet = original_compose(**kwargs)
        live_packets.append(packet)
        return packet

    monkeypatch.setattr(engine.composer, "compose", observe)
    _clock(monkeypatch, mode)
    result = engine.capsules.import_capsule(
        capsule, signer=engine.signer, target_model="target", target_runtime="runtime",
        expected_tenant_id=engine.tenant_id, expected_project_id=PROJECT)
    assert len(live_packets) == 1
    live = live_packets[0]
    included = requirement_id in {member["node_id"] for member in live["mandatory_control"]}
    challenge = result["challenge"]
    # Let the real import gate decide before inspecting the commitment. A mixed
    # frontier must not silently restore autonomy for newly active authority.
    assert challenge["passed"] is (not included), (
        "live mandatory authority changed while the capsule drift gate reported unchanged")
    _assert_frontier(live, requirement_id, bases, mode)
    if included:
        assert [item["kind"] for item in challenge["control_drift"]] == [
            "target_control_state_changed"]
        assert challenge["enforced_ceiling"] == 1
        assert engine.policy.active_downgrade_ceiling(PROJECT) == 1
    else:
        assert challenge["control_drift"] == []
        assert engine.policy.active_downgrade_ceiling(PROJECT) is None
