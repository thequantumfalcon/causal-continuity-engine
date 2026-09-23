"""Project continuity evidence never borrows a task packet's freshness."""

import copy

import pytest

from causal_continuity_engine.core import digest_obj
from tests.test_task_packets import PROJECT, _packet, _task
from tests.test_task_packets import engine as engine


def _reseal(engine, receipt):
    receipt.pop("signature", None)
    receipt["receipt_digest"] = digest_obj({
        key: value for key, value in receipt.items() if key != "receipt_digest"})
    receipt["signature"] = engine.signer.sign(receipt)
    return receipt


def test_task_packet_does_not_satisfy_project_receipt(engine):
    task = _task(engine, "receipt")
    _packet(engine, task.id)
    receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
    assert receipt["schema_version"] == "cce.continuity-receipt.v2"
    assert receipt["scope"] == {"kind": "project"}
    assert receipt["decision_state"]["packet"]["packet_id"] is None
    assert receipt["decision_state"]["packet"]["current"] is False
    assert any(item["predicate"] == "resume_packet_current" for item in receipt["blockers"])
    assert engine.verify_continuity_receipt(PROJECT, receipt)["verdict"] == "CURRENT"
    # CURRENT means authentic current evidence, not a successful decision.
    assert receipt["decision"] != "success"


def test_task_watermark_does_not_stale_project_receipt(engine):
    task = _task(engine, "independent")
    project_packet = _packet(engine)
    receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
    _packet(engine, task.id)
    result = engine.verify_continuity_receipt(PROJECT, receipt)
    assert result["verdict"] == "CURRENT"
    assert receipt["decision_state"]["packet"]["packet_id"] == project_packet["packet_id"]


@pytest.mark.parametrize("expected", [
    {"kind": "task", "task_id": "tsk_other"}, {"kind": "global"},
    {"kind": "project", "task_id": "tsk_other"}, {}, [], "project",
])
def test_project_receipt_cannot_satisfy_another_expected_scope(engine, expected):
    _packet(engine)
    receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
    assert engine.verify_continuity_receipt(
        PROJECT, receipt, expected_scope=expected)["verdict"] == "INVALID"


def test_authentic_task_scope_relabel_is_not_a_project_receipt(engine):
    task = _task(engine, "forgery")
    _packet(engine)
    original = engine.continuity_check(PROJECT)["continuity_receipt"]
    forged = copy.deepcopy(original)
    forged["scope"] = {"kind": "task", "task_id": task.id}
    _reseal(engine, forged)
    assert engine.signer.verify(forged)
    result = engine.verify_continuity_receipt(PROJECT, forged)
    assert result["verdict"] == "INVALID"
    assert "scope" in result["reason"]
    assert engine.verify_continuity_receipt(PROJECT, original)["verdict"] == "CURRENT"


def test_historical_receipt_version_is_not_live_scope_evidence(engine):
    _packet(engine)
    receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
    receipt["schema_version"] = "cce.continuity-receipt.v1"
    receipt.pop("scope")
    _reseal(engine, receipt)
    assert engine.signer.verify(receipt)
    assert engine.verify_continuity_receipt(PROJECT, receipt)["verdict"] == "INVALID"


def test_watermark_writer_compares_expected_scope_not_packet_claim(engine):
    alpha, beta = _task(engine, "alpha"), _task(engine, "beta")
    packet = _packet(engine, alpha.id)
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises(ValueError, match="scope"):
        engine._record_watermark(
            PROJECT, packet, task_id=beta.id,
            last_event_seq=packet["project_state_basis"]["event_seq"],
            control_basis_digest=packet["project_state_basis"]["control_basis_digest"])
    assert tuple(engine.store._conn.iterdump()) == before
