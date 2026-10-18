"""Completion refuses explicitly uncertain revisions, not an unstarted frontier."""

import pytest

from tests.test_dependency_drift_precision import PROJECT, _attest, _push
from tests.test_instrument_validation import _good


def _uncertain_push(engine):
    assert _push(engine, "Update readme", paths=("README.md",))["invalidations"] == []
    rejected = _push(engine, "Bump requests from 2.32.0 to 3.0.0", "fork-push",
                     before="9" * 40, after="c" * 40)
    assert rejected["invalidations"] == []
    assert engine.graph.get(PROJECT)["data"]["revision_frontier_uncertain"] is True
    assert engine.continuity_check(PROJECT)["trust_unavailable"] is True


@pytest.mark.parametrize("proof_required", [True, False])
def test_uncertain_revision_blocks_even_a_fresh_proof(tmp_path, proof_required):
    engine, task, _, _ = _good(
        tmp_path, require_proof_for=["task_complete"] if proof_required else [])
    try:
        _uncertain_push(engine)
        proof = _attest(engine, task.id)
        assert proof["status"] == "verified"
        assert engine.proof_currency(PROJECT, task.id, proof)["current"] is True
        version = engine.graph.get(task.id)["version"]
        with pytest.raises(PermissionError, match="revision trust unavailable"):
            engine.complete_task(PROJECT, task.id, proof=proof if proof_required else None)
        assert engine.graph.get(task.id)["version"] == version
        assert engine.graph.get(task.id)["status"] == "open"
        assert engine.store._conn.execute("SELECT COUNT(*) FROM spent_proofs").fetchone()[0] == 0
    finally:
        engine.close()


def test_uncertain_revision_blocks_an_exact_completion_retry(tmp_path):
    engine, task, proof, _ = _good(tmp_path)
    try:
        completed = engine.complete_task(PROJECT, task.id, proof=proof)
        _uncertain_push(engine)
        with pytest.raises(PermissionError, match="revision trust unavailable"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        assert engine.graph.get(task.id)["version"] == completed["version"]
    finally:
        engine.close()


def test_admitted_push_clears_the_uncertain_revision_completion_gate(tmp_path):
    engine, task, _, _ = _good(tmp_path)
    try:
        _uncertain_push(engine)
        proof = _attest(engine, task.id)
        with pytest.raises(PermissionError, match="revision trust unavailable"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        _push(engine, "Update readme", "reconciled-push", before="b" * 40,
              after="d" * 40, paths=("README.md",))
        assert engine.graph.get(PROJECT)["data"]["revision_frontier_uncertain"] is False
        assert engine.continuity_check(PROJECT)["trust_unavailable"] is False
        proof = _attest(engine, task.id)
        assert engine.complete_task(PROJECT, task.id, proof=proof)["status"] == "verified"
    finally:
        engine.close()


def test_project_without_a_tracked_revision_can_still_complete(tmp_path):
    engine, task, proof, _ = _good(tmp_path)
    try:
        project = engine.graph.get(PROJECT)["data"]
        assert not project.get("current_head_sha")
        assert not project.get("revision_frontier_uncertain")
        assert engine.continuity_check(PROJECT)["trust_unavailable"] is True
        assert engine.complete_task(PROJECT, task.id, proof=proof)["status"] == "verified"
    finally:
        engine.close()
