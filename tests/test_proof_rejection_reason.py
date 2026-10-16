"""A rejected proof envelope names the check that failed (PA-002).

Before this, every digest, signature, authenticity and sufficiency failure in
``complete_task`` raised the same text. An envelope whose body had been edited
and one issued under a key the verifier does not hold were indistinguishable
to the operator, which made a stale-looking rejection read as tampering.

The gate phrase "invalid or tampered" is unchanged; these tests pin only the
added detail, driven through the engine's own completion path.
"""
from __future__ import annotations

import json

import pytest

from tests.test_instrument_validation import PRJ, _good, _reseal


def _rejection(engine, task_id, proof) -> str:
    with pytest.raises(PermissionError) as excinfo:
        engine.complete_task(PRJ, task_id, proof=proof)
    return str(excinfo.value)


def test_edited_body_is_reported_as_a_digest_failure(tmp_path):
    engine, task, proof, _ = _good(tmp_path)
    forged = json.loads(json.dumps(proof))
    forged["action_intent"]["statement"] = "something else entirely"
    message = _rejection(engine, task.id, forged)
    assert "invalid or tampered" in message
    assert "(failed: digest" in message
    engine.close()


def test_resealed_body_is_reported_as_a_signature_failure_only(tmp_path):
    engine, task, proof, _ = _good(tmp_path)
    forged = json.loads(json.dumps(proof))
    forged["action_intent"]["statement"] = "something else entirely"
    forged = _reseal(forged)
    message = _rejection(engine, task.id, forged)
    assert "invalid or tampered" in message
    assert "failed: signature" in message
    assert "digest" not in message.split("(failed:", 1)[1].split(")", 1)[0]
    engine.close()
