from __future__ import annotations

import copy
import itertools

import pytest

from causal_continuity_engine.capsule import CapsuleError
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.github import continuity_conclusion

TENANT = "ten_round15_trust"
PROJECT = "prj_round15_trust"


@pytest.fixture
def engine():
    instance = Engine(tenant_id=TENANT)
    instance.create_project(
        "round15 trust", project_id=PROJECT,
        config={"require_proof_for": []})
    yield instance
    instance.close()


@pytest.fixture
def capsule(engine):
    engine.graph.put_node(
        entity_type="artifact", tenant_id=TENANT, project_id=PROJECT,
        status="recorded",
        data={"kind": "environment", "python": "3.13", "os": "test"})
    result = engine.capsules.export(
        tenant_id=TENANT, project_id=PROJECT, session_id=None,
        source_model="source-model", source_runtime="source-runtime",
        target_adapter="target-adapter", signer=engine.signer)
    assert engine.capsules.challenge(result)["passed"] is True
    return result


def _database_snapshot(engine: Engine) -> tuple[str, ...]:
    return tuple(engine.store._conn.iterdump())


def _set_path(value: dict, path: tuple[str, ...], replacement) -> None:
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement


@pytest.mark.parametrize("malformed", [None, "", False, []])
def test_capsule_challenge_rejects_non_object_input(engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(CapsuleError, match="challenge input"):
        engine.capsules.challenge(malformed)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    ("path", "malformed"),
    [
        (("resume_packet",), {}),
        (("observable_state",), {}),
        (("resume_packet", "environment"), "python-3.13"),
        (("resume_packet", "trust", "gaps"), {}),
        (("observable_state", "active_assumptions"), {}),
        (("observable_state", "open_invalidations"), {}),
        (("observable_state", "open_invalidations"), [""]),
        (("observable_state", "active_assumptions"), [{
            "node_id": "asm_round15",
            "statement": "dependency is stable",
            "status": "active",
            "criticality": "high",
            "confidence": float("nan"),
        }]),
    ],
)
def test_capsule_challenge_rejects_malformed_control_surfaces_before_state(
        engine, capsule, path, malformed):
    candidate = copy.deepcopy(capsule)
    _set_path(candidate, path, malformed)
    before = _database_snapshot(engine)
    with pytest.raises(CapsuleError):
        engine.capsules.challenge(candidate)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    ("field", "malformed"),
    list(itertools.product(
        ("source_model", "source_runtime", "target_adapter"),
        (None, "", "   ", 0, False, "\x1b[31m", "\u202eoverride", "x" * 257),
    )),
)
def test_capsule_export_rejects_unsafe_text_before_sign_or_write(
        engine, field, malformed):
    class CountingSigner:
        def __init__(self, signer):
            self.signer = signer
            self.calls = 0

        def sign(self, body):
            self.calls += 1
            return self.signer.sign(body)

    signer = CountingSigner(engine.signer)
    values = {
        "source_model": "source-model",
        "source_runtime": "source-runtime",
        "target_adapter": "target-adapter",
    }
    values[field] = malformed
    before = _database_snapshot(engine)
    with pytest.raises(CapsuleError):
        engine.capsules.export(
            tenant_id=TENANT, project_id=PROJECT, session_id=None,
            signer=signer, **values)
    assert signer.calls == 0
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    ("field", "malformed"),
    list(itertools.product(
        ("target_model", "target_runtime", "actor"),
        (None, "", "   ", 0, False, "\x1b[31m", "\u202eoverride", "x" * 257),
    )),
)
def test_capsule_import_rejects_unsafe_text_before_verify_or_write(
        engine, capsule, field, malformed):
    class CountingVerifier:
        algorithm = engine.signer.algorithm

        def __init__(self):
            self.calls = 0

        def verify(self, _body):
            self.calls += 1
            return True

    signer = CountingVerifier()
    values = {
        "target_model": "target-model",
        "target_runtime": "target-runtime",
        "actor": "reviewer",
    }
    values[field] = malformed
    before = _database_snapshot(engine)
    with pytest.raises(CapsuleError):
        engine.capsules.import_capsule(capsule, signer=signer, **values)
    assert signer.calls == 0
    assert _database_snapshot(engine) == before


def _pending_invalidation(engine: Engine) -> tuple[dict, dict]:
    target = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        status="active", criticality="high",
        data={"statement": "dependency is stable"})
    pending = engine.invalidation.fire(
        tenant_id=TENANT, project_id=PROJECT, target_node_id=target.id,
        trigger_type="dependency_drift", trigger_confidence=0.4)
    assert pending["status"] == "pending_confirmation"
    return target, pending


@pytest.mark.parametrize(
    "malformed", [None, 0, 1, "true", "false", [], {}])
def test_invalidation_confirmation_requires_an_exact_boolean(engine, malformed):
    _target, pending = _pending_invalidation(engine)
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="accept must be a boolean"):
        engine.invalidation.confirm(
            pending["node_id"], actor="reviewer", accept=malformed)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    "malformed",
    [None, "", "   ", 0, False, "\x1b[31m", "\u202eoverride", "x" * 257],
)
def test_invalidation_confirmation_requires_a_safe_actor(engine, malformed):
    _target, pending = _pending_invalidation(engine)
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="confirmation actor"):
        engine.invalidation.confirm(
            pending["node_id"], actor=malformed, accept=True)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    ("accept", "invalidation_status", "target_status"),
    [(False, "rejected", "active"), (True, "open", "invalidated")],
)
def test_invalidation_confirmation_preserves_true_and_false_semantics(
        engine, accept, invalidation_status, target_status):
    target, pending = _pending_invalidation(engine)
    result = engine.invalidation.confirm(
        pending["node_id"], actor="reviewer", accept=accept)
    assert result["status"] == invalidation_status
    assert result["data"]["accepted"] is accept
    assert engine.graph.get(target.id)["status"] == target_status
    audit = engine.store.audit_entries("invalidation.confirm")[-1]
    assert audit["actor"] == "reviewer"
    assert f"accepted={accept}" in audit["detail"]


def _expected_conclusion(values: dict[str, bool]) -> str:
    if values["trust_unavailable"]:
        return "cancelled"
    if (values["critical_invalidation"] or values["authority_conflict"]
            or values["approval_needed"]):
        return "action_required"
    if not values["proof_ok"]:
        return "failure"
    if values["packet_current"]:
        return "success"
    return "neutral"


def test_continuity_conclusion_complete_boolean_truth_table():
    fields = (
        "critical_invalidation", "proof_ok", "packet_current",
        "authority_conflict", "approval_needed", "trust_unavailable")
    for combination in itertools.product((False, True), repeat=len(fields)):
        values = dict(zip(fields, combination))
        assert continuity_conclusion(**values) == _expected_conclusion(values)


@pytest.mark.parametrize(
    ("field", "malformed"),
    list(itertools.product(
        (
            "critical_invalidation", "proof_ok", "packet_current",
            "authority_conflict", "approval_needed", "trust_unavailable",
        ),
        (None, 0, 1, "true", "false", [], {}),
    )),
)
def test_continuity_conclusion_rejects_non_boolean_inputs(field, malformed):
    values = {
        "critical_invalidation": False,
        "proof_ok": True,
        "packet_current": True,
        "authority_conflict": False,
        "approval_needed": False,
        "trust_unavailable": False,
    }
    values[field] = malformed
    with pytest.raises(ValueError, match=field):
        continuity_conclusion(**values)
