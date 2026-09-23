"""Refuse malformed persisted scope and contradictory explicit proof operands.

Scope corruption is planted only in disposable stores after genuine producer
confirmation. It tests fail-closed consumption, not an unprivileged SQL exploit.
"""

import pytest

from causal_continuity_engine.core import canonical_json
from causal_continuity_engine.engine import AttestationInputError
from causal_continuity_engine.verifiers import VerifierRunner
from tests.test_obligation_completeness import OBLIGATIONS, PROJECT, _confirm, _spent, _task
from tests.test_obligation_completeness import engine as engine


@pytest.fixture
def verifier_calls(monkeypatch):
    calls = []
    original = VerifierRunner.run

    def observe(runner, spec):
        calls.append(spec.name)
        return original(runner, spec)

    # Observe the real execution boundary; neither authorization nor verifier
    # outcomes are replaced. Positive controls prove this observer can fire.
    monkeypatch.setattr(VerifierRunner, "run", observe)
    return calls


def _attest(engine, task_id, **operands):
    return engine.attest_action(
        PROJECT, intent_type="task_complete", intent_statement="archive packaged",
        actor={"agent": "test"}, action_type="run_verifier",
        continuity=operands.pop("continuity", {"task_ids": [task_id]}), **operands)


def _assert_refused_before_execution(engine, task_id, verifier_calls, **operands):
    before = tuple(engine.store._conn.iterdump())
    before_task = engine.graph.get(task_id)
    before_spent = _spent(engine)
    rejection = None
    try:
        proof = _attest(engine, task_id, **operands)
    except AttestationInputError as exc:
        rejection = str(exc)
    else:
        # Record whether a wrongly admitted proof can actually be spent. This
        # is a disposable-store reproduction, not a fallback implementation.
        engine.complete_task(PROJECT, task_id, proof=proof)
    failures = []
    if rejection is None:
        failures.append("attestation accepted the invalid contract operands")
    if verifier_calls:
        failures.append("verifier execution occurred before refusal")
    if tuple(engine.store._conn.iterdump()) != before:
        failures.append("attestation or completion persisted state")
    if engine.graph.get(task_id) != before_task:
        failures.append("the task was mutated")
    if _spent(engine) != before_spent:
        failures.append("the proof was spent")
    assert not failures, "; ".join(failures)


@pytest.mark.parametrize("corruption", [
    "missing_data_scope",
    "missing_node_scope",
    "data_disagrees_with_canonical_scope",
    "node_disagrees_with_canonical_scope",
    "data_and_node_agree_but_disagree_with_canonical_scope",
])
def test_malformed_confirmed_scope_refuses_before_verifier_or_persistence(
        engine, verifier_calls, corruption):
    task_id = _task(engine)
    other_task_id = _task(engine, "other")
    requirement_id = _confirm(engine, *OBLIGATIONS[0], "scope-repair")
    original = engine.graph.get(requirement_id)
    assert original["data"]["authority_scope"] == {"kind": "global"}
    assert original["scope"] == {"kind": "global"}
    data = dict(original["data"])
    scope = original["scope"]
    if corruption == "missing_data_scope":
        data.pop("authority_scope")
    elif corruption == "missing_node_scope":
        scope = None
    elif corruption == "data_disagrees_with_canonical_scope":
        data["authority_scope"] = {"kind": "tasks", "task_ids": [task_id]}
    elif corruption == "node_disagrees_with_canonical_scope":
        scope = {"kind": "tasks", "task_ids": [task_id]}
    else:
        scope = {"kind": "tasks", "task_ids": [other_task_id]}
        data["authority_scope"] = scope
    with engine.store.transaction():
        engine.store._conn.execute(
            "UPDATE nodes SET data=?,scope=? WHERE node_id=? AND tx_to IS NULL",
            (canonical_json(data), None if scope is None else canonical_json(scope),
             requirement_id))
    assert not engine.graph.may_mandate(engine.graph.get(requirement_id))
    _assert_refused_before_execution(engine, task_id, verifier_calls)


def test_intact_confirmed_scope_runs_the_real_verifier_and_completes(engine, verifier_calls):
    task_id = _task(engine)
    requirement_id = _confirm(engine, *OBLIGATIONS[0], "healthy-scope")
    proof = _attest(engine, task_id)
    assert proof["status"] == "verified"
    assert proof["evidence_context"]["mutation"]["bound"] is True
    assert verifier_calls
    assert proof["action_intent"]["requirement_ids"] == [requirement_id]
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"


def test_explicit_empty_requirement_ids_disagree_with_nonempty_continuity(
        engine, verifier_calls):
    task_id = _task(engine)
    requirement_id = _confirm(engine, *OBLIGATIONS[0], "mismatched-requirements")
    _assert_refused_before_execution(
        engine, task_id, verifier_calls, requirement_ids=[],
        continuity={"task_ids": [task_id], "requirement_ids": [requirement_id]})


@pytest.mark.parametrize("has_requirement", [False, True])
def test_matching_explicit_requirement_operands_allow_completion(
        engine, verifier_calls, has_requirement):
    task_id = _task(engine)
    requirement_ids = ([_confirm(engine, *OBLIGATIONS[0], "matching-requirements")]
                       if has_requirement else [])
    proof = _attest(
        engine, task_id, requirement_ids=requirement_ids,
        continuity={"task_ids": [task_id], "requirement_ids": requirement_ids})
    assert proof["status"] == "verified"
    assert proof["evidence_context"]["mutation"]["bound"] is True
    assert verifier_calls
    assert proof["action_intent"]["requirement_ids"] == requirement_ids
    assert proof["continuity_links"]["requirement_ids"] == requirement_ids
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"
