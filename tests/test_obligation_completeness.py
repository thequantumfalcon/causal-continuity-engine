"""Completion covers applicable confirmed authority, not just caller links.

The verifier establishes a binding to the deliverable bytes, not the semantic
truth of any obligation. Confirmation uses the actual owner-local producer;
these tests do not authenticate a person apart from the local store capability.
"""

import shlex
import sys
from pathlib import Path

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.core import digest_obj
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.verifiers import VerifierSpec

PROJECT = "prj_obligation_completeness"
OBLIGATIONS = [
    ("requirement", "The exporter must retain archive checksums."),
    ("constraint", "The telemetry collector must not record passwords."),
    ("decision", "We decided to use SQLite for the offline catalog."),
    ("assumption", "We assume the build cache is reachable during validation."),
]


def _python_command(source):
    return shlex.join([sys.executable, "-c", source])


@pytest.fixture
def engine(tmp_path):
    assert Path(engine_module.__file__).resolve() == (
        Path(__file__).resolve().parents[1] / "causal_continuity_engine" / "engine.py")
    (tmp_path / "deliverable.txt").write_text("archive checksums retained\n")
    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "min_evidence_grade": "C",
        "required_verifiers": [{
            "name": "deliverable-check",
            "command": _python_command(
                "from pathlib import Path; "
                "assert Path('deliverable.txt').read_text() == "
                "'archive checksums retained\\n'"),
            "expect_fail_command": _python_command("raise SystemExit(1)"),
            "artifacts": ["deliverable.txt"],
        }],
    }
    instance = Engine(tmp_path / "obligations.sqlite3", workdir=tmp_path)
    instance.create_project("Obligation completeness", project_id=PROJECT,
                            capture_mode="full", config=config)
    instance.policy.grant(project_id=PROJECT, level=2, granted_by="lead")
    instance.policy.set_project_config(PROJECT, config)
    try:
        yield instance
    finally:
        instance.close()


def _propose(engine, kind, text, key):
    # Source identity is unique too: an unrelated source must not withdraw the
    # already-confirmed task and accidentally make the authority gate the test.
    report = engine.ingest_human_decision(
        PROJECT, actor="source-" + key, decision=text, request_id="ingest-" + key)
    proposals = [item["node_id"] for item in report["created"]
                 if item["kind"] == "claim" and not item.get("quarantined")]
    assert len(proposals) == 1
    proposal = engine.authority_proposal(PROJECT, proposals[0])
    assert proposal["proposed_kind"] == kind
    assert not engine.graph.may_mandate(engine.graph.get(proposals[0]))
    return proposal


def _confirm(engine, kind, text, key, scope=None):
    proposal = _propose(engine, kind, text, key)
    receipt = engine.record_authority_decision(PROJECT, {
        "operation": "confirm", "request_id": "confirm-" + key,
        "tenant_id": engine.tenant_id, "project_id": PROJECT,
        **proposal, "authority_scope": scope or {"kind": "global"},
    })
    node = engine.graph.get(receipt["confirmation_id"], tenant_id=engine.tenant_id,
                            project_id=PROJECT)
    assert node["entity_type"] == kind
    assert engine.graph.may_mandate(node)
    return node["node_id"]


def _task(engine, key="target"):
    return _confirm(engine, "task", "- [ ] package the " + key + " archive", key)


def _scope(mode, task_id):
    return ({"kind": "global"} if mode == "global"
            else {"kind": "tasks", "task_ids": [task_id]})


def _attest(engine, task_id):
    proof = engine.attest_action(
        PROJECT, intent_type="task_complete", intent_statement="archive packaged",
        actor={"agent": "test"}, action_type="run_verifier",
        continuity={"task_ids": [task_id]})
    assert proof["status"] == "verified"
    assert proof["evidence_context"]["mutation"]["bound"] is True
    assert engine.proof_currency(PROJECT, task_id, proof)["current"] is True
    return proof


def _spent(engine):
    return [tuple(row) for row in engine.store._conn.execute(
        "SELECT * FROM spent_proofs WHERE tenant_id=? AND project_id=? ORDER BY proof_id",
        (engine.tenant_id, PROJECT))]


@pytest.mark.parametrize("scope_mode", ["global", "task"])
def test_unlinked_applicable_requirement_is_included_by_the_engine(engine, scope_mode):
    task_id = _task(engine)
    requirement_id = _confirm(engine, *OBLIGATIONS[0], "existing-requirement",
                              scope=_scope(scope_mode, task_id))
    proof = _attest(engine, task_id)
    # No requirement_ids or requirement continuity links were supplied above.
    completed = engine.complete_task(PROJECT, task_id, proof=proof)
    assert completed["status"] == "verified"
    assert proof["action_intent"]["requirement_ids"] == [requirement_id]


@pytest.mark.parametrize("scope_mode", ["global", "task"])
@pytest.mark.parametrize("kind,text", OBLIGATIONS)
def test_added_applicable_authority_stales_proof_without_spend_or_task_mutation(
        engine, scope_mode, kind, text):
    task_id = _task(engine)
    proof = _attest(engine, task_id)
    _confirm(engine, kind, text, "added-" + kind, scope=_scope(scope_mode, task_id))
    assert engine.graph.may_mandate(engine.graph.get(task_id))
    assert engine.invalidation.blocking_invalidations(PROJECT, task_id) == []
    before_task = engine.graph.get(task_id)
    before_spent = _spent(engine)
    currency = engine.proof_currency(PROJECT, task_id, proof)
    rejection = None
    try:
        engine.complete_task(PROJECT, task_id, proof=proof)
    except (PermissionError, ValueError) as exc:
        rejection = str(exc)
    # Exercise both public deciding paths before asserting, so the baseline
    # records whether completion actually accepted the omitted obligation.
    failures = []
    if currency["current"]:
        failures.append("proof_currency reported current after applicable authority was added")
    if rejection is None or "no longer describes" not in rejection:
        failures.append(f"expected the currentness rejection, received {rejection!r}")
    if engine.graph.get(task_id) != before_task:
        failures.append("rejected completion mutated the task")
    if _spent(engine) != before_spent:
        failures.append("rejected completion spent the proof")
    assert not failures, "; ".join(failures)


def test_confirmed_task_with_zero_obligations_and_pinned_verifier_completes(engine):
    task_id = _task(engine)
    proof = _attest(engine, task_id)
    assert proof["action_intent"]["requirement_ids"] == []
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"


@pytest.mark.parametrize("kind,text", OBLIGATIONS)
def test_unconfirmed_noise_does_not_stale_the_proof(engine, kind, text):
    task_id = _task(engine)
    proof = _attest(engine, task_id)
    _propose(engine, kind, text, "noise-" + kind)
    assert engine.proof_currency(PROJECT, task_id, proof)["current"] is True
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"


@pytest.mark.parametrize("kind,text", OBLIGATIONS)
def test_authority_scoped_to_another_task_does_not_stale_the_proof(engine, kind, text):
    task_id = _task(engine)
    other_task_id = _task(engine, "other")
    proof = _attest(engine, task_id)
    _confirm(engine, kind, text, "unrelated-" + kind,
             scope={"kind": "tasks", "task_ids": [other_task_id]})
    assert engine.proof_currency(PROJECT, task_id, proof)["current"] is True
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"


def _basis(engine, task_id):
    # The missing proposed API is an unmet draft-2 contract, not evidence of a
    # defect in an API that the baseline already claimed to implement.
    assert callable(getattr(engine, "_obligation_basis", None)), (
        "unmet draft-2 field contract: Engine._obligation_basis is not implemented")
    basis = engine._obligation_basis(PROJECT, task_id)
    assert set(basis) == {
        "schema_version", "tenant_id", "project_id", "target", "scope",
        "obligations", "proof_policy",
    }
    assert basis["schema_version"] == "cce.obligation-basis.v1"
    assert basis["tenant_id"] == engine.tenant_id
    assert basis["project_id"] == PROJECT
    assert basis["scope"] == {"kind": "tasks", "task_ids": [task_id]}
    assert set(basis["target"]) == {
        "node_id", "proposal_id", "confirmation_event_id", "decision_event_id",
        "authority_version", "text_digest", "authority_scope",
    }
    task = engine.graph.get(task_id)
    data = task["data"]
    assert basis["target"] == {
        "node_id": task_id,
        "proposal_id": data["proposal_id"],
        "confirmation_event_id": data["confirmation_event_id"],
        "decision_event_id": data["decision_event_id"],
        "authority_version": data["authority_version"],
        "text_digest": digest_obj(data["statement"]),
        "authority_scope": {"kind": "global"},
    }
    assert set(basis["proof_policy"]) == {
        "task_proof_required", "min_evidence_grade", "required_verifiers",
    }
    verifier_entries = basis["proof_policy"]["required_verifiers"]
    assert len(verifier_entries) == 1
    assert set(verifier_entries[0]) == {"name", "pinned", "definition_digest"}
    definition, = engine.policy.required_verifier_defs(PROJECT)
    assert basis["proof_policy"] == {
        "task_proof_required": True,
        "min_evidence_grade": "C",
        "required_verifiers": [{
            "name": "deliverable-check", "pinned": True,
            "definition_digest": VerifierSpec.from_policy(definition).definition_digest,
        }],
    }
    identities = [(member["entity_type"], member["node_id"])
                  for member in basis["obligations"]]
    assert identities == sorted(identities)
    assert len({identity[1] for identity in identities}) == len(identities)
    return basis


def _assert_member_fields(member, node, *, scope, origin):
    assert set(member) == {
        "node_id", "entity_type", "origin", "status", "criticality", "confidence",
        "authority", "valid_from", "valid_to", "authority_scope", "content", "confirmation",
    }
    assert member["origin"] == origin
    for field in ("node_id", "entity_type", "status", "criticality", "confidence",
                  "authority", "valid_from", "valid_to"):
        assert member[field] == node[field]
    assert member["authority_scope"] == scope
    if origin == "confirmed":
        assert set(member["confirmation"]) == {
            "proposal_id", "confirmation_event_id", "decision_event_id", "authority_version",
        }
        assert member["confirmation"] == {
            "proposal_id": node["data"]["proposal_id"],
            "confirmation_event_id": node["data"]["confirmation_event_id"],
            "decision_event_id": node["data"]["decision_event_id"],
            "authority_version": node["data"]["authority_version"],
        }
        assert member["content"] == {
            key: value for key, value in node["data"].items() if key != "decided_at"}
    else:
        assert member["confirmation"] is None
        assert member["content"] == node["data"]


def test_literal_obligation_basis_contract_for_explicit_empty_set(engine):
    task_id = _task(engine)
    assert _basis(engine, task_id)["obligations"] == []


@pytest.mark.parametrize("kind,text", OBLIGATIONS)
def test_literal_confirmed_member_contract_excludes_only_decided_at(engine, kind, text):
    task_id = _task(engine)
    scope = {"kind": "tasks", "task_ids": [task_id]}
    member_id = _confirm(engine, kind, text, "field-contract-" + kind, scope=scope)
    node = engine.graph.put_node(
        entity_type=kind, tenant_id=engine.tenant_id, project_id=PROJECT, node_id=member_id,
        data={"completion_evidence": "evi_control", "proof_node_id": "act_control",
              "verification_ids": ["ver_control"], "last_verified_at": "semantic control",
              "conflict_requires_resolution": False, "supersedes_node_id": "req_prior",
              "nested": {"decided_at": "nested semantic timestamp"}})
    assert engine.graph.may_mandate(node)
    member, = _basis(engine, task_id)["obligations"]
    _assert_member_fields(member, node, scope=scope, origin="confirmed")
    retained = engine.authority_proposal(PROJECT, node["data"]["proposal_id"])
    assert member["content"]["statement"] == retained["text"]
    assert member["content"]["authority_scope"] == scope
    assert "decided_at" not in member["content"]
    assert member["content"]["nested"]["decided_at"] == "nested semantic timestamp"


def test_literal_runtime_member_contract_keeps_the_complete_data_object(engine):
    task_id = _task(engine)
    scope = {"kind": "tasks", "task_ids": [task_id]}
    data = {
        "statement": "The calibration clock has an observed stable rate.",
        "authority_scope": scope, "decided_at": "runtime semantic timestamp",
        "completion_evidence": "evi_runtime", "proof_node_id": "act_runtime",
        "verification_ids": ["ver_runtime"], "last_verified_at": "runtime semantic time",
        "nested": {"decided_at": "nested runtime semantic timestamp"},
    }
    node = engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        data=data, status="active", authority="human_decision", criticality="low",
        confidence=0.75, scope={"source_ref": "local-calibration"})
    member, = _basis(engine, task_id)["obligations"]
    _assert_member_fields(member, node, scope=scope, origin="runtime")
    assert member["content"] == data


def _confirmed_conflict(engine, scope):
    requirement_id = _confirm(
        engine, "requirement", "The pipeline must write to production.",
        "conflict-requirement", scope=scope)
    constraint_id = _confirm(
        engine, "constraint", "The pipeline must not write to production.",
        "conflict-constraint", scope=scope)
    for node_id in (requirement_id, constraint_id):
        node = engine.graph.get(node_id)
        assert engine.graph.may_mandate(node)
        assert node["status"] == "uncertain"
        assert node["data"]["conflict_requires_resolution"] is True


def test_fresh_proof_cannot_complete_with_applicable_authority_conflict(engine):
    task_id = _task(engine)
    _confirmed_conflict(engine, {"kind": "tasks", "task_ids": [task_id]})
    proof = _attest(engine, task_id)
    assert engine.invalidation.blocking_invalidations(PROJECT, task_id) == []
    before_task = engine.graph.get(task_id)
    before_spent = _spent(engine)
    with pytest.raises(PermissionError, match="authority conflict"):
        engine.complete_task(PROJECT, task_id, proof=proof)
    assert engine.graph.get(task_id) == before_task
    assert _spent(engine) == before_spent


def test_uncertainty_scoped_to_another_task_does_not_block_completion(engine):
    task_id = _task(engine)
    other_task_id = _task(engine, "other")
    _confirmed_conflict(engine, {"kind": "tasks", "task_ids": [other_task_id]})
    proof = _attest(engine, task_id)
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"


def test_resolved_confirmed_assumption_is_included_and_allows_completion(engine):
    task_id = _task(engine)
    member_id = _confirm(engine, *OBLIGATIONS[3], "resolved-assumption")
    node = engine.graph.put_node(
        entity_type="assumption", tenant_id=engine.tenant_id, project_id=PROJECT,
        node_id=member_id, data={}, status="resolved")
    assert engine.graph.may_mandate(node)
    proof = _attest(engine, task_id)
    member, = _basis(engine, task_id)["obligations"]
    assert member["node_id"] == member_id
    assert member["status"] == "resolved"
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"


def test_completed_sibling_does_not_remove_authority_for_remaining_scoped_task(engine):
    task_id = _task(engine)
    other_task_id = _task(engine, "other")
    _confirm(engine, *OBLIGATIONS[0], "shared-scope",
             scope={"kind": "tasks", "task_ids": sorted([task_id, other_task_id])})
    other_proof = _attest(engine, other_task_id)
    assert engine.complete_task(PROJECT, other_task_id, proof=other_proof)["status"] == "verified"
    proof = _attest(engine, task_id)
    assert engine.complete_task(PROJECT, task_id, proof=proof)["status"] == "verified"
