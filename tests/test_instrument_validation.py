"""Instrument validation for the completion gate (ADR-056).

A verifier that only ever reports PASS is not evidence of anything. This file
therefore exercises negative controls at the completion boundary.

CCE's completion gate has accumulated twenty independent rejection paths
across repeated adversarial review rounds. Every one is exercised by a test that
proves it CAN fire. Nothing until now proved that each fires **for the
reason it exists** and that the others stay quiet — which matters here more
than most places, because three of this project's worst defects were
controls that existed, were tested, and did not run in the path that
decided (ADR-014, ADR-033/044, ADR-043).

So this harness works the other way round from the rest of the suite. It
builds one known-good completion, plants a specific defect, and asserts:

  1. the gate that SHOULD catch it does, identified by name; and
  2. the baseline — unmodified — completes cleanly, so a gate that fires on
     everything is exposed rather than mistaken for rigour.

A defect caught by the WRONG gate is reported as a mismatch rather than a
pass. That is not pedantry: it means the model of which control covers what
is wrong, and a control believed to cover something it does not is exactly
how a gap survives a review round.
"""

from __future__ import annotations

import json
import shlex
import sys

import pytest

from causal_continuity_engine.core import digest_obj
from causal_continuity_engine.engine import Engine

PRJ = "prj_instrument"
REPOSITORY_ID = 18018
PRECHECK_SPENDER = "tsk_111111111111111111111111"
RACING_SPENDER = "tsk_222222222222222222222222"


def _python_command(source: str) -> str:
    return shlex.join([sys.executable, "-c", source])


PASS_COMMAND = _python_command("raise SystemExit(0)")
FAIL_COMMAND = _python_command("raise SystemExit(1)")

#: Each gate's identifying phrase, taken from the message it raises. Keyed by
#: the ADR that introduced it so a renamed message fails loudly here.
GATES = {
    "wrong_target":     "is not a task in the requested project",     # ADR-068
    "open_invalidation": "unresolved invalidation control state",       # CI-005
    "already_complete": "is already verified",                       # ADR-074
    "quarantined":      "is quarantined",                       # ADR-050
    "not_completable":  "is not completable",                        # ADR-074
    "no_proof":         "none was provided",                    # PA-005
    "malformed":        "malformed proof envelope",              # ADR-068
    "tampered":         "invalid or tampered",                  # PA-002
    "not_verified":     "not 'verified'",                       # PA-005
    "wrong_project":    "was issued for",                       # ADR-018
    "wrong_intent":     "proof intent is",                       # ADR-068
    "unbound_task":     "does not name task",                   # ADR-018
    "already_spent":    f"already used to complete {PRECHECK_SPENDER}",
    "claim_race":       f"already used to complete {RACING_SPENDER}",
    "not_current":      "no longer describes",                  # ADR-043
    "no_verifiers":     "no required verifiers",                # ADR-045
    "policy_moved":     "policy now requires",                  # ADR-054
    "policy_denied":    "policy decision is not 'allow'",        # ADR-068
    "low_grade":        "evidence grade",                       # ADR-027
    "state_changed":    "task state changed",                   # ADR-069
}


def _reads_deliverable() -> str:
    return _python_command(
        "import pathlib,sys; "
        "sys.exit(0 if pathlib.Path('deliverable.py').read_text() else 1)")


def _good(tmp_path, **overrides):
    """A completion that should be accepted, and the pieces to corrupt."""
    (tmp_path / "deliverable.py").write_text("def f(): return 1\n")
    cfg = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "min_evidence_grade": "C",
        "required_verifiers": [{
            "name": "unit-tests", "command": _reads_deliverable(),
            "expect_fail_command": FAIL_COMMAND,
            "artifacts": ["deliverable.py"]}],
        **overrides,
    }
    engine = Engine(workdir=tmp_path)
    engine.create_project(
        "p", project_id=PRJ, repository_id=REPOSITORY_ID, config=cfg)
    engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
    engine.policy.set_project_config(PRJ, cfg)
    task = engine.graph.put_node(
        entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
        data={"title": "ship the exporter"}, status="open")
    proof = engine.attest_action(
        PRJ, intent_type="task_complete", intent_statement="exporter done",
        actor={"agent": "test"}, action_type="run_verifier",
        continuity={"task_ids": [task.id]})
    return engine, task, proof, cfg


#: Exception types a REJECTION may use. Narrowing this to PermissionError
#: alone would make a gate that raised anything else look like a harness
#: error rather than a control firing, and it would go uncounted below —
#: an instrument blind to the very thing it exists to measure (ADR-067).
REJECTION_TYPES = (PermissionError, ValueError)


def _attempt(engine, task_id, proof):
    """Try the completion. Returns the gate name that fired, or None."""
    try:
        engine.complete_task(PRJ, task_id, proof=proof)
        return None
    except REJECTION_TYPES as exc:
        message = str(exc)
        fired = [name for name, phrase in GATES.items() if phrase in message]
        if not fired:
            pytest.fail(f"a {type(exc).__name__} rejection fired with an "
                        f"unrecognised message: {message}")
        if len(fired) > 1:
            pytest.fail(f"ambiguous gate message matches {fired}: {message}")
        return fired[0]


def _reseal(proof: dict) -> dict:
    """Recompute the digest so the tamper is internally consistent.

    Under HMAC an outsider cannot re-sign, so this isolates the SIGNATURE
    check from the digest check: a resealed body still fails on the signature
    alone, which is the property being asserted.
    """
    body = {k: v for k, v in proof.items()
            if k not in ("signature", "proof_digest")}
    proof["proof_digest"] = digest_obj(body)
    return proof


def _trusted_reseal(engine: Engine, proof: dict) -> dict:
    """Issue a modified envelope with the engine's actual trusted key.

    This is used only for semantic gates whose input must remain both
    internally consistent and authentic; otherwise the tamper gate would
    correctly intercept the fixture first.
    """
    issued = _reseal(json.loads(json.dumps(proof)))
    issued["signature"] = engine.signer.sign(issued)
    return issued


# ─────────────────────────── the mutation table ───────────────────────────
# Each entry plants one defect and names the single gate that must catch it.

class TestBaselineCompletesCleanly:
    def test_unmodified_completion_is_accepted(self, tmp_path):
        """If this fails, every result below is meaningless."""
        engine, task, proof, _ = _good(tmp_path)
        assert _attempt(engine, task.id, proof) is None, \
            "the known-good case is rejected: no gate result below can be trusted"
        engine.close()

    def test_the_good_proof_is_actually_verified(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        assert proof["status"] == "verified"
        assert proof["evidence_context"]["mutation"]["bound"] is True
        engine.close()


class TestEachDefectTripsItsOwnGate:
    def test_target_is_not_a_task_in_the_requested_project(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        assumption = engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id,
            project_id=PRJ, data={"statement": "not executable work"},
            status="active")
        assert _attempt(engine, assumption.id, proof) == "wrong_target"
        engine.close()

    def test_a_different_claim_cannot_overwrite_verified_completion(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        assert _attempt(engine, task.id, proof) is None
        version = engine.graph.get(task.id)["version"]
        # An exact retry is a no-op, so transport retries remain safe.
        assert engine.complete_task(PRJ, task.id, proof=proof)["version"] == version
        replacement = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="replacement",
            actor={"agent": "test"}, action_type="run_verifier",
            continuity={"task_ids": [task.id]})
        assert _attempt(engine, task.id, replacement) == "already_complete"
        completed = engine.graph.get(task.id)
        assert completed["version"] == version
        assert completed["data"]["completion_evidence"] == proof["proof_id"]
        engine.close()

    def test_quarantined_task(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        engine.partial.quarantine(task.id, actor="cce", reason="ambiguous output")
        assert _attempt(engine, task.id, proof) == "quarantined"
        engine.close()

    def test_blocked_task_cannot_bypass_state_gate_when_proof_is_optional(
            self, tmp_path):
        engine, task, proof, _ = _good(tmp_path, require_proof_for=[])
        engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id,
            project_id=PRJ, node_id=task.id, status="blocked", data={})
        assert _attempt(engine, task.id, None) == "not_completable"
        assert engine.graph.get(task.id)["status"] == "blocked"
        engine.close()

    def test_no_proof_at_all(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        assert _attempt(engine, task.id, None) == "no_proof"
        engine.close()

    def test_required_proof_field_is_missing(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        malformed = json.loads(json.dumps(proof))
        malformed.pop("proof_id")
        assert _attempt(engine, task.id, malformed) == "malformed"
        engine.close()

    def test_body_tampered_without_resealing(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        forged = json.loads(json.dumps(proof))
        forged["action_intent"]["statement"] = "something else entirely"
        assert _attempt(engine, task.id, forged) == "tampered"
        engine.close()

    def test_body_tampered_and_resealed_still_fails_on_the_signature(self, tmp_path):
        """The case that decides whether the signature check is decoration.

        The digest is recomputed so it agrees with the altered body; only the
        signature can catch it. This is the resealed-tamper negative control.
        """
        engine, task, proof, _ = _good(tmp_path)
        forged = _reseal(json.loads(json.dumps(proof)))
        forged["action_intent"]["statement"] = "something else entirely"
        forged = _reseal(forged)
        assert _attempt(engine, task.id, forged) == "tampered"
        engine.close()

    def test_status_forged_to_verified(self, tmp_path):
        engine, task, proof, cfg = _good(
            tmp_path, required_verifiers=[{
                "name": "unit-tests", "command": FAIL_COMMAND}])
        assert proof["status"] == "failed"
        assert _attempt(engine, task.id, proof) == "not_verified"
        engine.close()

    def test_proof_from_another_project(self, tmp_path):
        """A GENUINELY signed proof from elsewhere, not a JSON edit.

        Editing project_id in the body breaks the digest, so a naive swap is
        caught by the tamper gate and never reaches the scope check — which
        is why this mutation has to mint a real foreign proof to test what it
        claims to test.
        """
        engine, task, proof, cfg = _good(tmp_path)
        other = Engine(workdir=tmp_path, signer=engine.signer)   # same key
        other.create_project("o", project_id="prj_elsewhere", config=cfg)
        other.policy.grant(project_id="prj_elsewhere", level=2, granted_by="l")
        other.policy.set_project_config("prj_elsewhere", cfg)
        foreign_task = other.graph.put_node(
            entity_type="task", tenant_id=other.tenant_id,
            project_id="prj_elsewhere", data={"title": "their task"},
            status="open")
        foreign = other.attest_action(
            "prj_elsewhere", intent_type="task_complete",
            intent_statement="theirs", actor={"agent": "test"},
            action_type="run_verifier",
            continuity={"task_ids": [foreign_task.id]})
        assert _attempt(engine, task.id, foreign) == "wrong_project"
        other.close()
        engine.close()

    def test_proof_for_another_intent(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        wrong_intent = engine.attest_action(
            PRJ, intent_type="pr_ready", intent_statement="ready for review",
            actor={"agent": "test"}, action_type="run_verifier",
            continuity={"task_ids": [task.id]})
        assert wrong_intent["status"] == "verified"
        assert _attempt(engine, task.id, wrong_intent) == "wrong_intent"
        engine.close()

    def test_proof_that_names_no_task(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        unbound = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="unbound",
            actor={"agent": "test"}, action_type="run_verifier")
        assert _attempt(engine, task.id, unbound) == "unbound_task"
        engine.close()

    def test_proof_replayed_onto_a_second_task(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        second = engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            node_id=PRECHECK_SPENDER, data={"title": "another"},
            status="open")
        both = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="both",
            actor={"agent": "test"}, action_type="run_verifier",
            continuity={"task_ids": [task.id, second.id]})
        assert _attempt(engine, second.id, both) is None
        assert _attempt(engine, task.id, both) == "already_spent"
        engine.close()

    def test_proof_is_claimed_by_a_peer_after_the_precheck(
            self, tmp_path, monkeypatch):
        """The final atomic claim must reject a precheck/claim race."""
        engine, task, proof, _ = _good(tmp_path)

        def peer_won_claim(project_id, proof_id, task_id):
            return RACING_SPENDER

        monkeypatch.setattr(engine, "_claim_proof", peer_won_claim)
        assert _attempt(engine, task.id, proof) == "claim_race"
        assert engine.graph.get(task.id)["status"] == "open"
        engine.close()

    def test_deliverable_changed_after_attestation(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        (tmp_path / "deliverable.py").write_text("def f(): return 999\n")
        assert _attempt(engine, task.id, proof) == "not_current"
        engine.close()

    def test_invalidation_fired_after_attestation(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        asm = engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id,
            project_id=PRJ, data={"statement": "schema is stable"},
            status="active", criticality="critical")
        engine.invalidation.fire(
            tenant_id=engine.tenant_id, project_id=PRJ, target_node_id=asm.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.95)
        assert _attempt(engine, task.id, proof) == "open_invalidation"
        engine.close()

    def test_policy_declares_no_verifiers(self, tmp_path):
        engine, task, proof, cfg = _good(tmp_path)
        engine.policy.set_project_config(
            PRJ, {**cfg, "required_verifiers": []})
        assert _attempt(engine, task.id, proof) == "no_verifiers"
        engine.close()

    def test_policy_tightened_after_attestation(self, tmp_path):
        engine, task, proof, cfg = _good(tmp_path)
        engine.policy.set_project_config(PRJ, {
            **cfg, "required_verifiers": cfg["required_verifiers"] + [
                {"name": "security-scan", "command": PASS_COMMAND}]})
        assert _attempt(engine, task.id, proof) == "policy_moved"
        engine.close()

    def test_authentic_proof_records_policy_denial(self, tmp_path):
        engine, task, proof, _ = _good(tmp_path)
        denied = json.loads(json.dumps(proof))
        denied["policy_decision"] = {
            "decision": "deny",
            "reason": "trusted issuer recorded a denied action",
        }
        denied = _trusted_reseal(engine, denied)
        assert _attempt(engine, task.id, denied) == "policy_denied"
        engine.close()

    def test_evidence_below_the_grade_floor(self, tmp_path):
        """A check the claimant chose, rather than one the policy pinned."""
        engine, task, proof, cfg = _good(
            tmp_path, required_verifiers=["unit-tests"])   # bare name: unpinned
        from causal_continuity_engine.verifiers import VerifierSpec
        weak = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="weak",
            actor={"agent": "test"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests",
                                         command=PASS_COMMAND)],
            continuity={"task_ids": [task.id]})
        assert _attempt(engine, task.id, weak) == "low_grade"
        engine.close()

    def test_task_changes_during_validation(self, tmp_path, monkeypatch):
        engine, task, proof, _ = _good(tmp_path)
        original = engine.proof_currency

        def plant_change(project_id, task_id, envelope):
            result = original(project_id, task_id, envelope)
            engine.graph.put_node(
                entity_type="task", tenant_id=engine.tenant_id,
                project_id=PRJ, node_id=task.id, status="quarantined",
                data={"quarantine_reason": "arrived during validation"})
            return result

        monkeypatch.setattr(engine, "proof_currency", plant_change)
        assert _attempt(engine, task.id, proof) == "state_changed"
        # Rejection rolls the planted in-transaction mutation back too.
        assert engine.graph.get(task.id)["status"] == "open"
        engine.close()


class TestNoGateFiresSpuriously:
    """The other half of instrument validation, which CCE had none of: a
    control that fires on everything is not a control."""

    @pytest.mark.parametrize("harmless", [
        "add_an_unrelated_task",
        "compose_a_resume_packet",
        "run_an_evidence_probe",
        "record_an_audit_entry",
        "ingest_an_unrelated_event",
    ])
    def test_harmless_activity_does_not_block_completion(self, tmp_path, harmless):
        engine, task, proof, _ = _good(tmp_path)
        if harmless == "add_an_unrelated_task":
            engine.graph.put_node(
                entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
                data={"title": "unrelated"}, status="open")
        elif harmless == "compose_a_resume_packet":
            engine.resume_packet(PRJ)
        elif harmless == "run_an_evidence_probe":
            engine.probe_evidence(PRJ)
        elif harmless == "record_an_audit_entry":
            engine.store.audit(actor="someone", action="unrelated.thing")
        elif harmless == "ingest_an_unrelated_event":
            engine.ingest_github(PRJ, "issues", "unrelated-1", {
                "action": "opened",
                "issue": {"number": 99, "title": "T",
                          "body": "An unrelated observation.", "state": "open",
                          "labels": [], "author_association": "OWNER",
                          "created_at": "2026-07-31T10:00:00Z"},
                "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}})
        assert _attempt(engine, task.id, proof) is None, \
            f"{harmless} spuriously blocked an otherwise valid completion"
        engine.close()

    def test_a_non_critical_invalidation_elsewhere_does_not_block(self, tmp_path):
        """Only invalidations that touch this task, or critical ones, count."""
        engine, task, proof, _ = _good(tmp_path)
        unrelated = engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id,
            project_id=PRJ, data={"statement": "the office wifi is fast"},
            status="active", criticality="low")
        engine.invalidation.fire(
            tenant_id=engine.tenant_id, project_id=PRJ,
            target_node_id=unrelated.id, trigger_type="dependency_drift",
            trigger_confidence=0.95)
        assert _attempt(engine, task.id, proof) is None, \
            "an unrelated low-severity invalidation blocked completion"
        engine.close()

    def test_uncontested_atomic_proof_claim_does_not_block(
            self, tmp_path, monkeypatch):
        """Exercise the claim-race boundary with its harmless result."""
        engine, task, proof, _ = _good(tmp_path)
        original = engine._claim_proof
        calls = []

        def observe_claim(project_id, proof_id, task_id):
            calls.append((project_id, proof_id, task_id))
            return original(project_id, proof_id, task_id)

        monkeypatch.setattr(engine, "_claim_proof", observe_claim)
        assert _attempt(engine, task.id, proof) is None
        assert calls == [(PRJ, proof["proof_id"], task.id)]
        engine.close()


class TestGateCoverageIsComplete:
    """If a new rejection path is added without a negative control, say so.

    This class is the instrument for the instrument. Its own three defects —
    a substring count that a comment could inflate, no check that a NAMED
    gate is actually exercised, and a blind spot for any exception type but
    one — were the kind that leave a harness reporting full coverage of
    something it stopped covering (ADR-067).
    """

    @staticmethod
    def _rejection_count() -> int:
        """Rejections in complete_task, counted from the PARSED function.

        Counting `source.count("raise PermissionError")` counted text: a
        comment or a string literal mentioning the phrase inflated it, and a
        gate raised through a helper did not appear at all. The AST counts
        raise statements.
        """
        import ast
        import inspect
        import textwrap

        from causal_continuity_engine import engine as engine_module
        tree = ast.parse(textwrap.dedent(
            inspect.getsource(engine_module.Engine._complete_task_locked)))
        return sum(
            1 for node in ast.walk(tree)
            if isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id in {t.__name__ for t in REJECTION_TYPES})

    def test_every_rejection_path_has_a_named_gate(self):
        raises = self._rejection_count()
        assert raises == len(GATES), (
            f"complete_task has {raises} rejection paths but GATES names "
            f"{len(GATES)}. Add the new gate here with a planted defect that "
            f"trips it, or this harness silently stops covering it.")

    def test_every_named_gate_has_a_planted_defect_that_trips_it(self):
        """A name in GATES with no test behind it is coverage on paper.

        The count above would still pass: GATES and the rejection paths would
        agree while one of them was never exercised.
        """
        import inspect
        source = inspect.getsource(TestEachDefectTripsItsOwnGate)
        unexercised = sorted(name for name in GATES
                             if f'== "{name}"' not in source)
        assert not unexercised, (
            f"named but never planted: {unexercised}. Each gate needs a test "
            f"that plants its defect and asserts THAT gate catches it.")

    def test_the_counter_is_not_fooled_by_text(self):
        """Validates the instrument's own instrument: the AST counter must
        ignore a mention of the phrase that is not a raise."""
        import ast
        source = 'def f():\n    x = "raise PermissionError"  # raise ValueError\n'
        tree = ast.parse(source)
        assert not [n for n in ast.walk(tree) if isinstance(n, ast.Raise)], \
            "the counter would credit a comment or string as a rejection path"
