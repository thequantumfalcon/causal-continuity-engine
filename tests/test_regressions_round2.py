"""Regression tests for the second adversarial review round.

R1 is the important one: the earlier suite only ever fed complete_task
hand-built ProofEnvelope output, so the engine's real attest -> complete
path was broken end to end while every test passed. These tests drive the
engine's own API, never a hand-assembled envelope.
"""

import json
import shlex
import sys

import pytest

from causal_continuity_engine.engine import Engine, stable_node_id
from causal_continuity_engine.proof import ProofEnvelope, verify_envelope
from causal_continuity_engine.verifiers import VerifierSpec

PRJ = "prj_r2"
REPOSITORY_ID = 2002


def _python_command(source: str) -> str:
    return shlex.join([sys.executable, "-c", source])


PASS_COMMAND = _python_command("raise SystemExit(0)")
FAIL_COMMAND = _python_command("raise SystemExit(1)")


@pytest.fixture
def engine(tmp_path):
    e = Engine(workdir=tmp_path)
    e.create_project("p", project_id=PRJ, repository_id=REPOSITORY_ID,
                     config={"require_proof_for": ["task_complete"],
                             "required_verifiers": [
                                 {"name": "unit-tests",
                                  "command": PASS_COMMAND}]})
    yield e
    e.close()


def _allow(engine, level=2, command=PASS_COMMAND):
    """A realistic policy: proof required AND a pinned verifier saying what
    would count as proof. Requiring the first without the second is refused
    as a misconfiguration (ADR-045). `command` lets a test pin a check that
    genuinely fails."""
    engine.policy.grant(project_id=PRJ, level=level, granted_by="lead")
    engine.policy.set_project_config(
        PRJ, {"max_autonomy_level": level, "require_proof_for": ["task_complete"],
              "required_verifiers": [{"name": "unit-tests", "command": command}]})


class TestR1RealTrustPipeline:
    """attest_action output must verify and be accepted by complete_task."""

    def test_attest_output_passes_its_own_verification(self, engine):
        _allow(engine)
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="feature done",
            actor={"agent": "test"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=PASS_COMMAND)])
        assert proof["status"] == "verified"
        check = verify_envelope(proof, engine.signer)
        assert check["valid"], f"engine's own proof fails verification: {check}"

    def test_attest_then_complete_task_succeeds(self, engine):
        """The end-to-end path the product exists to support."""
        _allow(engine)
        task = engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"title": "ship the exporter"}, status="open")
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="exporter done",
            actor={"agent": "test"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=PASS_COMMAND)],
            continuity={"task_ids": [task.id]})
        out = engine.complete_task(PRJ, task.id, proof=proof)
        assert out["status"] == "verified"
        assert out["data"]["completion_evidence"] == proof["proof_id"]

    def test_proof_binds_its_action_node_inside_the_signature(self, engine):
        _allow(engine)
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="done",
            actor={"agent": "test"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=PASS_COMMAND)])
        node_id = proof["continuity_links"]["proof_node_id"]
        node = engine.graph.get(node_id)
        assert node["data"]["proof_id"] == proof["proof_id"]
        assert node["data"]["proof_digest"] == proof["proof_digest"]
        assert node["status"] == "verified"
        # the binding is signed: altering it invalidates the envelope
        tampered = json.loads(json.dumps(proof))
        tampered["continuity_links"]["proof_node_id"] = "act_someone_elses"
        assert not verify_envelope(tampered, engine.signer)["valid"]

    def test_failed_attest_still_verifies_and_is_still_rejected(self, engine):
        """A failed proof must be authentic (verifiable) AND refused."""
        _allow(engine, command=FAIL_COMMAND)
        task = engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"title": "broken work"}, status="open")
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="claimed done",
            actor={"agent": "test"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=FAIL_COMMAND)])
        assert proof["status"] == "failed"
        assert verify_envelope(proof, engine.signer)["valid"], \
            "a failed proof must still be an authentic record"
        with pytest.raises(PermissionError, match="not 'verified'"):
            engine.complete_task(PRJ, task.id, proof=proof)
        assert engine.policy.active_downgrade_ceiling(PRJ) == 1

    def test_tampering_with_a_real_proof_is_still_caught(self, engine):
        _allow(engine, command=FAIL_COMMAND)
        task = engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"title": "t"}, status="open")
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="done",
            actor={"agent": "test"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=FAIL_COMMAND)])
        forged = json.loads(json.dumps(proof))
        forged["status"] = "verified"
        forged["verifications"][0]["result"] = "passed"
        with pytest.raises(PermissionError, match="tampered"):
            engine.complete_task(PRJ, task.id, proof=forged)

    def test_cli_verify_path_produces_a_verifiable_proof(self, engine):
        """cmd_verify's shape: specs from the CLI, proof printed to the user."""
        _allow(engine)
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="verify sanity",
            actor={"agent": "cli", "model": "n/a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="sanity", kind="command",
                                         command=PASS_COMMAND)])
        assert proof["status"] == "verified"
        assert verify_envelope(proof, engine.signer)["valid"]


class TestR2FailedVerifierNeverMasked:
    """A recorded failure stands even if a later duplicate passes."""

    def test_failed_then_passed_is_failed(self, engine):
        env = ProofEnvelope(tenant_id=engine.tenant_id, project_id=PRJ,
                            intent_type="task_complete", intent_statement="x",
                            actor={"agent": "t"})
        env.add_verification({"verifier": "tests", "result": "failed",
                             "source": "executed"})
        env.add_verification({"verifier": "tests", "result": "passed",
                             "source": "executed"})
        out = env.finalize(engine.signer, ["tests"])
        assert out["status"] == "failed"
        assert out["verification_summary"]["failed"] == ["tests"]

    def test_order_does_not_change_the_verdict(self, engine):
        def build(order):
            env = ProofEnvelope(tenant_id=engine.tenant_id, project_id=PRJ,
                                intent_type="task_complete", intent_statement="x",
                                actor={"agent": "t"})
            for r in order:
                env.add_verification({"verifier": "tests", "result": r,
                                      "source": "executed"})
            return env.finalize(engine.signer, ["tests"])["status"]
        assert build(["failed", "passed"]) == build(["passed", "failed"]) == "failed"

    def test_inconclusive_then_passed_is_inconclusive(self, engine):
        env = ProofEnvelope(tenant_id=engine.tenant_id, project_id=PRJ,
                            intent_type="task_complete", intent_statement="x",
                            actor={"agent": "t"})
        env.add_verification({"verifier": "tests", "result": "inconclusive",
                             "source": "executed"})
        env.add_verification({"verifier": "tests", "result": "passed",
                             "source": "executed"})
        assert env.finalize(engine.signer, ["tests"])["status"] == "inconclusive"

    def test_retry_pattern_through_the_engine_is_not_laundered(self, engine):
        """Pinning removes the retry vector by construction: both caller
        specs are displaced and only the policy's command runs (ADR-024)."""
        _allow(engine, command=FAIL_COMMAND)
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="retried",
            actor={"agent": "t"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=FAIL_COMMAND),
                            VerifierSpec(name="unit-tests", command=PASS_COMMAND)])
        assert proof["status"] == "failed", "a red run was laundered by a retry"
        assert [v["verifier"] for v in proof["verifications"]] == ["unit-tests"]
        assert engine.policy.active_downgrade_ceiling(PRJ) == 1

    def test_caller_supplied_history_is_not_laundered(self, engine):
        """Caller claims cannot pass or poison the policy's observed check."""
        _allow(engine)
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="history",
            actor={"agent": "t"}, action_type="run_verifier",
            verification_outcomes=[
                {"verifier": "unit-tests", "result": "failed"},
                {"verifier": "unit-tests", "result": "passed"}])
        assert proof["status"] == "verified"
        authoritative = [
            item for item in proof["verifications"]
            if item["source"] == "executed"]
        asserted = [
            item for item in proof["verifications"]
            if item["source"] == "self_asserted"]
        assert [item["result"] for item in authoritative] == ["passed"]
        assert [item["result"] for item in asserted] == ["failed", "passed"]


class TestR3RedactionBeforeExtraction:
    """Graph content must never contain what the capture mode dropped."""

    SECRET = "ghp_ABCDEFghijklmnopqrstuvwx123456"

    def _issue(self, body, number=1):
        return {"action": "opened",
                "issue": {"number": number, "title": "T", "body": body,
                          "state": "open", "labels": [],
                          "author_association": "OWNER",
                          "created_at": "2026-07-29T10:00:00Z"},
                "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}}

    def test_secret_never_reaches_graph_nodes(self, engine):
        engine.ingest_github(PRJ, "issues", "d1", self._issue(
            f"The client must send token {self.SECRET} in every request header."))
        dump = json.dumps([dict(n) for n in engine.graph.current(PRJ)], default=str)
        assert self.SECRET not in dump, "raw secret persisted in the graph"
        assert "[REDACTED:github_token]" in dump

    def test_secret_never_reaches_the_resume_packet(self, engine):
        engine.ingest_github(PRJ, "issues", "d1", self._issue(
            f"The client must send token {self.SECRET} in every request header."))
        assert self.SECRET not in json.dumps(engine.resume_packet(PRJ), default=str)

    def test_rebuild_matches_in_redacted_mode(self, engine):
        engine.ingest_github(PRJ, "issues", "d1", self._issue(
            f"The client must send token {self.SECRET} in every request header."))
        before = engine.projection_fingerprint(PRJ)
        fresh = engine.rebuild_projection(PRJ)
        assert fresh.projection_fingerprint(PRJ) == before
        fresh.close()

    def test_metadata_only_mode_extracts_nothing_and_replays_identically(self):
        e = Engine()
        e.create_project(
            "p", project_id=PRJ, repository_id=REPOSITORY_ID,
            capture_mode="metadata_only")
        e.ingest_github(PRJ, "issues", "d1", self._issue(
            "The exporter must produce reconciled CSV files nightly."))
        dump = json.dumps([dict(n) for n in e.graph.current(PRJ)], default=str)
        assert "reconciled CSV" not in dump, \
            "metadata_only kept content it promised to drop"
        before = e.projection_fingerprint(PRJ)
        fresh = e.rebuild_projection(PRJ)
        assert fresh.projection_fingerprint(PRJ) == before
        fresh.close()
        e.close()


class TestR4AliasedSourceRefs:
    """One statement in two issues is one node held by two sources."""

    def _issue(self, number, body, action="opened"):
        return {"action": action,
                "issue": {"number": number, "title": "T", "body": body,
                          "state": "open", "labels": [],
                          "author_association": "OWNER",
                          "created_at": "2026-07-29T10:00:00Z"},
                "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}}

    REQ = "The exporter must write CSV output."

    def test_edit_of_one_source_does_not_invalidate_a_still_stated_requirement(
            self, engine):
        engine.ingest_github(PRJ, "issues", "d1", self._issue(1, self.REQ))
        engine.ingest_github(PRJ, "issues", "d2", self._issue(3, self.REQ))
        node_id = stable_node_id(PRJ, "requirement",
                                 "The exporter must write CSV output")
        assert len(engine.graph.get(node_id)["data"]["source_refs"]) == 2
        # issue 3 is edited to drop it; issue 1 still states it
        r = engine.ingest_github(PRJ, "issues", "d3", self._issue(
            3, "The exporter must write JSON output.", action="edited"))
        node = engine.graph.get(node_id)
        assert node["status"] not in ("invalidated", "superseded"), \
            "requirement retired though another issue still states it"
        assert node["data"]["source_refs"] == ["issue:1:body"]
        # it survives as a contested requirement awaiting human resolution
        assert node["status"] == "uncertain"
        assert node["data"].get("conflict_requires_resolution") is True
        assert any(c.get("requires_resolution") for c in r["conflicts"])
        pkt = engine.resume_packet(PRJ)
        assert any("CSV" in req["summary"]
                   for req in pkt["authority"]["active_requirements"])

    def test_last_source_dropping_it_does_invalidate(self, engine):
        engine.ingest_github(PRJ, "issues", "d1", self._issue(1, self.REQ))
        engine.ingest_github(PRJ, "issues", "d2", self._issue(3, self.REQ))
        node_id = stable_node_id(PRJ, "requirement",
                                 "The exporter must write CSV output")
        engine.ingest_github(PRJ, "issues", "d3", self._issue(
            3, "The exporter must write JSON output.", action="edited"))
        engine.ingest_github(PRJ, "issues", "d4", self._issue(
            1, "The exporter must write JSON output.", action="edited"))
        assert engine.graph.get(node_id)["status"] == "invalidated"
        assert any(i["data"]["trigger_type"] == "changed_requirement"
                   for i in engine.invalidation.open_invalidations(PRJ))

    def test_single_source_edit_still_invalidates(self, engine):
        engine.ingest_github(PRJ, "issues", "d1", self._issue(1, self.REQ))
        node_id = stable_node_id(PRJ, "requirement",
                                 "The exporter must write CSV output")
        engine.ingest_github(PRJ, "issues", "d2", self._issue(
            1, "The exporter must write JSON output.", action="edited"))
        assert engine.graph.get(node_id)["status"] == "invalidated"


class TestR5ProofBinding:
    """A signature proves a record is genuine, not what it is evidence FOR.
    A proof must also be scoped, subject-bound, and single-use.
    """

    def _task(self, engine, title, project_id=PRJ):
        return engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=project_id,
            data={"title": title}, status="open")

    def _proof_for(self, engine, task, project_id=PRJ):
        return engine.attest_action(
            project_id, intent_type="task_complete",
            intent_statement=f"{task['data']['title']} done",
            actor={"agent": "a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=PASS_COMMAND)],
            continuity={"task_ids": [task["node_id"]]})

    def test_proof_cannot_be_replayed_onto_another_task(self, engine):
        _allow(engine)
        t1, t2 = self._task(engine, "task ONE"), self._task(engine, "task TWO")
        proof = self._proof_for(engine, t1)
        engine.complete_task(PRJ, t1["node_id"], proof=proof)
        with pytest.raises(PermissionError, match="does not name task"):
            engine.complete_task(PRJ, t2["node_id"], proof=proof)
        assert engine.graph.get(t2["node_id"])["status"] == "open"

    def test_proof_is_single_use_even_for_its_own_task(self, engine):
        """A proof naming two tasks may still only be spent once."""
        _allow(engine)
        t1, t2 = self._task(engine, "task ONE"), self._task(engine, "task TWO")
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="both done",
            actor={"agent": "a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=PASS_COMMAND)],
            continuity={"task_ids": [t1["node_id"], t2["node_id"]]})
        engine.complete_task(PRJ, t1["node_id"], proof=proof)
        with pytest.raises(PermissionError, match="already used"):
            engine.complete_task(PRJ, t2["node_id"], proof=proof)

    def test_proof_from_another_project_is_refused(self, engine):
        _allow(engine)
        other = Engine(signer=engine.signer)          # same tenant + key
        other.create_project("o", project_id="prj_other")
        other.policy.grant(project_id="prj_other", level=2, granted_by="lead")
        other.policy.set_project_config("prj_other", {"max_autonomy_level": 2})
        foreign_task = self._task(other, "their task", project_id="prj_other")
        foreign = self._proof_for(other, foreign_task, project_id="prj_other")
        assert foreign["status"] == "verified"
        mine = self._task(engine, "my task")
        with pytest.raises(PermissionError, match="issued for"):
            engine.complete_task(PRJ, mine["node_id"], proof=foreign)
        assert engine.graph.get(mine["node_id"])["status"] == "open"
        other.close()

    def test_unbound_proof_is_refused(self, engine):
        _allow(engine)
        task = self._task(engine, "unbound")
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="done",
            actor={"agent": "a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests", command=PASS_COMMAND)])
        with pytest.raises(PermissionError, match="does not name task"):
            engine.complete_task(PRJ, task["node_id"], proof=proof)

    def test_correctly_bound_proof_still_completes(self, engine):
        _allow(engine)
        task = self._task(engine, "properly attested")
        proof = self._proof_for(engine, task)
        out = engine.complete_task(PRJ, task["node_id"], proof=proof)
        assert out["status"] == "verified"
