"""Round 4 — verifier-boundary defects reproduced against CCE.

Two were exploitable against the then-current engine and are reproduced here in
the form that worked:

  S1  a required verifier bound a NAME, so `VerifierSpec(name="unit-tests",
      command="/usr/bin/true")` produced a signed 'verified' proof
  S2  evidence was a VERDICT, so a conftest that rewrites pytest's report
      produced `1 passed`, exit 0, and a completed task with the work undone

S2 cannot be closed by hardening alone — a test must import the code under
test — so it is answered by making the runner render the verdict from
emitted values, by negative controls, and by mutation probes.
"""

import json
import shlex
import sqlite3
import subprocess
import sys

import pytest

from causal_continuity_engine import capabilities
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.evidence import grade_evidence
from causal_continuity_engine.store import Store
from causal_continuity_engine.verifiers import (
    UnsafeCommandError,
    VerifierRunner,
    VerifierSpec,
    check_command_safety,
)

PRJ = "prj_r4"


def _python_command(*args: str) -> str:
    return shlex.join([sys.executable, *args])


PASS_COMMAND = _python_command("-c", "raise SystemExit(0)")
FAIL_COMMAND = _python_command("-c", "raise SystemExit(1)")


def _engine(tmp_path, **config):
    e = Engine(workdir=tmp_path)
    cfg = {"max_autonomy_level": 2, "require_proof_for": ["task_complete"], **config}
    e.create_project("p", project_id=PRJ, config=cfg)
    e.policy.grant(project_id=PRJ, level=2, granted_by="lead")
    e.policy.set_project_config(PRJ, cfg)
    return e


def _task(engine, title="work"):
    return engine.graph.put_node(
        entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
        data={"title": title}, status="open")


class TestS1PinnedVerifierCannotBeSubstituted:
    def test_claimant_command_is_discarded_for_a_pinned_verifier(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "unit-tests", "command": FAIL_COMMAND}])
        task = _task(e)
        proof = e.attest_action(
            PRJ, intent_type="task_complete", intent_statement="done",
            actor={"agent": "a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests",
                                         command=PASS_COMMAND)],
            continuity={"task_ids": [task.id]})
        assert proof["status"] == "failed", "substitution passed the gate"
        with pytest.raises(PermissionError):
            e.complete_task(PRJ, task.id, proof=proof)
        e.close()

    def test_the_policys_command_is_what_actually_ran(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "unit-tests", "command": PASS_COMMAND}])
        proof = e.attest_action(
            PRJ, intent_type="task_complete", intent_statement="done",
            actor={"agent": "a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests",
                                         command=FAIL_COMMAND)])
        v = proof["verifications"][0]
        assert v["result"] == "passed" and v["pinned"] is True
        assert v["command_digest"] == VerifierSpec(
            name="x", command=PASS_COMMAND).command_digest
        e.close()

    def test_displacement_is_audited(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "unit-tests", "command": PASS_COMMAND}])
        e.attest_action(PRJ, intent_type="task_complete", intent_statement="x",
                        actor={"agent": "a"}, action_type="run_verifier",
                        verifier_specs=[VerifierSpec(name="unit-tests",
                                                     command=PASS_COMMAND)])
        assert e.store.audit_entries("verifier.displaced")
        e.close()

    def test_unpinned_name_is_recorded_as_claimant_chosen(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=["unit-tests"])
        proof = e.attest_action(
            PRJ, intent_type="task_complete", intent_statement="x",
            actor={"agent": "a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="unit-tests",
                                         command=PASS_COMMAND)])
        assert proof["evidence_context"]["unpinned_required"] == ["unit-tests"]
        assert e.grade_proof(PRJ, proof).grade == "D"
        e.close()

    def test_caller_may_still_add_extra_verifiers(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "unit-tests", "command": PASS_COMMAND}])
        proof = e.attest_action(
            PRJ, intent_type="task_complete", intent_statement="x",
            actor={"agent": "a"}, action_type="run_verifier",
            verifier_specs=[VerifierSpec(name="extra", command=PASS_COMMAND)])
        assert {v["verifier"] for v in proof["verifications"]} == {
            "unit-tests", "extra"}
        assert proof["status"] == "verified"
        e.close()


class TestS2EvidenceIsValuesNotVerdicts:
    """A subject that lies must lie about the VALUES, which the declared
    expectations catch, rather than about the verdict it no longer renders."""

    def _oracle_tree(self, tmp_path, contents="one line"):
        (tmp_path / "deliverable.txt").write_text(contents)
        (tmp_path / "oracle.py").write_text(
            "import json, pathlib\n"
            "p = pathlib.Path('deliverable.txt')\n"
            "print(json.dumps({'exists': p.exists(), "
            "'lines': len(p.read_text().splitlines()) if p.exists() else 0}))\n")
        return {"name": "shape", "kind": "value-oracle",
                "command": _python_command("oracle.py"),
                "expected_properties": {"values": {"exists": True, "lines": 1}},
                "artifacts": ["deliverable.txt"]}

    def test_runner_judges_the_values(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[self._oracle_tree(tmp_path)])
        proof = e.attest_action(PRJ, intent_type="task_complete",
                                intent_statement="x", actor={"agent": "a"},
                                action_type="run_verifier")
        v = proof["verifications"][0]
        assert v["result"] == "passed"
        assert v["observed"] == {"exists": True, "lines": 1}
        e.close()

    def test_wrong_values_fail_even_on_exit_zero(self, tmp_path):
        """The oracle exits 0 while reporting values that do not match."""
        spec = self._oracle_tree(tmp_path, contents="line one\nline two")
        e = _engine(tmp_path, required_verifiers=[spec])
        proof = e.attest_action(PRJ, intent_type="task_complete",
                                intent_statement="x", actor={"agent": "a"},
                                action_type="run_verifier")
        v = proof["verifications"][0]
        assert v["exit_code"] == 0, "the subject exited successfully"
        assert v["result"] == "failed", "the runner still rejected the values"
        assert "lines" in v["details"]
        e.close()

    def test_non_json_output_is_inconclusive_not_passed(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[{
            "name": "shape", "kind": "value-oracle", "command": PASS_COMMAND,
            "expected_properties": {"values": {"x": 1}}}])
        proof = e.attest_action(PRJ, intent_type="task_complete",
                                intent_statement="x", actor={"agent": "a"},
                                action_type="run_verifier")
        assert proof["verifications"][0]["result"] == "inconclusive"
        e.close()

    def test_policy_oracle_without_expectations_is_rejected(self, tmp_path):
        e = Engine(workdir=tmp_path)
        with pytest.raises(ValueError, match="at least one expected value"):
            e.create_project("p", project_id=PRJ, config={
                "required_verifiers": [{
                    "name": "shape", "kind": "value-oracle",
                    "command": _python_command("-c", "print('{}')")}],
            })
        assert e.store._conn.execute(
            "SELECT 1 FROM nodes WHERE node_id = ?", (PRJ,)).fetchone() is None
        e.close()


class TestS2MutationProbeCatchesUnboundEvidence:
    def test_check_that_ignores_the_deliverable_is_unbound(self, tmp_path):
        (tmp_path / "deliverable.txt").write_text("content")
        e = _engine(tmp_path, required_verifiers=[
            {"name": "vacuous", "command": PASS_COMMAND,
             "artifacts": ["deliverable.txt"]}])
        report = e.probe_evidence(PRJ)
        assert not report.bound
        assert len(report.undetected) == 2          # absent + truncate
        e.close()

    def test_check_that_reads_the_deliverable_is_bound(self, tmp_path):
        (tmp_path / "deliverable.txt").write_text("content")
        e = _engine(tmp_path, required_verifiers=[
            {"name": "reads-it",
             "command": _python_command(
                 "-c", "import pathlib,sys; "
                 "sys.exit(0 if pathlib.Path('deliverable.txt').read_text() else 1)"),
             "artifacts": ["deliverable.txt"]}])
        report = e.probe_evidence(PRJ)
        assert report.bound, report.undetected
        assert len(report.detected) == 2
        e.close()

    def test_probe_never_touches_the_real_tree(self, tmp_path):
        target = tmp_path / "deliverable.txt"
        target.write_text("precious")
        e = _engine(tmp_path, required_verifiers=[
            {"name": "vacuous", "command": PASS_COMMAND,
             "artifacts": ["deliverable.txt"]}])
        e.probe_evidence(PRJ)
        assert target.read_text() == "precious"
        e.close()

    def test_absolute_artifact_path_is_refused(self, tmp_path):
        absolute = str((tmp_path / "outside").resolve())
        e = Engine(workdir=tmp_path)
        with pytest.raises(ValueError, match="project-relative"):
            e.create_project("p", project_id=PRJ, config={
                "required_verifiers": [{
                    "name": "v", "command": PASS_COMMAND,
                    "artifacts": [absolute]}],
            })
        assert e.store._conn.execute(
            "SELECT 1 FROM nodes WHERE node_id = ?", (PRJ,)).fetchone() is None
        e.close()

    def test_no_declared_artifacts_is_not_silently_bound(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "v", "command": PASS_COMMAND}])
        report = e.probe_evidence(PRJ)
        assert not report.bound and "no declared artifacts" in report.error
        e.close()


class TestS2NegativeControls:
    def test_control_that_passes_marks_the_check_vacuous(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "always-green", "command": PASS_COMMAND,
             "expect_fail_command": PASS_COMMAND}])
        proof = e.attest_action(PRJ, intent_type="task_complete",
                                intent_statement="x", actor={"agent": "a"},
                                action_type="run_verifier")
        control = proof["verifications"][0]["control"]
        assert control["status"] == "unmet"
        assert e.grade_proof(PRJ, proof).grade == "C"
        e.close()

    def test_control_that_fails_is_held(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "real", "command": PASS_COMMAND,
             "expect_fail_command": FAIL_COMMAND}])
        proof = e.attest_action(PRJ, intent_type="task_complete",
                                intent_statement="x", actor={"agent": "a"},
                                action_type="run_verifier")
        assert proof["verifications"][0]["control"]["status"] == "held"
        e.close()

    def test_absent_control_caps_the_grade_at_c(self, tmp_path):
        e = _engine(tmp_path, required_verifiers=[
            {"name": "no-control", "command": PASS_COMMAND}])
        proof = e.attest_action(PRJ, intent_type="task_complete",
                                intent_statement="x", actor={"agent": "a"},
                                action_type="run_verifier")
        assert proof["verifications"][0]["control"]["status"] == "absent"
        assert e.grade_proof(PRJ, proof).grade == "C"
        e.close()


class TestEvidenceGradeGate:
    def test_min_grade_blocks_completion(self, tmp_path):
        e = _engine(tmp_path, min_evidence_grade="B", required_verifiers=[
            {"name": "no-control", "command": PASS_COMMAND}])
        task = _task(e)
        proof = e.attest_action(
            PRJ, intent_type="task_complete", intent_statement="x",
            actor={"agent": "a"}, action_type="run_verifier",
            continuity={"task_ids": [task.id]})
        assert proof["status"] == "verified"
        with pytest.raises(PermissionError, match="evidence grade"):
            e.complete_task(PRJ, task.id, proof=proof)
        e.close()

    def test_good_evidence_passes_the_gate(self, tmp_path):
        e = _engine(tmp_path, min_evidence_grade="C", required_verifiers=[
            {"name": "real", "command": PASS_COMMAND,
             "expect_fail_command": FAIL_COMMAND}])
        task = _task(e)
        proof = e.attest_action(
            PRJ, intent_type="task_complete", intent_statement="x",
            actor={"agent": "a"}, action_type="run_verifier",
            continuity={"task_ids": [task.id]})
        assert e.complete_task(PRJ, task.id, proof=proof)["status"] == "verified"
        e.close()

    def test_self_asserted_evidence_grades_f(self):
        grade = grade_evidence(
            outcomes=[{"verifier": "t", "result": "passed",
                       "source": "self_asserted"}],
            required=["t"])
        assert grade.grade == "F"

    def test_no_required_checks_grades_f(self):
        assert grade_evidence(outcomes=[], required=[]).grade == "F"


class TestVerifierHardening:
    @pytest.mark.parametrize("program", ["env", "sh", "bash", "timeout", "xargs"])
    def test_indirection_programs_are_refused(self, program):
        with pytest.raises(UnsafeCommandError):
            check_command_safety(f"{program} something-else")

    def test_direct_command_is_allowed(self):
        check_command_safety("/usr/bin/pytest -q")

    def test_indirection_yields_inconclusive_not_passed(self, tmp_path):
        out = VerifierRunner(None, tmp_path).run(
            VerifierSpec(name="v", command="/usr/bin/env true"))
        assert out.result == "inconclusive"

    def test_home_is_not_exposed_to_the_check(self, tmp_path):
        script = tmp_path / "e.py"
        script.write_text("import os,json; print(json.dumps({'home': "
                          "os.environ.get('HOME')}))")
        out = VerifierRunner(None, tmp_path).run(VerifierSpec(
            name="v", kind="value-oracle",
            command=_python_command("e.py"),
            expected_properties={"values": {"home": None}}))
        assert out.result == "passed", f"HOME leaked: {out.observed}"

    def test_missing_interpreter_is_inconclusive_not_failed(self, tmp_path):
        out = VerifierRunner(None, tmp_path).run(VerifierSpec(
            name="v", command=_python_command("-m", "definitely_not_a_module_xyz")))
        assert out.result == "inconclusive", \
            "an environment problem was reported as a failed check"


class TestTamperEvidence:
    def _store(self, tmp_path, n=4):
        s = Store(tmp_path / "t.db")
        for i in range(n):
            s.append_event(tenant_id="t", project_id="p", source_type="test",
                           idempotency_key=f"k{i}", payload={"i": i},
                           authority="repository_authoritative")
        s.audit(actor="lead", action="policy.grant", detail="level 2")
        return s

    def test_fresh_chains_are_intact(self, tmp_path):
        s = self._store(tmp_path)
        assert s.verify_chain("events")["intact"]
        assert s.verify_chain("audit_log")["intact"]
        s.close()

    @pytest.mark.parametrize("sql", [
        "UPDATE audit_log SET detail='level 3' WHERE seq=1",
        "DELETE FROM audit_log WHERE seq=1",
        "UPDATE events SET authority='tenant_policy' WHERE seq=2",
        "DELETE FROM events WHERE seq=2",
        "UPDATE events SET payload_digest='sha256:0' WHERE seq=2",
    ])
    def test_triggers_refuse_mutation(self, tmp_path, sql):
        s = self._store(tmp_path)
        with pytest.raises(sqlite3.IntegrityError):
            s._conn.execute(sql)
        s.close()

    def test_retention_redaction_is_still_allowed(self, tmp_path):
        from causal_continuity_engine.graph import Graph
        from causal_continuity_engine.memory import Memory
        s = self._store(tmp_path)
        m = Memory(s, Graph(s))
        assert m.sweep_retention(raw_days=0) == 4
        assert s.verify_chain("events")["intact"], \
            "redaction broke the chain: privacy and integrity must not trade"
        s.close()

    def test_chain_detects_a_rewrite_after_triggers_are_dropped(self, tmp_path):
        s = self._store(tmp_path)
        s.close()
        raw = sqlite3.connect(tmp_path / "t.db")
        for (name,) in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
            raw.execute(f"DROP TRIGGER {name}")
        raw.execute("UPDATE events SET authority='tenant_policy' WHERE seq=2")
        raw.commit()
        raw.close()
        s = Store(tmp_path / "t.db")
        result = s.verify_chain("events")
        assert not result["intact"] and result["checked"] == 2
        s.close()

    def test_anchor_detects_tail_truncation(self, tmp_path):
        s = self._store(tmp_path)
        anchor = s.export_anchor("events")
        assert anchor["count"] == 4
        s.close()
        raw = sqlite3.connect(tmp_path / "t.db")
        for (name,) in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
            raw.execute(f"DROP TRIGGER {name}")
        raw.execute("DELETE FROM events WHERE seq >= 3")
        raw.commit()
        raw.close()
        s = Store(tmp_path / "t.db")
        assert s.verify_chain("events")["intact"], \
            "precondition: truncation leaves a self-consistent chain"
        result = s.verify_against_anchor(anchor)
        assert not result["ok"] and "removed from the tail" in result["reason"]
        s.close()

    def test_anchor_accepts_honest_growth(self, tmp_path):
        s = self._store(tmp_path)
        anchor = s.export_anchor("events")
        s.append_event(tenant_id="t", project_id="p", source_type="test",
                       idempotency_key="later", payload={"i": 99},
                       authority="repository_authoritative")
        result = s.verify_against_anchor(anchor)
        assert result["ok"] and result["appended_since"] == 1
        s.close()

    def test_anchor_detects_rewritten_prefix(self, tmp_path):
        s = self._store(tmp_path)
        anchor = s.export_anchor("events")
        s.close()
        raw = sqlite3.connect(tmp_path / "t.db")
        for (name,) in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
            raw.execute(f"DROP TRIGGER {name}")
        raw.execute("UPDATE events SET entry_hash='sha256:deadbeef' WHERE seq=4")
        raw.commit()
        raw.close()
        s = Store(tmp_path / "t.db")
        assert not s.verify_against_anchor(anchor)["ok"]
        s.close()


class TestCapabilitiesAudit:
    def test_every_claim_resolves(self):
        failures = [(r.capability.requirement, r.problems)
                    for r in capabilities.verify() if not r.ok]
        assert not failures, f"stale capability claims: {failures}"

    def test_implemented_requires_symbols_and_tests(self):
        with pytest.raises(ValueError, match="requires both"):
            capabilities.Capability(
                requirement="X-1", layer="Core", summary="s",
                status="implemented", honest_limit="none")

    def test_every_claim_records_an_honest_limit(self):
        missing = [c.requirement for c in capabilities.CAPABILITIES
                   if c.status in ("implemented", "partial") and not c.honest_limit]
        assert not missing

    def test_a_broken_claim_is_detected(self):
        bogus = capabilities.Capability(
            requirement="X-2", layer="Core", summary="s", status="implemented",
            honest_limit="l",
            symbols=("causal_continuity_engine.graph:NoSuchThing",),
            tests=("tests/test_regressions_round4.py",))
        result = capabilities.verify([bogus])[0]
        assert not result.ok and "does not resolve" in result.problems[0]

    def test_audit_runs_as_a_module(self):
        proc = subprocess.run([sys.executable, "-m", "causal_continuity_engine.capabilities"],
                              capture_output=True, text=True,
                              cwd=str(capabilities.ROOT))
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_markdown_is_generated_from_declarations(self):
        md = capabilities.render_markdown()
        assert "| EV-007 |" in md and "mechanical LOWER BOUND" in md


class TestStrangerVerifiableSignatures:
    """HMAC verification requires the signing key, so a CCE proof was
    checkable only by its issuer. Lamport closes that — but only when the
    key fingerprint arrives from somewhere other than the artifact."""

    def _proof(self, tmp_path):
        from causal_continuity_engine.lamport import LamportSigner
        signer = LamportSigner("issuer-a")
        e = Engine(workdir=tmp_path, signer=signer)
        cfg = {"max_autonomy_level": 2, "require_proof_for": ["task_complete"],
               "required_verifiers": [{"name": "t", "command": PASS_COMMAND}]}
        e.create_project("p", project_id=PRJ, config=cfg)
        e.policy.grant(project_id=PRJ, level=2, granted_by="lead")
        e.policy.set_project_config(PRJ, cfg)
        proof = e.attest_action(PRJ, intent_type="task_complete",
                                intent_statement="x", actor={"agent": "a"},
                                action_type="run_verifier")
        e.close()
        return proof, signer

    def test_engine_proofs_verify_under_lamport(self, tmp_path):
        from causal_continuity_engine.proof import verify_envelope
        proof, signer = self._proof(tmp_path)
        assert proof["status"] == "verified"
        assert verify_envelope(proof, signer)["valid"]

    def test_a_stranger_verifies_with_a_registered_fingerprint(self, tmp_path):
        from causal_continuity_engine.lamport import verify_envelope_with
        proof, signer = self._proof(tmp_path)
        registry = list(signer.issued_fingerprints)      # published out of band
        result = verify_envelope_with(proof, expected_fingerprints=registry)
        assert result["valid"] and result["authentic"]

    def test_unregistered_key_is_intact_but_not_authentic(self, tmp_path):
        """An attacker re-signs a rewritten proof with their own keypair."""
        from causal_continuity_engine.lamport import LamportSigner, verify_envelope_with
        proof, signer = self._proof(tmp_path)
        registry = list(signer.issued_fingerprints)
        forged = json.loads(json.dumps(proof))
        forged["action_intent"]["statement"] = "something else entirely"
        attacker = LamportSigner("attacker")
        forged["signature"] = attacker.sign(forged)
        assert attacker.verify(forged), "precondition: internally consistent"
        result = verify_envelope_with(forged, expected_fingerprints=registry)
        assert not result["valid"] and result["authentic"] is False
        assert "not registered" in result["reason"]

    def test_refuses_to_verify_without_an_out_of_band_fingerprint(self, tmp_path):
        from causal_continuity_engine.lamport import UnregisteredKeyError, verify_envelope_with
        proof, _ = self._proof(tmp_path)
        with pytest.raises(UnregisteredKeyError):
            verify_envelope_with(proof, expected_fingerprints=[])

    def test_content_tampering_breaks_the_signature(self, tmp_path):
        from causal_continuity_engine.lamport import verify_envelope_with
        proof, signer = self._proof(tmp_path)
        tampered = json.loads(json.dumps(proof))
        tampered["status"] = "verified-but-actually-not"
        result = verify_envelope_with(
            tampered, expected_fingerprints=signer.issued_fingerprints)
        assert not result["valid"]

    def test_declared_fingerprint_must_match_the_attached_key(self, tmp_path):
        from causal_continuity_engine.lamport import verify_envelope_with
        proof, signer = self._proof(tmp_path)
        swapped = json.loads(json.dumps(proof))
        swapped["signature"]["fingerprint"] = "sha256:" + "0" * 64
        result = verify_envelope_with(
            swapped, expected_fingerprints=signer.issued_fingerprints)
        assert not result["valid"] and "does not match" in result["reason"]

    def test_each_signature_uses_a_fresh_keypair(self, tmp_path):
        from causal_continuity_engine.lamport import LamportSigner
        signer = LamportSigner()
        for obj in ({"a": 1}, {"a": 2}, {"a": 3}):
            obj["signature"] = signer.sign(obj)
        assert len(set(signer.issued_fingerprints)) == 3, \
            "a reused Lamport keypair leaks preimages and enables forgery"
