"""Trust layer: proof envelopes, verifiers, policy, capsules."""

import json
import shlex
import sys
import tempfile
from pathlib import Path

import pytest

import causal_continuity_engine.evidence as evidence_module
import causal_continuity_engine.verifiers as verifier_module
from causal_continuity_engine.capsule import CapsuleError
from causal_continuity_engine.core import Signer, sha256_hex
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.evidence import run_mutation_probe
from causal_continuity_engine.proof import (
    ProofEnvelope,
    detect_stale,
    from_intoto,
    to_intoto,
    verify_envelope,
)
from causal_continuity_engine.verifiers import VerifierRunner, VerifierSpec

TEN, PRJ = "ten_t", "prj_t"


def _python_command(source: str) -> str:
    return shlex.join([sys.executable, "-c", source])


PASS_COMMAND = _python_command("raise SystemExit(0)")
FAIL_COMMAND = _python_command("raise SystemExit(1)")


@pytest.fixture
def signer():
    return Signer.generate("test")


def _envelope(signer, results, required=None):
    env = ProofEnvelope(tenant_id=TEN, project_id=PRJ, intent_type="task_complete",
                        intent_statement="did the thing",
                        actor={"agent": "test"})
    env.add_subject("repo@abc", sha256_hex("state"))
    env.add_input("base_commit", sha256_hex("abc"))
    for name, result in results.items():
        env.add_verification({"verifier": name, "kind": "command",
                              "result": result, "source": "executed"})
    return env.finalize(signer, required_verifiers=required or list(results))


class TestProof:
    def test_all_passed_is_verified(self, signer):
        assert _envelope(signer, {"tests": "passed", "lint": "passed"})["status"] \
            == "verified"

    def test_any_failed_is_failed(self, signer):
        assert _envelope(signer, {"tests": "passed", "lint": "failed"})["status"] \
            == "failed"

    def test_missing_required_is_incomplete(self, signer):
        out = _envelope(signer, {"tests": "passed"}, required=["tests", "typecheck"])
        assert out["status"] == "incomplete"
        assert out["verification_summary"]["missing"] == ["typecheck"]

    def test_inconclusive_never_success(self, signer):
        assert _envelope(signer, {"tests": "inconclusive"})["status"] == "inconclusive"

    def test_skipped_required_is_incomplete(self, signer):
        assert _envelope(signer, {"tests": "skipped"})["status"] == "incomplete"

    def test_no_verifications_never_verified(self, signer):
        assert _envelope(signer, {})["status"] == "incomplete"

    def test_tamper_detection(self, signer):
        out = _envelope(signer, {"tests": "passed"})
        check = verify_envelope(out, signer)
        assert check["valid"]
        out["action_intent"]["statement"] = "did something else"
        check2 = verify_envelope(out, signer)
        assert not check2["valid"] and check2["status"] == "invalid"

    def test_intoto_round_trip(self, signer):
        out = _envelope(signer, {"tests": "passed"})
        statement = to_intoto(out)
        assert statement["_type"] == "https://in-toto.io/Statement/v1"
        back = from_intoto(statement)
        assert back == out

    def test_stale_detection(self, signer):
        out = _envelope(signer, {"tests": "passed"})
        fresh = detect_stale(out, {"base_commit": sha256_hex("abc")})
        assert not fresh["stale"]
        stale = detect_stale(out, {"base_commit": sha256_hex("def")})
        assert stale["stale"] and stale["changed_inputs"][0]["name"] == "base_commit"


class TestVerifierRunner:
    def test_command_pass_and_fail(self, tmp_path):
        r = VerifierRunner(workdir=tmp_path)
        ok = r.run(VerifierSpec(name="true", command=PASS_COMMAND))
        assert ok.result == "passed" and ok.exit_code == 0
        bad = r.run(VerifierSpec(name="false", command=FAIL_COMMAND))
        assert bad.result == "failed"

    def test_nested_temp_uses_external_workspace_and_cleans_up(
            self, tmp_path, monkeypatch):
        nested_temp = tmp_path / "process-environment" / "tmp"
        nested_temp.mkdir(parents=True)
        monkeypatch.setattr(tempfile, "tempdir", str(nested_temp))
        real_materialize = verifier_module.materialize_workspace
        disposable_roots = []
        excluded_paths = []

        def observe_root(source, destination, **kwargs):
            disposable_roots.append(Path(destination).parent.resolve())
            excluded_paths.extend(kwargs["excluded_paths"])
            return real_materialize(source, destination, **kwargs)

        monkeypatch.setattr(
            verifier_module, "materialize_workspace", observe_root)
        with tempfile.NamedTemporaryFile(dir=nested_temp):
            outcome = VerifierRunner(workdir=tmp_path).run(VerifierSpec(
                name="external-temp", command=PASS_COMMAND))

        assert outcome.result == "passed", outcome.details
        assert len(disposable_roots) == 1
        disposable = disposable_roots[0]
        subject = tmp_path.resolve()
        assert disposable != subject and subject not in disposable.parents
        assert not disposable.exists()
        assert nested_temp.resolve() in excluded_paths

        claimed = nested_temp / "claimed.txt"
        claimed.write_text("subject", encoding="utf-8")
        refused = VerifierRunner(workdir=tmp_path).run(VerifierSpec(
            name="excluded-artifact", command=PASS_COMMAND,
            artifacts=["process-environment/tmp/claimed.txt"]))
        assert refused.result == "inconclusive"
        assert "overlaps verifier-omitted runtime state" in refused.details

    def test_nested_temp_creation_failure_stays_inconclusive(
            self, tmp_path, monkeypatch):
        nested_temp = tmp_path / "process-environment" / "tmp"
        nested_temp.mkdir(parents=True)
        monkeypatch.setattr(tempfile, "tempdir", str(nested_temp))
        attempted_parents = []

        def refuse_temporary_directory(*args, **kwargs):
            attempted_parents.append(Path(kwargs["dir"]).resolve())
            raise PermissionError("injected unavailable sibling")

        monkeypatch.setattr(
            tempfile, "TemporaryDirectory", refuse_temporary_directory)
        outcome = VerifierRunner(workdir=tmp_path).run(VerifierSpec(
            name="no-external-temp", command=PASS_COMMAND))

        assert attempted_parents == [tmp_path.resolve().parent]
        assert outcome.result == "inconclusive"
        assert "verifier could not run" in outcome.details

    def test_nested_temp_keeps_all_probe_roots_external_and_cleans_up(
            self, tmp_path, monkeypatch):
        nested_temp = tmp_path / "process-environment" / "tmp"
        nested_temp.mkdir(parents=True)
        monkeypatch.setattr(tempfile, "tempdir", str(nested_temp))
        (tmp_path / "artifact.txt").write_text("subject", encoding="utf-8")
        real_materialize = evidence_module.materialize_workspace
        disposable_roots = []

        def observe_root(source, destination, **kwargs):
            disposable_roots.append(Path(destination).parent.resolve())
            return real_materialize(source, destination, **kwargs)

        monkeypatch.setattr(
            evidence_module, "materialize_workspace", observe_root)
        report = run_mutation_probe(
            workdir=tmp_path,
            artifacts=["artifact.txt"],
            specs=[VerifierSpec(name="probe", command=PASS_COMMAND)],
            runner_factory=lambda sandbox: VerifierRunner(None, sandbox),
            mutations=("truncate",),
            excluded_paths=(nested_temp.resolve(),),
        )

        assert report.baseline == {"probe": "passed"}
        assert len(disposable_roots) == 2
        subject = tmp_path.resolve()
        assert all(
            root != subject and subject not in root.parents
            for root in disposable_roots)
        assert all(not root.exists() for root in disposable_roots)

    def test_missing_binary_inconclusive(self, tmp_path):
        r = VerifierRunner(workdir=tmp_path)
        out = r.run(VerifierSpec(name="ghost", command="definitely-not-a-binary-xyz"))
        assert out.result == "inconclusive"

    def test_timeout_inconclusive(self, tmp_path):
        r = VerifierRunner(workdir=tmp_path)
        out = r.run(VerifierSpec(
            name="slow", command=_python_command("import time; time.sleep(5)"),
            timeout_seconds=1))
        assert out.result == "inconclusive" and "timeout" in out.details

    def test_file_digest_adapter(self, tmp_path):
        f = tmp_path / "a.txt"
        f.write_text("hello")
        spec = VerifierSpec(name="digest", kind="file-digest",
                            expected_properties={"files": {"a.txt": sha256_hex(b"hello")}})
        assert VerifierRunner(workdir=tmp_path).run(spec).result == "passed"
        f.write_text("tampered")
        assert VerifierRunner(workdir=tmp_path).run(spec).result == "failed"


class TestPolicy:
    @pytest.fixture
    def engine(self):
        e = Engine()
        e.create_project("p", project_id=PRJ)
        yield e
        e.close()

    def test_default_deny_level0(self, engine):
        d = engine.policy.decide(project_id=PRJ, action_type="run_verifier")
        assert d["decision"] == "deny" and d["effective_level"] == 0

    def test_grant_enables_then_expiry_blocks(self, engine):
        engine.policy.grant(project_id=PRJ, level=2, granted_by="lead",
                            expires_at="2020-01-01T00:00:00Z")
        assert engine.policy.effective_level(PRJ) == 0  # already expired
        engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
        assert engine.policy.effective_level(PRJ) == 2
        assert engine.policy.decide(project_id=PRJ,
                                    action_type="run_verifier")["decision"] == "allow"

    def test_level4_always_denied(self, engine):
        engine.policy.grant(project_id=PRJ, level=3, granted_by="lead")
        engine.policy.set_project_config(PRJ, {"max_autonomy_level": 3,
                                               "guarded_pr_enabled": True})
        d = engine.policy.decide(project_id=PRJ, action_type="merge")
        assert d["decision"] == "deny"
        with pytest.raises(ValueError):
            engine.policy.grant(project_id=PRJ, level=4, granted_by="lead")

    def test_irreversible_forces_level4_deny(self, engine):
        engine.policy.grant(project_id=PRJ, level=3, granted_by="lead")
        d = engine.policy.decide(project_id=PRJ, action_type="run_verifier",
                                 reversibility="irreversible")
        assert d["decision"] == "deny"

    def test_downgrade_and_clear(self, engine):
        engine.policy.grant(project_id=PRJ, level=3, granted_by="lead")
        engine.policy.set_project_config(PRJ, {"max_autonomy_level": 3})
        engine.policy.downgrade(PRJ, "failed_proof", ceiling=1)
        assert engine.policy.effective_level(PRJ) == 1
        engine.policy.clear_downgrades(PRJ, actor="lead")
        assert engine.policy.effective_level(PRJ) == 3

    def test_guarded_pr_requires_enablement(self, engine):
        engine.policy.grant(project_id=PRJ, level=3, granted_by="lead")
        engine.policy.set_project_config(PRJ, {"max_autonomy_level": 3})
        assert engine.policy.decide(project_id=PRJ,
                                    action_type="create_pr")["decision"] == "deny"
        engine.policy.set_project_config(PRJ, {"max_autonomy_level": 3,
                                               "guarded_pr_enabled": True})
        assert engine.policy.decide(project_id=PRJ,
                                    action_type="create_pr")["decision"] == "allow"

    def test_revoke_blocks(self, engine):
        gid = engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
        assert engine.policy.effective_level(PRJ) == 2
        engine.policy.revoke(gid, actor="lead")
        assert engine.policy.effective_level(PRJ) == 0


class TestFalseCompletionGate:
    @pytest.fixture
    def engine(self):
        e = Engine()
        e.create_project("p", project_id=PRJ,
                         config={"require_proof_for": ["task_complete"],
                                 "required_verifiers": [
                                     {"name": "tests",
                                      "command": PASS_COMMAND}]})
        yield e
        e.close()

    def _task(self, engine):
        return engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"title": "implement feature"}, status="open")

    def test_claim_without_proof_rejected(self, engine):
        task = self._task(engine)
        with pytest.raises(PermissionError, match="requires proof"):
            engine.complete_task(PRJ, task.id)

    def test_claim_with_unverified_proof_rejected(self, engine):
        task = self._task(engine)
        env = ProofEnvelope(tenant_id=engine.tenant_id, project_id=PRJ,
                            intent_type="task_complete", intent_statement="done",
                            actor={"agent": "a"})
        env.add_verification({"verifier": "tests", "result": "failed",
                              "source": "executed"})
        proof = env.finalize(engine.signer, ["tests"])
        with pytest.raises(PermissionError, match="not 'verified'"):
            engine.complete_task(PRJ, task.id, proof=proof)

    def test_claim_with_tampered_proof_rejected(self, engine):
        task = self._task(engine)
        env = ProofEnvelope(tenant_id=engine.tenant_id, project_id=PRJ,
                            intent_type="task_complete", intent_statement="done",
                            actor={"agent": "a"})
        env.add_verification({"verifier": "tests", "result": "passed",
                              "source": "executed"})
        proof = env.finalize(engine.signer, ["tests"])
        proof["verifications"][0]["result"] = "passed"  # unchanged
        proof["action_intent"]["statement"] = "something else"  # tampered
        with pytest.raises(PermissionError, match="tampered"):
            engine.complete_task(PRJ, task.id, proof=proof)

    def test_valid_proof_completes(self, engine):
        """Drives the engine rather than hand-building an envelope: a
        hand-built proof cannot carry the command_digest a pinned policy
        verifier now requires (ADR-058), and asserting on one would be the
        ADR-014 mistake again."""
        engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
        task = self._task(engine)
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="done",
            actor={"agent": "a"}, action_type="run_verifier",
            continuity={"task_ids": [task.id]})
        out = engine.complete_task(PRJ, task.id, proof=proof)
        assert out["status"] == "verified"
        assert out["data"]["completion_evidence"] == proof["proof_id"]


class TestCapsule:
    @pytest.fixture
    def engine(self):
        e = Engine()
        e.create_project("p", project_id=PRJ)
        yield e
        e.close()

    def _export(self, engine, session_id=None):
        return engine.capsules.export(
            tenant_id=engine.tenant_id, project_id=PRJ, session_id=session_id,
            source_model="model-a", source_runtime="runtime-a",
            target_adapter="model-b", signer=engine.signer)

    def test_export_import_round_trip(self, engine):
        capsule = self._export(engine)
        result = engine.capsules.import_capsule(
            capsule, signer=engine.signer, target_model="model-b",
            target_runtime="runtime-b")
        assert result["validation"]["valid"]
        session = result["session"]
        assert session["data"]["migrated_from_capsule"] == capsule["capsule_id"]
        assert session["data"]["source_model"] == "model-a"

    def test_tamper_detected(self, engine):
        capsule = self._export(engine)
        capsule["observable_state"]["open_invalidations"] = []
        capsule["resume_packet"]["mission"]["objective"] = "evil"
        with pytest.raises(CapsuleError, match="digest mismatch"):
            engine.capsules.validate(capsule, engine.signer)

    def test_serialization_round_trip_survives(self, engine):
        capsule = self._export(engine)
        again = json.loads(json.dumps(capsule))
        assert engine.capsules.validate(again, engine.signer)["valid"]

    def test_hidden_reasoning_stripped(self, engine):
        session = engine.graph.put_node(
            entity_type="session", tenant_id=engine.tenant_id, project_id=PRJ,
            status="ended",
            data={"model": "m", "chain_of_thought": "SECRET THOUGHTS",
                  "messages": ["visible"]})
        capsule = self._export(engine, session_id=session.id)
        assert "SECRET THOUGHTS" not in json.dumps(capsule)

    def test_challenge_gates_on_open_invalidations(self, engine):
        a = engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"statement": "db is reachable and consistent"}, status="active",
            criticality="high")
        engine.invalidation.fire(
            tenant_id=engine.tenant_id, project_id=PRJ, target_node_id=a.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.9)
        capsule = self._export(engine)
        challenge = engine.capsules.challenge(capsule)
        assert not challenge["passed"]
        assert challenge["max_autonomy_until_resolved"] == 1
        assert challenge["questions"]
