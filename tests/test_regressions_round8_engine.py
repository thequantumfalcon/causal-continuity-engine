"""Adversarial regressions for engine-level continuity and proof gates.

Every defect in this file was reproduced against f4da624 before its fix.  The
tests deliberately exercise the public Engine surface unless observing a
transaction rollback requires inspecting the projection that must disappear.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

from causal_continuity_engine.core import Signer, digest_obj
from causal_continuity_engine.engine import PROCESSOR_VERSION, Engine
from causal_continuity_engine.lamport import LamportSigner
from causal_continuity_engine.proof import verify_envelope
from causal_continuity_engine.verifiers import VerifierSpec

TENANT = "ten_round8_engine"
PROJECT = "prj_round8_engine"
OTHER = "prj_round8_other"
TRUSTED_APP_ID = 101
TRUSTED_INSTALLATION_ID = 501
REPOSITORY_ID = 8008


def _python(script: str) -> str:
    """A policy-pinnable command that works on POSIX and Windows."""
    executable = Path(sys.executable).as_posix()
    return f'"{executable}" -c "{script}"'


PASS = _python("raise SystemExit(0)")
FAIL = _python("raise SystemExit(17)")
READS_ARTIFACT = _python(
    "from pathlib import Path;"
    "p=Path('deliverable.txt');"
    "raise SystemExit(0 if p.exists() and p.read_text()=='ready' else 19)"
)


def _config(*, command: str = PASS, minimum: str | None = "C") -> dict:
    return {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "min_evidence_grade": minimum,
        "required_verifiers": [{
            "name": "policy-check",
            "command": command,
            "expect_fail_command": FAIL,
            "artifacts": ["deliverable.txt"],
        }],
        "trusted_verifier_apps": [{
            "app_id": TRUSTED_APP_ID, "slug": "actions"}],
    }


def _engine(tmp_path: Path, *, config: dict | None = None) -> Engine:
    (tmp_path / "deliverable.txt").write_text("ready", encoding="utf-8")
    engine = Engine(
        tmp_path / "cce.db", tenant_id=TENANT,
        signer=Signer.generate("round8-engine"), workdir=tmp_path,
    )
    engine.create_project("engine", project_id=PROJECT,
                          repository_id=REPOSITORY_ID,
                          config=config if config is not None else _config())
    engine.policy.grant(project_id=PROJECT, level=2, granted_by="lead")
    return engine


def _task(engine: Engine, project_id: str = PROJECT, node_id: str | None = None):
    return engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=project_id,
        node_id=node_id, status="open", data={"title": "ship"})


def _proof(engine: Engine, task_id: str, *, intent_type="task_complete") -> dict:
    return engine.attest_action(
        PROJECT, intent_type=intent_type, intent_statement="ship",
        actor={"agent": "worker"}, action_type="run_verifier",
        continuity={"task_ids": [task_id]},
    )


def _reseal(engine: Engine, proof: dict) -> dict:
    proof = copy.deepcopy(proof)
    proof.pop("signature", None)
    proof["proof_digest"] = digest_obj({
        key: value for key, value in proof.items()
        if key not in ("signature", "proof_digest")
    })
    proof["signature"] = engine.signer.sign(proof)
    return proof


def _reseal_receipt(engine: Engine, receipt: dict) -> dict:
    receipt = copy.deepcopy(receipt)
    receipt.pop("signature", None)
    receipt["receipt_digest"] = digest_obj({
        key: value for key, value in receipt.items()
        if key not in ("signature", "receipt_digest")
    })
    receipt["signature"] = engine.signer.sign(receipt)
    return receipt


def _push(after: str, *, before: str = "0" * 40) -> dict:
    return {
        "ref": "refs/heads/main", "before": before, "after": after,
        "forced": False, "deleted": False, "created": False,
        "commits": [],
        "head_commit": {"timestamp": "2026-08-02T12:00:00Z"},
        "repository": {"id": REPOSITORY_ID, "full_name": "owner/repo"},
    }


def _check(
        sha: str, *, app: str = "actions",
        app_id: int = TRUSTED_APP_ID,
        installation_id: int = TRUSTED_INSTALLATION_ID) -> dict:
    return {
        "action": "completed",
        "check_run": {
            "id": int(sha[0], 16) + 1, "name": "ci", "status": "completed",
            "conclusion": "success", "head_sha": sha,
            "completed_at": "2026-08-02T12:01:00Z",
            "app": {"id": app_id, "slug": app},
        },
        "installation": {"id": installation_id},
        "repository": {"id": REPOSITORY_ID, "full_name": "owner/repo"},
    }


def _workflow(sha: str, *, workflow_id: int = 42,
              path: str = ".github/workflows/ci.yml") -> dict:
    return {
        "action": "completed",
        "workflow_run": {
            "id": 9001, "workflow_id": workflow_id, "path": path,
            "name": "ci-workflow", "status": "completed",
            "conclusion": "success", "head_sha": sha,
            "updated_at": "2026-08-02T12:01:00Z",
            "actor": {"login": "untrusted-human", "type": "User"},
            "triggering_actor": {"login": "someone", "type": "User"},
        },
        "sender": {"login": "github", "type": "Bot"},
        "repository": {"id": REPOSITORY_ID, "full_name": "owner/repo"},
    }


class TestCompletionSubjectAndShape:
    def test_foreign_project_task_cannot_be_rehomed_by_completion(self, tmp_path):
        engine = _engine(tmp_path, config={"require_proof_for": []})
        engine.create_project("other", project_id=OTHER,
                              config={"require_proof_for": []})
        foreign = _task(engine, OTHER)

        with pytest.raises(PermissionError, match="project|scope"):
            engine.complete_task(PROJECT, foreign.id)

        unchanged = engine.graph.get(foreign.id)
        assert unchanged["project_id"] == OTHER
        assert unchanged["status"] == "open"
        engine.close()

    def test_non_task_node_cannot_be_retyped_by_completion(self, tmp_path):
        engine = _engine(tmp_path, config={"require_proof_for": []})
        requirement = engine.graph.put_node(
            entity_type="requirement", tenant_id=TENANT, project_id=PROJECT,
            status="active", data={"statement": "Keep identity immutable"})

        with pytest.raises(PermissionError, match="task|type"):
            engine.complete_task(PROJECT, requirement.id)

        assert engine.graph.get(requirement.id)["entity_type"] == "requirement"
        engine.close()

    def test_proof_for_another_intent_cannot_complete_a_task(self, tmp_path):
        # Keep evidence grading out of this subject-binding reproduction: the
        # envelope is otherwise acceptable and must fail *for its intent*.
        engine = _engine(tmp_path, config=_config(minimum=None))
        task = _task(engine)
        proof = _proof(engine, task.id, intent_type="pr_ready")
        assert proof["status"] == "verified"

        with pytest.raises(PermissionError, match="intent"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        assert engine.graph.get(task.id)["status"] == "open"
        engine.close()

    def test_task_binding_is_exact_not_a_substring_search(self, tmp_path):
        engine = _engine(tmp_path, config=_config(minimum=None))
        task = _task(engine)
        proof = _proof(engine, task.id)
        proof["continuity_links"]["task_ids"] = [
            f"prefix-{task.id}-suffix"]
        proof = _reseal(engine, proof)

        with pytest.raises(PermissionError, match="name task|bound|subject"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        engine.close()

    def test_attestation_rejects_unknown_task_link_before_writing_action(
            self, tmp_path):
        engine = _engine(tmp_path, config=_config(minimum=None))
        before = len(engine.graph.current(PROJECT, "action"))
        with pytest.raises(ValueError, match="same-project task"):
            _proof(engine, "tsk_missing")
        assert len(engine.graph.current(PROJECT, "action")) == before
        engine.close()

    def test_signed_proof_without_unique_id_is_malformed_not_reusable(self, tmp_path):
        engine = _engine(tmp_path, config=_config(minimum=None))
        task = _task(engine)
        proof = _proof(engine, task.id)
        proof.pop("proof_id")
        proof = _reseal(engine, proof)
        assert engine.signer.verify(proof), "fixture must be cryptographically valid"

        with pytest.raises(PermissionError, match="malformed|proof_id"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        engine.close()

    def test_optional_proof_is_still_validated_and_absence_is_labelled_honestly(
            self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        task = _task(engine)

        with pytest.raises(PermissionError, match="proof|malformed|invalid"):
            engine.complete_task(PROJECT, task.id, proof={"proof_id": "invented"})

        completed = engine.complete_task(PROJECT, task.id, actor="agent")
        assert completed["authority"] == "agent_inference"
        assert completed["data"]["completion_evidence"] is None
        engine.close()


class TestVerifierFrontier:
    def _external_project(self, tmp_path) -> Engine:
        return _engine(tmp_path, config={
            "require_proof_for": [], "min_evidence_grade": None,
            "required_verifiers": ["ci"],
            "trusted_verifier_apps": [{
                "app_id": TRUSTED_APP_ID, "slug": "actions"}],
        })

    def test_pass_for_previous_commit_does_not_satisfy_current_head(self, tmp_path):
        engine = self._external_project(tmp_path)
        first, second = "a" * 40, "b" * 40
        engine.ingest_github(PROJECT, "push", "push-a", _push(first))
        engine.ingest_github(PROJECT, "check_run", "check-a", _check(first))
        engine.resume_packet(PROJECT)
        assert engine.continuity_check(PROJECT)["conclusion"] == "success"

        engine.ingest_github(
            PROJECT, "push", "push-b", _push(second, before=first))
        engine.resume_packet(PROJECT)
        check = engine.continuity_check(PROJECT)
        assert check["conclusion"] != "success"
        assert check["verifier_gaps"] == ["ci"]
        engine.close()

    def test_untrusted_github_app_cannot_supply_authoritative_pass(self, tmp_path):
        engine = self._external_project(tmp_path)
        head = "c" * 40
        engine.ingest_github(PROJECT, "push", "push-c", _push(head))
        engine.ingest_github(
            PROJECT, "check_run", "evil-check", _check(head, app="evil-ci"))
        engine.resume_packet(PROJECT)

        check = engine.continuity_check(PROJECT)
        assert check["conclusion"] != "success"
        assert check["verifier_gaps"] == ["ci"]
        recorded = engine.graph.current(PROJECT, "verification")[-1]
        assert recorded["authority"] != "verifier_authoritative"
        engine.close()

    def test_same_slug_with_wrong_app_id_is_untrusted(self, tmp_path):
        engine = self._external_project(tmp_path)
        head = "c" * 40
        engine.ingest_github(PROJECT, "push", "id-push", _push(head))
        engine.ingest_github(
            PROJECT, "check_run", "wrong-app-id",
            _check(head, app="actions", app_id=TRUSTED_APP_ID + 1,
                   installation_id=999))
        engine.resume_packet(PROJECT)

        check = engine.continuity_check(PROJECT)
        assert check["verifier_gaps"] == ["ci"]
        recorded = engine.graph.current(PROJECT, "verification")[-1]
        assert recorded["authority"] == "repository_authoritative"
        assert recorded["data"]["app_id"] == TRUSTED_APP_ID + 1
        assert recorded["data"]["installation_id"] == 999
        engine.close()

    def test_revoking_a_trusted_app_revokes_its_prior_pass(self, tmp_path):
        engine = self._external_project(tmp_path)
        head = "d" * 40
        engine.ingest_github(PROJECT, "push", "push-d", _push(head))
        engine.ingest_github(PROJECT, "check_run", "check-d", _check(head))
        engine.resume_packet(PROJECT)
        assert engine.continuity_check(PROJECT)["conclusion"] == "success"

        engine.policy.set_project_config(PROJECT, {
            "require_proof_for": [], "min_evidence_grade": None,
            "required_verifiers": ["ci"], "trusted_verifier_apps": [],
        })
        packet = engine.resume_packet(PROJECT)
        check = engine.continuity_check(PROJECT)
        assert check["conclusion"] != "success"
        assert check["verifier_gaps"] == ["ci"]
        assert packet["trust"]["gaps"] == ["ci"]
        engine.close()

    def test_workflow_run_requires_policy_pinned_workflow_id_and_path(
            self, tmp_path):
        config = {
            "require_proof_for": [], "min_evidence_grade": None,
            "required_verifiers": ["ci-workflow"],
            "trusted_workflows": [{
                "workflow_id": 42, "path": ".github/workflows/ci.yml"}],
        }
        engine = _engine(tmp_path, config=config)
        head = "e" * 40
        engine.ingest_github(PROJECT, "push", "workflow-push", _push(head))
        engine.ingest_github(
            PROJECT, "workflow_run", "wrong-workflow",
            _workflow(head, path=".github/workflows/release.yml"))
        engine.resume_packet(PROJECT)
        assert engine.continuity_check(PROJECT)["verifier_gaps"] == [
            "ci-workflow"]

        engine.ingest_github(
            PROJECT, "workflow_run", "right-workflow", _workflow(head))
        packet = engine.resume_packet(PROJECT)
        assert engine.continuity_check(PROJECT)["conclusion"] == "success"
        assert packet["trust"]["gaps"] == []
        recorded = engine.graph.current(PROJECT, "verification")[-1]
        assert recorded["data"]["workflow_id"] == 42
        assert recorded["data"]["workflow_path"] == \
            ".github/workflows/ci.yml"
        engine.close()


class TestPacketControlFreshness:
    def test_policy_and_runtime_graph_changes_stale_a_signed_packet(self, tmp_path):
        config = {
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None, "max_autonomy_level": 2,
        }
        engine = _engine(tmp_path, config=config)
        packet = engine.resume_packet(PROJECT)
        assert packet["project_state_basis"]["control_basis_digest"]
        assert not engine.packet_is_stale(PROJECT)

        engine.policy.set_project_config(
            PROJECT, {**config, "max_autonomy_level": 1})
        assert engine.packet_is_stale(PROJECT)
        engine.resume_packet(PROJECT)
        assert not engine.packet_is_stale(PROJECT)

        _task(engine)
        assert engine.packet_is_stale(PROJECT)
        engine.close()

    def test_editing_the_watermark_cannot_bypass_its_audit_commitment(self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.resume_packet(PROJECT)
        engine.policy.set_project_config(PROJECT, {
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None, "max_autonomy_level": 1,
        })
        engine.store._conn.execute(
            "UPDATE packet_watermark SET last_event_seq = ? WHERE project_id = ?",
            (engine._latest_event_seq(PROJECT), PROJECT))
        engine.store._conn.commit()
        assert engine.packet_is_stale(PROJECT)
        engine.close()


class TestEvidenceAndClaimLifecycle:
    def test_definition_identity_covers_every_policy_verifier_semantic(self):
        base = {
            "name": "policy-check", "kind": "command", "command": PASS,
            "expected_properties": {}, "timeout_seconds": 300,
            "expect_fail_command": FAIL, "artifacts": ["deliverable.txt"],
        }
        baseline = VerifierSpec.from_policy(base).definition_digest
        changes = {
            "name": "renamed-check",
            "kind": "unit-tests",
            "command": READS_ARTIFACT,
            "timeout_seconds": 301,
            "expect_fail_command": PASS,
            "artifacts": ["other.txt"],
        }
        for field, value in changes.items():
            changed = copy.deepcopy(base)
            changed[field] = value
            assert VerifierSpec.from_policy(changed).definition_digest != baseline, field

        first_oracle = VerifierSpec.from_policy({
            "name": "oracle", "kind": "value-oracle", "command": PASS,
            "expected_properties": {"values": {"minimum": 1}},
        })
        second_oracle = VerifierSpec.from_policy({
            "name": "oracle", "kind": "value-oracle", "command": PASS,
            "expected_properties": {"values": {"minimum": 2}},
        })
        assert first_oracle.definition_digest != second_oracle.definition_digest

        explicit_defaults = {
            "name": "defaulted", "kind": "command", "command": PASS,
            "expected_properties": {}, "timeout_seconds": 300,
            "expect_fail_command": None, "artifacts": [],
        }
        assert VerifierSpec.from_policy({
            "name": "defaulted", "command": PASS,
        }).definition_digest == VerifierSpec.from_policy(
            explicit_defaults).definition_digest

    def test_determinism_is_collected_at_attestation_so_grade_a_is_reachable(
            self, tmp_path):
        engine = _engine(tmp_path, config=_config(
            command=READS_ARTIFACT, minimum="A"))
        task = _task(engine)
        proof = _proof(engine, task.id)

        assert proof["evidence_context"]["mutation"]["bound"] is True
        assert proof["evidence_context"]["determinism"]["policy-check"][
            "stable"] is True
        assert verify_envelope(proof, engine.signer)["valid"] is True
        assert engine.grade_proof(PROJECT, proof).grade == "A"
        assert engine.complete_task(PROJECT, task.id, proof=proof)[
            "status"] == "verified"
        engine.close()

    def test_new_success_supersedes_failed_attempt_for_the_same_claim(self, tmp_path):
        config = _config(command=READS_ARTIFACT, minimum=None)
        engine = _engine(tmp_path, config=config)
        task = _task(engine)
        (tmp_path / "deliverable.txt").write_text("not-ready", encoding="utf-8")
        failed = _proof(engine, task.id)
        assert failed["status"] == "failed"

        engine.policy.clear_downgrades(PROJECT, actor="lead")
        (tmp_path / "deliverable.txt").write_text("ready", encoding="utf-8")
        passed = _proof(engine, task.id)
        assert passed["status"] == "verified"
        engine.resume_packet(PROJECT)

        attempts = [n for n in engine.graph.current(PROJECT, "action")
                    if n["data"].get("kind") == "proof"]
        assert any(n["data"].get("proof_id") == failed["proof_id"]
                   and n["status"] == "superseded" for n in attempts)
        assert engine.continuity_check(PROJECT)["failed_proofs"] == []
        engine.close()

    def test_same_command_under_changed_definition_is_not_current_proof(
            self, tmp_path):
        config = _config(command=PASS, minimum=None)
        engine = _engine(tmp_path, config=config)
        task = _task(engine)
        proof = _proof(engine, task.id)
        assert proof["status"] == "verified"

        changed = copy.deepcopy(config)
        changed["required_verifiers"][0]["timeout_seconds"] = 301
        engine.policy.set_project_config(PROJECT, changed)

        with pytest.raises(PermissionError, match="definition|policy|re-attest"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        assert engine.graph.get(task.id)["status"] == "open"
        engine.close()

    def test_changed_verifier_semantics_cannot_launder_failed_proof(
            self, tmp_path):
        original = _config(command=READS_ARTIFACT, minimum=None)
        engine = _engine(tmp_path, config=original)
        task = _task(engine)
        (tmp_path / "deliverable.txt").write_text("not-ready", encoding="utf-8")
        failed = _proof(engine, task.id)
        assert failed["status"] == "failed"

        engine.policy.clear_downgrades(PROJECT, actor="lead")
        changed = copy.deepcopy(original)
        changed["required_verifiers"][0]["timeout_seconds"] = 301
        engine.policy.set_project_config(PROJECT, changed)
        (tmp_path / "deliverable.txt").write_text("ready", encoding="utf-8")
        passed = _proof(engine, task.id)
        assert passed["status"] == "verified"

        attempts = {
            node["data"].get("proof_id"): node
            for node in engine.graph.current(PROJECT, "action")
            if node["data"].get("kind") == "proof"
        }
        assert attempts[failed["proof_id"]]["status"] == "failed"
        assert attempts[passed["proof_id"]]["status"] == "verified"
        engine.close()

    def test_weaker_policy_success_cannot_erase_stronger_failed_claim(self, tmp_path):
        strong = _config(command=PASS, minimum=None)
        strong["required_verifiers"].append({
            "name": "extra-policy-check", "command": FAIL,
            "expect_fail_command": FAIL, "artifacts": ["deliverable.txt"],
        })
        engine = _engine(tmp_path, config=strong)
        task = _task(engine)
        failed = _proof(engine, task.id)
        assert failed["status"] == "failed"

        engine.policy.clear_downgrades(PROJECT, actor="lead")
        engine.policy.set_project_config(
            PROJECT, _config(command=PASS, minimum=None))
        passed = _proof(engine, task.id)
        assert passed["status"] == "verified"

        attempts = {
            node["data"].get("proof_id"): node
            for node in engine.graph.current(PROJECT, "action")
            if node["data"].get("kind") == "proof"
        }
        assert attempts[failed["proof_id"]]["status"] == "failed"
        assert attempts[passed["proof_id"]]["status"] == "verified"
        engine.resume_packet(PROJECT)
        assert failed["proof_id"] in {
            engine.graph.get(node_id)["data"].get("proof_id")
            for node_id in engine.continuity_check(PROJECT)["failed_proofs"]
        }
        engine.close()


class TestProjectionAndContinuityWitness:
    def test_projection_fingerprint_commits_to_semantics_and_edges(self, tmp_path):
        engine = _engine(tmp_path, config={"require_proof_for": []})
        semantic_event = engine.store.append_event(
            tenant_id=TENANT, project_id=PROJECT, source_type="test",
            idempotency_key="semantic-projection", payload={},
            authority="verifier_authoritative")
        event_id = semantic_event["event_id"]
        left = engine.graph.put_node(
            entity_type="requirement", tenant_id=TENANT, project_id=PROJECT,
            node_id="req_semantic_left", status="active", criticality="low",
            data={"statement": "Semantic field", "stable_key": "left"},
            event_id=event_id)
        right = engine.graph.put_node(
            entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
            node_id="asm_semantic_right", status="active", confidence=0.8,
            data={"statement": "Edge target", "stable_key": "right"},
            event_id=event_id)
        before = engine.projection_fingerprint(PROJECT)

        engine.graph.put_node(
            entity_type="requirement", tenant_id=TENANT, project_id=PROJECT,
            node_id=left.id, status="active", criticality="critical",
            data={}, event_id=event_id)
        critical_changed = engine.projection_fingerprint(PROJECT)
        assert critical_changed != before

        edge = engine.graph.put_edge(
            edge_type="depends_on", src_id=left.id, dst_id=right.id,
            tenant_id=TENANT, project_id=PROJECT, strength=0.2,
            data={"basis": "observed"}, event_id=event_id)
        edge_added = engine.projection_fingerprint(PROJECT)
        assert edge_added != critical_changed
        engine.graph.put_edge(
            edge_id=edge["edge_id"], edge_type="depends_on",
            src_id=left.id, dst_id=right.id, tenant_id=TENANT,
            project_id=PROJECT, strength=0.9,
            data={"basis": "observed"}, event_id=event_id)
        assert engine.projection_fingerprint(PROJECT) != edge_added
        engine.close()

    def test_failed_projection_rolls_back_but_canonical_event_is_quarantined(
            self, tmp_path, monkeypatch):
        engine = _engine(tmp_path, config={"require_proof_for": []})
        original = engine.graph.put_node

        def plant_failure(**kwargs):
            node = original(**kwargs)
            if kwargs.get("event_id"):
                raise RuntimeError("plant projection failure")
            return node

        monkeypatch.setattr(engine.graph, "put_node", plant_failure)
        with pytest.raises(RuntimeError, match="plant projection failure"):
            engine.ingest_human_decision(
                PROJECT, actor="lead",
                decision="We decided to use PostgreSQL for persistence.",
                request_id="atomic-event")

        event = engine.store.events(PROJECT)[-1]
        assert any(row["event_id"] == event["event_id"]
                   for row in engine.store.quarantined(PROCESSOR_VERSION))
        derived = [
            node for node in engine.graph.current(PROJECT)
            if any(version.get("event_id") == event["event_id"]
                   for version in engine.graph.history(node["node_id"]))
        ]
        assert derived == []
        engine.close()

    def test_open_authority_conflict_blocks_continuity(self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.ingest_github(
            PROJECT, "push", "conflict-frontier", _push("f" * 40))
        conflicted = engine.graph.put_node(
            entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
            status="uncertain", authority="human_intent",
            data={"statement": "Use region A", "conflict_requires_resolution": True})
        engine.resume_packet(PROJECT)

        check = engine.continuity_check(PROJECT)
        assert check["conclusion"] == "action_required"
        assert conflicted.id in check["authority_conflicts"]
        engine.close()

    def test_signed_bidirectional_receipt_commits_to_the_decision_frontier(
            self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.ingest_human_decision(
            PROJECT, actor="lead", decision="We decided to ship the parser.",
            request_id="receipt-event")
        engine.resume_packet(PROJECT)

        result = engine.continuity_check(PROJECT)
        receipt = result["continuity_receipt"]
        assert receipt["schema_version"] == "cce.continuity-receipt.v1"
        assert receipt["decision"] == result["conclusion"]
        assert receipt["basis"]["project_id"] == PROJECT
        assert receipt["basis"]["projection_digest"] == \
            engine.projection_fingerprint(PROJECT)
        assert receipt["basis"]["event_log"]["tip"] == \
            engine.store.verify_chain("events")["tip"]
        assert "satisfied" in receipt and "blockers" in receipt
        assert "flip_conditions" in receipt
        assert receipt["receipt_digest"] == digest_obj({
            key: value for key, value in receipt.items()
            if key not in ("signature", "receipt_digest")
        })
        assert engine.signer.verify(receipt)
        assert engine.verify_continuity_receipt(PROJECT, receipt)[
            "verdict"] == "CURRENT"

        old_digest = receipt["receipt_digest"]
        engine.policy.set_project_config(PROJECT, {
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None, "max_autonomy_level": 1,
        })
        changed = engine.continuity_check(PROJECT)["continuity_receipt"]
        assert changed["basis"]["policy_digest"] != receipt["basis"]["policy_digest"]
        assert changed["receipt_digest"] != old_digest
        assert engine.signer.verify(changed)
        assert engine.verify_continuity_receipt(PROJECT, receipt)[
            "verdict"] == "AUTHENTIC_HISTORICAL"
        engine.close()

    def test_trusted_reseal_cannot_make_predicates_contradict_state(self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.resume_packet(PROJECT)
        receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
        forged = copy.deepcopy(receipt)
        predicate = next(
            item for item in forged["decision_state"]["predicates"]
            if item["predicate"] == "critical_invalidations_empty")
        predicate["observed"] = 1
        top = next(
            item for item in forged["satisfied"]
            if item["predicate"] == "critical_invalidations_empty")
        top["observed"] = 1
        forged["basis"]["decision_state_digest"] = digest_obj(
            forged["decision_state"])
        forged = _reseal_receipt(engine, forged)

        result = engine.verify_continuity_receipt(PROJECT, forged)
        assert result["verdict"] == "INVALID"
        assert "predicate" in result["reason"]
        engine.close()

    @pytest.mark.parametrize("location", ["top", "nested"])
    def test_trusted_reseal_cannot_smuggle_unknown_v1_fields(
            self, tmp_path, location):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.resume_packet(PROJECT)
        receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
        forged = copy.deepcopy(receipt)
        if location == "top":
            forged["operator_override"] = "looks meaningful but is not v1"
        else:
            forged["decision_state"]["packet"]["operator_override"] = True
            forged["basis"]["decision_state_digest"] = digest_obj(
                forged["decision_state"])
        forged = _reseal_receipt(engine, forged)
        result = engine.verify_continuity_receipt(PROJECT, forged)
        assert result["verdict"] == "INVALID"
        assert "unknown" in result["reason"]
        engine.close()

    def test_predicate_partition_flip_and_issuer_claims_are_recomputed(
            self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.resume_packet(PROJECT)
        original = engine.continuity_check(PROJECT)["continuity_receipt"]

        partition = copy.deepcopy(original)
        partition["satisfied"].pop()
        partition = _reseal_receipt(engine, partition)
        assert engine.verify_continuity_receipt(PROJECT, partition)[
            "verdict"] == "INVALID"

        flips = copy.deepcopy(original)
        flips["flip_conditions"]["from_success"]["predicates"].pop()
        flips = _reseal_receipt(engine, flips)
        assert engine.verify_continuity_receipt(PROJECT, flips)[
            "verdict"] == "INVALID"

        issuer = copy.deepcopy(original)
        issuer["issuer"].update({
            "algorithm": "lamport-sha256/1",
            "verification_mode": "registered_public_key",
            "independently_verifiable": True,
        })
        issuer = _reseal_receipt(engine, issuer)
        assert engine.verify_continuity_receipt(PROJECT, issuer)[
            "verdict"] == "INVALID"

        reordered = copy.deepcopy(original)
        reordered["satisfied"].reverse()
        reordered["blockers"].reverse()
        reordered["flip_conditions"]["to_success"]["predicates"].reverse()
        reordered["flip_conditions"]["from_success"]["predicates"].reverse()
        reordered = _reseal_receipt(engine, reordered)
        assert engine.verify_continuity_receipt(PROJECT, reordered)[
            "verdict"] == "CURRENT"
        engine.close()

    @pytest.mark.parametrize("field", ["basis", "decision_state", "issuer"])
    def test_malformed_receipt_objects_fail_closed(self, tmp_path, field):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.resume_packet(PROJECT)
        receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
        malformed = copy.deepcopy(receipt)
        malformed[field] = []
        malformed = _reseal_receipt(engine, malformed)
        assert engine.verify_continuity_receipt(PROJECT, malformed)[
            "verdict"] == "INVALID"
        engine.close()

    def test_unregistered_lamport_key_cannot_forge_current_receipt(self, tmp_path):
        signer = LamportSigner("receipt-key")
        engine = Engine(
            tmp_path / "lamport.db", tenant_id=TENANT,
            signer=signer, workdir=tmp_path)
        engine.create_project("engine", project_id=PROJECT, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.resume_packet(PROJECT)
        receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
        issued = len(signer.issued_fingerprints)
        assert engine.verify_continuity_receipt(PROJECT, receipt)[
            "verdict"] == "CURRENT"
        assert len(signer.issued_fingerprints) == issued

        attacker = LamportSigner("receipt-key")
        forged = copy.deepcopy(receipt)
        forged["signature"] = attacker.sign(forged)
        assert attacker.derive_fingerprint(forged["signature"]) not in \
            signer.registered_fingerprints
        assert engine.verify_continuity_receipt(PROJECT, forged)[
            "verdict"] == "INVALID"
        engine.close()

    def test_global_chain_growth_does_not_stale_an_unrelated_project(self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.resume_packet(PROJECT)
        receipt = engine.continuity_check(PROJECT)["continuity_receipt"]

        engine.create_project("other", project_id=OTHER, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.ingest_human_decision(
            OTHER, actor="lead", decision="We decided to isolate projects.",
            request_id="unrelated-event")
        assert engine.verify_continuity_receipt(PROJECT, receipt)[
            "verdict"] == "CURRENT"
        engine.close()

    def test_broken_integrity_chain_is_an_explicit_continuity_blocker(self, tmp_path):
        engine = _engine(tmp_path, config={
            "require_proof_for": [], "required_verifiers": [],
            "min_evidence_grade": None,
        })
        engine.ingest_github(
            PROJECT, "push", "integrity-frontier", _push("e" * 40))
        engine.resume_packet(PROJECT)
        assert engine.continuity_check(PROJECT)["conclusion"] == "success"
        engine.store._conn.execute("DROP TRIGGER audit_no_update")
        engine.store._conn.execute(
            "UPDATE audit_log SET detail = 'tampered' WHERE seq = "
            "(SELECT MIN(seq) FROM audit_log)")
        engine.store._conn.commit()

        result = engine.continuity_check(PROJECT)
        blockers = {
            item["predicate"]
            for item in result["continuity_receipt"]["blockers"]
        }
        assert result["conclusion"] != "success"
        assert "integrity_chains_intact" in blockers
        engine.close()
