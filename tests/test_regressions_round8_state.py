"""Round-8 regressions for state, evidence, and migration trust boundaries."""

import json
import sqlite3

import pytest

from causal_continuity_engine.capsule import CapsuleError
from causal_continuity_engine.core import digest_obj
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.evidence import (
    grade_evidence,
    run_determinism_probe,
    run_mutation_probe,
)
from causal_continuity_engine.graph import Graph
from causal_continuity_engine.invalidation import InvalidationEngine
from causal_continuity_engine.lamport import LamportSigner
from causal_continuity_engine.policy import PolicyEngine
from causal_continuity_engine.store import EvidenceIntegrityError, Store

TEN, PRJ = "ten_round8_state", "prj_round8_state"
TRUSTED_APP_ID = 101


@pytest.fixture
def engine():
    value = Engine(tenant_id=TEN)
    value.create_project("state regressions", project_id=PRJ)
    yield value
    value.close()


def test_resume_digest_is_present_when_signature_is_made(engine):
    packet = engine.composer.compose(
        tenant_id=TEN, project_id=PRJ, signer=engine.signer)

    unsigned = {k: v for k, v in packet.items()
                if k not in ("signature", "packet_digest")}
    assert packet["packet_digest"] == digest_obj(unsigned)
    assert engine.signer.verify(packet), \
        "the producer appended packet_digest after signing it"


def test_resume_trust_only_counts_authoritative_current_frontier(engine):
    engine.policy.set_project_config(PRJ, {
        "required_verifiers": ["ci"],
        "trusted_verifier_apps": [{
            "app_id": TRUSTED_APP_ID, "slug": "actions"}],
    })
    engine.graph.put_node(
        entity_type="verification", tenant_id=TEN, project_id=PRJ,
        status="passed", authority="human_decision",
        data={"verifier": "ci", "source": "manual"},
    )
    stale = engine.graph.put_node(
        entity_type="verification", tenant_id=TEN, project_id=PRJ,
        status="passed", authority="verifier_authoritative",
        data={"verifier": "ci", "source": "github:check_run",
              "head_sha": "a" * 40, "app": "actions",
              "app_id": TRUSTED_APP_ID},
    )
    project = engine.graph.get(PRJ)
    tracked_basis = engine.policy.tracked_ref_basis(PRJ)
    engine.graph.put_node(
        node_id=PRJ, entity_type="project", tenant_id=TEN, project_id=PRJ,
        status=project["status"], authority=project["authority"],
        data=project["data"] | {
            "current_head_sha": "b" * 40,
            "tracked_ref": tracked_basis["tracked_ref"],
            "tracked_ref_revision": tracked_basis["revision"],
            "revision_frontier_uncertain": False,
        },
    )

    trust = engine.composer.compose(
        tenant_id=TEN, project_id=PRJ, signer=engine.signer)["trust"]
    assert trust["completed_checks"] == []
    assert trust["gaps"] == ["ci"]

    current = engine.graph.put_node(
        entity_type="verification", tenant_id=TEN, project_id=PRJ,
        status="passed", authority="verifier_authoritative",
        data={"verifier": "ci", "source": "github:check_run",
              "head_sha": "b" * 40, "app": "actions",
              "app_id": TRUSTED_APP_ID},
    )
    trust = engine.composer.compose(
        tenant_id=TEN, project_id=PRJ, signer=engine.signer)["trust"]
    assert [item["node_id"] for item in trust["completed_checks"]] == [
        current.id]
    assert stale.id not in {
        item["node_id"] for item in trust["completed_checks"]}
    assert trust["gaps"] == []


class _Spec:
    name = "always-red"


class _Outcome:
    result = "failed"
    details = "fails before and after mutation"


class _AlwaysRedRunner:
    def run(self, spec):
        return _Outcome()


def test_failed_pristine_baseline_cannot_detect_mutations(tmp_path):
    (tmp_path / "artifact.txt").write_text("deliverable", encoding="utf-8")
    report = run_mutation_probe(
        workdir=tmp_path, artifacts=["artifact.txt"], specs=[_Spec()],
        runner_factory=lambda _: _AlwaysRedRunner(),
    )

    assert report.baseline == {"always-red": "failed"}
    assert report.detected == []
    assert report.error and "baseline did not pass" in report.error
    assert report.bound is False


def test_repeating_failure_is_not_deterministic_success():
    report = run_determinism_probe(_Spec(), _AlwaysRedRunner())
    assert report["results"] == ["failed", "failed"]
    assert report["stable"] is False

    outcome = [{"verifier": "always-red", "result": "passed",
                "source": "executed"}]
    grade = grade_evidence(
        outcomes=outcome, required=["always-red"],
        controls={"always-red": {"status": "held"}},
        determinism={"always-red": report},
    )
    assert grade.grade == "C"
    assert "two passes" in " ".join(grade.caps)


def _capsule(engine):
    return engine.capsules.export(
        tenant_id=TEN, project_id=PRJ, session_id=None,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer,
    )


def test_capsule_import_requires_an_explicit_trust_root(engine):
    capsule = _capsule(engine)
    with pytest.raises(CapsuleError, match="trusted signer"):
        engine.capsules.validate(capsule, None)

    capsule.pop("signature")
    with pytest.raises(CapsuleError, match="signature is missing"):
        engine.capsules.validate(capsule, engine.signer)


def test_signed_capsule_still_cannot_carry_hidden_reasoning(engine):
    capsule = _capsule(engine)
    capsule["hidden_reasoning"] = "private scratch state"
    body = {k: v for k, v in capsule.items()
            if k not in ("content_digest", "signature")}
    capsule["content_digest"] = digest_obj(body)
    capsule["signature"] = engine.signer.sign(capsule)

    with pytest.raises(CapsuleError, match="hidden-reasoning"):
        engine.capsules.validate(capsule, engine.signer)


def test_trusted_reseal_cannot_add_unknown_capsule_semantics(engine):
    capsule = _capsule(engine)
    capsule["operator_override"] = "looks authoritative but is not v1"
    body = {k: v for k, v in capsule.items()
            if k not in ("content_digest", "signature")}
    capsule["content_digest"] = digest_obj(body)
    capsule["signature"] = engine.signer.sign(capsule)

    with pytest.raises(CapsuleError, match="unknown top-level"):
        engine.capsules.validate(capsule, engine.signer)


def test_unregistered_lamport_key_cannot_forge_a_capsule(tmp_path):
    issuer = LamportSigner("capsule-issuer")
    engine = Engine(tenant_id=TEN, signer=issuer, workdir=tmp_path)
    engine.create_project("capsules", project_id=PRJ)
    capsule = _capsule(engine)
    assert engine.capsules.validate(capsule, issuer)["valid"]

    attacker = LamportSigner("capsule-issuer")
    forged = json.loads(json.dumps(capsule))
    forged["source"]["model"] = "attacker-model"
    body = {k: v for k, v in forged.items()
            if k not in ("content_digest", "signature")}
    forged["content_digest"] = digest_obj(body)
    forged["signature"] = attacker.sign(forged)

    with pytest.raises(CapsuleError, match="authenticity"):
        engine.capsules.import_capsule(
            forged, signer=issuer, target_model="target",
            target_runtime="runtime", expected_tenant_id=TEN,
            expected_project_id=PRJ)
    engine.close()


def test_capsule_source_session_foreign_and_missing_are_scope_equivalent():
    outcomes = []
    source_session = "ses_scope_probe"
    for foreign_exists in (False, True):
        engine = Engine(tenant_id=TEN)
        try:
            engine.create_project("state regressions", project_id=PRJ)
            if foreign_exists:
                other = "prj_capsule_other"
                engine.create_project("other", project_id=other)
                engine.graph.put_node(
                    entity_type="session", tenant_id=TEN, project_id=other,
                    node_id=source_session, status="active",
                    data={"model": "foreign"})
            capsule = _capsule(engine)
            capsule["source"]["session_id"] = source_session
            capsule["lineage"]["exported_from_session"] = source_session
            body = {k: v for k, v in capsule.items()
                    if k not in ("content_digest", "signature")}
            capsule["content_digest"] = digest_obj(body)
            capsule["signature"] = engine.signer.sign(capsule)

            result = engine.capsules.import_capsule(
                capsule, signer=engine.signer, target_model="target",
                target_runtime="runtime", expected_tenant_id=TEN,
                expected_project_id=PRJ)
            lineage = engine.graph.out_edges(
                result["session"]["node_id"], {"migrated_from"})
            outcomes.append((
                result["validation"]["valid"],
                result["session"]["status"],
                lineage,
            ))
        finally:
            engine.close()
    assert outcomes == [(True, "active", []), (True, "active", [])]


def test_capsule_export_requires_a_scoped_real_session(engine):
    other = "prj_capsule_export_other"
    engine.create_project("other", project_id=other)
    foreign = engine.graph.put_node(
        entity_type="session", tenant_id=TEN, project_id=other,
        node_id="ses_export_scope_probe", status="active",
        data={"model": "foreign"})
    errors = []
    for session_id in (foreign.id, "ses_export_missing"):
        with pytest.raises(CapsuleError) as rejected:
            engine.capsules.export(
                tenant_id=TEN, project_id=PRJ, session_id=session_id,
                source_model="source", source_runtime="runtime",
                target_adapter="target", signer=engine.signer)
        errors.append(str(rejected.value))
    assert errors == [
        "capsule source session is not a session in the requested scope",
        "capsule source session is not a session in the requested scope",
    ]
    assert engine.store.audit_entries("capsule.export") == []

    local = engine.graph.put_node(
        entity_type="session", tenant_id=TEN, project_id=PRJ,
        status="active", data={"model": "local"})
    capsule = engine.capsules.export(
        tenant_id=TEN, project_id=PRJ, session_id=local.id,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer)
    assert capsule["source"]["session_id"] == local.id
    assert capsule["lineage"]["exported_from_session"] == local.id


def test_capsule_import_rolls_back_session_when_downgrade_fails(
        engine, monkeypatch):
    capsule = _capsule(engine)  # missing environment => challenge fails
    before = len(engine.graph.current(PRJ, "session"))

    def planted_failure(*args, **kwargs):
        raise RuntimeError("planted downgrade failure")

    monkeypatch.setattr(engine.policy, "downgrade", planted_failure)
    with pytest.raises(RuntimeError, match="planted downgrade"):
        engine.capsules.import_capsule(
            capsule, signer=engine.signer, target_model="target",
            target_runtime="runtime", expected_tenant_id=TEN,
            expected_project_id=PRJ)
    assert len(engine.graph.current(PRJ, "session")) == before
    assert engine.store.audit_entries("capsule.import") == []


def test_zero_confidence_and_missing_environment_both_fail_challenge(engine):
    engine.graph.put_node(
        entity_type="assumption", tenant_id=TEN, project_id=PRJ,
        data={"statement": "the unknown dependency is stable"},
        status="active", confidence=0.0,
    )
    challenge = engine.capsules.challenge(_capsule(engine))

    assert challenge["passed"] is False
    assert challenge["environment_missing"] is True
    assert challenge["uncertainties"][0]["kind"] == "low_confidence_assumption"
    assert challenge["max_autonomy_until_resolved"] == 1


def test_complete_migration_state_can_pass_challenge(engine):
    # This scenario isolates migration readiness; proof sufficiency is covered
    # separately and would make an unconfigured default project fail closed.
    engine.policy.set_project_config(PRJ, {"require_proof_for": []})
    engine.graph.put_node(
        entity_type="assumption", tenant_id=TEN, project_id=PRJ,
        data={"statement": "runtime parity was measured"},
        status="supported", confidence=0.95,
    )
    engine.graph.put_node(
        entity_type="artifact", tenant_id=TEN, project_id=PRJ,
        data={"kind": "environment", "python": "3.11", "os": "test"},
        status="recorded",
    )
    challenge = engine.capsules.challenge(_capsule(engine))
    assert challenge["passed"] is True
    assert challenge["questions"] == []


def test_scoped_grant_only_authorizes_matching_action_scope(engine):
    engine.policy.set_project_config(
        PRJ, {"max_autonomy_level": 3, "guarded_pr_enabled": True})
    engine.policy.grant(
        project_id=PRJ, level=3, granted_by="lead", scope="docs/**")

    assert engine.policy.effective_level(PRJ) == 0
    assert engine.policy.decide(
        project_id=PRJ, action_type="create_branch")["decision"] == "deny"
    assert engine.policy.decide(
        project_id=PRJ, action_type="create_branch",
        action_scope="src/core.py")["decision"] == "deny"
    assert engine.policy.decide(
        project_id=PRJ, action_type="create_branch",
        action_scope="docs/../src/core.py")["decision"] == "deny"
    allowed = engine.policy.decide(
        project_id=PRJ, action_type="create_branch",
        action_scope="docs/design.md")
    assert allowed["decision"] == "allow"
    assert allowed["applicable_grant_ids"]


def test_policy_mutations_reject_malformed_control_values_before_write(engine):
    grant_audits = len(engine.store.audit_entries("policy.grant"))
    downgrade_audits = len(engine.store.audit_entries("policy.downgrade"))

    for level in (True, 1.5, -1, 4):
        with pytest.raises(ValueError, match="grant level"):
            engine.policy.grant(
                project_id=PRJ, level=level, granted_by="lead")
    for expiry in ("", "not-a-timestamp", 7):
        with pytest.raises(ValueError, match="expires_at"):
            engine.policy.grant(
                project_id=PRJ, level=2, granted_by="lead",
                expires_at=expiry)
    for actor in ("", "   ", None):
        with pytest.raises(ValueError, match="granted_by"):
            engine.policy.grant(
                project_id=PRJ, level=2, granted_by=actor)
    for ceiling in (True, 1.5, -1, 4):
        with pytest.raises(ValueError, match="downgrade ceiling"):
            engine.policy.downgrade(
                PRJ, "failed_proof", ceiling=ceiling)

    assert engine.policy.active_grants(PRJ) == []
    assert engine.policy.active_downgrade_ceiling(PRJ) is None
    assert len(engine.store.audit_entries("policy.grant")) == grant_audits
    assert len(engine.store.audit_entries(
        "policy.downgrade")) == downgrade_audits


@pytest.mark.parametrize(("kwargs", "message"), [
    ({"evidence_quality": float("nan")}, "evidence_quality"),
    ({"evidence_quality": float("inf")}, "evidence_quality"),
    ({"evidence_quality": -0.1}, "evidence_quality"),
    ({"evidence_quality": "0.9"}, "evidence_quality"),
    ({"historical_reliability": float("nan")}, "historical_reliability"),
    ({"historical_reliability": 1.1}, "historical_reliability"),
    ({"historical_reliability": None}, "historical_reliability"),
    ({"blast_radius": float("nan")}, "blast_radius"),
    ({"blast_radius": 1.5}, "blast_radius"),
    ({"blast_radius": -1}, "blast_radius"),
    ({"blast_radius": True}, "blast_radius"),
    ({"reversibility": "unknown"}, "reversibility"),
    ({"reversibility": None}, "reversibility"),
    ({"reversibility": []}, "reversibility"),
])
def test_policy_decision_rejects_malformed_risk_inputs(
        engine, kwargs, message):
    before = len(engine.store.audit_entries("policy.decide"))
    with pytest.raises(ValueError, match=message):
        engine.policy.decide(
            project_id=PRJ, action_type="run_verifier", **kwargs)
    assert len(engine.store.audit_entries("policy.decide")) == before


def test_malformed_persisted_policy_rows_fail_closed(engine):
    engine.policy.set_project_config(PRJ, {"max_autonomy_level": 3})
    elevated = engine.policy.grant(
        project_id=PRJ, level=2, granted_by="lead")
    bad_expiry = engine.policy.grant(
        project_id=PRJ, level=2, granted_by="lead")
    with engine.store.write_scope():
        engine.store._conn.execute(
            "UPDATE autonomy_grants SET level = 99 WHERE grant_id = ?",
            (elevated,))
        engine.store._conn.execute(
            "UPDATE autonomy_grants SET expires_at = ? WHERE grant_id = ?",
            ("not-a-timestamp", bad_expiry))

    assert engine.policy.active_grants(PRJ) == []
    assert engine.policy.effective_level(PRJ) == 0

    engine.policy.grant(project_id=PRJ, level=3, granted_by="lead")
    assert engine.policy.effective_level(PRJ) == 3
    with engine.store.write_scope():
        engine.store._conn.execute(
            "INSERT INTO autonomy_downgrades "
            "(project_id, ceiling, trigger, at) VALUES (?,?,?,?)",
            (PRJ, 99, "failed_proof", "2026-01-01T00:00:00Z"))

    assert engine.policy.active_downgrade_ceiling(PRJ) == 0
    assert engine.policy.effective_level(PRJ) == 0
    assert engine.policy.decide(
        project_id=PRJ, action_type="run_verifier")["decision"] == "deny"


def test_trusted_verifier_app_registry_is_validated_and_fail_closed(engine):
    assert engine.policy.trusted_verifier_apps(PRJ) == []
    engine.policy.set_project_config(
        PRJ, {"trusted_verifier_apps": [
            {"app_id": 1, "slug": "github-actions"},
            {"app_id": 2},
        ]})
    assert engine.policy.trusted_verifier_apps(PRJ) == [
        {"app_id": 1, "slug": "github-actions"}, {"app_id": 2}]
    with pytest.raises(ValueError, match="legacy slug-only"):
        engine.policy.set_project_config(
            PRJ, {"trusted_verifier_apps": ["github-actions"]})


def test_legacy_slug_only_registry_is_untrusted_at_the_deciding_path(engine):
    legacy = engine.policy.project_config(PRJ)
    legacy["trusted_verifier_apps"] = ["actions"]
    with engine.store.write_scope():
        engine.store._conn.execute(
            "UPDATE project_policy SET config = ? WHERE project_id = ?",
            (json.dumps(legacy), PRJ))

    assert engine.policy.trusted_verifier_apps(PRJ) == []
    assert engine.policy.external_verifier_trusted(
        PRJ, "github:check_run",
        {"app_id": TRUSTED_APP_ID, "app": "actions"}) is False


@pytest.mark.parametrize(("config", "message"), [
    ({"unrecognized_control": True}, "unknown project policy"),
    ({"max_autonomy_level": True}, "max_autonomy_level"),
    ({"guarded_pr_enabled": 1}, "guarded_pr_enabled"),
    ({"require_proof_for": "task_complete"}, "require_proof_for"),
    ({"required_verifiers": "unit-tests"}, "required_verifiers"),
    ({"required_verifiers": [{"name": ""}]}, "non-empty name"),
    ({"required_verifiers": [{"name": "t", "timeout_seconds": True}]},
     "timeout_seconds"),
    ({"required_verifiers": [{"name": "t", "ignored": "field"}]},
     "unknown required_verifiers"),
    ({"required_verifiers": [{"name": "t", "command": "env true"}]},
     "delegates"),
    ({"min_evidence_grade": "Z"}, "min_evidence_grade"),
    ({"trusted_workflows": [{"workflow_id": 7, "actor": "trusted"}]},
     "unknown trusted_workflows"),
    ({"tracked_ref": "main"}, "refs/heads"),
])
def test_project_policy_schema_rejects_before_persistence(engine, config, message):
    before = engine.policy.project_config(PRJ)
    audits = len(engine.store.audit_entries("policy.config"))

    with pytest.raises(ValueError, match=message):
        engine.policy.set_project_config(PRJ, config, actor="operator")

    assert engine.policy.project_config(PRJ) == before
    assert len(engine.store.audit_entries("policy.config")) == audits


def test_project_policy_normalizes_only_declared_fields(engine):
    engine.policy.set_project_config(PRJ, {
        "require_proof_for": [" task_complete ", "task_complete"],
        "required_verifiers": [" unit-tests "],
        "trusted_verifier_apps": [
            {"app_id": TRUSTED_APP_ID, "slug": " actions "},
            {"app_id": TRUSTED_APP_ID, "slug": "actions"},
        ],
        "trusted_workflows": [{
            "workflow_id": 7, "path": ".github\\workflows\\ci.yml"}],
        "tracked_ref": "refs/heads/main",
    })

    config = engine.policy.project_config(PRJ)
    assert config["require_proof_for"] == ["task_complete"]
    assert config["required_verifiers"] == ["unit-tests"]
    assert config["trusted_verifier_apps"] == [{
        "app_id": TRUSTED_APP_ID, "slug": "actions"}]
    assert config["trusted_workflows"] == [{
        "workflow_id": 7, "path": ".github/workflows/ci.yml"}]
    assert config["tracked_ref"] == "refs/heads/main"


def _invalidation_graph():
    store = Store(":memory:")
    graph = Graph(store)
    return store, graph, InvalidationEngine(store, graph)


def _blocked_task(graph, invalidation, *, status="open"):
    assumption = graph.put_node(
        entity_type="assumption", tenant_id=TEN, project_id=PRJ,
        data={"statement": "the schema is stable"}, status="active",
        criticality="high",
    )
    task = graph.put_node(
        entity_type="task", tenant_id=TEN, project_id=PRJ,
        data={"title": "build importer"}, status=status, criticality="high",
    )
    graph.put_edge(
        edge_type="assumes", src_id=task.id, dst_id=assumption.id,
        tenant_id=TEN, project_id=PRJ,
    )
    fired = invalidation.fire(
        tenant_id=TEN, project_id=PRJ, target_node_id=assumption.id,
        trigger_type="contradictory_evidence", trigger_confidence=0.95,
    )
    return assumption, task, fired


def test_replacement_resolution_requires_live_same_project_evidence():
    store, graph, invalidation = _invalidation_graph()
    try:
        _, task, fired = _blocked_task(graph, invalidation)
        with pytest.raises(ValueError, match="requires replacement_node_id"):
            invalidation.resolve(
                fired["node_id"], mode="replacement_evidence", actor="lead")

        unrelated = graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": "not evidence"}, status="recorded")
        with pytest.raises(ValueError, match="requires a evidence node"):
            invalidation.resolve(
                fired["node_id"], mode="replacement_evidence", actor="lead",
                replacement_node_id=unrelated.id)

        foreign = graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id="prj_other",
            data={"name": "foreign report"}, status="recorded")
        # Project-bound resolution does not disclose whether an identifier is
        # absent or belongs to another project (ADR-083).
        with pytest.raises(
                ValueError, match="does not exist in this tenant and project"):
            invalidation.resolve(
                fired["node_id"], mode="replacement_evidence", actor="lead",
                replacement_node_id=foreign.id)
        assert graph.get(fired["node_id"])["status"] == "open"
        assert graph.get(task.id)["status"] == "blocked"
    finally:
        store.close()


def test_valid_resolution_emits_typed_receipt_and_restores_task_status():
    store, graph, invalidation = _invalidation_graph()
    try:
        assumption, task, fired = _blocked_task(graph, invalidation, status="in_progress")
        evidence = graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id=PRJ,
            data={"name": "schema compatibility report",
                  "subject_node_id": assumption.id}, status="verified",
            authority="verifier_authoritative")
        resolved = invalidation.resolve(
            fired["node_id"], mode="replacement_evidence", actor="lead",
            replacement_node_id=evidence.id)

        assert graph.get(assumption.id)["status"] == "resolved"
        assert graph.get(task.id)["status"] == "in_progress"
        receipt = resolved["data"]["resolution"]
        assert receipt["replacement"] == {
            "node_id": evidence.id, "entity_type": "evidence", "status": "verified"}
        assert task.id in receipt["released_nodes"]
    finally:
        store.close()


def test_last_overlapping_invalidation_restores_original_task_status():
    store, graph, invalidation = _invalidation_graph()
    try:
        assumptions = [graph.put_node(
            entity_type="assumption", tenant_id=TEN, project_id=PRJ,
            data={"statement": f"premise {index}"}, status="active",
            criticality="high") for index in range(2)]
        task = graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "continue migration"}, status="in_progress",
            criticality="high")
        fired = []
        for assumption in assumptions:
            graph.put_edge(
                edge_type="assumes", src_id=task.id, dst_id=assumption.id,
                tenant_id=TEN, project_id=PRJ)
            fired.append(invalidation.fire(
                tenant_id=TEN, project_id=PRJ, target_node_id=assumption.id,
                trigger_type="contradictory_evidence", trigger_confidence=0.95))
        evidence = [graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id=PRJ,
            data={"name": f"report {index}",
                  "subject_node_id": assumptions[index].id}, status="verified",
            authority="verifier_authoritative")
            for index in range(2)]

        invalidation.resolve(
            fired[0]["node_id"], mode="replacement_evidence", actor="lead",
            replacement_node_id=evidence[0].id)
        assert graph.get(task.id)["status"] == "blocked"
        invalidation.resolve(
            fired[1]["node_id"], mode="replacement_evidence", actor="lead",
            replacement_node_id=evidence[1].id)
        assert graph.get(task.id)["status"] == "in_progress"
    finally:
        store.close()


def test_evidence_rows_are_immutable_but_retention_can_tombstone():
    store = Store(":memory:")
    try:
        digest = store.put_evidence(b"original")
        with pytest.raises(sqlite3.IntegrityError, match="redact"):
            with store._conn:
                store._conn.execute(
                    "UPDATE evidence_blobs SET content = ? WHERE digest = ?",
                    (b"forged!", digest))
        with pytest.raises(sqlite3.IntegrityError, match="metadata is immutable"):
            with store._conn:
                store._conn.execute(
                    "UPDATE evidence_blobs SET size = size + 1 WHERE digest = ?",
                    (digest,))

        assert store.delete_evidence(digest, actor="privacy", reason="retention")
        assert store.get_evidence(digest) is None
        assert store.audit_entries("evidence.delete")
        with pytest.raises(sqlite3.IntegrityError, match="redact"):
            with store._conn:
                store._conn.execute(
                    "UPDATE evidence_blobs SET content = ?, deleted_at = NULL"
                    " WHERE digest = ?", (b"original", digest))
    finally:
        store.close()


def test_read_rehash_detects_tampering_even_if_database_triggers_were_removed():
    store = Store(":memory:")
    try:
        digest = store.put_evidence(b"original")
        with store._conn:
            store._conn.execute("DROP TRIGGER evidence_content_redaction_only")
            store._conn.execute(
                "UPDATE evidence_blobs SET content = ? WHERE digest = ?",
                (b"forged!!", digest))
        with pytest.raises(EvidenceIntegrityError, match="content-address"):
            store.get_evidence(digest)
    finally:
        store.close()


def test_outer_transaction_rolls_back_store_and_policy_writes_together():
    store = Store(":memory:")
    policy = PolicyEngine(store)
    try:
        with pytest.raises(RuntimeError, match="abort projection"):
            with store.transaction():
                store.put_evidence(b"transient")
                store.mark_processed("evt_transient", "processor/1")
                policy.grant(project_id=PRJ, level=2, granted_by="lead")
                raise RuntimeError("abort projection")

        assert store._conn.execute("SELECT COUNT(*) FROM evidence_blobs").fetchone()[0] == 0
        assert store._conn.execute("SELECT COUNT(*) FROM processed_events").fetchone()[0] == 0
        assert policy.active_grants(PRJ) == []
        assert store.audit_entries() == []
    finally:
        store.close()


def test_canonical_event_append_cannot_commit_an_outer_projection_transaction():
    store = Store(":memory:")
    try:
        with pytest.raises(RuntimeError, match="standalone canonical-log commit"):
            with store.transaction():
                store.append_event(
                    tenant_id=TEN, project_id=PRJ, source_type="human",
                    idempotency_key="nested-event", payload={"value": 1},
                    authority="human_decision")
        assert store.events() == []
    finally:
        store.close()
