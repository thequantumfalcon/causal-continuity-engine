"""Final integration regressions: scope, atomicity, and typed resolution."""

from __future__ import annotations

import copy
import json
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from causal_continuity_engine.api import make_handler
from causal_continuity_engine.capsule import CapsuleError
from causal_continuity_engine.core import (
    digest_obj,
    is_canonical_utc_timestamp,
)
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.graph import Graph
from causal_continuity_engine.invalidation import InvalidationEngine
from causal_continuity_engine.memory import Memory
from causal_continuity_engine.policy import DEFAULT_CONFIG, PolicyEngine
from causal_continuity_engine.store import (
    DuplicateEventError,
    EventPayloadIntegrityError,
    PayloadMismatchError,
    Store,
)

TEN = "ten_round9"
PRJ = "prj_round9"


def test_event_idempotency_is_scoped_to_tenant_and_project():
    store = Store(":memory:")
    try:
        first = store.append_event(
            tenant_id="tenant-a", project_id="project-a", source_type="agent",
            idempotency_key="trace:shared-span", payload={"value": 1},
            authority="agent_observed")
        second = store.append_event(
            tenant_id="tenant-b", project_id="project-b", source_type="agent",
            idempotency_key="trace:shared-span", payload={"value": 1},
            authority="agent_observed")

        assert first["event_id"] != second["event_id"]
        with pytest.raises(DuplicateEventError):
            store.append_event(
                tenant_id="tenant-b", project_id="project-b", source_type="agent",
                idempotency_key="trace:shared-span", payload={"value": 1},
                authority="agent_observed")
        with pytest.raises(PayloadMismatchError):
            store.append_event(
                tenant_id="tenant-b", project_id="project-b", source_type="agent",
                idempotency_key="trace:shared-span", payload={"value": 2},
                authority="agent_observed")
    finally:
        store.close()


def test_legacy_global_idempotency_schema_is_migrated_losslessly(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("""
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
            project_id TEXT NOT NULL, source_type TEXT NOT NULL,
            source_id TEXT, idempotency_key TEXT NOT NULL UNIQUE,
            observed_at TEXT NOT NULL, recorded_at TEXT NOT NULL,
            valid_from TEXT, valid_to TEXT, actor_type TEXT, actor_id TEXT,
            authority TEXT NOT NULL, sensitivity TEXT NOT NULL DEFAULT 'internal',
            capture_mode TEXT NOT NULL DEFAULT 'full', payload_digest TEXT NOT NULL,
            payload TEXT, schema_version TEXT NOT NULL, seq INTEGER,
            prev_hash TEXT, entry_hash TEXT
        )
    """)
    connection.commit()
    connection.close()

    store = Store(path)
    try:
        store.append_event(
            tenant_id="tenant-a", project_id="project-a", source_type="agent",
            idempotency_key="shared", payload={}, authority="agent_observed")
        store.append_event(
            tenant_id="tenant-b", project_id="project-b", source_type="agent",
            idempotency_key="shared", payload={}, authority="agent_observed")
        indexes = {
            row["name"] for row in store._conn.execute("PRAGMA index_list(events)")}
        assert "idx_events_idempotency_scope" in indexes
    finally:
        store.close()


def test_retention_redaction_and_its_audit_are_one_transaction(monkeypatch):
    store = Store(":memory:")
    graph = Graph(store)
    memory = Memory(store, graph)
    try:
        event = store.append_event(
            tenant_id=TEN, project_id=PRJ, source_type="agent",
            idempotency_key="old-event", payload={"secret": "erase me"},
            authority="agent_observed")

        def fail_audit(**_kwargs):
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(store, "audit", fail_audit)
        with pytest.raises(RuntimeError, match="audit unavailable"):
            memory.sweep_retention(now="2100-01-01T00:00:00Z")

        assert store.get_event(event["event_id"])["payload"] == {
            "secret": "erase me"}
    finally:
        store.close()


def _invalidation_fixture():
    store = Store(":memory:")
    graph = Graph(store)
    invalidation = InvalidationEngine(store, graph)
    assumption = graph.put_node(
        entity_type="assumption", tenant_id=TEN, project_id=PRJ,
        data={"statement": "the schema is stable"}, status="active",
        criticality="high")
    return store, graph, invalidation, assumption


def test_invalidation_fire_prevalidates_trigger_evidence_without_partial_state():
    store, graph, invalidation, assumption = _invalidation_fixture()
    try:
        with pytest.raises(ValueError, match="trigger evidence"):
            invalidation.fire(
                tenant_id=TEN, project_id=PRJ, target_node_id=assumption.id,
                trigger_type="contradictory_evidence",
                trigger_evidence_id="evd_missing")

        assert graph.current(PRJ, "invalidation") == []
        assert graph.get(assumption.id)["status"] == "active"
        assert store.audit_entries("invalidation.fire") == []
    finally:
        store.close()


def test_invalidation_confirmation_rolls_back_when_audit_fails(monkeypatch):
    store, graph, invalidation, assumption = _invalidation_fixture()
    try:
        pending = invalidation.fire(
            tenant_id=TEN, project_id=PRJ, target_node_id=assumption.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.2)
        assert pending["status"] == "pending_confirmation"

        def fail_audit(**_kwargs):
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(store, "audit", fail_audit)
        with pytest.raises(RuntimeError, match="audit unavailable"):
            invalidation.confirm(pending["node_id"], actor="reviewer", accept=True)

        assert graph.get(pending["node_id"])["status"] == "pending_confirmation"
        assert graph.get(assumption.id)["status"] == "active"
    finally:
        store.close()


def test_replacement_evidence_must_explicitly_bind_the_invalidated_target():
    store, graph, invalidation, assumption = _invalidation_fixture()
    try:
        fired = invalidation.fire(
            tenant_id=TEN, project_id=PRJ, target_node_id=assumption.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.95)
        unrelated = graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id=PRJ,
            data={"name": "valid report", "subject_node_id": "asm_elsewhere"},
            status="verified", authority="verifier_authoritative")

        with pytest.raises(ValueError, match="explicitly bind"):
            invalidation.resolve(
                fired["node_id"], mode="replacement_evidence", actor="reviewer",
                replacement_node_id=unrelated.id)
        assert graph.get(fired["node_id"])["status"] == "open"

        self_asserted = graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id=PRJ,
            data={"name": "I say it is fixed", "subject_node_id": assumption.id},
            status="recorded", authority="agent_asserted")
        with pytest.raises(ValueError, match="verified authoritative"):
            invalidation.resolve(
                fired["node_id"], mode="replacement_evidence", actor="reviewer",
                replacement_node_id=self_asserted.id)
        assert graph.get(fired["node_id"])["status"] == "open"

        replacement = graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id=PRJ,
            data={"name": "targeted report", "subject_node_id": assumption.id},
            status="verified", authority="verifier_authoritative")
        resolved = invalidation.resolve(
            fired["node_id"], mode="replacement_evidence", actor="reviewer",
            replacement_node_id=replacement.id)
        assert resolved["status"] == "resolved"
    finally:
        store.close()


def test_default_policy_views_cannot_mutate_future_projects():
    store = Store(":memory:")
    policy = PolicyEngine(store)
    try:
        view = policy.project_config("missing")
        view["require_proof_for"].clear()
        view["trusted_workflows"].append({"workflow_id": 1, "path": None})

        fresh = policy.project_config("also-missing")
        assert fresh["require_proof_for"] == DEFAULT_CONFIG["require_proof_for"]
        assert fresh["trusted_workflows"] == []
    finally:
        store.close()


def test_api_rejects_unknown_assumption_action_without_mutation():
    engine = Engine(tenant_id=TEN)
    engine.create_project("round9", project_id=PRJ)
    assumption = engine.graph.put_node(
        entity_type="assumption", tenant_id=TEN, project_id=PRJ,
        data={"statement": "keep me active"}, status="active")
    api_token = "round9-api-token-0123456789abcdef"
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(engine, PRJ, api_token=api_token))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_port}/v1/assumptions/{assumption.id}:resolve",
            data=json.dumps({"action": "accpet"}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            },
            method="POST")
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(request)
        try:
            assert rejected.value.code == 400
        finally:
            rejected.value.close()
        assert engine.graph.get(assumption.id)["status"] == "active"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
        engine.close()


def _python_command(script: str) -> str:
    executable = Path(sys.executable).as_posix()
    return f'"{executable}" -c "{script}"'


def _reseal_capsule(engine: Engine, capsule: dict) -> dict:
    capsule = copy.deepcopy(capsule)
    packet = capsule["resume_packet"]
    packet["packet_digest"] = digest_obj({
        key: value for key, value in packet.items()
        if key not in ("packet_digest", "signature")
    })
    body = {
        key: value for key, value in capsule.items()
        if key not in ("content_digest", "signature")
    }
    capsule["content_digest"] = digest_obj(body)
    capsule["signature"] = engine.signer.sign(capsule)
    return capsule


@pytest.mark.parametrize(
    "timestamp",
    [
        "20260804T123456Z",
        "2026-08-04 12:34:56.123456Z",
        "2026-02-30T12:34:56.123456Z",
        "2026-08-04T12:34:56Z",
    ],
)
@pytest.mark.parametrize(
    "field",
    ["created_at", "generated_at", "packet_generation_time"],
)
def test_resigned_capsule_rejects_noncanonical_timestamps(field, timestamp):
    engine = Engine(tenant_id=TEN)
    engine.create_project("capsule-time", project_id=PRJ)
    capsule = engine.capsules.export(
        tenant_id=TEN, project_id=PRJ, session_id=None,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer)
    try:
        assert is_canonical_utc_timestamp(capsule["created_at"])
        assert is_canonical_utc_timestamp(
            capsule["resume_packet"]["generated_at"])
        assert is_canonical_utc_timestamp(
            capsule["resume_packet"]["continuity_lineage"][
                "packet_generation_time"])
        malformed = copy.deepcopy(capsule)
        if field == "created_at":
            malformed["created_at"] = timestamp
        elif field == "generated_at":
            malformed["resume_packet"]["generated_at"] = timestamp
        else:
            malformed["resume_packet"]["continuity_lineage"][
                "packet_generation_time"] = timestamp
        malformed = _reseal_capsule(engine, malformed)

        with pytest.raises(CapsuleError, match="malformed"):
            engine.capsules.validate(malformed, engine.signer)
        with pytest.raises(CapsuleError, match="malformed"):
            engine.capsules.import_capsule(
                malformed, signer=engine.signer,
                target_model="target", target_runtime="runtime")
    finally:
        engine.close()


@pytest.mark.parametrize(
    "case",
    [
        "capsule_id", "created_at", "source", "resume_schema",
        "watermark", "assumption", "environment", "packet_unknown",
        "signature_unknown", "nested_summary",
    ],
)
def test_resigned_capsule_with_malformed_semantics_is_rejected(case):
    engine = Engine(tenant_id=TEN)
    engine.create_project("capsule-shape", project_id=PRJ)
    engine.graph.put_node(
        entity_type="assumption", tenant_id=TEN, project_id=PRJ,
        data={"statement": "database is reachable"}, status="active",
        confidence=0.9)
    capsule = engine.capsules.export(
        tenant_id=TEN, project_id=PRJ, session_id=None,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer)
    try:
        malformed = copy.deepcopy(capsule)
        if case == "capsule_id":
            malformed["capsule_id"] = ""
        elif case == "created_at":
            malformed["created_at"] = "not-a-time"
        elif case == "source":
            malformed["source"]["model"] = ""
        elif case == "resume_schema":
            malformed["resume_packet"]["schema_version"] = "cce.resume.v999"
        elif case == "watermark":
            malformed["lineage"]["event_watermark"] = "event:evt_not_the_packet"
        elif case == "assumption":
            assumption = malformed["observable_state"]["active_assumptions"][0]
            assumption["status"] = "forged"
            assumption["confidence"] = 999
        elif case == "environment":
            malformed["resume_packet"]["environment"] = 1
        elif case == "packet_unknown":
            malformed["resume_packet"]["interpret_as_trusted"] = True
        elif case == "nested_summary":
            malformed["resume_packet"]["accepted_decisions"] = [{}]

        malformed = _reseal_capsule(engine, malformed)
        if case == "signature_unknown":
            # Signature metadata is excluded from the signed body. A closed
            # signature shape is what prevents unsigned semantic extensions.
            malformed["signature"]["interpret_as_trusted"] = True
        with pytest.raises(CapsuleError):
            engine.capsules.validate(malformed, engine.signer)
    finally:
        engine.close()


def test_capsule_import_gates_new_target_control_state():
    engine = Engine(tenant_id=TEN)
    # Proof is outside this control-drift scenario; disable its independent
    # fail-closed gate so the exported capsule begins migration-ready.
    engine.create_project(
        "capsule-drift", project_id=PRJ,
        config={"require_proof_for": []})
    engine.graph.put_node(
        entity_type="artifact", tenant_id=TEN, project_id=PRJ,
        status="recorded", data={"kind": "environment", "python": "3.13"})
    capsule = engine.capsules.export(
        tenant_id=TEN, project_id=PRJ, session_id=None,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer)
    assert engine.capsules.challenge(capsule)["passed"]

    engine.graph.put_node(
        entity_type="constraint", tenant_id=TEN, project_id=PRJ,
        status="active", criticality="critical",
        data={"statement": "Never publish externally"})
    result = engine.capsules.import_capsule(
        capsule, signer=engine.signer, target_model="target",
        target_runtime="runtime")
    try:
        assert not result["challenge"]["passed"]
        assert any(
            item["kind"] == "target_control_state_changed"
            for item in result["challenge"]["control_drift"])
        assert result["challenge"]["enforced_ceiling"] == 1
    finally:
        engine.close()


def test_capsule_import_gates_changed_declared_artifact_bytes(tmp_path):
    artifact = tmp_path / "deliverable.txt"
    artifact.write_text("ready", encoding="utf-8")
    config = {
        "max_autonomy_level": 2,
        "required_verifiers": [{
            "name": "artifact-check",
            "command": _python_command("raise SystemExit(0)"),
            "expect_fail_command": _python_command("raise SystemExit(17)"),
            "artifacts": ["deliverable.txt"],
        }],
    }
    engine = Engine(
        tmp_path / "capsule.db", tenant_id=TEN, workdir=tmp_path)
    engine.create_project("capsule-bytes", project_id=PRJ, config=config)
    engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
    engine.graph.put_node(
        entity_type="artifact", tenant_id=TEN, project_id=PRJ,
        status="recorded", data={"kind": "environment", "python": "3.13"})
    task = engine.graph.put_node(
        entity_type="task", tenant_id=TEN, project_id=PRJ,
        status="open", data={"title": "ship"})
    proof = engine.attest_action(
        PRJ, intent_type="task_complete", intent_statement="ship",
        actor={"agent": "worker"}, action_type="run_verifier",
        continuity={"task_ids": [task.id]})
    assert proof["status"] == "verified"
    capsule = engine.capsules.export(
        tenant_id=TEN, project_id=PRJ, session_id=None,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer)
    assert engine.capsules.challenge(capsule)["passed"]

    artifact.write_text("substituted", encoding="utf-8")
    result = engine.capsules.import_capsule(
        capsule, signer=engine.signer, target_model="target",
        target_runtime="runtime")
    try:
        assert not result["challenge"]["passed"]
        assert any(
            item["kind"] == "target_control_state_changed"
            for item in result["challenge"]["control_drift"])
    finally:
        engine.close()


def test_engine_owned_managers_reject_foreign_tenant_substitution(tmp_path):
    database = tmp_path / "shared.sqlite3"
    owner = Engine(database, tenant_id="ten_owner")
    owner.create_project("owner", project_id=PRJ)
    assumption = owner.graph.put_node(
        entity_type="assumption", tenant_id="ten_owner", project_id=PRJ,
        status="active", data={"statement": "OWNER SECRET"})
    failure = owner.composter.compost(
        tenant_id="ten_owner", project_id=PRJ,
        description="tool crash", failing_step="build")
    foreign = Engine(database, tenant_id="ten_foreign")
    try:
        with pytest.raises(PermissionError):
            foreign.composer.compose(
                tenant_id="ten_owner", project_id=PRJ)
        with pytest.raises(PermissionError):
            foreign.invalidation.fire(
                tenant_id="ten_owner", project_id=PRJ,
                target_node_id=assumption.id,
                trigger_type="contradictory_evidence")
        with pytest.raises(PermissionError):
            foreign.policy.grant(
                project_id=PRJ, level=2, granted_by="foreign")
        with pytest.raises(PermissionError):
            foreign.memory.correct(
                PRJ, assumption.id,
                {"statement": "FOREIGN REWRITE"}, actor="foreign")
        with pytest.raises(PermissionError):
            foreign.partial.quarantine(
                assumption.id, actor="foreign", reason="foreign")
        with pytest.raises(PermissionError):
            foreign.evalgen.from_failure(failure.id)
        assert owner.graph.get(assumption.id)["data"]["statement"] == "OWNER SECRET"
        assert owner.graph.get(assumption.id)["status"] == "active"
    finally:
        foreign.close()
        owner.close()


def test_policy_grant_and_audit_roll_back_together(monkeypatch):
    engine = Engine(tenant_id=TEN)
    engine.create_project("policy-atomic", project_id=PRJ)

    def fail_audit(**_kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(engine.store, "audit", fail_audit)
    try:
        with pytest.raises(RuntimeError, match="audit unavailable"):
            engine.policy.grant(
                project_id=PRJ, level=2, granted_by="lead")
        assert engine.policy.active_grants(PRJ) == []
    finally:
        engine.close()


def test_authorization_cannot_read_a_grant_that_later_rolls_back():
    engine = Engine(tenant_id=TEN)
    engine.create_project(
        "isolation", project_id=PRJ,
        config={"max_autonomy_level": 3})
    grant_inserted = threading.Event()
    release_writer = threading.Event()
    decision_finished = threading.Event()
    decisions = []
    failures = []

    def writer():
        try:
            with engine.store.transaction():
                engine.policy.grant(
                    project_id=PRJ, level=3, granted_by="lead")
                grant_inserted.set()
                if not release_writer.wait(5):
                    raise AssertionError("reader did not release writer")
                raise RuntimeError("roll back the provisional grant")
        except RuntimeError:
            pass
        except BaseException as exc:
            failures.append(exc)

    def reader():
        try:
            decisions.append(engine.policy.decide(
                project_id=PRJ, action_type="create_branch",
                evidence_quality=1.0, historical_reliability=1.0))
        except BaseException as exc:
            failures.append(exc)
        finally:
            decision_finished.set()

    writer_thread = threading.Thread(target=writer)
    reader_thread = threading.Thread(target=reader)
    writer_thread.start()
    assert grant_inserted.wait(5)
    reader_thread.start()
    assert not decision_finished.wait(0.15), (
        "reader observed the writer's uncommitted transaction")
    release_writer.set()
    writer_thread.join(5)
    reader_thread.join(5)
    try:
        assert not failures
        assert decisions[0]["decision"] == "deny"
        assert decisions[0]["effective_level"] == 0
        assert engine.policy.active_grants(PRJ) == []
    finally:
        engine.close()


def test_invalid_project_policy_leaves_no_partial_project():
    engine = Engine(tenant_id=TEN)
    try:
        with pytest.raises(ValueError, match="max_autonomy_level"):
            engine.create_project(
                "invalid", project_id=PRJ,
                config={"max_autonomy_level": 99})
        with pytest.raises(KeyError):
            engine.graph.get(PRJ)
        row = engine.store._conn.execute(
            "SELECT 1 FROM project_policy WHERE project_id = ?",
            (PRJ,)).fetchone()
        assert row is None
        assert engine.store.audit_entries("project.create") == []
    finally:
        engine.close()


def test_process_event_requires_same_scope_and_canonical_stored_semantics(tmp_path):
    database = tmp_path / "process-scope.sqlite3"
    owner = Engine(database, tenant_id="ten_process_owner")
    owner.create_project("owner", project_id="prj_process_owner")
    foreign = Engine(database, tenant_id="ten_process_foreign")
    foreign.create_project("foreign", project_id="prj_process_foreign")
    foreign_event = foreign.store.append_event(
        tenant_id=foreign.tenant_id, project_id="prj_process_foreign",
        source_type="agent_trace", idempotency_key="foreign",
        payload={"message": "foreign requirement"},
        authority="agent_observed")
    owner_event = owner.store.append_event(
        tenant_id=owner.tenant_id, project_id="prj_process_owner",
        source_type="agent_trace", idempotency_key="owner",
        payload={"message": "owner requirement"},
        authority="agent_observed")
    try:
        with pytest.raises(PermissionError, match="outside this Engine tenant"):
            owner.process_event(foreign_event)
        with pytest.raises(PermissionError):
            owner.projection_fingerprint("prj_process_foreign")
        with pytest.raises(PermissionError):
            owner.replay_completeness("prj_process_foreign")

        substituted = copy.deepcopy(owner_event)
        substituted["payload"] = {"message": "substituted requirement"}
        with pytest.raises(ValueError, match="canonical stored event"):
            owner.process_event(substituted)
        with pytest.raises(KeyError):
            owner.graph.get(owner_event["event_id"])

        report = owner.process_event(owner_event)
        assert report["event_id"] == owner_event["event_id"]
        assert owner.graph.get(
            owner_event["event_id"], tenant_id=owner.tenant_id,
            project_id="prj_process_owner", entity_type="event")
    finally:
        foreign.close()
        owner.close()


def test_foreign_event_cannot_launder_provenance_into_distilled_memory():
    store = Store(":memory:")
    graph = Graph(store)
    memory = Memory(store, graph, tenant_id="ten_memory_owner")
    foreign_event = store.append_event(
        tenant_id="ten_memory_foreign", project_id="prj_memory_foreign",
        source_type="agent_trace", idempotency_key="foreign-provenance",
        payload={"message": "not owner evidence"},
        authority="agent_observed")
    graph.put_node(
        entity_type="project", tenant_id="ten_memory_owner",
        project_id="prj_memory_owner", node_id="prj_memory_owner",
        status="active", data={"name": "owner"})
    node = graph.put_node(
        entity_type="claim", tenant_id="ten_memory_owner",
        project_id="prj_memory_owner", status="recorded",
        data={"statement": "owner claim"})
    try:
        with pytest.raises(ValueError, match="event provenance must belong"):
            graph.put_node(
                entity_type="claim", tenant_id="ten_memory_owner",
                project_id="prj_memory_owner", node_id=node.id,
                data={"statement": "foreign-backed claim"},
                event_id=foreign_event["event_id"])
        with pytest.raises(ValueError, match="event provenance must belong"):
            memory.correct(
                "prj_memory_owner", node.id,
                {"statement": "foreign correction"}, actor="reviewer",
                event_id=foreign_event["event_id"])

        current = graph.get(node.id)
        assert current["version"] == 1
        assert current["data"]["statement"] == "owner claim"
        assert store.audit_entries("memory.correct") == []
        with pytest.raises(ValueError, match="without provenance"):
            memory.promote(
                "prj_memory_owner", node.id, "L3", actor="distiller")
    finally:
        store.close()


@pytest.mark.parametrize(
    "actor,environment,error",
    [
        ([], None, "invalid attestation input"),
        ({"agent": "worker"}, {"temperature": float("nan")},
         "finite canonical JSON"),
    ],
    ids=["non-object-actor", "non-finite-environment"],
)
def test_attestation_rejects_malformed_input_without_partial_state(
        actor, environment, error):
    engine = Engine(tenant_id=TEN)
    engine.create_project("attestation-atomic", project_id=PRJ)
    audits_before = engine.store.audit_entries()
    try:
        with pytest.raises(ValueError, match=error):
            engine.attest_action(
                PRJ, intent_type="task_complete", intent_statement="ship",
                actor=actor, environment=environment)
        assert engine.graph.current(PRJ, "action", tenant_id=TEN) == []
        assert engine.store.audit_entries() == audits_before
    finally:
        engine.close()


@pytest.mark.parametrize(
    "config,ref,expected_tracked",
    [
        ({}, "refs/heads/feature/untrusted", "refs/heads/main"),
        ({"tracked_ref": None}, "refs/heads/main", None),
    ],
    ids=["default-main", "explicitly-undecidable"],
)
def test_first_untrusted_push_cannot_choose_the_revision_frontier(
        config, ref, expected_tracked):
    repository_id = 9009
    engine = Engine(tenant_id=TEN)
    engine.create_project(
        "frontier", project_id=PRJ, repository_id=repository_id,
        config=config)
    payload = {
        "ref": ref,
        "before": "0" * 40,
        "after": "a" * 40,
        "forced": False,
        "deleted": False,
        "created": True,
        "commits": [],
        "head_commit": {"timestamp": "2026-08-03T12:00:00Z"},
        "repository": {"id": repository_id, "full_name": "owner/repo"},
    }
    try:
        engine.ingest_github(PRJ, "push", "first-untrusted-push", payload)
        project = engine.graph.get(PRJ)
        assert project["data"].get("current_head_sha") is None
        assert project["data"].get("tracked_ref") is None

        engine.resume_packet(PRJ)
        receipt = engine.continuity_check(PRJ)["continuity_receipt"]
        revision = receipt["decision_state"]["revision"]
        assert revision["tracked_ref"] == expected_tracked
        assert revision["current_head_sha"] is None
        assert revision["external_without_frontier"]
        assert receipt["decision"] != "success"
    finally:
        engine.close()


def test_protected_ref_reconfiguration_cannot_reuse_an_old_head_or_check():
    repository_id = 9010
    trusted_app_id = 15368
    base_config = {
        "require_proof_for": [],
        "required_verifiers": ["ci"],
        "trusted_verifier_apps": [
            {"app_id": trusted_app_id, "slug": "actions"}],
        "min_evidence_grade": None,
        "tracked_ref": "refs/heads/main",
    }
    engine = Engine(tenant_id=TEN)
    engine.create_project(
        "ref-epoch", project_id=PRJ, repository_id=repository_id,
        config=base_config)

    def push(ref, before, after):
        return {
            "ref": ref, "before": before, "after": after,
            "forced": False, "deleted": False, "created": before == "0" * 40,
            "commits": [],
            "head_commit": {"timestamp": "2026-08-03T12:00:00Z"},
            "repository": {"id": repository_id, "full_name": "owner/repo"},
        }

    def check(head, check_id):
        return {
            "action": "completed",
            "check_run": {
                "id": check_id, "name": "ci", "status": "completed",
                "conclusion": "success", "head_sha": head,
                "completed_at": "2026-08-03T12:01:00Z",
                "app": {"id": trusted_app_id, "slug": "actions"},
            },
            "repository": {"id": repository_id, "full_name": "owner/repo"},
        }

    main_head = "a" * 40
    release_head = "b" * 40
    try:
        engine.ingest_github(
            PRJ, "push", "main-head", push("refs/heads/main", "0" * 40, main_head))
        engine.ingest_github(PRJ, "check_run", "main-ci", check(main_head, 1))
        engine.resume_packet(PRJ)
        assert engine.continuity_check(PRJ)["conclusion"] == "success"
        main_revision = engine.policy.tracked_ref_basis(PRJ)["revision"]

        release_config = {**base_config, "tracked_ref": "refs/heads/release"}
        engine.policy.set_project_config(PRJ, release_config)
        engine.resume_packet(PRJ)
        changed = engine.continuity_check(PRJ)
        revision = changed["continuity_receipt"]["decision_state"]["revision"]
        assert revision == {
            "tracked_ref": "refs/heads/release",
            "current_head_sha": None,
            "uncertain": True,
            "external_without_frontier": True,
        }
        assert changed["verifier_gaps"] == ["ci"]
        assert changed["conclusion"] != "success"
        assert engine.policy.tracked_ref_basis(PRJ)["revision"] > main_revision

        engine.ingest_github(
            PRJ, "push", "release-head",
            push("refs/heads/release", "0" * 40, release_head))
        engine.resume_packet(PRJ)
        assert engine.continuity_check(PRJ)["verifier_gaps"] == ["ci"]
        engine.ingest_github(
            PRJ, "check_run", "release-ci", check(release_head, 2))
        engine.resume_packet(PRJ)
        assert engine.continuity_check(PRJ)["conclusion"] == "success"

        engine.policy.set_project_config(
            PRJ, {**base_config, "tracked_ref": None})
        engine.resume_packet(PRJ)
        unset = engine.continuity_check(PRJ)
        unset_revision = unset["continuity_receipt"]["decision_state"]["revision"]
        assert unset_revision["tracked_ref"] is None
        assert unset_revision["current_head_sha"] is None
        assert unset_revision["external_without_frontier"]
        assert unset["conclusion"] != "success"

        # Switching back is another epoch: the earlier main observation is
        # historical, not a current frontier that can be resurrected.
        engine.policy.set_project_config(PRJ, base_config)
        engine.resume_packet(PRJ)
        restored = engine.continuity_check(PRJ)
        restored_revision = restored[
            "continuity_receipt"]["decision_state"]["revision"]
        assert restored_revision["tracked_ref"] == "refs/heads/main"
        assert restored_revision["current_head_sha"] is None
        assert restored["conclusion"] != "success"
    finally:
        engine.close()


def test_rewritten_persisted_event_payload_fails_chain_and_processing_closed():
    engine = Engine(tenant_id=TEN)
    engine.create_project("payload-commitment", project_id=PRJ)
    event = engine.store.append_event(
        tenant_id=TEN, project_id=PRJ, source_type="agent_trace",
        idempotency_key="payload-commitment",
        payload={"message": "The system must preserve privacy."},
        authority="agent_observed")
    try:
        engine.store._conn.execute("DROP TRIGGER events_payload_redaction_only")
        engine.store._conn.execute(
            "UPDATE events SET payload = ? WHERE event_id = ?",
            ('{"message":"The system must leak secrets."}', event["event_id"]))
        engine.store._conn.commit()

        chain = engine.store.verify_chain("events")
        assert not chain["intact"]
        assert chain["broken_at"] == event["event_id"]
        assert "payload differs" in chain["reason"]
        with pytest.raises(EventPayloadIntegrityError, match="failed its commitment"):
            engine.store.get_event(event["event_id"])
        with pytest.raises(EventPayloadIntegrityError, match="failed its commitment"):
            engine.process_event(event)
        with pytest.raises(KeyError):
            engine.graph.get(event["event_id"])
    finally:
        engine.close()


def test_retention_tombstone_preserves_chain_but_reports_payload_unavailable():
    engine = Engine(tenant_id=TEN)
    engine.create_project("retention-commitment", project_id=PRJ)
    event = engine.store.append_event(
        tenant_id=TEN, project_id=PRJ, source_type="agent_trace",
        idempotency_key="retained-payload",
        payload={"message": "retire these bytes"},
        authority="agent_observed")
    try:
        assert engine.memory.sweep_retention(now="2100-01-01T00:00:00Z") == 1
        retained = engine.store.get_event(event["event_id"])
        assert retained["payload"] is None
        assert retained["stored_payload_digest"] == event["stored_payload_digest"]

        chain = engine.store.verify_chain("events")
        assert chain["intact"]
        assert chain["payload_integrity"] == "unavailable"
        assert chain["payloads_unavailable"] == 1
        replay = engine.replay_completeness(PRJ)
        assert not replay["replayable"]
        assert replay["redacted_payloads"] == 1
    finally:
        engine.close()
