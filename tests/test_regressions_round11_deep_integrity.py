"""Planted regressions for proof lifetime, provenance, and state machines."""

from __future__ import annotations

import copy
import json
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from jsonschema import ValidationError

from causal_continuity_engine.core import canonical_json, sha256_hex
from causal_continuity_engine.engine import PROCESSOR_VERSION, Engine
from causal_continuity_engine.verifiers import VerifierRunner
from tests.schema_validation import draft202012_validator

TENANT = "ten_round11"
PROJECT = "prj_round11"
ROOT = Path(__file__).resolve().parents[1]


def _command(script: str) -> str:
    return f'"{Path(sys.executable).as_posix()}" -c "{script}"'


def _proof_engine(tmp_path, *, database=":memory:", tenant_id=TENANT,
                  project_id=PROJECT, command: str | None = None) -> Engine:
    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "required_verifiers": [{
            "name": "round11-pass",
            "command": command or _command("raise SystemExit(0)"),
        }],
    }
    engine = Engine(
        database, tenant_id=tenant_id, workdir=tmp_path)
    engine.create_project("round11", project_id=project_id, config=config)
    engine.policy.grant(
        project_id=project_id, level=2, granted_by="lead")
    return engine


def _attest(engine: Engine, task_id: str, *, continuity: dict | None = None):
    return engine.attest_action(
        PROJECT, intent_type="task_complete", intent_statement="ship",
        actor={"agent": "worker"}, action_type="run_verifier",
        continuity=continuity or {"task_ids": [task_id]})


def test_proof_commits_the_task_version_it_verified(tmp_path):
    engine = _proof_engine(tmp_path)
    task = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        status="open", data={"title": "ship version one"})
    proof = _attest(engine, task.id)
    assert engine.proof_currency(PROJECT, task.id, proof)["current"]

    engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        node_id=task.id, status="open", data={"title": "ship version two"})

    currency = engine.proof_currency(PROJECT, task.id, proof)
    assert not currency["current"]
    assert any(
        change["name"] == f"continuity:task_ids:{task.id}"
        for change in currency["changed_inputs"])
    with pytest.raises(PermissionError, match="continuity state changed"):
        engine.complete_task(PROJECT, task.id, proof=proof)
    assert engine.graph.get(task.id)["status"] == "open"
    engine.close()


def test_proof_commits_every_linked_requirement_and_assumption(tmp_path):
    engine = _proof_engine(tmp_path)
    task = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        status="open", data={"title": "ship"})
    requirement = engine.graph.put_node(
        entity_type="requirement", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"statement": "preserve output"})
    assumption = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"statement": "input is stable"})
    proof = engine.attest_action(
        PROJECT, intent_type="task_complete", intent_statement="ship",
        actor={"agent": "worker"}, action_type="run_verifier",
        requirement_ids=[requirement.id], continuity={
            "task_ids": [task.id],
            "assumption_ids": [assumption.id],
        })
    assert proof["continuity_links"]["requirement_ids"] == [requirement.id]
    assert f"continuity:requirement_ids:{requirement.id}" in {
        item["name"] for item in proof["inputs"]}

    engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        node_id=assumption.id, status="active",
        data={"statement": "input is no longer stable"})
    currency = engine.proof_currency(PROJECT, task.id, proof)
    assert not currency["current"]
    assert f"continuity:assumption_ids:{assumption.id}" in {
        item["name"] for item in currency["changed_inputs"]}
    engine.close()


def test_proof_currency_foreign_target_is_indistinguishable_from_missing(tmp_path):
    database = tmp_path / "currency-scope.db"
    owner = Engine(database, tenant_id="ten_owner")
    owner.create_project("owner", project_id="prj_owner")
    secret = owner.graph.put_node(
        entity_type="task", tenant_id="ten_owner", project_id="prj_owner",
        status="blocked", data={"title": "OWNER SECRET"})
    foreign = Engine(database, tenant_id="ten_foreign")
    foreign.create_project("foreign", project_id="prj_foreign")

    messages = []
    for target in (secret.id, "tsk_000000000000000000000000"):
        with pytest.raises(PermissionError) as caught:
            foreign.proof_currency("prj_foreign", target, {})
        messages.append(str(caught.value))
    assert messages[0] == messages[1]
    assert "blocked" not in messages[0]
    assert "OWNER SECRET" not in messages[0]
    foreign.close()
    owner.close()


def test_ingestion_and_continuity_ignore_foreign_rows_with_same_project_label():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("scoped", project_id=PROJECT)
    foreign_requirement = engine.graph.put_node(
        entity_type="requirement", tenant_id="ten_foreign",
        project_id=PROJECT, node_id="req_foreign_same_project",
        status="active", data={
            "statement": "FOREIGN SECRET",
            "source_ref": "trace:scope-check",
            "source_refs": ["trace:scope-check"],
            "conflict_requires_resolution": True,
        })

    report = engine.ingest_agent_trace(
        PROJECT, session_id=None, span_id="scope-check",
        payload={"message": "ordinary trace with no extracted requirement"})
    assert report is not None
    assert engine.graph.get(foreign_requirement.id)["version"] == 1
    check = engine.continuity_check(PROJECT)
    assert foreign_requirement.id not in check["authority_conflicts"]
    engine.close()


def test_spent_proof_identity_is_tenant_and_project_scoped(tmp_path):
    database = tmp_path / "spent-scope.db"
    first = Engine(database, tenant_id="ten_a")
    first.create_project("a1", project_id="prj_a1")
    first.create_project("a2", project_id="prj_a2")
    task_a1 = first.graph.put_node(
        entity_type="task", tenant_id="ten_a", project_id="prj_a1",
        status="open", data={"title": "a1"})
    task_a1_other = first.graph.put_node(
        entity_type="task", tenant_id="ten_a", project_id="prj_a1",
        status="open", data={"title": "a1 other"})
    task_a2 = first.graph.put_node(
        entity_type="task", tenant_id="ten_a", project_id="prj_a2",
        status="open", data={"title": "a2"})

    second = Engine(database, tenant_id="ten_b")
    second.create_project("b", project_id="prj_b")
    task_b = second.graph.put_node(
        entity_type="task", tenant_id="ten_b", project_id="prj_b",
        status="open", data={"title": "b"})
    proof_id = "prf_111111111111111111111111"

    assert first._claim_proof("prj_a1", proof_id, task_a1.id) is None
    assert first._claim_proof("prj_a2", proof_id, task_a2.id) is None
    assert second._claim_proof("prj_b", proof_id, task_b.id) is None
    assert first._claim_proof(
        "prj_a1", proof_id, task_a1_other.id) == task_a1.id
    rows = first.store._conn.execute(
        "SELECT tenant_id, project_id FROM spent_proofs "
        "WHERE proof_id = ? ORDER BY tenant_id, project_id",
        (proof_id,)).fetchall()
    assert [(row["tenant_id"], row["project_id"]) for row in rows] == [
        ("ten_a", "prj_a1"), ("ten_a", "prj_a2"), ("ten_b", "prj_b")]
    second.close()
    first.close()


def test_spent_proof_backfill_scans_history_and_deduplicates_per_project(
        tmp_path):
    database = tmp_path / "spent-history.db"
    engine = Engine(database, tenant_id=TENANT)
    engine.create_project("one", project_id="prj_history_one")
    engine.create_project("two", project_id="prj_history_two")
    proof_id = "prf_222222222222222222222222"
    first = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT,
        project_id="prj_history_one", status="complete",
        data={"title": "historical first", "completion_evidence": proof_id})
    engine.graph.put_node(
        entity_type="task", tenant_id=TENANT,
        project_id="prj_history_one", node_id=first.id, status="reopened",
        data={"completion_evidence": None})
    engine.graph.put_node(
        entity_type="task", tenant_id=TENANT,
        project_id="prj_history_one", status="complete",
        data={"title": "duplicate", "completion_evidence": proof_id})
    second_project = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT,
        project_id="prj_history_two", status="complete",
        data={"title": "other scope", "completion_evidence": proof_id})
    assert engine.store._conn.execute(
        "SELECT COUNT(*) FROM spent_proofs").fetchone()[0] == 0
    engine.close()

    reopened = Engine(database, tenant_id=TENANT)
    rows = reopened.store._conn.execute(
        "SELECT project_id, task_id FROM spent_proofs "
        "WHERE tenant_id = ? AND proof_id = ? ORDER BY project_id",
        (TENANT, proof_id)).fetchall()
    assert [(row["project_id"], row["task_id"]) for row in rows] == [
        ("prj_history_one", first.id),
        ("prj_history_two", second_project.id),
    ]
    assert reopened.graph.get(
        first.id, tenant_id=TENANT,
        project_id="prj_history_one")["data"]["completion_evidence"] is None
    assert reopened._backfill_spent_proofs() == 0
    reopened.close()


def test_spent_proof_backfill_audit_failure_rolls_back_and_retries(
        tmp_path, monkeypatch):
    database = tmp_path / "spent-audit-atomic.db"
    engine = Engine(database, tenant_id=TENANT)
    engine.create_project("audit atomicity", project_id=PROJECT)
    proof_id = "prf_444444444444444444444444"
    task = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        status="complete",
        data={"title": "historical", "completion_evidence": proof_id})
    original_audit = engine.store.audit

    def fail_after_audit(**kwargs):
        original_audit(**kwargs)
        raise RuntimeError("planted backfill audit failure")

    monkeypatch.setattr(engine.store, "audit", fail_after_audit)
    with pytest.raises(RuntimeError, match="backfill audit failure"):
        engine._backfill_spent_proofs()

    assert engine.store._conn.execute(
        "SELECT COUNT(*) FROM spent_proofs WHERE tenant_id = ? "
        "AND project_id = ? AND proof_id = ?",
        (TENANT, PROJECT, proof_id)).fetchone()[0] == 0
    assert engine.store.audit_entries("spent_proofs.backfill") == []
    engine.close()

    retried = Engine(database, tenant_id=TENANT)
    row = retried.store._conn.execute(
        "SELECT task_id FROM spent_proofs WHERE tenant_id = ? "
        "AND project_id = ? AND proof_id = ?",
        (TENANT, PROJECT, proof_id)).fetchone()
    assert row["task_id"] == task.id
    audits = retried.store.audit_entries("spent_proofs.backfill")
    assert len(audits) == 1
    assert "carried 1 pre-existing completion" in audits[0]["detail"]
    retried.close()


def test_spent_proof_legacy_ddl_rolls_back_as_one_atomic_migration(tmp_path):
    engine = Engine(tmp_path / "legacy-proof.db", tenant_id=TENANT)
    engine.create_project("migration", project_id=PROJECT)
    tasks = [
        engine.graph.put_node(
            entity_type="task", tenant_id=TENANT, project_id=PROJECT,
            status="complete", data={"title": title})
        for title in ("first", "second")
    ]
    proof_id = "prf_333333333333333333333333"
    with engine.store._lock, engine.store._conn:
        engine.store._conn.execute("DROP TABLE spent_proofs")
        engine.store._conn.execute(
            "CREATE TABLE spent_proofs ("
            "project_id TEXT NOT NULL, proof_id TEXT NOT NULL, "
            "task_id TEXT NOT NULL, spent_at TEXT NOT NULL)")
        engine.store._conn.executemany(
            "INSERT INTO spent_proofs VALUES (?,?,?,?)",
            [(PROJECT, proof_id, task.id, f"2026-01-0{index}T00:00:00Z")
             for index, task in enumerate(tasks, start=1)])

    with pytest.raises(sqlite3.IntegrityError):
        engine._migrate_spent_proofs_scope()

    columns = engine.store._conn.execute(
        "PRAGMA table_info(spent_proofs)").fetchall()
    assert [row["name"] for row in columns] == [
        "project_id", "proof_id", "task_id", "spent_at"]
    assert engine.store._conn.execute(
        "SELECT COUNT(*) FROM spent_proofs").fetchone()[0] == 2
    assert engine.store._conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'spent_proofs_legacy_scope'").fetchone() is None
    assert not engine.store._conn.in_transaction
    engine.close()


def test_unsupported_provenance_chain_and_cycle_cannot_reach_l3():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("provenance", project_id=PROJECT)
    claim_a = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "A"})
    claim_b = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "B"})
    engine.graph.put_edge(
        edge_type="supports", src_id=claim_b.id, dst_id=claim_a.id,
        tenant_id=TENANT, project_id=PROJECT)
    with pytest.raises(ValueError, match="without provenance"):
        engine.memory.promote(PROJECT, claim_a.id, "L3", actor="worker")

    engine.graph.put_edge(
        edge_type="supports", src_id=claim_a.id, dst_id=claim_b.id,
        tenant_id=TENANT, project_id=PROJECT)
    with pytest.raises(ValueError, match="without provenance"):
        engine.memory.promote(PROJECT, claim_a.id, "L3", actor="worker")
    engine.close()


def test_l3_provenance_rejects_stale_event_bindings_and_id_collisions():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("provenance", project_id=PROJECT)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="stale-source", payload={"message": "version one"},
        authority="agent_observed")
    source = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "version one"},
        event_id=event["event_id"])
    target = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "derived target"})
    engine.graph.put_edge(
        edge_type="supports", src_id=source.id, dst_id=target.id,
        tenant_id=TENANT, project_id=PROJECT)
    engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        node_id=source.id, status="recorded",
        data={"statement": "materially changed version"})

    with pytest.raises(ValueError, match="without provenance"):
        engine.memory.promote(PROJECT, target.id, "L3", actor="worker")

    collision = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        node_id=event["event_id"], status="recorded",
        data={"statement": "identifier collision only"})
    collision_target = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "collision target"})
    engine.graph.put_edge(
        edge_type="supports", src_id=collision.id, dst_id=collision_target.id,
        tenant_id=TENANT, project_id=PROJECT)
    with pytest.raises(ValueError, match="without provenance"):
        engine.memory.promote(
            PROJECT, collision_target.id, "L3", actor="worker")
    engine.close()


def test_direct_provenance_edge_accepts_an_unprojected_canonical_event():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("provenance", project_id=PROJECT)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="raw-source", payload={"message": "observed"},
        authority="agent_observed")
    target = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "directly derived"})
    engine.graph.put_edge(
        edge_type="derived_from", src_id=target.id,
        dst_id=event["event_id"], tenant_id=TENANT, project_id=PROJECT)

    engine.memory.promote(PROJECT, target.id, "L3", actor="worker")
    assert engine.memory.tier_of(PROJECT, target.id) == "L3"
    engine.close()


def test_recursive_provenance_accepts_a_chain_ending_in_a_canonical_event():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("provenance", project_id=PROJECT)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="source", payload={"message": "observed"},
        authority="agent_observed")
    source = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "event backed"},
        event_id=event["event_id"])
    middle = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "middle"})
    target = engine.graph.put_node(
        entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"statement": "target"})
    engine.graph.put_edge(
        edge_type="supports", src_id=source.id, dst_id=middle.id,
        tenant_id=TENANT, project_id=PROJECT)
    engine.graph.put_edge(
        edge_type="supports", src_id=middle.id, dst_id=target.id,
        tenant_id=TENANT, project_id=PROJECT)

    engine.memory.promote(PROJECT, target.id, "L3", actor="worker")
    assert engine.memory.tier_of(PROJECT, target.id) == "L3"
    engine.close()


def test_projection_and_success_marker_commit_or_roll_back_together(
        tmp_path, monkeypatch):
    engine = Engine(tmp_path / "projection.db", tenant_id=TENANT)
    engine.create_project("projection", project_id=PROJECT)
    original = engine.store.mark_processed

    def fail_success(event_id, processor_version, status="ok", error=None):
        if status == "ok":
            raise RuntimeError("planted success-marker failure")
        return original(event_id, processor_version, status, error)

    monkeypatch.setattr(engine.store, "mark_processed", fail_success)
    with pytest.raises(RuntimeError, match="success-marker failure"):
        engine.ingest_agent_trace(
            PROJECT, session_id=None, span_id="atomic-marker",
            payload={"message": "Requirement: preserve atomic projection"})

    assert len(engine.store.events(PROJECT, tenant_id=TENANT)) == 1
    assert [
        node for node in engine.graph.current(PROJECT, tenant_id=TENANT)
        if node["entity_type"] != "project"
    ] == []
    quarantined = engine.store.quarantined(PROCESSOR_VERSION)
    assert len(quarantined) == 1
    assert "success-marker failure" in quarantined[0]["error"]
    engine.close()


def test_direct_process_event_rolls_back_every_partial_projection(monkeypatch):
    engine = Engine(tenant_id=TENANT)
    engine.create_project("direct projection", project_id=PROJECT)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="direct-atomic",
        payload={"message": "Requirement: preserve direct atomicity"},
        authority="agent_observed")
    original = engine._process_text

    def fail_after_projection(processed_event, block, report):
        original(processed_event, block, report)
        raise RuntimeError("planted direct projection failure")

    monkeypatch.setattr(engine, "_process_text", fail_after_projection)
    with pytest.raises(RuntimeError, match="direct projection failure"):
        engine.process_event(event)

    assert [
        node for node in engine.graph.current(
            PROJECT, tenant_id=TENANT)
        if node["entity_type"] != "project"
    ] == []
    engine.close()


@pytest.mark.parametrize("field", ["prev_hash", "entry_hash"])
def test_processing_rejects_substituted_chain_metadata(field):
    engine = Engine(tenant_id=TENANT)
    engine.create_project("canonical", project_id=PROJECT)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key=f"metadata-{field}", payload={"message": "observed"},
        authority="agent_observed")
    substituted = copy.deepcopy(event)
    substituted[field] = "sha256:" + "f" * 64

    with pytest.raises(ValueError, match="canonical stored event"):
        engine.process_event(substituted)
    assert engine.graph.current(
        PROJECT, "event", tenant_id=TENANT) == []
    engine.close()


def test_replay_results_require_the_replay_ready_source_state():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("replay", project_id=PROJECT)
    generated = engine.graph.put_node(
        entity_type="evaluation", tenant_id=TENANT, project_id=PROJECT,
        status="candidate", data={"kind": "generated_eval"})
    with pytest.raises(ValueError, match="replay_ready"):
        engine.replay.record_result(
            generated.id, diff={"forged": True}, outcome="pass")
    assert engine.graph.get(generated.id)["status"] == "candidate"

    replay = engine.graph.put_node(
        entity_type="evaluation", tenant_id=TENANT, project_id=PROJECT,
        status="replay_ready",
        data={"kind": "replay", "fidelity": "non_reproducible"})
    assert engine.replay.record_result(
        replay.id, diff={}, outcome="pass")["status"] == "replay_done"
    with pytest.raises(ValueError, match="replay_ready"):
        engine.replay.record_result(replay.id, diff={}, outcome="pass")
    engine.close()


def test_learning_event_scope_hides_foreign_existence_like_missing(tmp_path):
    database = tmp_path / "learning-event-scope.db"
    owner = Engine(database, tenant_id="ten_learning_owner")
    owner.create_project("owner", project_id="prj_learning_owner")
    foreign_event = owner.store.append_event(
        tenant_id="ten_learning_owner", project_id="prj_learning_owner",
        source_type="agent_trace", idempotency_key="owner-secret-event",
        payload={"message": "OWNER SECRET"}, authority="agent_observed")
    requester = Engine(database, tenant_id="ten_learning_requester")
    requester.create_project("requester", project_id="prj_learning_requester")
    missing = "evt_000000000000000000000000"

    operations = (
        lambda event_id: requester.replay.start(
            tenant_id="ten_learning_requester",
            project_id="prj_learning_requester", from_event_id=event_id),
        lambda event_id: requester.composter.compost(
            tenant_id="ten_learning_requester",
            project_id="prj_learning_requester", description="failed",
            failing_step="scope boundary", trace_event_ids=[event_id]),
    )
    for operation in operations:
        messages = []
        for event_id in (foreign_event["event_id"], missing):
            with pytest.raises(PermissionError) as caught:
                operation(event_id)
            messages.append(str(caught.value))
        assert messages[0] == messages[1]
        assert foreign_event["event_id"] not in messages[0]
        assert "OWNER SECRET" not in messages[0]
    requester.close()
    owner.close()


def test_skill_approval_requires_exactly_the_proposed_source_state():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("skills", project_id=PROJECT)
    quarantined = engine.graph.put_node(
        entity_type="skill", tenant_id=TENANT, project_id=PROJECT,
        status="quarantined", data={"name": "unsafe"})
    with pytest.raises(ValueError, match="proposed"):
        engine.skills.approve(
            quarantined.id, actor="lead", sandbox_eval_passed=True)

    proposed = engine.graph.put_node(
        entity_type="skill", tenant_id=TENANT, project_id=PROJECT,
        status="proposed", data={"name": "safe"})
    approved = engine.skills.approve(
        proposed.id, actor="lead", sandbox_eval_passed=True)
    assert approved["status"] == "approved"
    with pytest.raises(ValueError, match="proposed"):
        engine.skills.approve(
            proposed.id, actor="lead", sandbox_eval_passed=True)
    assert engine.graph.get(proposed.id)["version"] == approved["version"]
    engine.close()


def test_generated_eval_dedup_is_atomic_across_connections(tmp_path):
    database = tmp_path / "eval-race.db"
    first = Engine(database, tenant_id=TENANT)
    first.create_project("evals", project_id=PROJECT)
    failure = first.composter.compost(
        tenant_id=TENANT, project_id=PROJECT,
        description="test failed at shared boundary", failing_step="pytest")
    second = Engine(database, tenant_id=TENANT)
    barrier = threading.Barrier(2)

    def generate(engine):
        barrier.wait(timeout=5)
        return engine.evalgen.from_failure(failure.id)["node_id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(generate, engine) for engine in (first, second)]
        node_ids = [future.result(timeout=15) for future in futures]
    assert node_ids[0] == node_ids[1]
    generated = [
        node for node in first.graph.current(
            PROJECT, "evaluation", tenant_id=TENANT)
        if node["data"].get("kind") == "generated_eval"
    ]
    assert [node["node_id"] for node in generated] == [node_ids[0]]
    second.close()
    first.close()


def test_mid_verifier_peer_mutation_discards_every_staged_record(
        tmp_path, monkeypatch):
    database = tmp_path / "staged-race.db"
    engine = _proof_engine(
        tmp_path, database=database,
        command=_command("import time; time.sleep(1)"))
    task = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        status="open", data={"title": "version one"})
    peer = Engine(database, tenant_id=TENANT, workdir=tmp_path)
    verifier_started = threading.Event()
    original_run = VerifierRunner.run

    def signaled_run(runner, spec):
        verifier_started.set()
        return original_run(runner, spec)

    monkeypatch.setattr(VerifierRunner, "run", signaled_run)
    failures = []

    def attest():
        try:
            _attest(engine, task.id)
        except BaseException as exc:  # captured for the parent-thread assertion
            failures.append(exc)

    thread = threading.Thread(target=attest)
    thread.start()
    assert verifier_started.wait(timeout=5)
    peer.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        node_id=task.id, status="open", data={"title": "peer mutation"})
    thread.join(timeout=15)

    assert not thread.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], RuntimeError)
    assert "control state changed" in str(failures[0])
    assert engine.graph.current(
        PROJECT, "action", tenant_id=TENANT) == []
    assert engine.graph.current(
        PROJECT, "verification", tenant_id=TENANT) == []
    assert engine.store._conn.execute(
        "SELECT COUNT(*) FROM evidence_blobs").fetchone()[0] == 0
    peer.close()
    engine.close()


def test_emitted_event_matches_closed_schema_and_exposes_both_commitments():
    schema = json.loads(
        (ROOT / "schemas" / "cce.event.v1.json").read_text(encoding="utf-8"))
    validator = draft202012_validator(schema)
    engine = Engine(tenant_id=TENANT)
    engine.create_project("schema", project_id=PROJECT)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="schema-event", payload={"message": "observed"},
        authority="agent_observed")

    validator.validate(event)
    assert event["payload_digest"].startswith("sha256:")
    assert event["stored_payload_digest"] == sha256_hex(
        canonical_json(event["payload"]))
    forged = event | {"undeclared": True}
    with pytest.raises(ValidationError):
        validator.validate(forged)
    with pytest.raises(ValidationError):
        validator.validate(event | {"stored_payload_digest": None})
    validator.validate(event | {
        "payload": None, "stored_payload_digest": None})
    assert "delivery/idempotency" in schema["properties"]["payload_digest"][
        "description"]
    assert "persisted" in schema["properties"]["stored_payload_digest"][
        "description"]
    engine.close()


@pytest.mark.parametrize(("override", "message"), [
    ({"tenant_id": ""}, "tenant_id"),
    ({"authority": "self_declared_root"}, "authority"),
    ({"authority": []}, "authority"),
    ({"authority": {}}, "authority"),
    ({"actor_type": "robot"}, "actor_type"),
    ({"actor_type": []}, "actor_type"),
    ({"actor_type": {}}, "actor_type"),
    ({"capture_mode": "everything"}, "capture_mode"),
    ({"capture_mode": []}, "capture_mode"),
    ({"capture_mode": {}}, "capture_mode"),
    ({"schema_version": "cce.event.v2"}, "schema_version"),
    ({"payload_digest": "sha256:not-a-digest"}, "payload_digest"),
    ({"observed_at": "2026-01-01T12:30Z"}, "observed_at"),
    ({"observed_at": "20260101T123000Z"}, "observed_at"),
])
def test_append_event_rejects_non_schema_values_before_writing(
        override, message):
    engine = Engine(tenant_id=TENANT)
    engine.create_project("event boundary", project_id=PROJECT)
    arguments = {
        "tenant_id": TENANT,
        "project_id": PROJECT,
        "source_type": "agent_trace",
        "idempotency_key": "invalid-event",
        "payload": {"message": "observed"},
        "authority": "agent_observed",
    }
    arguments.update(override)

    with pytest.raises(ValueError, match=message):
        engine.store.append_event(**arguments)
    assert engine.store.events(PROJECT, tenant_id=TENANT) == []
    assert engine.store._conn.execute(
        "SELECT n FROM event_seq").fetchone()[0] == 0
    engine.close()


def test_null_event_payload_has_an_exact_empty_payload_commitment():
    engine = Engine(tenant_id=TENANT)
    engine.create_project("event boundary", project_id=PROJECT)
    event = engine.store.append_event(
        tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
        idempotency_key="null-payload", payload=None,
        authority="agent_observed")
    assert event["stored_payload_digest"] == sha256_hex("")
    engine.close()


def test_deferred_commit_failure_rolls_back_and_store_remains_reusable():
    engine = Engine(tenant_id=TENANT)
    with engine.store._conn:
        engine.store._conn.execute(
            "CREATE TABLE deferred_parent (id INTEGER PRIMARY KEY)")
        engine.store._conn.execute(
            "CREATE TABLE deferred_child ("
            "id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, "
            "FOREIGN KEY (parent_id) REFERENCES deferred_parent(id) "
            "DEFERRABLE INITIALLY DEFERRED)")

    with pytest.raises(sqlite3.IntegrityError):
        with engine.store.transaction():
            engine.store._conn.execute(
                "INSERT INTO deferred_child VALUES (1, 99)")
    assert engine.store._transaction_depth == 0
    assert not engine.store._conn.in_transaction

    with engine.store.transaction():
        engine.store._conn.execute(
            "INSERT INTO deferred_parent VALUES (99)")
        engine.store._conn.execute(
            "INSERT INTO deferred_child VALUES (2, 99)")
    assert engine.store._conn.execute(
        "SELECT id FROM deferred_child").fetchone()[0] == 2
    engine.close()


def test_concurrent_initializers_atomically_upgrade_legacy_schema(tmp_path):
    database = tmp_path / "concurrent-legacy-startup.db"
    seed = Engine(database, tenant_id=TENANT)
    seed.close()
    connection = sqlite3.connect(database)
    connection.executescript("""
        DROP TRIGGER IF EXISTS events_no_delete;
        DROP TRIGGER IF EXISTS events_no_rewrite;
        DROP TRIGGER IF EXISTS events_payload_redaction_only;
        DROP TABLE events;
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT,
            idempotency_key TEXT NOT NULL UNIQUE,
            observed_at TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            valid_from TEXT,
            valid_to TEXT,
            actor_type TEXT,
            actor_id TEXT,
            authority TEXT NOT NULL,
            sensitivity TEXT NOT NULL DEFAULT 'internal',
            capture_mode TEXT NOT NULL DEFAULT 'full',
            payload_digest TEXT NOT NULL,
            payload TEXT,
            schema_version TEXT NOT NULL,
            seq INTEGER,
            prev_hash TEXT,
            entry_hash TEXT
        );
        DROP TABLE packet_watermark;
        CREATE TABLE packet_watermark (
            project_id TEXT PRIMARY KEY,
            last_event_seq INTEGER NOT NULL,
            composed_at TEXT NOT NULL,
            packet_id TEXT
        );
    """)
    connection.close()
    barrier = threading.Barrier(2)

    def initialize():
        barrier.wait(timeout=5)
        engine = Engine(database, tenant_id=TENANT)
        event_columns = {
            row["name"] for row in engine.store._conn.execute(
                "PRAGMA table_info(events)")}
        watermark_columns = {
            row["name"] for row in engine.store._conn.execute(
                "PRAGMA table_info(packet_watermark)")}
        engine.close()
        return event_columns, watermark_columns

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(initialize) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    for event_columns, watermark_columns in results:
        assert "stored_payload_digest" in event_columns
        assert {
            "packet_digest", "control_basis_digest", "audit_entry_hash",
        } <= watermark_columns

    connection = sqlite3.connect(database)
    table_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' "
        "AND name = 'events'").fetchone()[0]
    trigger_count = connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' "
        "AND tbl_name = 'events'").fetchone()[0]
    connection.close()
    assert "idempotency_key TEXT NOT NULL UNIQUE" not in table_sql
    assert trigger_count == 3
