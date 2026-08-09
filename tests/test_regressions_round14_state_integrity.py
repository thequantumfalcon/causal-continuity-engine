"""Release-blocking state, recovery, and trust regressions.

These cases are intentionally public-path first: each reproduced a state that
looked safe to an operator while a stricter control path disagreed.
"""

from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import causal_continuity_engine.engine as engine_module
import causal_continuity_engine.store as store_module
import causal_continuity_engine.verifiers as verifiers_module
from causal_continuity_engine.cli import main
from causal_continuity_engine.core import (
    is_public_identifier,
    validate_public_identifier,
)
from causal_continuity_engine.engine import (
    AttestationInputError,
    Engine,
    UnsafeArtifactError,
)
from causal_continuity_engine.evidence import grade_evidence, run_mutation_probe
from causal_continuity_engine.policy import PolicyEngine
from causal_continuity_engine.store import GENESIS, AnchorExportError, Store
from causal_continuity_engine.verifiers import VerifierRunner, VerifierSpec

TENANT = "ten_round14"
PROJECT = "prj_round14"


def _python(script: str) -> str:
    executable = Path(sys.executable).as_posix()
    return f'"{executable}" -c "{script}"'


PASS = _python("raise SystemExit(0)")
FAIL = _python("raise SystemExit(17)")


@pytest.mark.parametrize(
    "identifier",
    [
        "has/slash", "has%2Fescape", "has space", "has\x00control",
        ".", "..", "_leading", "é", "a" * 129, "", [], {}, None,
    ],
    ids=[
        "slash", "percent", "space", "control", "dot", "dot-dot",
        "leading-symbol", "unicode", "too-long", "empty", "array",
        "object", "null",
    ],
)
def test_public_identifier_contract_rejects_unaddressable_values(identifier):
    assert not is_public_identifier(identifier)
    with pytest.raises(ValueError, match="ASCII URI-unreserved"):
        validate_public_identifier(identifier)


def test_explicit_project_and_node_ids_fail_before_creation():
    engine = Engine(tenant_id=TENANT)
    try:
        with pytest.raises(ValueError, match="project_id"):
            engine.create_project("unsafe", project_id="project/child")
        # The read boundary rejects the same malformed identifier, so inspect
        # storage directly to prove the failed public call wrote no node.
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE node_id = ?",
            ("project/child",),
        ).fetchone()[0] == 0

        engine.create_project("safe", project_id=PROJECT)
        before = engine.graph.stats(PROJECT)
        with pytest.raises(ValueError, match="node_id"):
            engine.graph.put_node(
                entity_type="task", tenant_id=TENANT, project_id=PROJECT,
                node_id="task%2Fchild", data={"title": "unsafe"})
        assert engine.graph.stats(PROJECT) == before
    finally:
        engine.close()


def test_public_identifier_contract_accepts_full_unreserved_alphabet():
    value = "AazZ09._~-"
    assert is_public_identifier(value)
    assert validate_public_identifier(value) == value


def _proof_engine(tmp_path: Path, *, artifact: str = "deliverable.txt"):
    (tmp_path / "deliverable.txt").write_text("ready", encoding="utf-8")
    command = _python(
        "from pathlib import Path;"
        "raise SystemExit(0 if Path('deliverable.txt').read_text()"
        "=='ready' else 19)")
    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "min_evidence_grade": "D",
        "required_verifiers": [{
            "name": "release-check", "command": command,
            "expect_fail_command": FAIL, "artifacts": [artifact],
        }],
    }
    engine = Engine(
        tmp_path / "state.sqlite3", tenant_id=TENANT, workdir=tmp_path)
    engine.create_project("state", project_id=PROJECT, config=config)
    engine.policy.grant(project_id=PROJECT, level=2, granted_by="lead")
    return engine


def _task(engine: Engine, name: str, *, criticality: str = "medium"):
    return engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        status="open", criticality=criticality, data={"title": name})


def _proof(engine: Engine, task_id: str):
    return engine.attest_action(
        PROJECT, intent_type="task_complete", intent_statement="ship",
        actor={"agent": "worker"}, action_type="run_verifier",
        continuity={"task_ids": [task_id]})


def test_later_proof_cannot_bypass_pending_or_critical_invalidation(tmp_path):
    engine = _proof_engine(tmp_path)
    try:
        blocked = _task(engine, "blocked", criticality="high")
        pending = engine.invalidation.fire(
            tenant_id=TENANT, project_id=PROJECT,
            target_node_id=blocked.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.2)
        assert pending["status"] == "pending_confirmation"
        assert engine.graph.get(blocked.id)["status"] == "open"

        later_proof = _proof(engine, blocked.id)
        assert later_proof["status"] == "verified"
        currency = engine.proof_currency(PROJECT, blocked.id, later_proof)
        assert not currency["current"]
        assert pending["node_id"] in " ".join(currency["reasons"])
        with pytest.raises(PermissionError, match="unresolved invalidation"):
            engine.complete_task(PROJECT, blocked.id, proof=later_proof)
        assert engine.graph.get(blocked.id)["status"] == "open"

        # A noncritical invalidation is scoped to the nodes it actually
        # touches; unrelated work must not become globally unavailable.
        unrelated = _task(engine, "unrelated")
        unrelated_proof = _proof(engine, unrelated.id)
        assert engine.proof_currency(
            PROJECT, unrelated.id, unrelated_proof)["current"]
        assert engine.complete_task(
            PROJECT, unrelated.id, proof=unrelated_proof)["status"] == "verified"

        critical_target = engine.graph.put_node(
            entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
            status="active", criticality="critical",
            data={"statement": "release channel is trustworthy"})
        critical = engine.invalidation.fire(
            tenant_id=TENANT, project_id=PROJECT,
            target_node_id=critical_target.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.95)
        assert critical["data"]["severity"] == "critical"
        globally_blocked = _task(engine, "globally blocked")
        after_critical = _proof(engine, globally_blocked.id)
        assert not engine.proof_currency(
            PROJECT, globally_blocked.id, after_critical)["current"]
        with pytest.raises(PermissionError, match="unresolved invalidation"):
            engine.complete_task(
                PROJECT, globally_blocked.id, proof=after_critical)
    finally:
        engine.close()


def _push(repository_id: int, ref: str, before: str, after: str) -> dict:
    return {
        "ref": ref, "before": before, "after": after,
        "forced": False, "deleted": False, "created": before == "0" * 40,
        "commits": [],
        "head_commit": {"timestamp": "2026-08-03T12:00:00Z"},
        "repository": {"id": repository_id, "full_name": "owner/repo"},
    }


def _check(repository_id: int, app_id: int, head: str, check_id: int) -> dict:
    return {
        "action": "completed",
        "check_run": {
            "id": check_id, "name": "ci", "status": "completed",
            "conclusion": "success", "head_sha": head,
            "completed_at": "2026-08-03T12:01:00Z",
            "app": {"id": app_id, "slug": "actions"},
        },
        "repository": {"id": repository_id, "full_name": "owner/repo"},
    }


def test_resume_external_pass_obeys_ref_epoch_and_uncertain_frontier():
    repository_id = 1414
    app_id = 15368
    base = {
        "require_proof_for": [], "required_verifiers": ["ci"],
        "trusted_verifier_apps": [{"app_id": app_id, "slug": "actions"}],
        "tracked_ref": "refs/heads/main", "min_evidence_grade": None,
    }
    engine = Engine(tenant_id=TENANT)
    engine.create_project(
        "frontier", project_id=PROJECT, repository_id=repository_id,
        config=base)
    main_head = "a" * 40
    release_head = "b" * 40
    try:
        engine.ingest_github(
            PROJECT, "push", "main-head",
            _push(repository_id, "refs/heads/main", "0" * 40, main_head))
        engine.ingest_github(
            PROJECT, "check_run", "main-ci",
            _check(repository_id, app_id, main_head, 1))
        trusted = engine.resume_packet(PROJECT)["trust"]
        assert trusted["gaps"] == []
        assert len(trusted["completed_checks"]) == 1

        engine.policy.set_project_config(
            PROJECT, {**base, "tracked_ref": "refs/heads/release"})
        changed = engine.resume_packet(PROJECT)["trust"]
        assert changed["completed_checks"] == []
        assert changed["gaps"] == ["ci"]
        assert engine.continuity_check(PROJECT)["verifier_gaps"] == ["ci"]

        engine.ingest_github(
            PROJECT, "push", "release-head",
            _push(repository_id, "refs/heads/release", "0" * 40,
                  release_head))
        engine.ingest_github(
            PROJECT, "check_run", "release-ci",
            _check(repository_id, app_id, release_head, 2))
        assert engine.resume_packet(PROJECT)["trust"]["gaps"] == []

        engine.ingest_github(
            PROJECT, "push", "out-of-order",
            _push(repository_id, "refs/heads/release", "c" * 40, "d" * 40))
        uncertain = engine.resume_packet(PROJECT)["trust"]
        assert uncertain["completed_checks"] == []
        assert uncertain["gaps"] == ["ci"]

        engine.policy.set_project_config(
            PROJECT, {**base, "tracked_ref": None})
        unset = engine.resume_packet(PROJECT)["trust"]
        assert unset["completed_checks"] == []
        assert unset["gaps"] == ["ci"]
    finally:
        engine.close()


def test_retention_comparator_flags_live_only_replayable_nodes_and_edges(
        tmp_path):
    engine = Engine(tmp_path / "replay.sqlite3", tenant_id=TENANT)
    engine.create_project("replay", project_id=PROJECT)
    try:
        engine.ingest_human_decision(
            PROJECT, actor="lead", decision="Retire this event payload")
        assert engine.memory.sweep_retention(raw_days=0) == 1
        retained = engine.ingest_human_decision(
            PROJECT, actor="lead", decision="Keep this retained event")
        event_id = retained["event_id"]

        extra = engine.graph.put_node(
            entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
            status="active", data={
                "statement": "processor-only extra",
                "stable_key": "round14-extra",
            }, event_id=event_id, extractor="faulty", extractor_version="1")
        engine.graph.put_edge(
            edge_type="supports", src_id=event_id, dst_id=extra.id,
            tenant_id=TENANT, project_id=PROJECT, event_id=event_id)

        # Runtime/event hybrids remain outside the event-log rebuild promise.
        hybrid = engine.graph.put_node(
            entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
            status="active", data={
                "statement": "runtime prefix", "stable_key": "fixture-key"})
        engine.graph.put_node(
            entity_type="claim", tenant_id=TENANT, project_id=PROJECT,
            node_id=hybrid.id, status="active",
            data={"statement": "runtime prefix later event-touched"},
            event_id=event_id, extractor="faulty", extractor_version="1")

        fresh = engine.rebuild_projection(PROJECT)
        try:
            partial = engine.replay_agrees_where_replayable(PROJECT, fresh)
        finally:
            fresh.close()
        assert not partial["agrees"]
        assert any(
            item["kind"] == "node"
            and item.get("semantic_id") == "stable:claim:round14-extra"
            and item["issue"] == "live but not replayed from retained events"
            for item in partial["disagreements"])
        assert any(
            item["kind"] == "edge"
            and item["issue"] == "live but not replayed from retained events"
            for item in partial["disagreements"])
        assert not any(
            "round14-hybrid" in json.dumps(item)
            for item in partial["disagreements"])
    finally:
        engine.close()


def test_duplicate_explicit_project_id_is_atomic_and_preserves_original():
    engine = Engine(tenant_id=TENANT)
    original_config = {
        "tracked_ref": "refs/heads/release", "require_proof_for": []}
    original = engine.create_project(
        "original", project_id=PROJECT, repository="owner/original",
        config=original_config)
    original_policy = engine.policy.project_config(PROJECT)
    creates_before = len(engine.store.audit_entries("project.create"))
    try:
        with pytest.raises(ValueError, match="already in use"):
            engine.create_project(
                "replacement", project_id=PROJECT,
                config={"tracked_ref": "refs/heads/main"})
        current = engine.graph.get(PROJECT)
        assert current["version"] == original["version"] == 1
        assert current["data"]["name"] == "original"
        assert current["data"]["repository"] == "owner/original"
        assert engine.policy.project_config(PROJECT) == original_policy
        assert len(engine.store.audit_entries("project.create")) == creates_before
    finally:
        engine.close()


def test_concurrent_explicit_project_creators_have_one_winner(tmp_path):
    database = tmp_path / "projects.sqlite3"
    engines = [Engine(database, tenant_id=TENANT) for _ in range(2)]
    barrier = threading.Barrier(2)
    outcomes = []
    lock = threading.Lock()

    def create(index: int):
        barrier.wait()
        try:
            engines[index].create_project(
                f"creator-{index}", project_id=PROJECT,
                config={"tracked_ref": f"refs/heads/release-{index}"})
            result = "created"
        except ValueError as exc:
            result = str(exc)
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=create, args=(index,))
               for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    try:
        assert all(not thread.is_alive() for thread in threads)
        assert outcomes.count("created") == 1
        assert sum("already in use" in value for value in outcomes) == 1
        project = engines[0].graph.get(PROJECT)
        assert project["version"] == 1
        assert len(engines[0].store.audit_entries("project.create")) == 1
    finally:
        for engine in engines:
            engine.close()


def test_tracked_ref_migration_serializes_two_initializers(
        tmp_path, monkeypatch):
    database = tmp_path / "legacy-policy.sqlite3"
    # Install every surrounding schema first, then downgrade only the target
    # table.  The concurrency schedule below is therefore about this ALTER,
    # not unrelated first-open CREATE TABLE locks.
    seed = Store(database)
    PolicyEngine(seed)
    with seed._conn:
        seed._conn.execute("DROP TABLE project_policy")
        seed._conn.execute(
            "CREATE TABLE project_policy ("
            "project_id TEXT PRIMARY KEY, config TEXT NOT NULL)")
    seed.close()

    rendezvous = threading.Barrier(2)
    original_connect = sqlite3.connect

    class BarrierConnection(sqlite3.Connection):
        def executescript(self, script):
            result = super().executescript(script)
            if "CREATE TABLE IF NOT EXISTS project_policy" in script:
                rendezvous.wait(timeout=10)
            return result

    def connect(*args, **kwargs):
        kwargs["factory"] = BarrierConnection
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(store_module.sqlite3, "connect", connect)
    stores = [Store(database), Store(database)]
    policies = []
    errors = []
    lock = threading.Lock()

    def initialize(index: int):
        try:
            value = PolicyEngine(stores[index])
            with lock:
                policies.append(value)
        except BaseException as exc:  # preserve the actual concurrent failure
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=initialize, args=(index,))
               for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    try:
        assert all(not thread.is_alive() for thread in threads)
        assert errors == []
        assert len(policies) == 2
        columns = [
            row["name"] for row in stores[0]._conn.execute(
                "PRAGMA table_info(project_policy)")]
        assert columns.count("tracked_ref_revision") == 1
    finally:
        for store in stores:
            store.close()


def _migration_ready_engine() -> Engine:
    engine = Engine(tenant_id=TENANT)
    engine.create_project(
        "capsule", project_id=PROJECT,
        config={"require_proof_for": [], "required_verifiers": []})
    engine.graph.put_node(
        entity_type="artifact", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"kind": "environment", "python": "3.13"})
    for index in range(10):
        engine.graph.put_node(
            entity_type="task", tenant_id=TENANT, project_id=PROJECT,
            status="verified", data={"title": f"completed {index}"})
    return engine


def _export_capsule(engine: Engine, *, token_budget: int):
    return engine.capsules.export(
        tenant_id=TENANT, project_id=PROJECT, session_id=None,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer,
        token_budget=token_budget)


def test_capsule_budget_trimming_is_not_control_drift():
    engine = _migration_ready_engine()
    try:
        capsule = _export_capsule(engine, token_budget=1)
        assert capsule["resume_packet"]["omissions"]
        # Trimming must be attributed rather than silent. This deliberately
        # does not assert a surviving item count: that encoded the old fixed
        # cap, which made token_budget a trigger instead of a bound.
        assert any(o["section"] == "verified progress detail"
                   for o in capsule["resume_packet"]["omissions"])

        result = engine.capsules.import_capsule(
            capsule, signer=engine.signer, target_model="target",
            target_runtime="runtime")
        challenge = result["challenge"]
        assert challenge["passed"]
        assert challenge["control_drift"] == []
        assert challenge["source_packet_omissions"] == \
            capsule["resume_packet"]["omissions"]
        assert challenge["source_control_digest"] == \
            challenge["target_control_digest"]
    finally:
        engine.close()


def test_capsule_semantic_basis_still_detects_actual_control_drift():
    engine = _migration_ready_engine()
    try:
        capsule = _export_capsule(engine, token_budget=1)
        engine.graph.put_node(
            entity_type="constraint", tenant_id=TENANT, project_id=PROJECT,
            status="active", criticality="critical",
            data={"statement": "new release constraint"})
        result = engine.capsules.import_capsule(
            capsule, signer=engine.signer, target_model="target",
            target_runtime="runtime")
        challenge = result["challenge"]
        assert not challenge["passed"]
        assert challenge["source_control_digest"] != \
            challenge["target_control_digest"]
        assert any(
            item["kind"] == "target_control_state_changed"
            for item in challenge["control_drift"])
    finally:
        engine.close()


def test_anchor_v1_rejects_malformed_documents_without_raising():
    store = Store(":memory:")
    try:
        store.append_event(
            tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
            idempotency_key="anchor-event", payload={"value": 1},
            authority="agent_observed")
        valid = store.export_anchor("events")
        assert store.verify_against_anchor(valid)["ok"]
        assert not store.verify_against_anchor(
            valid, expected_tenant_id=TENANT,
            expected_project_id=PROJECT)["ok"]

        malformed = []

        def changed(**values):
            value = copy.deepcopy(valid)
            value.update(values)
            return value

        missing = copy.deepcopy(valid)
        missing.pop("count")
        malformed.extend([
            missing,
            changed(extra=True),
            changed(schema_version="cce.anchor.v0"),
            changed(table="nodes"),
            changed(count=-1),
            changed(count=False),
            changed(count=1.5),
            changed(tip="sha256:not-a-digest"),
            changed(tip=valid["tip"].upper()),
            changed(count=0),
            changed(tip=GENESIS),
            changed(intact_at_export=False),
            changed(exported_at="nonsense"),
            changed(exported_at="2026-08-03T12:00:00+00:00"),
            changed(exported_at="20260803T120000Z"),
            changed(exported_at="2026-08-03 12:00:00.000000Z"),
            changed(exported_at="2026-02-30T12:00:00.000000Z"),
            changed(exported_at="2026-08-03T12:00:00Z"),
            changed(tenant_id=TENANT),
            changed(tenant_id="", project_id=PROJECT),
        ])
        for anchor in malformed:
            result = store.verify_against_anchor(anchor)
            assert not result["ok"], anchor
            assert result["reason"].startswith("invalid anchor document:")

        bound = store.export_anchor(
            "events", tenant_id=TENANT, project_id=PROJECT)
        assert store.verify_against_anchor(
            bound, expected_tenant_id=TENANT,
            expected_project_id=PROJECT) == {
                "ok": True, "bound": True, "anchored": 1,
                "live": 1, "appended_since": 0,
            }
        assert not store.verify_against_anchor(
            bound, expected_tenant_id="ten_other",
            expected_project_id=PROJECT)["ok"]
        assert not store.verify_against_anchor(
            bound, expected_tenant_id=TENANT,
            expected_project_id="prj_other")["ok"]
    finally:
        store.close()


def test_broken_chain_cannot_emit_a_public_anchor():
    store = Store(":memory:")
    try:
        store.append_event(
            tenant_id=TENANT, project_id=PROJECT, source_type="agent_trace",
            idempotency_key="broken-anchor", payload={"value": 1},
            authority="agent_observed")
        with store.write_scope():
            triggers = store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ).fetchall()
            for trigger in triggers:
                store._conn.execute(f"DROP TRIGGER {trigger['name']}")
            store._conn.execute(
                "UPDATE events SET entry_hash = ? WHERE seq = 1",
                ("sha256:" + "f" * 64,))
        assert not store.verify_chain("events")["intact"]
        with pytest.raises(AnchorExportError, match="chain is not intact"):
            store.export_anchor("events")
    finally:
        store.close()


def test_anchor_export_holds_one_snapshot_across_count_and_tip(
        tmp_path, monkeypatch):
    path = tmp_path / "anchor-snapshot.db"
    primary = Store(path)
    primary._conn.execute("PRAGMA journal_mode=WAL").fetchone()
    secondary = Store(path)
    try:
        first = primary.append_event(
            tenant_id=TENANT, project_id=PROJECT,
            source_type="agent_trace", idempotency_key="anchor-first",
            payload={"value": 1}, authority="agent_observed")
        original_tip = primary._chain_tip
        raced = False

        def append_between_count_and_tip(table):
            nonlocal raced
            if table == "events" and not raced:
                secondary.append_event(
                    tenant_id=TENANT, project_id=PROJECT,
                    source_type="agent_trace",
                    idempotency_key="anchor-second",
                    payload={"value": 2}, authority="agent_observed")
                raced = True
            return original_tip(table)

        monkeypatch.setattr(primary, "_chain_tip", append_between_count_and_tip)
        anchor = primary.export_anchor("events")

        assert raced
        assert anchor["count"] == 1
        assert anchor["tip"] == first["entry_hash"]
        assert len(primary.events(PROJECT, tenant_id=TENANT)) == 2
        assert primary.verify_against_anchor(anchor) == {
            "ok": True, "bound": False, "anchored": 1,
            "live": 2, "appended_since": 1,
        }
    finally:
        secondary.close()
        primary.close()


def test_cli_invalid_anchor_is_clean_nonzero(tmp_path, capsys):
    main(["--dir", str(tmp_path), "--json", "init"])
    capsys.readouterr()
    anchor_path = tmp_path / "anchor.json"
    main([
        "--dir", str(tmp_path), "--json", "audit", "anchor",
        "--out", str(anchor_path),
    ])
    capsys.readouterr()
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    anchor["count"] = False
    anchor_path.write_text(json.dumps(anchor), encoding="utf-8")

    with pytest.raises(SystemExit) as stopped:
        main([
            "--dir", str(tmp_path), "--json", "audit", "check-anchor",
            "--anchor", str(anchor_path),
        ])
    captured = capsys.readouterr()
    assert stopped.value.code != 0
    assert "Traceback" not in captured.out + captured.err
    result = json.loads(captured.out)
    assert not result["ok"]
    assert "invalid anchor document" in result["reason"]


def test_cli_does_not_write_anchor_for_broken_chain(tmp_path, capsys):
    main(["--dir", str(tmp_path), "--json", "init"])
    capsys.readouterr()
    database = tmp_path / ".cce" / "cce.db"
    raw = sqlite3.connect(database)
    try:
        for (name,) in raw.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"):
            raw.execute(f"DROP TRIGGER {name}")
        raw.execute(
            "UPDATE audit_log SET entry_hash = ? WHERE seq = 1",
            ("sha256:" + "e" * 64,))
        raw.commit()
    finally:
        raw.close()
    anchor_path = tmp_path / "must-not-exist.json"

    with pytest.raises(SystemExit) as stopped:
        main([
            "--dir", str(tmp_path), "--json", "audit", "anchor",
            "--table", "audit_log", "--out", str(anchor_path),
        ])
    result = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 1
    assert not result["ok"]
    assert "chain is not intact" in result["reason"]
    assert not anchor_path.exists()


@pytest.mark.parametrize("artifact", [
    "",
    " ",
    ".",
    "..",
    "../outside.txt",
    "nested/../../outside.txt",
    "/outside.txt",
    r"C:\outside.txt",
    r"\\server\share\outside.txt",
    r"nested\outside.txt",
    "./deliverable.txt",
    "nested//deliverable.txt",
    "nested/",
    ".git/HEAD",
    "dist/.cce/proof.json",
    "dist/node_modules/package.json",
    "dist/__pycache__/module.pyc",
    "dist/cache.pyc",
])
def test_artifact_policy_rejects_non_project_relative_paths_before_creation(
        tmp_path, artifact):
    config = {
        "required_verifiers": [{
            "name": "unsafe", "command": PASS,
            "expect_fail_command": FAIL, "artifacts": [artifact],
        }],
    }
    engine = Engine(
        tmp_path / "unsafe.sqlite3", tenant_id=TENANT, workdir=tmp_path)
    try:
        with pytest.raises(ValueError, match="project-relative"):
            engine.create_project(
                "unsafe", project_id=PROJECT, config=config)
        with pytest.raises(KeyError):
            engine.graph.get(PROJECT)
    finally:
        engine.close()


def test_invalid_direct_probe_declaration_cannot_run_or_grade_as_bound(tmp_path):
    called = []
    report = run_mutation_probe(
        workdir=tmp_path,
        artifacts=["../outside.txt"],
        specs=[VerifierSpec(name="check", command=PASS)],
        runner_factory=lambda sandbox: called.append(sandbox),
    )

    assert not called
    assert not report.bound
    assert report.error and "project-relative" in report.error
    grade = grade_evidence(
        outcomes=[{
            "verifier": "check", "result": "passed", "source": "executed",
        }],
        required=["check"],
        controls={"check": {"status": "held"}},
        mutation=report,
        determinism={"check": {"stable": True}},
    )
    assert grade.grade == "D"
    assert any("not bound" in reason for reason in grade.caps)


def test_declared_directory_preserves_ignored_descendants_for_verifier(tmp_path):
    subject_files = {
        "dist/node_modules/package.txt": "dependency-subject",
        "dist/.git/HEAD": "vcs-subject",
        "dist/.pytest_cache/state.txt": "cache-subject",
    }
    for relative, content in subject_files.items():
        path = tmp_path.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    command = _python(
        "from pathlib import Path;"
        f"expected={subject_files!r};"
        "raise SystemExit(0 if all(Path(p).read_text()==v "
        "for p,v in expected.items()) else 23)")
    spec = VerifierSpec(
        name="directory-subject", command=command,
        expect_fail_command=FAIL, artifacts=["dist"])

    outcome = VerifierRunner(None, tmp_path).run(spec)

    assert outcome.result == "passed", outcome.details


@pytest.mark.parametrize(
    ("store_relative", "artifact"),
    [
        ("dist/state.sqlite3", "dist"),
        ("state.sqlite3", "state.sqlite3"),
        ("state.sqlite3", "state.sqlite3-wal"),
    ],
    ids=["database-beneath-directory", "database-equality", "wal-equality"],
)
def test_store_overlapping_artifact_is_refused_before_execution_or_proof(
        tmp_path, monkeypatch, store_relative, artifact):
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    store_path = workdir.joinpath(*store_relative.split("/"))
    store_path.parent.mkdir(parents=True, exist_ok=True)
    if artifact == "dist":
        (workdir / "dist" / "payload.txt").write_text(
            "ready", encoding="utf-8")
    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "required_verifiers": [{
            "name": "overlap", "command": PASS,
            "expect_fail_command": FAIL, "artifacts": [artifact],
        }],
    }
    engine = Engine(
        store_path, tenant_id=TENANT, workdir=workdir)
    engine.create_project("overlap", project_id=PROJECT, config=config)
    engine.policy.grant(project_id=PROJECT, level=2, granted_by="lead")
    task = _task(engine, "store overlap")
    executed = False

    def must_not_execute(*args, **kwargs):
        nonlocal executed
        executed = True
        raise AssertionError("overlapping verifier command executed")

    monkeypatch.setattr(
        verifiers_module, "_run_bounded_process", must_not_execute)
    try:
        with pytest.raises(
                AttestationInputError,
                match="artifact declaration.*overlaps.*store"):
            _proof(engine, task.id)
        assert not executed
        assert engine.graph.current(PROJECT, "action") == []
        assert engine.graph.current(PROJECT, "verification") == []
    finally:
        engine.close()


def test_corrupt_legacy_artifact_path_fails_before_attestation(tmp_path):
    engine = _proof_engine(tmp_path)
    task = _task(engine, "legacy unsafe policy")
    try:
        corrupt = engine.policy.project_config(PROJECT)
        corrupt["required_verifiers"][0]["artifacts"] = ["../outside.txt"]
        with engine.store.write_scope():
            engine.store._conn.execute(
                "UPDATE project_policy SET config = ? WHERE project_id = ?",
                (json.dumps(corrupt), PROJECT),
            )

        with pytest.raises(ValueError, match="project-relative"):
            _proof(engine, task.id)
        assert engine.graph.current(PROJECT, "action") == []
        assert engine.graph.current(PROJECT, "verification") == []
    finally:
        engine.close()


def test_attestation_rejects_artifact_changed_by_verifier(tmp_path):
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    artifact = workdir / "deliverable.txt"
    artifact.write_text("ready", encoding="utf-8")
    mutating_command = _python(
        "from pathlib import Path;"
        "Path('deliverable.txt').write_text('changed',encoding='utf-8')")
    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "min_evidence_grade": "D",
        "required_verifiers": [{
            "name": "mutating", "command": mutating_command,
            "expect_fail_command": FAIL, "artifacts": ["deliverable.txt"],
        }],
    }
    engine = Engine(
        tmp_path / "mutating.sqlite3", tenant_id=TENANT, workdir=workdir)
    engine.create_project("mutating", project_id=PROJECT, config=config)
    engine.policy.grant(project_id=PROJECT, level=2, granted_by="lead")
    task = _task(engine, "stable verifier input")
    try:
        with pytest.raises(RuntimeError, match="artifacts changed"):
            _proof(engine, task.id)
        assert artifact.read_text(encoding="utf-8") == "ready"
        assert engine.graph.current(PROJECT, "action") == []
        assert engine.graph.current(PROJECT, "verification") == []
    finally:
        engine.close()


def test_file_snapshot_detects_mutation_during_hash(tmp_path, monkeypatch):
    engine = _proof_engine(tmp_path)
    artifact = tmp_path / "deliverable.txt"
    original = engine_module._hash_artifact_file
    changed = False

    def mutate_after_hash(path, *, fd=None):
        nonlocal changed
        digest = original(path, fd=fd)
        if Path(path) == artifact and not changed:
            changed = True
            artifact.write_text("changed-after-read", encoding="utf-8")
        return digest

    monkeypatch.setattr(engine_module, "_hash_artifact_file", mutate_after_hash)
    try:
        with pytest.raises(UnsafeArtifactError, match="changed while hashing"):
            engine._artifact_digests(PROJECT)
    finally:
        engine.close()


def test_directory_snapshot_detects_inventory_change_during_hash(
        tmp_path, monkeypatch):
    deliverable = tmp_path / "dist"
    deliverable.mkdir()
    payload = deliverable / "payload.txt"
    payload.write_text("ready", encoding="utf-8")
    config = {
        "required_verifiers": [{
            "name": "directory", "command": PASS,
            "expect_fail_command": FAIL, "artifacts": ["dist"],
        }],
    }
    engine = Engine(
        tmp_path / "directory.sqlite3", tenant_id=TENANT, workdir=tmp_path)
    engine.create_project("directory", project_id=PROJECT, config=config)
    original = engine_module._hash_artifact_file
    changed = False

    def add_entry_after_hash(path, *, fd=None):
        nonlocal changed
        digest = original(path, fd=fd)
        if Path(path) == payload and not changed:
            changed = True
            (deliverable / "late.txt").write_text("late", encoding="utf-8")
        return digest

    monkeypatch.setattr(
        engine_module, "_hash_artifact_file", add_entry_after_hash)
    try:
        with pytest.raises(UnsafeArtifactError, match="changed while hashing"):
            engine._artifact_digests(PROJECT)
    finally:
        engine.close()


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "O_NOFOLLOW"),
    reason="POSIX no-follow descriptor coverage",
)
def test_posix_snapshot_refuses_symlink_swap_between_stat_and_open(
        tmp_path, monkeypatch):
    engine = _proof_engine(tmp_path)
    artifact = tmp_path / "deliverable.txt"
    outside = tmp_path / "outside.txt"
    outside.write_text("outside-secret", encoding="utf-8")
    original_open = engine_module.os.open
    swapped = False

    def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "deliverable.txt" and dir_fd is not None and not swapped:
            swapped = True
            assert flags & os.O_NOFOLLOW
            artifact.unlink()
            artifact.symlink_to(outside)
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(engine_module.os, "open", swap_before_open)
    try:
        with pytest.raises(UnsafeArtifactError, match="symlink|route changed"):
            engine._artifact_digests(PROJECT)
    finally:
        engine.close()


def _symlink_or_skip(
        link: Path, target: Path, *, target_is_directory: bool = False):
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        if (isinstance(exc, NotImplementedError)
                or getattr(exc, "winerror", None) == 1314):
            pytest.skip(f"host cannot create symlinks: {exc}")
        raise


def test_retargeted_declared_artifact_symlink_makes_proof_noncurrent(tmp_path):
    engine = _proof_engine(tmp_path)
    try:
        task = _task(engine, "symlink currency")
        proof = _proof(engine, task.id)
        artifact = tmp_path / "deliverable.txt"
        alternate = tmp_path / "alternate.txt"
        alternate.write_text("ready", encoding="utf-8")
        artifact.unlink()
        _symlink_or_skip(artifact, alternate)
        currency = engine.proof_currency(PROJECT, task.id, proof)
        assert not currency["current"]
        assert "symlink or reparse" in " ".join(currency["reasons"])
        with pytest.raises(PermissionError, match="no longer describes"):
            engine.complete_task(PROJECT, task.id, proof=proof)
    finally:
        engine.close()


def test_nested_declared_artifact_symlink_blocks_attestation(tmp_path):
    deliverable = tmp_path / "dist"
    deliverable.mkdir()
    (deliverable / "payload.txt").write_text("ready", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("ready", encoding="utf-8")
    _symlink_or_skip(deliverable / "route.txt", outside)
    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "required_verifiers": [{
            "name": "nested", "command": PASS,
            "expect_fail_command": FAIL, "artifacts": ["dist"],
        }],
    }
    engine = Engine(
        tmp_path / "nested.sqlite3", tenant_id=TENANT, workdir=tmp_path)
    engine.create_project("nested", project_id=PROJECT, config=config)
    engine.policy.grant(project_id=PROJECT, level=2, granted_by="lead")
    task = _task(engine, "nested route")
    try:
        with pytest.raises(UnsafeArtifactError, match="contains a symlink"):
            _proof(engine, task.id)
    finally:
        engine.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction coverage")
def test_windows_junction_declared_artifact_is_rejected(tmp_path):
    target = tmp_path / "junction-target"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, text=True, check=False)
    if created.returncode:
        pytest.skip(f"host cannot create a junction: {created.stderr}")
    config = {
        "require_proof_for": [],
        "required_verifiers": [{
            "name": "junction", "command": PASS,
            "expect_fail_command": FAIL, "artifacts": ["junction"],
        }],
    }
    engine = Engine(
        tmp_path / "junction.sqlite3", tenant_id=TENANT, workdir=tmp_path)
    engine.create_project("junction", project_id=PROJECT, config=config)
    try:
        with pytest.raises(UnsafeArtifactError, match="symlink or reparse"):
            engine._artifact_digests(PROJECT)
    finally:
        engine.close()
