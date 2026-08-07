from __future__ import annotations

import itertools
import shlex
import sys

import pytest

from causal_continuity_engine.core import utcnow
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.evidence import MutationReport, grade_evidence
from causal_continuity_engine.store import Store
from causal_continuity_engine.verifiers import (
    VerificationOutcome,
    VerifierRunner,
    VerifierSpec,
    record_verification,
)

TENANT = "ten_round15_public"
PROJECT = "prj_round15_public"


@pytest.fixture
def engine():
    instance = Engine(tenant_id=TENANT)
    instance.create_project("round15 public", project_id=PROJECT)
    yield instance
    instance.close()


def _database_snapshot(engine: Engine) -> tuple[str, ...]:
    return tuple(engine.store._conn.iterdump())


def _event(engine: Engine) -> dict:
    engine.ingest_agent_trace(
        PROJECT, session_id=None, span_id="round15-span",
        payload={"message": "captured trace"})
    return engine.store.events(PROJECT, tenant_id=TENANT)[0]


def _failure(engine: Engine) -> dict:
    return engine.composter.compost(
        tenant_id=TENANT, project_id=PROJECT,
        description="tool timeout", failing_step="run build")


@pytest.mark.parametrize(
    ("field", "malformed"),
    list(itertools.product(
        ("captured_inputs", "mocks", "fork"),
        ("", 0, False, [], {"bad": float("nan")}, {1: "bad"}),
    )),
)
def test_replay_rejects_malformed_optional_objects_without_writes(
        engine, field, malformed):
    event = _event(engine)
    before = _database_snapshot(engine)
    with pytest.raises(ValueError):
        engine.replay.start(
            tenant_id=TENANT, project_id=PROJECT,
            from_event_id=event["event_id"], **{field: malformed})
    assert _database_snapshot(engine) == before


def test_replay_accepts_finite_objects_and_preserves_fidelity(engine):
    event = _event(engine)
    replay = engine.replay.start(
        tenant_id=TENANT, project_id=PROJECT,
        from_event_id=event["event_id"],
        captured_inputs={"repository": {"sha": "a" * 40}},
        mocks={"model": "fixed-response"},
        fork={"branch": "release"})
    assert replay["data"]["captured_inputs"] == ["repository"]
    assert replay["data"]["mocks"] == ["model"]
    assert replay["data"]["fork"] == {"branch": "release"}
    assert replay["data"]["fidelity"] == "mocked"


@pytest.mark.parametrize(
    ("field", "malformed"),
    list(itertools.product(
        ("description", "failing_step"),
        (None, "", "   ", 0, False, "\x1b[31m", "\u202eoverride", "x" * 8193),
    )),
)
def test_failure_compost_rejects_unsafe_or_empty_text_without_writes(
        engine, field, malformed):
    values = {"description": "tool timeout", "failing_step": "run build"}
    values[field] = malformed
    before = _database_snapshot(engine)
    with pytest.raises(ValueError):
        engine.composter.compost(
            tenant_id=TENANT, project_id=PROJECT, **values)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    "malformed", ["", 0, False, {}, "event", ["evt_missing", "evt_missing"]])
def test_failure_compost_rejects_malformed_trace_ids_without_writes(
        engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises((ValueError, PermissionError)):
        engine.composter.compost(
            tenant_id=TENANT, project_id=PROJECT,
            description="tool timeout", failing_step="run build",
            trace_event_ids=malformed)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize("malformed", ["", 0, False, {}, []])
def test_failure_compost_uses_none_only_for_taxonomy_default(
        engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError):
        engine.composter.compost(
            tenant_id=TENANT, project_id=PROJECT,
            description="tool timeout", failing_step="run build",
            taxonomy_override=malformed)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize("malformed", [None, 0, 1, "false", [], {}])
def test_eval_split_requires_an_exact_boolean_without_writes(engine, malformed):
    failure = _failure(engine)
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="withheld must be a boolean"):
        engine.evalgen.from_failure(failure["node_id"], withheld=malformed)
    assert _database_snapshot(engine) == before


def test_eval_split_preserves_true_and_false_semantics(engine):
    first = _failure(engine)
    second = engine.composter.compost(
        tenant_id=TENANT, project_id=PROJECT,
        description="policy denied action", failing_step="deploy")
    development = engine.evalgen.from_failure(
        first["node_id"], withheld=False)
    withheld = engine.evalgen.from_failure(second["node_id"], withheld=True)
    assert development["data"]["split"] == "development"
    assert withheld["data"]["split"] == "withheld"


def _proposed_skill(engine: Engine) -> dict:
    failure = _failure(engine)
    return engine.skills.propose(
        tenant_id=TENANT, project_id=PROJECT, name="retry-build",
        description="retry a bounded build", source_failure_ids=[failure["node_id"]],
        tests=["test_retry"], rollback_plan="remove retry wrapper")


@pytest.mark.parametrize(
    "malformed",
    [None, "", "   ", 0, False, "\x1b[31m", "\u202eoverride", "x" * 257],
)
def test_skill_approval_rejects_unsafe_actor_without_writes(engine, malformed):
    skill = _proposed_skill(engine)
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="skill approval actor"):
        engine.skills.approve(
            skill["node_id"], actor=malformed, sandbox_eval_passed=True)
    assert _database_snapshot(engine) == before


def test_skill_approval_records_a_safe_human_actor(engine):
    skill = _proposed_skill(engine)
    approved = engine.skills.approve(
        skill["node_id"], actor="release-reviewer",
        sandbox_eval_passed=True)
    assert approved["status"] == "approved"
    assert approved["data"]["gate_results"]["human_approval"] == \
        "release-reviewer"
    assert engine.store.audit_entries("skill.approve")[-1]["actor"] == \
        "release-reviewer"


@pytest.mark.parametrize("malformed", ["", 0, False, {}, []])
def test_partial_outcome_rejects_malformed_session_without_writes(
        engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="session_id"):
        engine.partial.record_outcome(
            tenant_id=TENANT, project_id=PROJECT, session_id=malformed,
            status="failed")
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    ("field", "malformed"),
    list(itertools.product(
        ("completed", "failed", "blocked", "skipped", "unverified"),
        ("", 0, False, {}, [{"bad": float("nan")}]),
    )),
)
def test_partial_outcome_rejects_malformed_item_groups_without_writes(
        engine, field, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError):
        engine.partial.record_outcome(
            tenant_id=TENANT, project_id=PROJECT, session_id=None,
            status="failed", **{field: malformed})
    assert _database_snapshot(engine) == before


def test_partial_outcome_links_a_real_session(engine):
    session = engine.graph.put_node(
        entity_type="session", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"model": "test"})
    outcome = engine.partial.record_outcome(
        tenant_id=TENANT, project_id=PROJECT, session_id=session.id,
        status="partially_completed", completed=[], failed=[])
    assert outcome["data"]["session_id"] == session.id
    assert any(
        edge["src_id"] == session.id and edge["dst_id"] == outcome.id
        for edge in engine.graph.out_edges(session.id))


@pytest.mark.parametrize("malformed", ["", 0, False, {}, []])
def test_recovery_packet_rejects_malformed_session_without_scope_fallback(
        engine, malformed):
    engine.partial.record_outcome(
        tenant_id=TENANT, project_id=PROJECT, session_id=None,
        status="failed", failed=[])
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="recovery session_id"):
        engine.partial.recovery_packet(PROJECT, session_id=malformed)
    assert _database_snapshot(engine) == before


def test_recovery_packet_filters_to_a_real_same_project_session(engine):
    first = engine.graph.put_node(
        entity_type="session", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"model": "first"})
    second = engine.graph.put_node(
        entity_type="session", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"model": "second"})
    engine.partial.record_outcome(
        tenant_id=TENANT, project_id=PROJECT, session_id=first.id,
        status="failed", failed=[])
    engine.partial.record_outcome(
        tenant_id=TENANT, project_id=PROJECT, session_id=second.id,
        status="completed", completed=[])
    assert engine.partial.recovery_packet(
        PROJECT, session_id=first.id)["last_outcome"]["status"] == "failed"
    assert engine.partial.recovery_packet(
        PROJECT, session_id=second.id)["last_outcome"]["status"] == "completed"


def _action(engine: Engine) -> dict:
    return engine.graph.put_node(
        entity_type="action", tenant_id=TENANT, project_id=PROJECT,
        status="failed", data={"kind": "test action"})


@pytest.mark.parametrize(
    "malformed", [None, "", "success", "verified", 0, False, [], {}])
def test_rollback_rejects_arbitrary_status_without_writes(engine, malformed):
    action = _action(engine)
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="rollback outcome"):
        engine.partial.record_rollback(
            tenant_id=TENANT, project_id=PROJECT, action_id=action.id,
            compensating_action="restore snapshot", status=malformed)
    assert _database_snapshot(engine) == before


def test_rollback_accepts_a_declared_run_outcome(engine):
    action = _action(engine)
    rollback = engine.partial.record_rollback(
        tenant_id=TENANT, project_id=PROJECT, action_id=action.id,
        compensating_action="restore snapshot", status="completed")
    assert rollback["status"] == "rollback_completed"
    assert rollback["data"]["compensates"] == action.id


@pytest.mark.parametrize("malformed", [None, 0, 1, "false", [], {}])
def test_checkpoint_verified_requires_an_exact_boolean_without_writes(
        engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="verified must be a boolean"):
        engine.memory.checkpoint(
            tenant_id=TENANT, project_id=PROJECT, session_id=None,
            label="before release", working_state={}, verified=malformed)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    "malformed", [None, "", "   ", 0, False, "\x1b[31m", "\u202eoverride",
                  "x" * 1025])
def test_checkpoint_rejects_unsafe_label_without_writes(engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="checkpoint label"):
        engine.memory.checkpoint(
            tenant_id=TENANT, project_id=PROJECT, session_id=None,
            label=malformed, working_state={}, verified=False)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    "malformed", [None, "", 0, False, [], {"bad": float("nan")}, {1: "bad"}])
def test_checkpoint_rejects_malformed_working_state_without_writes(
        engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="working_state"):
        engine.memory.checkpoint(
            tenant_id=TENANT, project_id=PROJECT, session_id=None,
            label="before release", working_state=malformed, verified=False)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize("malformed", ["", 0, False, {}, []])
def test_checkpoint_rejects_malformed_session_without_writes(engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="session_id"):
        engine.memory.checkpoint(
            tenant_id=TENANT, project_id=PROJECT, session_id=malformed,
            label="before release", working_state={}, verified=False)
    assert _database_snapshot(engine) == before


def test_verified_checkpoint_is_typed_linked_and_promoted(engine):
    session = engine.graph.put_node(
        entity_type="session", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"model": "test"})
    checkpoint = engine.memory.checkpoint(
        tenant_id=TENANT, project_id=PROJECT, session_id=session.id,
        label="before release", working_state={"step": 3}, verified=True)
    assert checkpoint["status"] == "verified"
    assert checkpoint.id in engine.memory.tier_members(PROJECT, "L1")
    assert engine.memory.last_safe_checkpoint(PROJECT).id == checkpoint.id


@pytest.mark.parametrize("malformed", ["", 0, False, {}, ["tsk_a", "tsk_a"]])
def test_memory_retrieve_rejects_malformed_anchor_collections_without_writes(
        engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="anchor_node_ids"):
        engine.memory.retrieve(PROJECT, anchor_node_ids=malformed)
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        ("query", None), ("query", 0), ("query", False),
        ("query", {}), ("query", "\x1b[31m"),
        ("limit", False), ("limit", -1), ("limit", 1.5),
        ("limit", "20"), ("limit", 10_001),
        ("half_life_days", False), ("half_life_days", 0),
        ("half_life_days", -1), ("half_life_days", float("nan")),
        ("half_life_days", float("inf")), ("half_life_days", "14"),
        ("now", ""), ("now", 0), ("now", False), ("now", "not-a-date"),
    ],
)
def test_memory_retrieve_rejects_malformed_ranking_inputs_without_writes(
        engine, field, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError):
        engine.memory.retrieve(PROJECT, **{field: malformed})
    assert _database_snapshot(engine) == before


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        ("raw_days", False), ("raw_days", -1), ("raw_days", 1.5),
        ("raw_days", "30"),
        ("now", ""), ("now", 0), ("now", False), ("now", "not-a-date"),
        ("actor", None), ("actor", ""), ("actor", "   "),
        ("actor", 0), ("actor", False), ("actor", "\x1b[31m"),
        ("actor", "\u202eoverride"), ("actor", "x" * 257),
    ],
)
def test_retention_rejects_malformed_inputs_without_deleting_payloads(
        engine, field, malformed):
    event = _event(engine)
    assert engine.store.get_event(
        event["event_id"], tenant_id=TENANT,
        project_id=PROJECT)["payload"] is not None
    before = _database_snapshot(engine)
    with pytest.raises(ValueError):
        engine.memory.sweep_retention(**{field: malformed})
    assert _database_snapshot(engine) == before
    assert engine.store.get_event(
        event["event_id"], tenant_id=TENANT,
        project_id=PROJECT)["payload"] is not None


def test_retention_zero_days_remains_an_explicit_destructive_choice(engine):
    event = _event(engine)
    assert engine.memory.sweep_retention(
        raw_days=0, actor="retention-reviewer") == 1
    assert engine.store.get_event(
        event["event_id"], tenant_id=TENANT,
        project_id=PROJECT)["payload"] is None
    assert engine.store.audit_entries("retention.sweep")[-1]["actor"] == \
        "retention-reviewer"


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        ("corrections", None), ("corrections", ""),
        ("corrections", []), ("corrections", {"bad": float("nan")}),
        ("corrections", {1: "bad"}),
        ("actor", None), ("actor", ""), ("actor", "   "),
        ("actor", 0), ("actor", False), ("actor", "\x1b[31m"),
        ("actor", "\u202eoverride"), ("actor", "x" * 257),
    ],
)
def test_memory_correction_rejects_malformed_inputs_without_writes(
        engine, field, malformed):
    node = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"statement": "old"})
    values = {"corrections": {"statement": "new"}, "actor": "reviewer"}
    values[field] = malformed
    before = _database_snapshot(engine)
    with pytest.raises(ValueError):
        engine.memory.correct(PROJECT, node.id, **values)
    assert _database_snapshot(engine) == before


def test_memory_correction_persists_finite_state_and_safe_actor(engine):
    node = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"statement": "old"})
    corrected = engine.memory.correct(
        PROJECT, node.id, {"statement": "new"}, actor="reviewer")
    assert corrected["data"]["statement"] == "new"
    assert engine.store.audit_entries("memory.correct")[-1]["actor"] == \
        "reviewer"


def _grade_inputs() -> dict:
    return {
        "outcomes": [{
            "verifier": "ci", "source": "executed", "result": "passed"}],
        "required": ["ci"],
        "controls": {"ci": {"status": "held"}},
        "mutation": MutationReport(
            artifacts=["artifact"], detected=[{"artifact": "artifact"}],
            baseline={"ci": "passed"}),
        "determinism": {
            "ci": {"stable": True, "results": ["passed", "passed"]}},
        "unpinned_required": [],
    }


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        ("outcomes", None), ("outcomes", ""), ("outcomes", {}),
        ("required", None), ("required", ""), ("required", {}),
        ("controls", ""), ("controls", 0), ("controls", False),
        ("controls", []),
        ("determinism", ""), ("determinism", 0),
        ("determinism", False), ("determinism", []),
        ("unpinned_required", ""), ("unpinned_required", 0),
        ("unpinned_required", False), ("unpinned_required", {}),
        ("mutation", ""), ("mutation", 0), ("mutation", False),
        ("mutation", {}), ("mutation", []),
    ],
)
def test_evidence_grade_rejects_malformed_typed_inputs(field, malformed):
    values = _grade_inputs()
    values[field] = malformed
    with pytest.raises(ValueError):
        grade_evidence(**values)


def test_unpinned_required_cannot_be_silently_upgraded_to_grade_a():
    values = _grade_inputs()
    values["unpinned_required"] = ["ci"]
    assert grade_evidence(**values).grade == "D"
    values["unpinned_required"] = False
    with pytest.raises(ValueError, match="unpinned_required"):
        grade_evidence(**values)


@pytest.mark.parametrize("malformed", [None, "", 0, 1, [], {}])
def test_verifier_runner_requires_exact_persistence_boolean(tmp_path, malformed):
    store = Store(tmp_path / "verifier.sqlite3")
    try:
        with pytest.raises(ValueError, match="persist_evidence"):
            VerifierRunner(store, tmp_path, persist_evidence=malformed)
    finally:
        store.close()


def _python_command(source: str) -> str:
    return shlex.join([sys.executable, "-c", source])


def test_verifier_runner_false_does_not_persist_transcript(tmp_path):
    store = Store(tmp_path / "private.sqlite3")
    try:
        runner = VerifierRunner(store, tmp_path, persist_evidence=False)
        outcome = runner.run(VerifierSpec(
            name="privacy", command=_python_command("print('private-output')")))
        assert outcome.result == "passed"
        count = store._conn.execute(
            "SELECT COUNT(*) FROM evidence_blobs").fetchone()[0]
        assert count == 0
    finally:
        store.close()


@pytest.mark.parametrize("malformed", [None, "", 0, False, [], {}])
def test_verifier_runner_cleanly_refuses_non_specs_without_writes(
        tmp_path, malformed):
    store = Store(tmp_path / "invalid-spec.sqlite3")
    try:
        before = tuple(store._conn.iterdump())
        outcome = VerifierRunner(store, tmp_path).run(malformed)
        assert outcome.result == "inconclusive"
        assert outcome.verifier == "<invalid>"
        assert "expected a VerifierSpec" in outcome.details
        assert tuple(store._conn.iterdump()) == before
    finally:
        store.close()


def _verification_outcome() -> VerificationOutcome:
    return VerificationOutcome(
        verifier="ci", kind="command", result="passed",
        started_at=utcnow(), duration_seconds=0.1)


@pytest.mark.parametrize("malformed", ["", 0, False, {}, []])
def test_record_verification_rejects_falsey_subject_without_writes(
        engine, malformed):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="subject_node_id"):
        record_verification(
            engine.graph, _verification_outcome(), tenant_id=TENANT,
            project_id=PROJECT, subject_node_id=malformed)
    assert _database_snapshot(engine) == before


def test_record_verification_rejects_missing_subject_without_writes(engine):
    before = _database_snapshot(engine)
    with pytest.raises(ValueError, match="must identify a node"):
        record_verification(
            engine.graph, _verification_outcome(), tenant_id=TENANT,
            project_id=PROJECT, subject_node_id="tsk_missing")
    assert _database_snapshot(engine) == before


def test_record_verification_links_a_valid_subject_atomically(engine):
    subject = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        status="open", data={"title": "release"})
    verification = record_verification(
        engine.graph, _verification_outcome(), tenant_id=TENANT,
        project_id=PROJECT, subject_node_id=subject.id)
    edges = engine.graph.out_edges(verification.id)
    assert len(edges) == 1
    assert edges[0]["edge_type"] == "verifies"
    assert edges[0]["dst_id"] == subject.id
