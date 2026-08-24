"""Invalidation propagation/classification and resume packet composition."""

import pytest

from causal_continuity_engine.engine import Engine
from causal_continuity_engine.graph import Graph
from causal_continuity_engine.invalidation import InvalidationEngine, classify
from causal_continuity_engine.memory import Memory
from causal_continuity_engine.resume import ResumeComposer
from causal_continuity_engine.store import Store

TEN, PRJ = "ten_t", "prj_t"


@pytest.fixture
def env():
    store = Store(":memory:")
    graph = Graph(store)
    memory = Memory(store, graph)
    inv = InvalidationEngine(store, graph)
    composer = ResumeComposer(store, graph, memory)
    graph.put_node(
        entity_type="project", tenant_id=TEN, project_id=PRJ,
        node_id=PRJ, status="active", data={"name": "resume fixture"})
    yield store, graph, memory, inv, composer
    store.close()


@pytest.fixture
def public_engine(tmp_path):
    engine = Engine(tmp_path / "cce.db", tenant_id=TEN, workdir=tmp_path)
    engine.create_project(
        "resume public fixture",
        project_id=PRJ,
        repository="local/resume",
        repository_id=1)
    yield engine
    engine.close()


def _chain(graph):
    """assumption <- (assumes) task <- (depends_on) decision."""
    a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                       data={"statement": "schema is stable"}, status="active",
                       criticality="high")
    t = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                       data={"title": "build importer"}, status="open",
                       criticality="high")
    d = graph.put_node(entity_type="decision", tenant_id=TEN, project_id=PRJ,
                       data={"title": "batch nightly"}, status="accepted",
                       criticality="medium")
    graph.put_edge(edge_type="assumes", src_id=t.id, dst_id=a.id,
                   tenant_id=TEN, project_id=PRJ)
    graph.put_edge(edge_type="depends_on", src_id=d.id, dst_id=t.id,
                   tenant_id=TEN, project_id=PRJ)
    return a, t, d


class TestClassify:
    def test_matrix_deterministic(self):
        assert classify(0.9, "high", 0.9) == "blocked"
        assert classify(0.9, "high", 0.5) == "review_required"
        assert classify(0.6, "medium", 0.9) == "review_required"
        assert classify(0.2, "low", 0.9) == "valid"


@pytest.mark.parametrize("target", [False, [], "issue-1", 7])
def test_resume_target_must_be_object_or_null(env, target):
    _, _, _, _, composer = env
    with pytest.raises(ValueError, match="target must be an object or null"):
        composer.compose(
            tenant_id=TEN, project_id=PRJ, target=target)


@pytest.mark.parametrize("budget", [True, False, 0, -1, 100_001, 1.5, "10"])
def test_resume_token_budget_is_exact_bounded_integer(env, budget):
    _, _, _, _, composer = env
    with pytest.raises(ValueError, match="token_budget.*1 to 100000"):
        composer.compose(
            tenant_id=TEN, project_id=PRJ, token_budget=budget)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target": {"score": float("nan")}},
        {"target": {"score": float("inf")}},
        {"target": {"value": object()}},
        {"state_basis": {"score": float("-inf")}},
    ],
)
def test_resume_inputs_must_be_finite_canonical_json(env, kwargs):
    _, _, _, _, composer = env
    with pytest.raises(ValueError, match="finite canonical JSON"):
        composer.compose(tenant_id=TEN, project_id=PRJ, **kwargs)


class TestInvalidation:
    def test_fire_propagates_and_transitions(self, env):
        store, graph, memory, inv, _ = env
        a, t, d = _chain(graph)
        result = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                          trigger_type="contradictory_evidence",
                          trigger_confidence=0.95, reason="schema changed")
        assert graph.get(a.id)["status"] == "invalidated"
        assert graph.get(t.id)["status"] == "blocked"
        affected = {c["node_id"]: c for c in result["data"]["affected"]}
        assert affected[t.id]["impact"] == "blocked"
        assert result["data"]["minimal_causal_path"]
        assert result["data"]["recommended_action"]

    def test_unknown_trigger_rejected(self, env):
        store, graph, memory, inv, _ = env
        a, _, _ = _chain(graph)
        with pytest.raises(ValueError):
            inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                     trigger_type="vibes")

    def test_low_confidence_high_criticality_needs_human(self, env):
        store, graph, memory, inv, _ = env
        a, t, d = _chain(graph)
        result = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                          trigger_type="dependency_drift",
                          trigger_confidence=0.4, reason="maybe")
        assert result["status"] == "pending_confirmation"
        # No automatic state change happened (ADR-008 / CI-005)
        assert graph.get(a.id)["status"] == "active"
        assert graph.get(t.id)["status"] == "open"

    def test_confirm_applies_reject_discards(self, env):
        store, graph, memory, inv, _ = env
        a, t, d = _chain(graph)
        pending = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                           trigger_type="dependency_drift", trigger_confidence=0.4)
        inv.confirm(pending["node_id"], actor="lead", accept=True)
        assert graph.get(a.id)["status"] == "invalidated"
        # second scenario: reject
        a2 = graph.put_node(entity_type="assumption", tenant_id=TEN,
                            project_id=PRJ, data={"statement": "x is stable"},
                            status="active", criticality="high")
        pending2 = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a2.id,
                            trigger_type="dependency_drift", trigger_confidence=0.4)
        inv.confirm(pending2["node_id"], actor="lead", accept=False)
        assert graph.get(a2.id)["status"] == "active"
        assert graph.get(pending2["node_id"])["status"] == "rejected"

    def test_resolution_supersede_preserves_history(self, env):
        store, graph, memory, inv, _ = env
        a, t, d = _chain(graph)
        fired = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                         trigger_type="changed_requirement", trigger_confidence=0.9)
        replacement = graph.put_node(
            entity_type="decision", tenant_id=TEN, project_id=PRJ,
            data={"title": "adopt schema v2", "supersedes_node_id": a.id},
            status="accepted",
            authority="human_decision")
        out = inv.resolve(fired["node_id"], mode="superseding_decision",
                          actor="lead", replacement_node_id=replacement.id)
        assert out["status"] == "resolved"
        assert graph.get(a.id)["status"] == "superseded"
        assert len(graph.history(a.id)) >= 3          # active -> invalidated -> superseded
        assert graph.get(t.id)["status"] == "open"  # exact pre-invalidation state
        edges = graph.out_edges(replacement.id, {"supersedes"})
        assert edges and edges[0]["dst_id"] == a.id

    def test_metrics(self, env):
        store, graph, memory, inv, _ = env
        a, _, _ = _chain(graph)
        inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                 trigger_type="failed_check", trigger_confidence=0.9)
        m = inv.metrics(PRJ)
        assert m["total"] == 1 and m["by_trigger"]["failed_check"] == 1


class TestResume:
    def test_packet_sections_present(self, env):
        store, graph, memory, inv, composer = env
        _chain(graph)
        pkt = composer.compose(tenant_id=TEN, project_id=PRJ)
        for section in ("mission", "authority", "accepted_decisions",
                        "verified_progress", "invalidations", "open_work",
                        "environment", "trust", "continuity_lineage",
                        "evidence_index", "omissions"):
            assert section in pkt

    def test_l0_never_dropped_under_budget(self, env):
        store, graph, memory, inv, composer = env
        pin = graph.put_node(entity_type="constraint", tenant_id=TEN,
                             project_id=PRJ,
                             data={"statement": "never push to main"},
                             status="active", criticality="critical")
        memory.promote(PRJ, pin.id, "L0", actor="h")
        for i in range(40):
            graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                           data={"statement": f"filler fact number {i} about the"
                                 " system architecture and its many details"},
                           status="recorded")
        pkt = composer.compose(tenant_id=TEN, project_id=PRJ, token_budget=300)
        pinned_ids = [p["node_id"] for p in pkt["mission"]["pinned_control_state"]]
        assert pin.id in pinned_ids
        assert pkt["omissions"], "budget pressure must be disclosed"

    def test_open_invalidation_blocks_next_safe_action(self, env):
        store, graph, memory, inv, composer = env
        a, t, d = _chain(graph)
        inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                 trigger_type="contradictory_evidence", trigger_confidence=0.95)
        pkt = composer.compose(tenant_id=TEN, project_id=PRJ)
        assert pkt["invalidations"], "open invalidation must surface"
        nsa = pkt["open_work"]["next_safe_action"]["summary"]
        assert "invalidation" in nsa.lower() or "blocked" not in nsa

    def test_render_markdown(self, env):
        store, graph, memory, inv, composer = env
        _chain(graph)
        pkt = composer.compose(tenant_id=TEN, project_id=PRJ)
        md = ResumeComposer.render_markdown(pkt)
        assert "# CCE Resume Packet" in md and "Next safe action" in md

    def test_all_blocked_work_is_not_reported_as_no_open_tasks(self, env):
        _, graph, _, _, composer = env
        graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "wait for the schema owner"}, status="blocked")

        packet = composer.compose(tenant_id=TEN, project_id=PRJ)

        action = packet["open_work"]["next_safe_action"]
        assert "node_id" not in action
        assert "blocked" in action["summary"].lower()
        assert "No open tasks" not in action["summary"]

    def test_budgeted_next_action_always_names_a_retained_task(self, env):
        _, graph, _, _, composer = env
        graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "blocked migration " + "x" * 80},
            status="blocked")
        graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "run the actionable migration " + "y" * 80},
            status="open")

        partial = None
        for budget in range(1, 1000):
            packet = composer.compose(
                tenant_id=TEN, project_id=PRJ, token_budget=budget)
            if len(packet["open_work"]["tasks"]) == 1:
                partial = packet
                break
        assert partial is not None, "fixture never reached a one-task packet"

        retained = {task["node_id"] for task in partial["open_work"]["tasks"]}
        action = partial["open_work"]["next_safe_action"]
        assert "node_id" not in action or action["node_id"] in retained
        if "node_id" not in action:
            assert "withheld" in action["summary"].lower()

    def test_budget_trimmed_blocker_still_visible_is_not_withheld(
            self, public_engine):
        blocked = public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "wait for the schema owner " + "x" * 80},
            status="blocked")

        packet = public_engine.resume_packet(
            PRJ, token_budget=1, fmt="json")

        assert packet["open_work"]["tasks"] == []
        assert {item["node_id"] for item in packet["open_work"]["blockers"]} \
            == {blocked.id}
        omission = next(
            item for item in packet["omissions"]
            if item.get("reason") == "token_budget"
            and item.get("section") == "open work detail")
        assert omission["count"] == 1
        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert summary == (
            "All visible open work is blocked; resolve a blocker before continuing.")

    def test_budget_counts_only_a_task_absent_from_every_visible_view(
            self, public_engine):
        blocked = public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "blocked migration " + "x" * 80},
            status="blocked")
        actionable = public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "run the actionable migration " + "y" * 80},
            status="open")

        partial = None
        for budget in range(1, 1000):
            packet = public_engine.resume_packet(
                PRJ, token_budget=budget, fmt="json")
            task_ids = {
                item["node_id"] for item in packet["open_work"]["tasks"]}
            if task_ids == {blocked.id}:
                partial = packet
                break

        assert partial is not None, "fixture never retained only the blocker"
        assert actionable.id not in {
            item["node_id"] for item in partial["open_work"]["tasks"]}
        summary = partial["open_work"]["next_safe_action"]["summary"]
        assert "1 additional open task" in summary
        assert "2 additional open task" not in summary

    def test_budget_only_hidden_task_keeps_budget_cause(
            self, public_engine):
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "run the isolated migration " + "z" * 80},
            status="open")

        packet = public_engine.resume_packet(
            PRJ, token_budget=1, fmt="json")

        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert "1 open task" in summary
        assert "token budget" in summary

    def test_budget_and_quarantine_overlap_counts_one_hidden_task(
            self, public_engine):
        text = "review the shared deployment instruction " + "x" * 80
        public_engine.graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="open")

        packet = public_engine.resume_packet(
            PRJ, token_budget=1, fmt="json")

        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert "1 open task" in summary
        assert "2 open task" not in summary

    def test_collision_only_withholding_names_quarantine_cause(
            self, public_engine):
        text = "review the shared deployment instruction " + "c" * 80
        public_engine.graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="open")

        packet = public_engine.resume_packet(
            PRJ, token_budget=100_000, fmt="json")

        assert not any(
            item.get("reason") == "token_budget"
            for item in packet["omissions"])
        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert "matches quarantined content" in summary
        assert "human review is required" in summary
        assert "token budget" not in summary

    def test_budget_overlap_uses_collision_as_the_deciding_cause(
            self, public_engine):
        text = "review the shared deployment instruction " + "d" * 80
        public_engine.graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="open")

        packet = public_engine.resume_packet(
            PRJ, token_budget=1, fmt="json")

        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert "1 open task" in summary
        assert "matches quarantined content" in summary
        assert "token budget" not in summary

    def test_distinct_collision_and_budget_causes_are_both_reported(
            self, public_engine):
        text = "review the shared deployment instruction " + "e" * 80
        public_engine.graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="open")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "run the independent migration " + "f" * 80},
            status="open")

        packet = public_engine.resume_packet(
            PRJ, token_budget=1, fmt="json")

        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert summary.count("1 open task") == 2
        assert "matches quarantined content" in summary
        assert "token budget" in summary
        assert summary.index("quarantined content") < summary.index("token budget")

    def test_blocked_collision_names_quarantine_instead_of_absence(
            self, public_engine):
        text = "review the shared deployment instruction " + "g" * 80
        public_engine.graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="blocked")

        packet = public_engine.resume_packet(
            PRJ, token_budget=100_000, fmt="json")

        assert packet["open_work"]["tasks"] == []
        assert packet["open_work"]["blockers"] == []
        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert "matches quarantined content" in summary
        assert "No open tasks" not in summary
        assert "token budget" not in summary

    def test_visible_blocker_precedes_additional_collision_disclosure(
            self, public_engine):
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "wait for the schema owner"}, status="blocked")
        text = "review the shared deployment instruction " + "h" * 80
        public_engine.graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="open")

        packet = public_engine.resume_packet(
            PRJ, token_budget=100_000, fmt="json")

        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert summary.startswith("All visible open work is blocked")
        assert "1 additional open task" in summary
        assert "matches quarantined content" in summary
        assert "token budget" not in summary

    def test_policy_demoted_collision_is_not_hidden_open_work(
            self, public_engine):
        text = "review the untrusted deployment instruction " + "x" * 80
        public_engine.graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined",
            authority="untrusted_content")
        public_engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="open",
            authority="untrusted_content", extractor="github-prose")

        packet = public_engine.resume_packet(PRJ, fmt="json")

        assert packet["open_work"]["tasks"] == []
        assert packet["open_work"]["blockers"] == []
        summary = packet["open_work"]["next_safe_action"]["summary"]
        assert summary == "No open tasks; verify project state and await instruction."

    def test_quarantine_collision_does_not_claim_withheld_work_is_absent(self, env):
        _, graph, _, _, composer = env
        text = "review the shared deployment instruction " + "x" * 40
        graph.put_node(
            entity_type="claim", tenant_id=TEN, project_id=PRJ,
            data={"statement": text}, status="quarantined")
        graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": text}, status="open")

        packet = composer.compose(tenant_id=TEN, project_id=PRJ)

        assert packet["open_work"]["tasks"] == []
        action = packet["open_work"]["next_safe_action"]["summary"]
        assert "withheld" in action.lower()
        assert "No open tasks" not in action

    def test_markdown_contract_covers_every_packet_field(self, env):
        import json
        from pathlib import Path

        schema = json.loads((Path(__file__).resolve().parent.parent / "schemas" /
                             "cce.resume.v1.json").read_text(encoding="utf-8"))
        covered = (ResumeComposer.MARKDOWN_RENDERED_TOP_LEVEL
                   | ResumeComposer.MARKDOWN_DECLARED_METADATA)
        assert covered == set(schema["properties"])
        assert not (ResumeComposer.MARKDOWN_RENDERED_TOP_LEVEL
                    & ResumeComposer.MARKDOWN_DECLARED_METADATA)

    def test_markdown_exposes_decision_relevant_sections(self, env):
        _, graph, _, _, composer = env
        _chain(graph)
        graph.put_node(
            entity_type="assumption", tenant_id=TEN, project_id=PRJ,
            data={"statement": "the feed remains ordered"}, status="uncertain")
        graph.put_node(
            entity_type="verification", tenant_id=TEN, project_id=PRJ,
            data={"statement": "integration verifier failed"}, status="failed")

        markdown = ResumeComposer.render_markdown(
            composer.compose(tenant_id=TEN, project_id=PRJ))

        for heading in (
                "## Mission control state", "## Assumptions",
                "## Environment", "## Evidence index",
                "## Recent context", "## Continuity lineage",
                "## Transport and cryptographic metadata"):
            assert heading in markdown
        assert "the feed remains ordered" in markdown
        assert "integration verifier failed" in markdown


def test_token_budget_bounds_the_packet_rather_than_merely_triggering_a_trim():
    """`token_budget` trimmed each section to a fixed cap and then stopped.

    Once every trimmable section had been cut to its cap the loop exited,
    however far over budget the packet still was, so a project large enough to
    matter returned a byte-identical packet at every budget. Sections are now
    reduced progressively, so a smaller budget produces a smaller packet until
    only authority — which is deliberately never dropped — remains.
    """
    import tempfile
    from pathlib import Path

    from causal_continuity_engine.engine import Engine

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        engine = Engine(work / "cce.db", tenant_id="ten_budget", workdir=work)
        engine.create_project("demo", project_id="prj_budget",
                              repository_id=1, repository="octo/demo")
        try:
            for number in range(1, 25):
                engine.ingest_github(
                    "prj_budget", "issues", f"d{number}", {
                        "action": "opened",
                        "repository": {"id": 1, "full_name": "octo/demo"},
                        "issue": {
                            "number": number, "title": f"issue {number}",
                            "state": "open", "labels": [],
                            "body": (
                                f"The exporter{number} must stream rows rather"
                                f" than buffering dataset {number}."),
                            "author_association": "OWNER",
                            "created_at": "2026-08-01T00:00:00Z",
                            "updated_at": "2026-08-01T00:00:00Z"}})

            # Both budgets are below the untrimmed size, so both trim. The
            # old fixed-cap code cut each section to the same cap either way
            # and returned byte-identical packets; a bound must not.
            untrimmed = engine.resume_packet(
                "prj_budget", token_budget=50_000, fmt="json")["token_estimate"]
            small = engine.resume_packet(
                "prj_budget", token_budget=200, fmt="json")
            larger = engine.resume_packet(
                "prj_budget", token_budget=untrimmed - 40, fmt="json")

            assert small["token_estimate"] < larger["token_estimate"]
            # Trimming must be attributed, not silent.
            assert any(o["reason"] == "token_budget"
                       for o in small["omissions"])
            # Authority survives regardless: that is the point of the design.
            assert small["authority"] == larger["authority"]
        finally:
            engine.close()
