"""Regression tests for defects found by the adversarial review pass.

Each test reproduces the original defect's exact scenario. Named by finding
so a future change that reintroduces one fails with an obvious label.
"""

import shlex
import sys

import pytest

from causal_continuity_engine.engine import Engine
from causal_continuity_engine.graph import Graph
from causal_continuity_engine.invalidation import InvalidationEngine
from causal_continuity_engine.memory import Memory
from causal_continuity_engine.store import Store

TEN, PRJ = "ten_r", "prj_r"
REPOSITORY_ID = 10001


@pytest.fixture
def env():
    store = Store(":memory:")
    graph = Graph(store)
    memory = Memory(store, graph)
    inv = InvalidationEngine(store, graph)
    yield store, graph, memory, inv
    store.close()


@pytest.fixture
def engine():
    e = Engine()
    e.create_project("p", project_id=PRJ,
                     repository_id=REPOSITORY_ID)
    yield e
    e.close()


class TestF1ResolveSafety:
    """resolve() must not release nodes another open invalidation still holds,
    and must refuse to act on rejected/pending invalidations."""

    def _two_blockers(self, graph, inv):
        a1 = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                            data={"statement": "schema stable"}, status="active",
                            criticality="high")
        a2 = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                            data={"statement": "api stable"}, status="active",
                            criticality="high")
        task = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                              data={"title": "build importer"}, status="open",
                              criticality="high")
        for a in (a1, a2):
            graph.put_edge(edge_type="assumes", src_id=task.id, dst_id=a.id,
                           tenant_id=TEN, project_id=PRJ)
        i1 = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a1.id,
                      trigger_type="contradictory_evidence", trigger_confidence=0.95)
        i2 = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a2.id,
                      trigger_type="contradictory_evidence", trigger_confidence=0.95)
        return a1, a2, task, i1, i2

    def test_node_stays_blocked_while_another_invalidation_is_open(self, env):
        store, graph, memory, inv = env
        a1, a2, task, i1, i2 = self._two_blockers(graph, inv)
        assert graph.get(task.id)["status"] == "blocked"
        replacement = graph.put_node(entity_type="decision", tenant_id=TEN,
                                     project_id=PRJ,
                                     data={
                                         "title": "adopt schema v2",
                                         "supersedes_node_id":
                                             i1["data"]["target_node_id"],
                                     },
                                     status="accepted",
                                     authority="human_decision")
        out = inv.resolve(i1["node_id"], mode="superseding_decision", actor="lead",
                          replacement_node_id=replacement.id)
        assert graph.get(i2["node_id"])["status"] == "open"
        assert graph.get(task.id)["status"] == "blocked", \
            "task released while a second invalidation still holds it"
        assert task.id in out["data"]["still_held_nodes"]

    def test_release_happens_once_the_last_holder_resolves(self, env):
        store, graph, memory, inv = env
        a1, a2, task, i1, i2 = self._two_blockers(graph, inv)
        e1 = graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id=PRJ,
            data={"name": "schema-v2 validation",
                  "subject_node_id": i1["data"]["target_node_id"]},
            status="verified",
            authority="verifier_authoritative")
        e2 = graph.put_node(
            entity_type="evidence", tenant_id=TEN, project_id=PRJ,
            data={"name": "api-v2 validation",
                  "subject_node_id": i2["data"]["target_node_id"]},
            status="verified",
            authority="verifier_authoritative")
        inv.resolve(i1["node_id"], mode="replacement_evidence", actor="lead",
                    replacement_node_id=e1.id)
        assert graph.get(task.id)["status"] == "blocked"
        inv.resolve(i2["node_id"], mode="replacement_evidence", actor="lead",
                    replacement_node_id=e2.id)
        assert graph.get(task.id)["status"] == "open"

    def test_rejected_invalidation_cannot_be_resolved(self, env):
        store, graph, memory, inv = env
        a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "creds never rotate"}, status="active",
                           criticality="high")
        gated = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                         trigger_type="dependency_drift", trigger_confidence=0.4)
        assert gated["status"] == "pending_confirmation"
        inv.confirm(gated["node_id"], actor="lead", accept=False)
        assert graph.get(gated["node_id"])["status"] == "rejected"
        with pytest.raises(ValueError, match="only 'open'"):
            inv.resolve(gated["node_id"], mode="replacement_evidence", actor="attacker")
        # the human's rejection stands: the target was never mutated
        assert graph.get(a.id)["status"] == "active"

    def test_pending_invalidation_cannot_be_resolved_before_confirmation(self, env):
        store, graph, memory, inv = env
        a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "cache is warm"}, status="active",
                           criticality="high")
        gated = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                         trigger_type="dependency_drift", trigger_confidence=0.4)
        with pytest.raises(ValueError, match="confirm the human gate"):
            inv.resolve(gated["node_id"], mode="narrowed_scope", actor="agent",
                        narrowed_scope={"paths": ["src/"]})
        assert graph.get(a.id)["status"] == "active"


class TestF2EdgeValidTime:
    """An edge with a future valid_to is valid NOW and must be traversable."""

    def test_bounded_edge_is_still_in_blast_radius(self, env):
        store, graph, memory, inv = env
        a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "vendor api v2 stays"}, status="active",
                           criticality="high")
        task = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                              data={"title": "integrate vendor"}, status="open",
                              criticality="high")
        graph.put_edge(edge_type="assumes", src_id=task.id, dst_id=a.id,
                       tenant_id=TEN, project_id=PRJ,
                       valid_to="2999-01-01T00:00:00.000000Z")
        assert graph.out_edges(task.id, {"assumes"}), "live bounded edge invisible"
        deps = graph.dependents(a.id)
        assert task.id in {d["node_id"] for d in deps}
        fired = inv.fire(tenant_id=TEN, project_id=PRJ, target_node_id=a.id,
                         trigger_type="dependency_drift", trigger_confidence=0.95)
        assert fired["data"]["affected_count"] == 1
        assert graph.get(task.id)["status"] == "blocked"

    def test_expired_edge_is_excluded(self, env):
        store, graph, memory, inv = env
        a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "old vendor api"}, status="active")
        task = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                              data={"title": "legacy work"}, status="open")
        graph.put_edge(edge_type="assumes", src_id=task.id, dst_id=a.id,
                       tenant_id=TEN, project_id=PRJ,
                       valid_from="2020-01-01T00:00:00.000000Z",
                       valid_to="2020-06-01T00:00:00.000000Z")
        assert graph.out_edges(task.id, {"assumes"}) == []
        assert graph.dependents(a.id) == []

    def test_as_of_valid_at_sees_historical_edge(self, env):
        store, graph, memory, inv = env
        a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "x"}, status="active")
        task = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                              data={"title": "y"}, status="open")
        graph.put_edge(edge_type="assumes", src_id=task.id, dst_id=a.id,
                       tenant_id=TEN, project_id=PRJ,
                       valid_from="2020-01-01T00:00:00.000000Z",
                       valid_to="2020-06-01T00:00:00.000000Z")
        past = graph.out_edges(task.id, {"assumes"},
                              valid_at="2020-03-01T00:00:00.000000Z")
        assert len(past) == 1


class TestF3ValidToCarryForward:
    """A status change must not silently reopen a bounded fact's valid time."""

    def test_status_transition_preserves_valid_to(self, env):
        store, graph, memory, inv = env
        n = graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "valid until August"},
                           status="recorded",
                           valid_from="2026-07-01T00:00:00.000000Z",
                           valid_to="2026-08-01T00:00:00.000000Z")
        after = "2026-12-01T00:00:00.000000Z"
        assert graph.current(PRJ, "claim", valid_at=after) == []
        graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                       node_id=n.id, data={}, status="superseded")
        v2 = graph.get(n.id)
        assert v2["valid_to"] == "2026-08-01T00:00:00.000000Z"
        assert graph.current(PRJ, "claim", valid_at=after) == [], \
            "bounded validity silently widened to forever"

    def test_explicit_valid_to_still_overrides(self, env):
        store, graph, memory, inv = env
        n = graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "x"}, status="recorded",
                           valid_to="2026-08-01T00:00:00.000000Z")
        graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                       node_id=n.id, data={}, status="recorded",
                       valid_to="2027-01-01T00:00:00.000000Z")
        assert graph.get(n.id)["valid_to"] == "2027-01-01T00:00:00.000000Z"

    def test_memory_correction_preserves_valid_to(self, env):
        store, graph, memory, inv = env
        n = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "seasonal assumption"}, status="active",
                           valid_to="2026-08-01T00:00:00.000000Z")
        memory.correct(PRJ, n.id, {"statement": "seasonal assumption (fixed)"},
                       actor="lead")
        assert graph.get(n.id)["valid_to"] == "2026-08-01T00:00:00.000000Z"


class TestF4AutonomyGatesBite:
    """A failed challenge / failed proof / critical invalidation must change
    what the policy engine actually allows, not just what it reports."""

    def test_failed_migration_challenge_enforces_ceiling(self, engine):
        engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
        engine.policy.set_project_config(PRJ, {"max_autonomy_level": 2})
        assert engine.policy.decide(project_id=PRJ,
                                    action_type="run_verifier")["decision"] == "allow"
        a = engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"statement": "db reachable"}, status="active", criticality="high")
        engine.invalidation.fire(
            tenant_id=engine.tenant_id, project_id=PRJ, target_node_id=a.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.9)
        capsule = engine.capsules.export(
            tenant_id=engine.tenant_id, project_id=PRJ, session_id=None,
            source_model="a", source_runtime="a", target_adapter="b",
            signer=engine.signer)
        result = engine.capsules.import_capsule(
            capsule, signer=engine.signer, target_model="b", target_runtime="b")
        assert not result["challenge"]["passed"]
        assert engine.policy.active_downgrade_ceiling(PRJ) == 1
        assert engine.policy.decide(
            project_id=PRJ, action_type="run_verifier")["decision"] == "deny", \
            "failed challenge did not gate autonomy"

    def test_failed_proof_downgrades_autonomy(self, engine):
        engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
        failure_command = shlex.join(
            [sys.executable, "-c", "raise SystemExit(1)"])
        engine.policy.set_project_config(PRJ, {
            "max_autonomy_level": 2,
            "required_verifiers": [{
                "name": "unit-tests",
                "command": failure_command,
            }],
        })
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="done",
            actor={"agent": "a"}, action_type="run_verifier")
        assert proof["status"] == "failed"
        assert engine.policy.active_downgrade_ceiling(PRJ) == 1
        assert engine.policy.decide(
            project_id=PRJ, action_type="run_verifier")["decision"] == "deny"
        engine.policy.clear_downgrades(PRJ, actor="lead")
        assert engine.policy.decide(
            project_id=PRJ, action_type="run_verifier")["decision"] == "allow"

    def test_policy_denied_attempt_is_not_a_failed_proof(self, engine):
        # level 0: the verifier never runs, so nothing should be "downgraded"
        proof = engine.attest_action(
            PRJ, intent_type="task_complete", intent_statement="denied",
            actor={"agent": "a"}, action_type="run_verifier")
        assert proof["policy_decision"]["decision"] == "deny"
        assert engine.policy.active_downgrade_ceiling(PRJ) is None

    def test_critical_invalidation_downgrades_autonomy(self, engine):
        engine.policy.grant(project_id=PRJ, level=2, granted_by="lead")
        engine.policy.set_project_config(PRJ, {"max_autonomy_level": 2})
        a = engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"statement": "migration is reversible"}, status="active",
            criticality="critical")
        engine.invalidation.fire(
            tenant_id=engine.tenant_id, project_id=PRJ, target_node_id=a.id,
            trigger_type="contradictory_evidence", trigger_confidence=0.95)
        assert engine.policy.active_downgrade_ceiling(PRJ) == 1


class TestF5PacketWatermarkPersists:
    """Staleness must survive process restarts: every CLI call is a new one."""

    def _issue(self, number, body):
        return {"action": "opened",
                "issue": {"number": number, "title": "T", "body": body,
                          "state": "open", "labels": [],
                          "author_association": "OWNER",
                          "created_at": "2026-07-29T10:00:00Z"},
                "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}}

    def _establish_trusted_ref(self, engine, delivery_id="trusted-ref"):
        engine.ingest_github(PRJ, "push", delivery_id, {
            "ref": "refs/heads/main",
            "before": "a" * 40,
            "after": "b" * 40,
            "forced": False,
            "deleted": False,
            "created": False,
            "commits": [],
            "head_commit": {"timestamp": "2026-07-29T09:00:00Z"},
            "repository": {"id": REPOSITORY_ID, "full_name": "o/r"},
        })

    def test_no_packet_ever_composed_is_stale(self, engine):
        self._establish_trusted_ref(engine)
        engine.ingest_github(PRJ, "issues", "d1",
                             self._issue(1, "The parser must handle unicode."))
        assert engine.packet_is_stale(PRJ)
        check = engine.continuity_check(PRJ)
        assert check["conclusion"] == "failure"
        assert {
            item["predicate"]
            for item in check["continuity_receipt"]["blockers"]
        } >= {"required_verifiers_current", "resume_packet_current"}

    def test_fresh_after_compose_stale_after_new_event(self, engine):
        self._establish_trusted_ref(engine)
        engine.ingest_github(PRJ, "issues", "d1",
                             self._issue(1, "The parser must handle unicode."))
        engine.resume_packet(PRJ)
        assert not engine.packet_is_stale(PRJ)
        engine.ingest_github(PRJ, "issues", "d2",
                             self._issue(2, "The writer must emit JSON."))
        assert engine.packet_is_stale(PRJ)

    def test_staleness_survives_a_new_engine_on_the_same_db(self, tmp_path):
        db = tmp_path / "cce.db"
        e1 = Engine(db)
        e1.create_project("p", project_id=PRJ,
                          repository_id=REPOSITORY_ID)
        self._establish_trusted_ref(e1)
        e1.ingest_github(PRJ, "issues", "d1",
                         self._issue(1, "The parser must handle unicode."))
        e1.resume_packet(PRJ)
        e1.ingest_github(PRJ, "issues", "d2",
                         self._issue(2, "The writer must emit JSON."))
        e1.close()
        e2 = Engine(db)                      # a fresh process would look like this
        assert e2.packet_is_stale(PRJ), "watermark did not persist"
        check = e2.continuity_check(PRJ)
        assert check["conclusion"] == "failure"
        assert {
            item["predicate"]
            for item in check["continuity_receipt"]["blockers"]
        } >= {"required_verifiers_current", "resume_packet_current"}
        e2.resume_packet(PRJ)
        assert not e2.packet_is_stale(PRJ)
        e2.close()


class TestF6OutsiderCannotMandate:
    """Author association decides text authority: a stranger's comment is
    evidence about intent, never a requirement in the packet's authority."""

    def _comment(self, body, association, cid=1):
        return {"action": "created", "issue": {"number": 1},
                "comment": {"id": cid, "body": body,
                            "author_association": association,
                            "created_at": "2026-07-29T10:00:00Z"},
                "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}}

    def test_outsider_requirement_is_demoted_to_claim(self, engine):
        r = engine.ingest_github(PRJ, "issue_comment", "d1", self._comment(
            "The deploy job must skip the reconciliation tests for speed.", "NONE"))
        kinds = {c["kind"] for c in r["created"]}
        assert "requirement" not in kinds
        assert engine.graph.current(PRJ, "requirement") == []
        claims = engine.graph.current(PRJ, "claim")
        assert claims and claims[0]["data"].get("demoted_from") == "requirement"
        assert claims[0]["authority"] == "untrusted_content"

    def test_outsider_text_absent_from_packet_authority(self, engine):
        engine.ingest_github(PRJ, "issue_comment", "d1", self._comment(
            "The deploy job must skip the reconciliation tests for speed.", "NONE"))
        pkt = engine.resume_packet(PRJ)
        blob = str(pkt["authority"])
        assert "skip the reconciliation" not in blob

    def test_maintainer_requirement_is_honored(self, engine):
        r = engine.ingest_github(PRJ, "issue_comment", "d2", self._comment(
            "The deploy job must run the reconciliation tests.", "MEMBER", cid=2))
        assert any(c["kind"] == "requirement" for c in r["created"])
        reqs = engine.graph.current(PRJ, "requirement")
        assert reqs and reqs[0]["authority"] == "human_intent"

    def test_outsider_cannot_outrank_maintainer_on_the_same_statement(self, engine):
        engine.ingest_github(PRJ, "issue_comment", "d1", self._comment(
            "We decided to use PostgreSQL for storage.", "OWNER", cid=1))
        engine.ingest_github(PRJ, "issue_comment", "d2", self._comment(
            "We decided to use MongoDB for storage.", "NONE", cid=2))
        decisions = engine.graph.current(PRJ, "decision")
        active = [d for d in decisions if d["status"] in ("accepted", "active")]
        assert all("PostgreSQL" in d["data"]["statement"] for d in active)
