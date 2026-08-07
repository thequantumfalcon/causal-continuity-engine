"""Learning layer, partial progress, and the HTTP API."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from causal_continuity_engine.api import make_handler
from causal_continuity_engine.engine import Engine

PRJ = "prj_l"
REPOSITORY_ID = 12012
API_TOKEN = "test-api-token-00123456789abcdef"


@pytest.fixture
def engine():
    e = Engine()
    e.create_project("p", project_id=PRJ,
                     repository_id=REPOSITORY_ID)
    yield e
    e.close()


class TestPartialProgress:
    def test_multi_state_outcome(self, engine):
        out = engine.partial.record_outcome(
            tenant_id=engine.tenant_id, project_id=PRJ, session_id=None,
            status="partially_completed",
            completed=[{"name": "step1"}], failed=[{"name": "step2"}],
            unverified=[{"name": "step3"}], failure_mode="tool")
        assert out["status"] == "partially_completed"
        assert out["data"]["failed"] == [{"name": "step2"}]

    def test_invalid_status_rejected(self, engine):
        with pytest.raises(ValueError):
            engine.partial.record_outcome(
                tenant_id=engine.tenant_id, project_id=PRJ, session_id=None,
                status="sort_of_done")

    @pytest.mark.parametrize(
        "field,value",
        [
            ("failure_mode", 7),
            ("failure_mode", "made-up"),
            ("completed", [1]),
            ("failed", "step"),
            ("blocked", [None]),
            ("skipped", [False]),
            ("unverified", [{"name": "ok"}, "bad"]),
        ],
    )
    def test_invalid_outcome_payload_rejected_before_write(
            self, engine, field, value):
        before = len(engine.graph.current(PRJ, "outcome"))
        kwargs = {
            "tenant_id": engine.tenant_id,
            "project_id": PRJ,
            "session_id": None,
            "status": "failed",
            field: value,
        }
        with pytest.raises(ValueError):
            engine.partial.record_outcome(**kwargs)
        assert len(engine.graph.current(PRJ, "outcome")) == before

    def test_recovery_rejects_non_string_summary_source(self, engine):
        engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"title": 7}, status="open")
        with pytest.raises(ValueError, match="summary source"):
            engine.partial.recovery_packet(PRJ)

    def test_recovery_rejects_non_string_checkpoint_label(self, engine):
        engine.graph.put_node(
            entity_type="checkpoint", tenant_id=engine.tenant_id,
            project_id=PRJ, data={"label": 7, "working_state": {}},
            status="verified")
        with pytest.raises(ValueError, match="checkpoint label"):
            engine.partial.recovery_packet(PRJ)

    def test_quarantine_blocks_completion_and_l3(self, engine):
        art = engine.graph.put_node(
            entity_type="artifact", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"name": "half-written file"}, status="unverified")
        engine.partial.quarantine(art.id, actor="cce", reason="tool crashed mid-write")
        assert engine.graph.get(art.id)["status"] == "quarantined"
        with pytest.raises(ValueError):
            engine.memory.promote(PRJ, art.id, "L3", actor="cce")

    def test_recovery_packet_names_boundary_and_gaps(self, engine):
        cp = engine.memory.checkpoint(
            tenant_id=engine.tenant_id, project_id=PRJ, session_id=None,
            label="after schema migration", working_state={"step": 2}, verified=True)
        engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"title": "wire the API"}, status="open")
        engine.partial.record_outcome(
            tenant_id=engine.tenant_id, project_id=PRJ, session_id=None,
            status="failed", failed=[{"name": "deploy step"}], failure_mode="tool")
        rp = engine.partial.recovery_packet(PRJ)
        assert rp["last_safe_checkpoint"]["node_id"] == cp["node_id"]
        assert rp["last_outcome"]["status"] == "failed"
        assert any("deploy step" in s for s in rp["rerun_instructions"])
        assert rp["remaining_tasks"]

    def test_failed_action_preserves_unrelated_verified_work(self, engine):
        done = engine.graph.put_node(
            entity_type="task", tenant_id=engine.tenant_id, project_id=PRJ,
            data={"title": "finished feature"}, status="verified")
        engine.partial.record_outcome(
            tenant_id=engine.tenant_id, project_id=PRJ, session_id=None,
            status="failed", failed=[{"name": "unrelated step"}])
        assert engine.graph.get(done.id)["status"] == "verified"
        rp = engine.partial.recovery_packet(PRJ)
        assert any(w["node_id"] == done.id for w in rp["verified_work_to_keep"])


class TestReplay:
    def test_fidelity_classification(self, engine):
        engine.ingest_github(PRJ, "check_run", "d1", {
            "action": "completed",
            "check_run": {"id": 1, "name": "t", "status": "completed",
                          "conclusion": "success", "head_sha": "c" * 40,
                          "completed_at": "2026-07-29T12:00:00Z",
                          "app": {"id": 1, "slug": "a"}},
            "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}})
        ev = engine.store.events(PRJ)[0]
        bare = engine.replay.start(tenant_id=engine.tenant_id, project_id=PRJ,
                                   from_event_id=ev["event_id"])
        assert bare["data"]["fidelity"] == "non_reproducible"
        captured = engine.replay.start(
            tenant_id=engine.tenant_id, project_id=PRJ,
            from_event_id=ev["event_id"], captured_inputs={"repo": "snapshot"})
        assert captured["data"]["fidelity"] == "environment_equivalent"
        mocked = engine.replay.start(
            tenant_id=engine.tenant_id, project_id=PRJ,
            from_event_id=ev["event_id"], captured_inputs={"repo": "snapshot"},
            mocks={"llm": "canned"})
        assert mocked["data"]["fidelity"] == "mocked"

    def test_replay_never_upgrades_fidelity(self, engine):
        engine.ingest_github(PRJ, "check_run", "d1", {
            "action": "completed",
            "check_run": {"id": 1, "name": "t", "status": "completed",
                          "conclusion": "success", "head_sha": "c" * 40,
                          "completed_at": "2026-07-29T12:00:00Z",
                          "app": {"id": 1, "slug": "a"}},
            "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}})
        ev = engine.store.events(PRJ)[0]
        node = engine.replay.start(tenant_id=engine.tenant_id, project_id=PRJ,
                                   from_event_id=ev["event_id"])
        node["data"]["fidelity"] = "exact"   # attacker edit on a copy
        done = engine.replay.record_result(node["node_id"],
                                           diff={"same": True}, outcome="pass")
        assert done["data"]["fidelity"] == "non_reproducible"


class TestComposting:
    def test_taxonomy_classification(self, engine):
        assert engine.composter.classify("the unit test failed on assert") \
            == "verification"
        assert engine.composter.classify("ModuleNotFoundError: missing module x") \
            == "environment"
        assert engine.composter.classify("stale assumption about the schema") \
            == "stale_assumption"
        assert engine.composter.classify("total mystery") == "unknown"

    def test_compost_produces_recovery(self, engine):
        f = engine.composter.compost(
            tenant_id=engine.tenant_id, project_id=PRJ,
            description="subprocess timeout during packaging",
            failing_step="run packaging command")
        assert f["data"]["taxonomy"] == "tool"
        assert f["data"]["recovery_candidate"]
        assert f["data"]["minimal_failing_boundary"] == "run packaging command"

    def test_clusters_group_recurrences(self, engine):
        for i in range(3):
            engine.composter.compost(
                tenant_id=engine.tenant_id, project_id=PRJ,
                description="subprocess timeout during packaging",
                failing_step="run packaging command")
        clusters = engine.composter.clusters(PRJ)
        assert any(len(v) == 3 for v in clusters.values())


class TestEvalGen:
    def test_from_failure_and_dedup(self, engine):
        f = engine.composter.compost(
            tenant_id=engine.tenant_id, project_id=PRJ,
            description="unit test failed after dependency bump",
            failing_step="pytest run")
        e1 = engine.evalgen.from_failure(f["node_id"])
        e2 = engine.evalgen.from_failure(f["node_id"])
        assert e1["node_id"] == e2["node_id"]        # deduplicated
        assert e1["data"]["case"]["ground_truth"]["taxonomy"] == "verification"
        assert e1["data"]["split"] == "development"

    def test_withheld_split(self, engine):
        f = engine.composter.compost(
            tenant_id=engine.tenant_id, project_id=PRJ,
            description="policy denied the deploy", failing_step="deploy gate")
        e = engine.evalgen.from_failure(f["node_id"], withheld=True)
        assert e["data"]["split"] == "withheld"


class TestSkills:
    def test_proposal_only_and_approval_gate(self, engine):
        f = engine.composter.compost(
            tenant_id=engine.tenant_id, project_id=PRJ,
            description="tool crash", failing_step="x")
        s = engine.skills.propose(
            tenant_id=engine.tenant_id, project_id=PRJ, name="retry-with-backoff",
            description="wrap flaky tool", source_failure_ids=[f["node_id"]],
            tests=["test_retry"], rollback_plan="remove wrapper")
        assert s["status"] == "proposed"
        with pytest.raises(ValueError):
            engine.skills.approve(s["node_id"], actor="lead",
                                  sandbox_eval_passed=False)
        out = engine.skills.approve(s["node_id"], actor="lead",
                                    sandbox_eval_passed=True)
        assert out["status"] == "approved"      # never 'active'


class TestHTTPAPI:
    @pytest.fixture
    def server(self, engine):
        httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(engine, PRJ, api_token=API_TOKEN))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{httpd.server_port}"
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)

    @pytest.fixture
    def authenticated_server(self, engine):
        httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(engine, PRJ, api_token=API_TOKEN))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{httpd.server_port}"
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)

    def _get(self, base, path, *, authenticated=True):
        request = urllib.request.Request(
            base + path,
            headers=({"Authorization": f"Bearer {API_TOKEN}"}
                     if authenticated else {}))
        with urllib.request.urlopen(request) as r:
            return r.status, json.loads(r.read())

    def _post(self, base, path, body, *, headers=None, authenticated=True):
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        if authenticated:
            request_headers.setdefault("Authorization", f"Bearer {API_TOKEN}")
        req = urllib.request.Request(
            base + path, data=json.dumps(body).encode(),
            headers=request_headers,
            method="POST")
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())

    def test_health_and_resume(self, server):
        status, body = self._get(server, "/v1/health")
        assert status == 200 and body == {"status": "ok"}
        status, packet = self._post(
            server, f"/v1/projects/{PRJ}/resume-packets:compose", {})
        assert status == 200 and packet["schema_version"] == "cce.resume.v1"

    def test_ingest_and_assumptions(self, server):
        status, report = self._post(server, "/v1/events:ingest", {
            "event_name": "issues", "delivery_id": "api-d1",
            "payload": {
                "action": "opened",
                "issue": {"number": 1, "title": "T",
                          "body": "We assume the queue is durable across restarts.",
                          "state": "open", "labels": [],
                          "created_at": "2026-07-29T10:00:00Z"},
                "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}}})
        assert status == 202 and report["created"]
        status, rows = self._get(server, f"/v1/projects/{PRJ}/assumptions")
        assert status == 200 and len(rows) == 1

    def test_compose_with_budget(self, server):
        status, packet = self._post(
            server, f"/v1/projects/{PRJ}/resume-packets:compose",
            {"token_budget": 500})
        assert status == 200 and packet["schema_version"] == "cce.resume.v1"

    def test_attest_endpoint(self, server):
        status, proof = self._post(server, "/v1/actions:attest", {
            "intent_type": "task_complete", "intent_statement": "done",
            "verifications": [{"verifier": "tests", "result": "failed"}]})
        assert status == 200 and proof["status"] == "incomplete"
        assert proof["verifications"] == [{
            "verifier": "tests",
            "result": "failed",
            "source": "self_asserted",
        }]

    def test_migrations_round_trip(self, server):
        status, capsule = self._post(server, "/v1/migrations:prepare",
                                     {"source_model": "a", "target_adapter": "b"})
        assert status == 200
        status, result = self._post(server, "/v1/migrations:validate",
                                    {"capsule": capsule, "target_model": "b"})
        assert status == 200 and result["validation"]["valid"]

    def test_receipt_verification_is_authenticated_and_project_scoped(
            self, engine, authenticated_server):
        receipt = engine.continuity_check(PRJ)["continuity_receipt"]
        path = f"/v1/projects/{PRJ}/continuity-receipts:verify"
        with pytest.raises(urllib.error.HTTPError) as unauthorized:
            self._post(
                authenticated_server, path, {"receipt": receipt},
                authenticated=False)
        try:
            assert unauthorized.value.code == 401
        finally:
            unauthorized.value.close()

        auth = {"Authorization": f"Bearer {API_TOKEN}"}
        status, result = self._post(
            authenticated_server, path, {"receipt": receipt}, headers=auth)
        assert status == 200 and result["verdict"] == "CURRENT"

        tampered = {**receipt, "decision": "failure"}
        status, result = self._post(
            authenticated_server, path, {"receipt": tampered}, headers=auth)
        assert status == 200 and result["verdict"] == "INVALID"

        with pytest.raises(urllib.error.HTTPError) as wrong_project:
            self._post(
                authenticated_server,
                "/v1/projects/prj_elsewhere/continuity-receipts:verify",
                {"receipt": receipt}, headers=auth)
        try:
            assert wrong_project.value.code == 403
        finally:
            wrong_project.value.close()

    def test_unexpected_server_errors_do_not_disclose_internal_values(
            self, engine, server, monkeypatch):
        leaked = r"C:\\private\\operator\\cce.db"

        def fail(*args, **kwargs):
            raise RuntimeError(f"database failed at {leaked}")

        monkeypatch.setattr(engine, "resume_packet", fail)
        with pytest.raises(urllib.error.HTTPError) as failure:
            self._post(
                server, f"/v1/projects/{PRJ}/resume-packets:compose", {})
        try:
            assert failure.value.code == 500
            body = json.loads(failure.value.read())
        finally:
            failure.value.close()
        assert body == {"error": {
            "code": "internal_error", "message": "internal server error"}}
        assert leaked not in json.dumps(body)

    def test_unknown_route_404(self, server):
        try:
            self._get(server, "/v1/nope")
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            try:
                assert e.code == 404
            finally:
                e.close()
