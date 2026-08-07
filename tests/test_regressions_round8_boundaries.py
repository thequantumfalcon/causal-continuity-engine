"""Adversarial regressions for the round-8 process and trust boundaries.

Each case was first exercised against f4da624.  The graph accepted identity
changes and cross-project edges, the HTTP server accepted unauthenticated and
unbounded requests, the webhook endpoint accepted unsigned decoded JSON, the
verification endpoint ran a caller's command, and init placed the HMAC key in
metadata inside the verifier working tree.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import os
import shlex
import shutil
import stat
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from causal_continuity_engine.api import make_handler
from causal_continuity_engine.cli import main
from causal_continuity_engine.core import Signer, strict_json_loads
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.store import Store
from causal_continuity_engine.verifiers import VerifierRunner, VerifierSpec

TEN = "ten_boundary"
PRJ = "prj_boundary"
OTHER = "prj_other"
REPOSITORY_ID = 8808
API_TOKEN = "boundary-api-token-0123456789abcdef"
WEBHOOK_SECRET = "boundary-webhook-secret-0123456789abcdef"


def _engine(tmp_path: Path) -> Engine:
    return Engine(
        tmp_path / "cce.db", tenant_id=TEN,
        signer=Signer.generate("boundary"), workdir=tmp_path,
    )


class _Server:
    def __init__(self, engine, **handler_options):
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(engine, PRJ, **handler_options))
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def request(self, path, *, body=None, headers=None, method=None):
        data = body
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                payload = json.loads(response.read() or b"{}")
                return response.status, payload
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read() or b"{}")
                return exc.code, payload
            finally:
                exc.close()


def _auth(token=API_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


class TestGraphIdentityBoundary:
    @pytest.mark.parametrize(
        "raw", ['{"decision":"allow","decision":"deny"}',
                '{"confidence":NaN}', '{"confidence":Infinity}'])
    def test_control_json_rejects_duplicate_keys_and_nonfinite_values(self, raw):
        with pytest.raises(ValueError):
            strict_json_loads(raw)

    def test_graph_rejects_nonfinite_semantic_values(self, tmp_path):
        engine = _engine(tmp_path)
        try:
            with pytest.raises(ValueError, match="confidence"):
                engine.graph.put_node(
                    entity_type="claim", tenant_id=TEN, project_id=PRJ,
                    confidence=float("nan"), data={"statement": "ambiguous"})
            with pytest.raises(ValueError, match="Out of range|finite"):
                engine.graph.put_node(
                    entity_type="claim", tenant_id=TEN, project_id=PRJ,
                    data={"score": float("inf")})
            left = engine.graph.put_node(
                entity_type="claim", tenant_id=TEN, project_id=PRJ,
                data={"statement": "left"})
            right = engine.graph.put_node(
                entity_type="claim", tenant_id=TEN, project_id=PRJ,
                data={"statement": "right"})
            with pytest.raises(ValueError, match="strength"):
                engine.graph.put_edge(
                    edge_type="supports", src_id=left.id, dst_id=right.id,
                    tenant_id=TEN, project_id=PRJ, strength=float("inf"))
        finally:
            engine.close()

    def test_node_identity_cannot_be_retyped_retenanted_or_rehomed(self, tmp_path):
        engine = _engine(tmp_path)
        node = engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "victim"}, status="open")

        with pytest.raises(ValueError, match="immutable node identity"):
            engine.graph.put_node(
                entity_type="requirement", tenant_id="ten_other",
                project_id=OTHER, node_id=node.id,
                data={"statement": "retagged"}, status="active")

        current = engine.graph.get(node.id)
        assert (current["entity_type"], current["tenant_id"], current["project_id"]) == (
            "task", TEN, PRJ)
        assert current["version"] == 1
        engine.close()

    def test_edge_requires_endpoints_in_its_tenant_and_project(self, tmp_path):
        engine = _engine(tmp_path)
        left = engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ,
            data={"title": "left"})
        right = engine.graph.put_node(
            entity_type="assumption", tenant_id=TEN, project_id=OTHER,
            data={"statement": "right"})

        with pytest.raises(ValueError, match="edge endpoints must belong"):
            engine.graph.put_edge(
                edge_type="depends_on", src_id=left.id, dst_id=right.id,
                tenant_id=TEN, project_id=PRJ)
        assert engine.graph.out_edges(left.id) == []
        engine.close()

    def test_edge_identity_is_immutable_and_current_edges_are_scoped(self, tmp_path):
        engine = _engine(tmp_path)
        src = engine.graph.put_node(
            entity_type="task", tenant_id=TEN, project_id=PRJ, data={"title": "s"})
        dst = engine.graph.put_node(
            entity_type="assumption", tenant_id=TEN, project_id=PRJ,
            data={"statement": "d"})
        event = engine.store.append_event(
            tenant_id=TEN, project_id=PRJ, source_type="test",
            idempotency_key="edge-identity", payload={"edge": "supports"},
            authority="repository_authoritative")
        edge = engine.graph.put_edge(
            edge_type="depends_on", src_id=src.id, dst_id=dst.id,
            tenant_id=TEN, project_id=PRJ, event_id=event["event_id"])

        with pytest.raises(ValueError, match="immutable edge identity"):
            engine.graph.put_edge(
                edge_id=edge["edge_id"], edge_type="supports",
                src_id=src.id, dst_id=dst.id, tenant_id=TEN, project_id=PRJ)
        with pytest.raises(PermissionError, match="does not belong"):
            engine.graph.end_edge(
                edge["edge_id"], tenant_id=TEN, project_id=OTHER)
        assert [row["edge_id"] for row in engine.graph.current_edges(PRJ)] == [
            edge["edge_id"]]
        assert [row["edge_id"] for row in engine.graph.current_edges(
            PRJ, event_derived_only=True)] == [edge["edge_id"]]
        assert engine.graph.current_edges(OTHER) == []
        engine.close()

    def test_project_scoping_preserves_canonical_event_provenance(self, tmp_path):
        engine = _engine(tmp_path)
        event = engine.store.append_event(
            tenant_id=TEN, project_id=PRJ, source_type="test",
            idempotency_key="event-edge-1", payload={"value": 1},
            authority="repository_authoritative")
        node = engine.graph.put_node(
            entity_type="requirement", tenant_id=TEN, project_id=PRJ,
            data={"statement": "event-derived"}, event_id=event["event_id"])
        edge = engine.graph.put_edge(
            edge_type="supports", src_id=event["event_id"], dst_id=node.id,
            tenant_id=TEN, project_id=PRJ, event_id=event["event_id"])

        assert engine.graph.out_edges(event["event_id"])[0]["edge_id"] == \
            edge["edge_id"]
        assert engine.graph.current_edges(
            PRJ, event_derived_only=True)[0]["edge_id"] == edge["edge_id"]
        engine.close()

    def test_graph_writes_roll_back_with_store_transaction(self, tmp_path):
        store = Store(tmp_path / "tx.db")
        graph = __import__("causal_continuity_engine.graph", fromlist=["Graph"]).Graph(store)
        node_id = None
        with pytest.raises(RuntimeError, match="plant rollback"):
            with store.transaction():
                node = graph.put_node(
                    entity_type="task", tenant_id=TEN, project_id=PRJ,
                    data={"title": "must disappear"})
                node_id = node.id
                raise RuntimeError("plant rollback")
        assert node_id is not None
        with pytest.raises(KeyError):
            graph.get(node_id)
        store.close()


class TestAuthenticatedBoundedAPI:
    @pytest.mark.parametrize(
        "raw",
        [
            b'{"span_id":"first","span_id":"second"}',
            b'{"span_id":"trace-1","payload":{"confidence":NaN}}',
            b'{"span_id":"trace-1","payload":{"confidence":Infinity}}',
        ],
    )
    def test_api_rejects_ambiguous_or_nonfinite_json(self, tmp_path, raw):
        engine = _engine(tmp_path)
        server = _Server(engine, api_token=API_TOKEN)
        try:
            status, _ = server.request(
                "/v1/traces:ingest", body=raw, headers=_auth(), method="POST")
            assert status == 400
            assert engine.store.events(PRJ) == []
        finally:
            server.close()
            engine.close()

    def test_bearer_auth_and_project_binding(self, tmp_path):
        engine = _engine(tmp_path)
        server = _Server(engine, api_token=API_TOKEN)
        try:
            status, _ = server.request(f"/v1/projects/{PRJ}/assumptions")
            assert status == 401
            status, _ = server.request(
                f"/v1/projects/{PRJ}/assumptions", headers=_auth())
            assert status == 200
            status, _ = server.request(
                f"/v1/projects/{OTHER}/assumptions", headers=_auth())
            assert status == 403
        finally:
            server.close()
            engine.close()

    def test_api_reads_ignore_foreign_tenant_rows_with_same_project_label(
            self, tmp_path):
        engine = _engine(tmp_path)
        own_assumption = engine.graph.put_node(
            entity_type="assumption", tenant_id=TEN, project_id=PRJ,
            data={"statement": "owned"})
        engine.graph.put_node(
            entity_type="assumption", tenant_id="ten_foreign", project_id=PRJ,
            data={"statement": "foreign secret"})
        own_evaluation = engine.graph.put_node(
            entity_type="evaluation", tenant_id=TEN, project_id=PRJ,
            data={"kind": "owned"})
        engine.graph.put_node(
            entity_type="evaluation", tenant_id="ten_foreign", project_id=PRJ,
            data={"kind": "foreign secret"})
        server = _Server(engine, api_token=API_TOKEN)
        try:
            status, assumptions = server.request(
                f"/v1/projects/{PRJ}/assumptions", headers=_auth())
            assert status == 200
            assert [row["node_id"] for row in assumptions] == [
                own_assumption.id]

            status, evaluations = server.request(
                "/v1/evaluations", headers=_auth())
            assert status == 200
            assert [row["node_id"] for row in evaluations] == [
                own_evaluation.id]
        finally:
            server.close()
            engine.close()

    def test_attestation_hides_same_tenant_cross_project_node_existence(
            self, tmp_path):
        target_id = "req_scope_probe"
        base = {
            "intent_type": "task_complete",
            "intent_statement": "must not disclose target existence",
            "continuity": {"requirement_ids": [target_id]},
        }
        outcomes = []
        for foreign_exists in (False, True):
            root = tmp_path / ("foreign" if foreign_exists else "missing")
            root.mkdir()
            engine = _engine(root)
            engine.graph.put_node(
                entity_type="project", tenant_id=TEN, project_id=PRJ,
                node_id=PRJ, data={"name": "bound"})
            if foreign_exists:
                engine.graph.put_node(
                    entity_type="requirement", tenant_id=TEN,
                    project_id=OTHER, node_id=target_id,
                    data={"statement": "foreign secret"})
            server = _Server(engine, api_token=API_TOKEN)
            try:
                outcomes.append(server.request(
                    "/v1/actions:attest", body=base,
                    headers=_auth(), method="POST"))
            finally:
                server.close()
                engine.close()
        assert outcomes[0] == outcomes[1]
        assert outcomes[0][0] == 400
        assert OTHER not in json.dumps(outcomes[0][1])

    def test_local_session_claims_reject_foreign_and_missing_identically(
            self, tmp_path):
        session_id = "ses_scope_probe"
        outcomes = []
        for foreign_exists in (False, True):
            root = tmp_path / ("session-foreign" if foreign_exists
                               else "session-missing")
            root.mkdir()
            engine = _engine(root)
            engine.graph.put_node(
                entity_type="project", tenant_id=TEN, project_id=PRJ,
                node_id=PRJ, data={"name": "bound"})
            if foreign_exists:
                engine.graph.put_node(
                    entity_type="session", tenant_id=TEN, project_id=OTHER,
                    node_id=session_id, data={"model": "foreign"})
            server = _Server(engine, api_token=API_TOKEN)
            try:
                trace = server.request(
                    "/v1/traces:ingest",
                    body={"session_id": session_id, "span_id": "scope-probe",
                          "payload": {"message": "must not be stored"}},
                    headers=_auth(), method="POST")
                migration = server.request(
                    "/v1/migrations:prepare",
                    body={"session_id": session_id, "source_model": "source",
                          "target_adapter": "target"},
                    headers=_auth(), method="POST")
                outcomes.append((trace, migration))
            finally:
                server.close()
                engine.close()
        assert outcomes[0] == outcomes[1]
        for status, body in outcomes[0]:
            assert status == 400
            assert body == {"error": {
                "code": "invalid_request",
                "field": "session_id",
                "message": "session_id is not a session in the bound project",
            }}

    def test_request_body_is_bounded_before_json_decode(self, tmp_path):
        engine = _engine(tmp_path)
        server = _Server(engine, api_token=API_TOKEN, max_body_bytes=32)
        try:
            status, body = server.request(
                "/v1/traces:ingest", body=b"{" + b"x" * 64 + b"}",
                headers=_auth(), method="POST")
            assert status == 413
            assert "limit" in body["error"]["message"]
        finally:
            server.close()
            engine.close()

    def test_webhook_uses_headers_and_signature_over_the_raw_body(self, tmp_path):
        engine = _engine(tmp_path)
        engine.create_project(
            "repository-bound", project_id=PRJ, repository="o/r",
            repository_id=REPOSITORY_ID)
        secret = WEBHOOK_SECRET
        server = _Server(engine, api_token=API_TOKEN, webhook_secret=secret)
        payload = {
            "action": "opened",
            "issue": {
                "number": 1, "title": "T",
                "body": "We assume the queue is durable across restarts.",
                "state": "open", "labels": [],
                "created_at": "2026-08-04T12:00:00Z",
            },
            "repository": {"id": REPOSITORY_ID, "full_name": "o/r"},
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signed = {
            "Content-Type": "application/json",
            "X-GitHub-Event": "issues",
            "X-GitHub-Delivery": "signed-1",
            "X-Hub-Signature-256": "sha256=" + hmac.new(
                secret.encode(), raw, hashlib.sha256).hexdigest(),
        }
        try:
            status, report = server.request(
                "/v1/events:ingest", body=raw, headers=signed, method="POST")
            assert status == 202 and report["created"]
            unsigned = dict(signed)
            unsigned.pop("X-Hub-Signature-256")
            status, _ = server.request(
                "/v1/events:ingest", body=raw, headers=unsigned, method="POST")
            assert status == 403
            forged = {**signed, "X-Hub-Signature-256": "sha256=" + "0" * 64}
            status, _ = server.request(
                "/v1/events:ingest", body=b"not-json", headers=forged,
                method="POST")
            assert status == 403  # authenticate raw bytes before parsing them
        finally:
            server.close()
            engine.close()

    def test_github_delivery_is_bound_to_the_project_repository(self, tmp_path):
        engine = _engine(tmp_path)
        try:
            engine.create_project(
                "repository-bound", project_id=PRJ, repository="owner/right",
                repository_id=REPOSITORY_ID)
            with pytest.raises(PermissionError, match="repository"):
                engine.ingest_github(
                    PRJ, "issues", "cross-repository-delivery", {
                        "action": "opened",
                        "repository": {
                            "id": REPOSITORY_ID + 1,
                            "full_name": "owner/wrong"},
                        "issue": {
                            "number": 7,
                            "title": "foreign issue",
                            "body": "must not enter this project",
                            "author_association": "OWNER",
                            "state": "open", "labels": [],
                            "created_at": "2026-08-04T12:00:00Z",
                        },
                    })
            assert engine.store.events(project_id=PRJ) == []
            rejected = engine.store.audit_entries("webhook.rejected")
            assert rejected and "repository id mismatch" in rejected[-1]["detail"]
        finally:
            engine.close()

    def test_non_github_ingestion_rejects_an_unknown_project(self, tmp_path):
        engine = _engine(tmp_path)
        try:
            with pytest.raises(
                    PermissionError,
                    match="does not exist .* or belongs to another scope"):
                engine.ingest_agent_trace(
                    OTHER, session_id=None, span_id="foreign-span",
                    payload={"message": "must not create a foreign scope"})
            assert engine.store.events(project_id=OTHER) == []
        finally:
            engine.close()

    def test_verification_endpoint_rejects_commands_and_runs_policy_specs(self, tmp_path):
        engine = _engine(tmp_path)
        engine.create_project("boundary", project_id=PRJ)
        passed = shlex.join(
            [sys.executable, "-c", "raise SystemExit(0)"])
        failed = shlex.join(
            [sys.executable, "-c", "raise SystemExit(7)"])
        engine.policy.set_project_config(PRJ, {
            "max_autonomy_level": 3,
            "required_verifiers": [{
                "name": "policy-check", "command": passed,
                "expect_fail_command": failed,
            }],
            "require_proof_for": ["task_complete"],
            "min_evidence_grade": "C",
        })
        engine.policy.grant(
            project_id=PRJ, level=2, granted_by="operator",
            reason="permit the policy-owned verifier baseline")
        server = _Server(engine, api_token=API_TOKEN)
        marker = tmp_path / "caller-owned.txt"
        caller = f'cmd.exe /c echo owned>{marker}' if os.name == "nt" else \
            f'/usr/bin/touch {marker}'
        try:
            status, _ = server.request(
                "/v1/verifications:run",
                body={"verifiers": [{"name": "caller", "command": caller}]},
                headers=_auth(), method="POST")
            assert status == 400
            assert not marker.exists()

            status, proof = server.request(
                "/v1/verifications:run",
                body={"intent_type": "task_complete", "intent_statement": "check"},
                headers=_auth(), method="POST")
            assert status == 200
            assert proof["verification_summary"]["passed"] == ["policy-check"]
        finally:
            server.close()
            engine.close()


class TestLocalSecretBoundary:
    def test_init_separates_signing_key_from_metadata_and_verifier_snapshot(
            self, tmp_path):
        with contextlib.redirect_stdout(io.StringIO()):
            main(["--dir", str(tmp_path), "--json", "init"])
        meta = json.loads((tmp_path / ".cce" / "meta.json").read_text("utf-8"))
        assert "signing_key_hex" not in meta
        key_path = tmp_path / ".cce" / meta["signing_key_file"]
        assert key_path.is_file() and len(key_path.read_bytes()) == 32
        if os.name != "nt":
            assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

        command = (
            f'"{sys.executable}" -c "import pathlib,sys;'
            f"sys.exit(pathlib.Path('.cce').exists())\"")
        outcome = VerifierRunner(None, tmp_path).run(VerifierSpec(
            name="snapshot-boundary", command=command, pinned=True))
        assert outcome.result == "passed", outcome.details

    def test_custom_location_store_is_not_in_verifier_snapshot(self, tmp_path):
        engine = _engine(tmp_path)
        command = (
            f'"{sys.executable}" -c "from pathlib import Path;'
            "Path('cce.db').write_bytes(b'forged')\"")
        outcome = engine.verifier_runner.run(VerifierSpec(
            name="store-boundary", command=command, pinned=True))

        assert outcome.result == "passed", outcome.details
        assert (tmp_path / "cce.db").read_bytes().startswith(b"SQLite format 3\x00")
        assert engine.graph.current(PRJ) == []
        engine.close()

    def test_relative_workdir_still_excludes_custom_store(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        store = Store("relative.db")
        command = (
            f'"{sys.executable}" -c "from pathlib import Path;'
            "Path('relative.db').write_bytes(b'forged')\"")
        outcome = VerifierRunner(store, ".").run(VerifierSpec(
            name="relative-store-boundary", command=command, pinned=True))

        assert outcome.result == "passed", outcome.details
        assert (tmp_path / "relative.db").read_bytes().startswith(
            b"SQLite format 3\x00")
        store.close()

    @pytest.mark.skipif(os.name != "nt", reason="Windows executable search order")
    def test_pinned_verifier_cannot_resolve_executable_from_subject(
            self, tmp_path, monkeypatch):
        system_root = Path(os.environ["SYSTEMROOT"])
        shutil.copy2(system_root / "System32" / "cmd.exe", tmp_path / "policy-tool.exe")
        monkeypatch.chdir(tmp_path)
        outcome = VerifierRunner(None, tmp_path).run(VerifierSpec(
            name="no-subject-shadow", command="policy-tool.exe /c exit 0",
            pinned=True))

        assert outcome.result == "inconclusive"
        assert "absolute path" in outcome.details
