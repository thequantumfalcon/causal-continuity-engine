"""Mechanical and adversarial contracts for the local HTTP boundary."""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import math
import socket
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from causal_continuity_engine.api import (
    API_ROUTES,
    BoundedThreadingHTTPServer,
    make_handler,
    render_api_document,
    serve,
)
from causal_continuity_engine.cli import _tcp_port
from causal_continuity_engine.core import Signer
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.github import SUBSCRIBED_EVENTS, normalize

TENANT = "ten_api_contract"
PROJECT = "prj_api_contract"
REPOSITORY_ID = 424242
INSTALLATION_ID = 9191
API_TOKEN = "contract-api-token-0123456789abcdef"
WEBHOOK_SECRET = "contract-webhook-secret-0123456789abcdef"
_UNSET = object()


class LocalAPI:
    def __init__(
            self, engine, *, project_id=PROJECT, webhook_secret=None,
            **options):
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                engine, project_id, api_token=API_TOKEN,
                webhook_secret=webhook_secret, **options))
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        body=_UNSET,
        *,
        raw: bytes | None = None,
        headers: dict | None = None,
        authenticated: bool = True,
        content_type: str | None = "application/json",
    ):
        data = raw
        if body is not _UNSET:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request_headers = dict(headers or {})
        if authenticated:
            request_headers.setdefault("Authorization", f"Bearer {API_TOKEN}")
        if content_type is not None:
            request_headers.setdefault("Content-Type", content_type)
        request = urllib.request.Request(
            self.base + path, data=data, headers=request_headers, method=method)
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as exc:
            response = exc
        try:
            payload = response.read()
            parsed = json.loads(payload) if payload else None
            return response.status, parsed, dict(response.headers.items())
        finally:
            response.close()


@pytest.fixture
def api(tmp_path: Path):
    engine = Engine(
        tmp_path / "cce.db", tenant_id=TENANT,
        signer=Signer.generate("api-contract"), workdir=tmp_path)
    engine.create_project(
        "api contract", project_id=PROJECT,
        repository="owner/repo", repository_id=REPOSITORY_ID)
    server = LocalAPI(engine)
    yield server, engine
    server.close()
    engine.close()


def _error(response: tuple) -> dict:
    return response[1]["error"]


def _signed_headers(secret: str, raw: bytes, event: str, delivery: str) -> dict:
    return {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": "sha256=" + hmac.new(
            secret.encode(), raw, hashlib.sha256).hexdigest(),
    }


def _event_count(engine: Engine) -> int:
    return engine.store._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def _raw_exchange(server: LocalAPI, request: bytes) -> bytes:
    with socket.create_connection(
            ("127.0.0.1", server.httpd.server_port), timeout=2) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(65_536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def test_route_registry_is_complete_unique_and_documentation_is_current():
    identities = [(route.method, route.template) for route in API_ROUTES]
    assert len(API_ROUTES) == 14
    assert len(identities) == len(set(identities))
    expected = render_api_document()
    assert Path("docs/API.md").read_text(encoding="utf-8") == expected
    for route in API_ROUTES:
        assert f"| {route.method} | `{route.template}` |" in expected


def test_non_ascii_bearer_token_is_stable_401_without_mutation(api):
    server, engine = api
    before = _event_count(engine)
    response = server.request(
        "GET", f"/v1/projects/{PROJECT}/assumptions",
        headers={"Authorization": "Bearer " + "é" * 32},
        authenticated=False)
    assert response[0] == 401
    assert _error(response)["code"] == "unauthorized"
    assert response[2]["WWW-Authenticate"] == "Bearer"
    assert _event_count(engine) == before


def test_non_ascii_webhook_signature_is_stable_403_without_mutation(
        tmp_path):
    engine = Engine(
        tmp_path / "bad-signature.db", tenant_id=TENANT,
        signer=Signer.generate("bad-signature"), workdir=tmp_path)
    engine.create_project(
        "bad signature", project_id=PROJECT,
        repository="owner/repo", repository_id=REPOSITORY_ID)
    server = LocalAPI(engine, webhook_secret=WEBHOOK_SECRET)
    raw = json.dumps({
        "repository": {"id": REPOSITORY_ID, "full_name": "owner/repo"},
        "after": "a" * 40,
    }).encode("utf-8")
    try:
        response = server.request(
            "POST", "/v1/events:ingest", raw=raw, authenticated=False,
            headers={
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "bad-signature",
                "X-Hub-Signature-256": "sha256=" + "é" * 64,
            })
        assert response[0] == 403
        assert _error(response)["code"] == "forbidden"
        assert _event_count(engine) == 0
    finally:
        server.close()
        engine.close()


def test_zero_length_post_is_invalid_json(api):
    server, engine = api
    before = _event_count(engine)
    response = server.request(
        "POST", "/v1/traces:ingest", raw=b"")
    assert response[0] == 400
    assert _error(response) == {
        "code": "invalid_json",
        "message": "request body must be a valid JSON object",
        "field": "body",
    }
    assert _event_count(engine) == before


@pytest.mark.parametrize(
    "framing",
    [
        b"Content-Length: 2\r\nContent-Length: 9\r\n",
        b"Transfer-Encoding:\r\nTransfer-Encoding: chunked\r\n",
    ],
    ids=["duplicate-content-length", "any-transfer-encoding"],
)
def test_ambiguous_http_framing_closes_connection_without_mutation(
        api, framing):
    server, engine = api
    before = _event_count(engine)
    request = (
        b"POST /v1/traces:ingest HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        + f"Authorization: Bearer {API_TOKEN}\r\n".encode("ascii")
        + b"Content-Type: application/json\r\n"
        + framing
        + b"Connection: keep-alive\r\n\r\n{}"
        + b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    )
    response = _raw_exchange(server, request)
    assert response.startswith(b"HTTP/1.0 400 ")
    assert response.count(b"HTTP/1.") == 1
    assert b'"code":"invalid_request"' in response
    assert _event_count(engine) == before


def test_extreme_content_length_is_stable_413_and_closes_without_mutation(api):
    server, engine = api
    before = _event_count(engine)
    request = (
        b"POST /v1/traces:ingest HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        + f"Authorization: Bearer {API_TOKEN}\r\n".encode("ascii")
        + b"Content-Type: application/json\r\nContent-Length: "
        + b"9" * 5000
        + b"\r\nConnection: keep-alive\r\n\r\n"
        + b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    )
    response = _raw_exchange(server, request)
    assert response.startswith(b"HTTP/1.0 413 ")
    assert response.count(b"HTTP/1.") == 1
    assert b'"code":"request_too_large"' in response
    assert _event_count(engine) == before


def test_duplicate_authorization_header_is_stable_400_without_mutation(api):
    server, engine = api
    request = (
        b"POST /v1/traces:ingest HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        + f"Authorization: Bearer {API_TOKEN}\r\n".encode("ascii")
        + f"Authorization: Bearer {API_TOKEN}\r\n".encode("ascii")
        + b"Content-Type: application/json\r\n"
        + b"Content-Length: 2\r\n\r\n{}"
    )
    response = _raw_exchange(server, request)
    assert response.startswith(b"HTTP/1.0 400 ")
    assert b'"field":"Authorization"' in response
    assert _event_count(engine) == 0


@pytest.mark.parametrize(
    ("path", "body", "field"),
    [
        (f"/v1/projects/{PROJECT}/resume-packets:compose",
         {"token_budget": None}, "token_budget"),
        (f"/v1/projects/{PROJECT}/resume-packets:compose",
         {"token_budget": []}, "token_budget"),
        (f"/v1/projects/{PROJECT}/resume-packets:compose",
         {"token_budget": True}, "token_budget"),
        (f"/v1/projects/{PROJECT}/resume-packets:compose",
         {"token_budget": 1.5}, "token_budget"),
        (f"/v1/projects/{PROJECT}/resume-packets:compose",
         {"target": ["wrong"]}, "target"),
        ("/v1/traces:ingest", {"span_id": "s", "payload": []}, "payload"),
        ("/v1/traces:ingest", {"span_id": "", "payload": {}}, "span_id"),
        ("/v1/actions:attest", {
            "intent_type": "task_complete", "verifications": "bad"},
         "verifications"),
        ("/v1/actions:attest", {
            "intent_type": "task_complete", "continuity": []}, "continuity"),
        ("/v1/migrations:prepare", {"source_model": ""}, "source_model"),
        ("/v1/migrations:validate", {"capsule": []}, "capsule"),
        ("/v1/replays", {
            "from_event_id": "evt_missing", "captured_inputs": []},
         "captured_inputs"),
        (f"/v1/projects/{PROJECT}/continuity-receipts:verify",
         {"receipt": []}, "receipt"),
    ],
)
def test_malformed_request_field_types_are_stable_400(api, path, body, field):
    server, _ = api
    response = server.request("POST", path, body)
    assert response[0] == 400
    error = _error(response)
    assert error["code"] in {"invalid_request", "missing_field"}
    assert error["field"] == field
    assert "ValueError" not in error["message"]
    assert "KeyError" not in error["message"]


def test_invalid_query_field_is_stable_400(api):
    server, _ = api
    response = server.request(
        "GET", f"/v1/projects/{PROJECT}/assumptions?status=activ")
    assert response[0] == 400
    assert _error(response)["field"] == "status"


@pytest.mark.parametrize(
    "segment", ["prj%2Fshadow", "prj%252Fshadow", "prj%ZZ", "prj%00bad"],
    ids=["encoded-slash", "double-encoded", "malformed-percent", "control"],
)
def test_encoded_or_malformed_project_segments_are_stable_400(api, segment):
    server, _ = api
    response = server.request(
        "GET", f"/v1/projects/{segment}/assumptions")
    assert response[0] == 400
    assert _error(response)["code"] == "invalid_identifier"
    assert _error(response)["field"] == "project_id"


@pytest.mark.parametrize(
    "segment", ["asm%2Fshadow", "asm%252Fshadow", "asm%ZZ"],
    ids=["encoded-slash", "double-encoded", "malformed-percent"],
)
def test_encoded_or_malformed_node_segments_are_stable_400(api, segment):
    server, _ = api
    response = server.request(
        "POST", f"/v1/assumptions/{segment}:resolve", {"action": "accept"})
    assert response[0] == 400
    assert _error(response)["code"] == "invalid_identifier"
    assert _error(response)["field"] == "assumption_id"


def test_literal_slash_does_not_alias_a_resource_segment(api):
    server, _ = api
    response = server.request(
        "GET", "/v1/projects/prj/shadow/assumptions")
    assert response[0] == 404
    assert _error(response)["code"] == "not_found"


def test_custom_uri_safe_project_and_node_ids_are_addressable(tmp_path):
    tenant_id = "Tenant-1._~"
    project_id = "Project-1._~"
    assumption_id = "Assumption-1._~"
    engine = Engine(
        tmp_path / "addressable.db", tenant_id=tenant_id,
        signer=Signer.generate("addressable"), workdir=tmp_path)
    engine.create_project("addressable", project_id=project_id)
    engine.graph.put_node(
        entity_type="assumption", tenant_id=tenant_id,
        project_id=project_id, node_id=assumption_id, status="active",
        data={"statement": "the identifier remains one URI segment"})
    server = LocalAPI(engine, project_id=project_id)
    try:
        listed = server.request(
            "GET", f"/v1/projects/{project_id}/assumptions")
        assert listed[0] == 200
        assert [item["node_id"] for item in listed[1]] == [assumption_id]
        resolved = server.request(
            "POST", f"/v1/assumptions/{assumption_id}:resolve",
            {"action": "accept"})
        assert resolved[0] == 200
        assert resolved[1]["node_id"] == assumption_id
    finally:
        server.close()
        engine.close()


@pytest.mark.parametrize(
    "result", [[], {}, None, 7],
    ids=["array", "object", "null", "number"],
)
def test_attestation_enum_types_are_stable_400(api, result):
    server, _ = api
    response = server.request("POST", "/v1/actions:attest", {
        "intent_type": "task_complete",
        "verifications": [{"verifier": "tests", "result": result}],
    })
    assert response[0] == 400
    assert _error(response) == {
        "code": "invalid_request",
        "field": "verifications[0].result",
        "message": "verifications[0].result is not recognized",
    }


@pytest.mark.parametrize(
    "status", [[], {}], ids=["array", "object"])
def test_migration_capsule_enum_types_are_stable_400(api, status):
    server, engine = api
    engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"statement": "the queue is durable"})
    prepared = server.request(
        "POST", "/v1/migrations:prepare", {"source_model": "source"})
    assert prepared[0] == 200
    capsule = prepared[1]
    capsule["observable_state"]["active_assumptions"][0]["status"] = status

    response = server.request(
        "POST", "/v1/migrations:validate", {"capsule": capsule})
    assert response[0] == 400
    error = _error(response)
    assert error["code"] == "invalid_capsule"
    assert error["field"] == "capsule"
    assert "internal" not in error["message"].lower()


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/v1/health?verbose=true", _UNSET),
        ("POST", "/v1/traces:ingest?mode=fast", {"span_id": "s"}),
    ],
)
def test_undeclared_query_parameters_are_stable_400(api, method, path, body):
    server, _ = api
    response = server.request(method, path, body)
    assert response[0] == 400
    assert _error(response) == {
        "code": "unknown_field",
        "field": "query",
        "message": "query parameters are not supported for this route",
    }


@pytest.mark.parametrize(
    ("method", "path", "allow"),
    [
        ("GET", "/v1/actions:attest", "POST"),
        ("POST", "/v1/health", "GET"),
        ("PUT", "/v1/health", "GET"),
        ("OPTIONS", "/v1/health", "GET"),
        ("HEAD", "/v1/health", "GET"),
    ],
)
def test_known_wrong_methods_are_uniform_json_405(api, method, path, allow):
    server, _ = api
    body = {} if method == "POST" else _UNSET
    status, payload, headers = server.request(method, path, body)
    assert status == 405
    assert headers["Allow"] == allow
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "Python" not in headers["Server"]
    if method == "HEAD":
        assert payload is None
    else:
        assert payload["error"]["code"] == "method_not_allowed"


def test_unknown_path_and_unknown_method_stay_json(api):
    server, _ = api
    status, body, headers = server.request("PUT", "/v1/nope")
    assert status == 404
    assert body["error"]["code"] == "not_found"
    status, body, headers = server.request("BREW", "/v1/health")
    assert status == 501
    assert body["error"]["code"] == "unsupported_method"
    assert headers["Content-Type"] == "application/json; charset=utf-8"


def test_authentication_challenge_and_media_type_contract(api):
    server, _ = api
    status, body, headers = server.request(
        "GET", f"/v1/projects/{PROJECT}/assumptions", authenticated=False)
    assert status == 401
    assert headers["WWW-Authenticate"] == "Bearer"
    assert body["error"]["code"] == "unauthorized"

    status, body, _ = server.request(
        "POST", "/v1/traces:ingest", {"span_id": "s"},
        content_type="text/plain")
    assert status == 415
    assert body["error"] == {
        "code": "unsupported_media_type",
        "field": "Content-Type",
        "message": "Content-Type must be application/json",
    }


def test_trace_payload_mismatch_is_409_and_audited(api):
    server, engine = api
    first = server.request(
        "POST", "/v1/traces:ingest",
        {"span_id": "same", "payload": {"message": "one"}})
    conflict = server.request(
        "POST", "/v1/traces:ingest",
        {"span_id": "same", "payload": {"message": "two"}})
    assert first[0] == 202
    assert conflict[0] == 409
    assert _error(conflict)["code"] == "idempotency_conflict"
    assert engine.store.payload_mismatches()


def test_scoped_missing_assumption_is_explicit_404(api):
    server, _ = api
    response = server.request(
        "POST", "/v1/assumptions/asm_missing:resolve", {"action": "accept"})
    assert response[0] == 404
    assert _error(response) == {
        "code": "not_found", "message": "assumption was not found"}


def test_invalidation_resolution_is_bound_to_path_resource(api):
    server, engine = api
    target = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        data={"statement": "target"}, status="active")
    other = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        data={"statement": "other"}, status="active")
    invalidation = engine.invalidation.fire(
        tenant_id=TENANT, project_id=PROJECT, target_node_id=target.id,
        trigger_type="contradictory_evidence", reason="contract test")
    request = {
        "invalidation_id": invalidation["node_id"],
        "mode": "narrowed_scope",
        "narrowed_scope": {"scope": "target only"},
    }

    mismatch = server.request(
        "POST", f"/v1/assumptions/{other.id}:resolve", request)
    assert mismatch[0] == 400
    assert _error(mismatch) == {
        "code": "resource_mismatch",
        "field": "invalidation_id",
        "message": "invalidation_id does not target or affect assumption_id",
    }
    assert engine.graph.get(invalidation["node_id"])["status"] == "open"

    matched = server.request(
        "POST", f"/v1/assumptions/{target.id}:resolve", request)
    assert matched[0] == 200
    assert matched[1] == {
        "invalidation": invalidation["node_id"], "status": "resolved"}


@pytest.mark.parametrize(
    "exception",
    [
        KeyError("internal_column"),
        ValueError("private"),
        PermissionError("private filesystem path"),
    ],
)
def test_internal_builtin_exceptions_are_generic_500(api, monkeypatch, exception):
    server, engine = api

    def fail(*args, **kwargs):
        raise exception

    monkeypatch.setattr(engine, "resume_packet", fail)
    response = server.request(
        "POST", f"/v1/projects/{PROJECT}/resume-packets:compose", {})
    assert response[0] == 500
    assert _error(response) == {
        "code": "internal_error", "message": "internal server error"}
    assert "internal_column" not in json.dumps(response[1])
    assert "private" not in json.dumps(response[1])


def test_nonfinite_or_unknown_response_never_becomes_success(api, monkeypatch):
    server, engine = api
    monkeypatch.setattr(
        engine, "resume_packet", lambda *args, **kwargs: {"value": math.nan})
    response = server.request(
        "POST", f"/v1/projects/{PROJECT}/resume-packets:compose", {})
    assert response[0] == 500
    assert _error(response)["code"] == "internal_error"


def test_removed_latest_resume_get_is_404_and_never_mutates_state(api):
    server, engine = api
    before = engine.store._conn.total_changes
    response = server.request(
        "GET", f"/v1/projects/{PROJECT}/resume-packets/latest")
    assert response[0] == 404
    assert _error(response)["code"] == "not_found"
    assert engine.store._conn.total_changes == before


def test_signed_ping_is_bound_and_has_no_state_mutation(tmp_path: Path):
    engine = Engine(
        tmp_path / "ping.db", tenant_id=TENANT,
        signer=Signer.generate("ping"), workdir=tmp_path)
    engine.create_project(
        "ping", project_id=PROJECT, repository="owner/repo",
        repository_id=REPOSITORY_ID,
        github_installation_id=INSTALLATION_ID)
    server = LocalAPI(engine, webhook_secret=WEBHOOK_SECRET)
    try:
        payload = {
            "hook": {"type": "Repository"},
            "hook_id": 123,
            "zen": "Approachable is better than simple.",
            "repository": {"id": REPOSITORY_ID, "full_name": "owner/repo"},
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        before = (engine.store.events(PROJECT), engine.store.audit_entries())
        status, body, _ = server.request(
            "POST", "/v1/events:ingest", raw=raw,
            headers=_signed_headers(WEBHOOK_SECRET, raw, "ping", "ping-1"),
            authenticated=False)
        after = (engine.store.events(PROJECT), engine.store.audit_entries())
        assert status == 200
        assert body == {"status": "ok", "event": "ping"}
        assert before == after

        payload["installation"] = {"id": INSTALLATION_ID + 1}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        status, body, _ = server.request(
            "POST", "/v1/events:ingest", raw=raw,
            headers=_signed_headers(WEBHOOK_SECRET, raw, "ping", "ping-2"),
            authenticated=False)
        assert status == 403
        assert body["error"]["code"] == "forbidden"
    finally:
        server.close()
        engine.close()


def test_authenticated_unsupported_webhook_event_is_422(tmp_path: Path):
    engine = Engine(
        tmp_path / "unsupported.db", tenant_id=TENANT,
        signer=Signer.generate("unsupported"), workdir=tmp_path)
    engine.create_project(
        "unsupported", project_id=PROJECT,
        repository="owner/repo", repository_id=REPOSITORY_ID)
    server = LocalAPI(engine, webhook_secret=WEBHOOK_SECRET)
    try:
        raw = json.dumps({
            "repository": {"id": REPOSITORY_ID, "full_name": "owner/repo"},
        }).encode()
        response = server.request(
            "POST", "/v1/events:ingest", raw=raw,
            headers=_signed_headers(WEBHOOK_SECRET, raw, "unknown", "unknown-1"),
            authenticated=False)
        assert response[0] == 422
        assert _error(response)["code"] == "unsupported_webhook_event"
        assert engine.store.events(PROJECT) == []
    finally:
        server.close()
        engine.close()


def _valid_webhook_payload(event_name: str) -> dict:
    timestamp = "2026-08-04T12:00:00Z"
    repository = {"id": REPOSITORY_ID, "full_name": "owner/repo"}
    installation = {"id": INSTALLATION_ID}
    common = {
        "action": "completed", "repository": repository,
        "installation": installation,
    }
    payloads = {
        "push": {
            "ref": "refs/heads/main", "before": "a" * 40,
            "after": "b" * 40, "forced": False, "deleted": False,
            "created": False, "commits": [],
            "head_commit": {"timestamp": timestamp},
            "repository": repository, "installation": installation,
        },
        "pull_request": {**common, "pull_request": {
            "number": 1, "title": "PR", "body": "body", "state": "open",
            "merged": False, "updated_at": timestamp,
            "created_at": timestamp, "base": {"sha": "a" * 40},
            "head": {"sha": "b" * 40},
        }},
        "pull_request_review": {**common, "pull_request": {"number": 1},
                                "review": {
                                    "id": 2, "state": "approved",
                                    "submitted_at": timestamp, "body": "ok",
                                }},
        "issues": {**common, "issue": {
            "number": 3, "title": "Issue", "body": "body",
            "state": "open", "created_at": timestamp,
            "updated_at": timestamp, "labels": [],
        }},
        "issue_comment": {**common, "issue": {"number": 3}, "comment": {
            "id": 4, "body": "comment", "created_at": timestamp,
        }},
        "check_run": {**common, "check_run": {
            "id": 5, "name": "ci", "status": "completed",
            "conclusion": "success", "head_sha": "b" * 40,
            "completed_at": timestamp,
            "app": {"id": 6, "slug": "actions"},
        }},
        "check_suite": {**common, "check_suite": {
            "id": 7, "status": "completed", "conclusion": "success",
            "head_sha": "b" * 40, "updated_at": timestamp,
            "app": {"id": 6, "slug": "actions"},
        }},
        "workflow_run": {**common, "workflow_run": {
            "id": 8, "workflow_id": 9, "name": "ci",
            "status": "completed", "conclusion": "success",
            "head_sha": "b" * 40, "path": ".github/workflows/ci.yml",
            "updated_at": timestamp,
        }},
        "installation": {
            "action": "created", "installation": {"id": INSTALLATION_ID},
        },
        "installation_repositories": {
            "action": "added", "installation": {"id": INSTALLATION_ID},
            "repositories_added": [repository], "repositories_removed": [],
        },
        "repository": {**common, "action": "renamed", "changes": {
            "repository": {"name": {"from": "old-name"}},
        }},
        "release": {**common, "action": "published", "release": {
            "id": 10, "tag_name": "v1.0.0", "body": "notes",
            "published_at": timestamp,
        }},
    }
    assert set(payloads) == SUBSCRIBED_EVENTS
    return copy.deepcopy(payloads[event_name])


def _replace_nested(payload: dict, route: tuple[str, ...], value) -> None:
    cursor = payload
    for field in route[:-1]:
        cursor = cursor[field]
    cursor[route[-1]] = value


@pytest.mark.parametrize("delivery_id", ["bad\ndelivery", "d" * 129])
def test_bearer_ingest_rejects_malformed_delivery_as_400_without_write(
        api, delivery_id):
    server, engine = api
    before = engine.store._conn.total_changes
    response = server.request(
        "POST", "/v1/events:ingest",
        body={
            "project_id": PROJECT,
            "event_name": "push",
            "delivery_id": delivery_id,
            "payload": _valid_webhook_payload("push"),
        })

    assert response[0] == 400
    assert _error(response)["code"] == "invalid_identifier"
    assert _error(response)["field"] == "delivery_id"
    assert engine.store._conn.total_changes == before
    assert engine.store.events(PROJECT) == []


@pytest.mark.parametrize("delivery_id", ["bad\ndelivery", "d" * 129])
def test_direct_github_ingest_rejects_malformed_delivery_before_any_write(
        tmp_path, delivery_id):
    payload = _valid_webhook_payload("push")
    engine = Engine(
        tmp_path / "delivery-direct.db", tenant_id=TENANT,
        signer=Signer.generate("delivery-direct"), workdir=tmp_path)
    engine.create_project(
        "delivery direct", project_id=PROJECT,
        repository="owner/repo", repository_id=REPOSITORY_ID)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="delivery_id.*ASCII URI-unreserved"):
            engine.ingest_github(PROJECT, "push", delivery_id, payload)
        with pytest.raises(ValueError, match="delivery_id.*ASCII URI-unreserved"):
            normalize("push", delivery_id, payload)
        assert engine.store._conn.total_changes == before
        assert engine.store.events(PROJECT) == []
    finally:
        engine.close()


@pytest.mark.parametrize("project_id", ["../bad\nproject", "p" * 129])
def test_direct_github_ingest_rejects_malformed_project_before_any_write(
        tmp_path, project_id):
    engine = Engine(
        tmp_path / "project-direct.db", tenant_id=TENANT,
        signer=Signer.generate("project-direct"), workdir=tmp_path)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="project_id.*ASCII URI-unreserved"):
            engine.ingest_github(
                project_id, "push", "valid-delivery",
                _valid_webhook_payload("push"))
        assert engine.store._conn.total_changes == before
        assert _event_count(engine) == 0
    finally:
        engine.close()


@pytest.mark.parametrize("capture_mode", ["not-a-mode", [], None])
def test_create_project_rejects_invalid_capture_mode_before_any_write(
        tmp_path, capture_mode):
    engine = Engine(
        tmp_path / "capture-mode.db", tenant_id=TENANT,
        signer=Signer.generate("capture-mode"), workdir=tmp_path)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="unknown capture mode"):
            engine.create_project(
                "invalid capture", project_id=PROJECT,
                capture_mode=capture_mode)
        assert engine.store._conn.total_changes == before
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes").fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("name", "kwargs", "message"),
    [
        (None, {}, "project name"),
        ("", {}, "project name"),
        (7, {}, "project name"),
        ([], {}, "project name"),
        ({}, {}, "project name"),
        ("bad\nname", {}, "control character"),
        ("n" * 257, {}, "at most 256"),
        ("valid", {"repository": 7}, "repository"),
        ("valid", {"repository": ""}, "repository"),
        ("valid", {"repository": "owner/bad\nrepo"}, "repository"),
        ("valid", {"repository": "owner/" + "r" * 101}, "repository"),
        ("valid", {"project_id": ""}, "project_id"),
        ("valid", {"project_id": 0}, "project_id"),
        ("valid", {"project_id": False}, "project_id"),
        ("valid", {"project_id": []}, "project_id"),
        ("valid", {"config": []}, "project policy"),
        ("valid", {"config": ""}, "project policy"),
        ("valid", {"config": False}, "project policy"),
        ("valid", {"config": 0}, "project policy"),
        ("valid", {"github_installation_id": 42}, "requires repository_id"),
    ],
)
def test_create_project_rejects_malformed_metadata_before_any_write(
        tmp_path, name, kwargs, message):
    engine = Engine(
        tmp_path / "project-metadata.db", tenant_id=TENANT,
        signer=Signer.generate("project-metadata"), workdir=tmp_path)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match=message):
            engine.create_project(name, **kwargs)
        assert engine.store._conn.total_changes == before
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM nodes").fetchone()[0] == 0
        assert engine.store._conn.execute(
            "SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0
    finally:
        engine.close()


@pytest.mark.parametrize("repository", [7, "", "owner/bad\nrepo", "./repo"])
def test_repository_rebinding_rejects_malformed_name_before_any_write(
        tmp_path, repository):
    engine = Engine(
        tmp_path / "repository-binding.db", tenant_id=TENANT,
        signer=Signer.generate("repository-binding"), workdir=tmp_path)
    project = engine.create_project("binding", project_id=PROJECT)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="repository"):
            engine.bind_github_repository(
                PROJECT, repository_id=REPOSITORY_ID,
                repository=repository)
        assert engine.store._conn.total_changes == before
        assert engine.graph.get(PROJECT) == project
    finally:
        engine.close()


@pytest.mark.parametrize("event_name", sorted(SUBSCRIBED_EVENTS))
def test_every_subscribed_webhook_has_a_concrete_identity_and_returns_202(
        tmp_path, event_name):
    payload = _valid_webhook_payload(event_name)
    envelope = normalize(event_name, f"direct-{event_name}", payload)
    assert isinstance(envelope["source_id"], str)
    assert envelope["source_id"] and "None" not in envelope["source_id"]

    engine = Engine(
        tmp_path / "valid.db", tenant_id=TENANT,
        signer=Signer.generate(f"valid-{event_name}"), workdir=tmp_path)
    engine.create_project(
        "valid webhook", project_id=PROJECT,
        repository="owner/repo", repository_id=REPOSITORY_ID,
        github_installation_id=INSTALLATION_ID)
    server = LocalAPI(engine, webhook_secret=WEBHOOK_SECRET)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    try:
        response = server.request(
            "POST", "/v1/events:ingest", raw=raw,
            headers=_signed_headers(
                WEBHOOK_SECRET, raw, event_name, f"valid-{event_name}"),
            authenticated=False)
        assert response[0] == 202, response[1]
        assert len(engine.store.events(PROJECT)) == 1
    finally:
        server.close()
        engine.close()


_IDENTITY_MUTATIONS = [
    ("push", ("after",), {}),
    ("pull_request", ("pull_request", "number"), {}),
    ("pull_request_review", ("review", "id"), {}),
    ("issues", ("issue",), None),
    ("issue_comment", ("comment", "id"), []),
    ("check_run", ("check_run", "id"), {}),
    ("check_suite", ("check_suite", "id"), []),
    ("workflow_run", ("workflow_run", "id"), "wrong"),
    ("installation", ("installation", "id"), {}),
    ("installation", ("installation",), {}),
    ("installation_repositories", ("repositories_added",), []),
    ("installation_repositories", ("installation",), {}),
    ("repository", ("repository", "id"), {}),
    ("repository", ("repository",), {}),
    ("repository", ("changes", "repository", "name"), None),
    ("release", ("release", "id"), {}),
]


_TIMESTAMP_MUTATIONS = [
    ("push", ("head_commit", "timestamp")),
    ("pull_request", ("pull_request", "updated_at")),
    ("pull_request_review", ("review", "submitted_at")),
    ("issues", ("issue", "created_at")),
    ("issue_comment", ("comment", "created_at")),
    ("check_run", ("check_run", "completed_at")),
    ("check_suite", ("check_suite", "updated_at")),
    ("workflow_run", ("workflow_run", "updated_at")),
    ("release", ("release", "published_at")),
]


@pytest.mark.parametrize(
    ("event_name", "route", "malformed"),
    _IDENTITY_MUTATIONS + [
        (event_name, route, "not-a-time")
        for event_name, route in _TIMESTAMP_MUTATIONS
    ],
)
def test_malformed_signed_webhook_is_400_before_persistence(
        tmp_path, event_name, route, malformed):
    payload = _valid_webhook_payload(event_name)
    _replace_nested(payload, route, malformed)
    engine = Engine(
        tmp_path / "malformed.db", tenant_id=TENANT,
        signer=Signer.generate(f"malformed-{event_name}"), workdir=tmp_path)
    engine.create_project(
        "malformed webhook", project_id=PROJECT,
        repository="owner/repo", repository_id=REPOSITORY_ID,
        github_installation_id=INSTALLATION_ID)
    server = LocalAPI(engine, webhook_secret=WEBHOOK_SECRET)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    try:
        response = server.request(
            "POST", "/v1/events:ingest", raw=raw,
            headers=_signed_headers(
                WEBHOOK_SECRET, raw, event_name, f"bad-{event_name}"),
            authenticated=False)
        assert response[0] == 400
        assert _error(response)["code"] == "invalid_webhook_payload"
        assert _error(response)["field"] == "body"
        assert engine.store.events(PROJECT) == []
    finally:
        server.close()
        engine.close()


def test_empty_signed_delivery_header_is_400_not_unsupported_event(tmp_path):
    payload = _valid_webhook_payload("push")
    engine = Engine(
        tmp_path / "delivery.db", tenant_id=TENANT,
        signer=Signer.generate("delivery"), workdir=tmp_path)
    engine.create_project(
        "delivery", project_id=PROJECT,
        repository="owner/repo", repository_id=REPOSITORY_ID)
    server = LocalAPI(engine, webhook_secret=WEBHOOK_SECRET)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    try:
        response = server.request(
            "POST", "/v1/events:ingest", raw=raw,
            headers=_signed_headers(WEBHOOK_SECRET, raw, "push", ""),
            authenticated=False)
        assert response[0] == 400
        assert _error(response)["field"] == "X-GitHub-Delivery"
        assert engine.store.events(PROJECT) == []
    finally:
        server.close()
        engine.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"project_id": ""},
        {"api_token": "short"},
        {"api_token": 7},
        {"api_token": "é" * 32},
        {"webhook_secret": "short"},
        {"webhook_secret": 7},
        {"max_body_bytes": True},
        {"max_body_bytes": math.nan},
        {"max_body_bytes": 0},
        {"max_body_bytes": 25 * 1024 * 1024 + 1},
        {"request_timeout_seconds": True},
        {"request_timeout_seconds": math.nan},
        {"request_timeout_seconds": 0},
        {"request_timeout_seconds": 301},
    ],
)
def test_invalid_handler_configuration_fails_before_use(kwargs):
    options = {
        "project_id": PROJECT,
        "api_token": API_TOKEN,
        "webhook_secret": None,
        "max_body_bytes": 1024,
        "request_timeout_seconds": 15,
    }
    options.update(kwargs)
    project_id = options.pop("project_id")
    with pytest.raises(ValueError):
        make_handler(object(), project_id, **options)


@pytest.mark.parametrize("value", [True, 0, 65, 1.5, math.nan, math.inf])
def test_invalid_worker_configuration_fails_before_bind(value):
    with pytest.raises(ValueError):
        BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), BaseHTTPRequestHandler, max_workers=value)


@pytest.mark.parametrize("value", ["0", "-1", "65536", "70000", "bad"])
def test_cli_port_validator_rejects_out_of_range_values(value):
    with pytest.raises(argparse.ArgumentTypeError) as failure:
        _tcp_port(value)
    assert "1 and 65535" in str(failure.value)


@pytest.mark.parametrize("port", [True, 0, -1, 65_536])
def test_serve_rejects_invalid_port_before_server_creation(port):
    with pytest.raises(ValueError, match="port"):
        serve(
            object(), PROJECT, port=port,
            api_token=API_TOKEN, webhook_secret=WEBHOOK_SECRET)
