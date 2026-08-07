"""Final public-boundary regressions for strict transport and audit inputs."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import socket

import pytest

import causal_continuity_engine.capabilities as capabilities
import causal_continuity_engine.cli as cli
from causal_continuity_engine.core import Signer, strict_json_loads
from causal_continuity_engine.engine import Engine
from tests.test_api_contract import LocalAPI

PROJECT = "prj_round16_boundary"
TENANT = "ten_round16_boundary"
WEBHOOK_SECRET = "round16-webhook-secret-0123456789abcdef"


@pytest.fixture
def api_server(tmp_path):
    engine = Engine(
        tmp_path / "cce.db", tenant_id=TENANT,
        signer=Signer.generate("round16-boundary"), workdir=tmp_path)
    engine.create_project(
        "round16 boundary", project_id=PROJECT,
        repository="owner/repo", repository_id=424242,
        github_installation_id=1)
    server = LocalAPI(
        engine, project_id=PROJECT, webhook_secret=WEBHOOK_SECRET)
    try:
        yield server, engine
    finally:
        server.close()
        engine.close()


@pytest.mark.parametrize(
    "raw",
    [
        b'\xef\xbb\xbf{"ok":true}',
        '{"ok":true}'.encode("utf-16"),
        '{"ok":true}'.encode("utf-32"),
    ],
    ids=["utf8-bom", "utf16", "utf32"],
)
def test_strict_json_bytes_require_bomless_utf8(raw):
    with pytest.raises(ValueError, match="UTF-8|BOM"):
        strict_json_loads(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'\xef\xbb\xbf{"span_id":"alternate_encoding"}',
        json.dumps({"span_id": "alternate_encoding"}).encode("utf-16"),
    ],
    ids=["utf8-bom", "utf16"],
)
def test_api_rejects_non_utf8_json_without_appending_event(api_server, raw):
    server, engine = api_server
    before = engine.store._conn.execute(
        "SELECT COUNT(*) FROM events").fetchone()[0]

    status, body, _ = server.request(
        "POST", "/v1/traces:ingest", raw=raw)

    assert status == 400
    assert body["error"]["code"] == "invalid_json"
    assert engine.store._conn.execute(
        "SELECT COUNT(*) FROM events").fetchone()[0] == before


def _raw_get(server: LocalAPI, target: bytes) -> tuple[int, dict]:
    request = (
        b"GET " + target + b" HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
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
    response = b"".join(chunks)
    head, body = response.split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, json.loads(body)


@pytest.mark.parametrize(
    "target",
    [
        b"http://127.0.0.1/v1/health",
        b"/v1/health#alias",
        b"http://[::1/v1/health",
    ],
    ids=["absolute-form", "fragment", "malformed-authority"],
)
def test_api_rejects_non_origin_or_ambiguous_request_targets(
        api_server, target):
    server, _ = api_server

    status, body = _raw_get(server, target)

    assert status == 400
    assert body["error"]["field"] == "request_target"


def test_signed_ping_rejects_boolean_configured_installation_id(
        api_server, monkeypatch):
    server, engine = api_server
    original_get = engine.graph.get

    def corrupted_get(*args, **kwargs):
        node = original_get(*args, **kwargs)
        if node.get("entity_type") == "project":
            node = copy.deepcopy(node)
            node["data"]["github_installation_id"] = True
        return node

    monkeypatch.setattr(engine.graph, "get", corrupted_get)
    payload = {
        "hook": {"id": 7},
        "hook_id": 7,
        "zen": "strict identities",
        "repository": {"id": 424242, "full_name": "owner/repo"},
        "installation": {"id": 1},
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    before = engine.store._conn.execute(
        "SELECT COUNT(*) FROM events").fetchone()[0]

    status, _, _ = server.request(
        "POST", "/v1/events:ingest", raw=raw,
        headers={
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "delivery_round16_ping",
            "X-Hub-Signature-256": signature,
        },
        authenticated=False)

    assert status == 403
    assert engine.store._conn.execute(
        "SELECT COUNT(*) FROM events").fetchone()[0] == before


@pytest.mark.parametrize("body", [{}, {"data": {}}], ids=["omitted", "empty-patch"])
def test_resolve_preserves_existing_node_data_when_patch_is_empty(
        api_server, body):
    server, engine = api_server
    node = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        status="active",
        data={"statement": "retain this", "source": "operator", "weight": 3})

    status, _, _ = server.request(
        "POST", f"/v1/assumptions/{node.id}:resolve", body=body)

    assert status == 200
    current = engine.graph.get(
        node.id, tenant_id=TENANT, project_id=PROJECT,
        entity_type="assumption")
    assert current["data"] == {
        "statement": "retain this", "source": "operator", "weight": 3}


def test_resolve_rejects_malformed_patch_without_writing(api_server):
    server, engine = api_server
    node = engine.graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        status="active", data={"statement": "retain this"})
    before = engine.store._conn.total_changes

    status, body, _ = server.request(
        "POST", f"/v1/assumptions/{node.id}:resolve",
        body={"data": []})

    assert status == 400
    assert body["error"]["field"] == "data"
    assert engine.store._conn.total_changes == before
    assert engine.graph.get(
        node.id, tenant_id=TENANT, project_id=PROJECT,
        entity_type="assumption")["data"] == {"statement": "retain this"}


def _checkout_root(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text(
        "[project]\nname='boundary'\n", encoding="utf-8")
    monkeypatch.setattr(capabilities, "ROOT", checkout)
    return checkout


def test_capability_evidence_must_be_a_regular_file(tmp_path, monkeypatch):
    checkout = _checkout_root(tmp_path, monkeypatch)
    (checkout / "tests" / "fake.py").mkdir(parents=True)

    assert not capabilities._evidence_exists("tests/fake.py")


def test_capability_evidence_cannot_escape_checkout(tmp_path, monkeypatch):
    checkout = _checkout_root(tmp_path, monkeypatch)
    outside = tmp_path / "outside.txt"
    outside.write_text("not repository evidence", encoding="utf-8")

    assert not capabilities._evidence_exists("../outside.txt")
    assert not capabilities._evidence_exists(str(outside.resolve()))
    assert checkout != outside.parent


def test_capability_symbol_requires_explicit_dotted_attribute():
    claim = capabilities.Capability(
        requirement="X-ROUND16", layer="Core", summary="boundary",
        status="implemented", honest_limit="focused regression",
        symbols=("causal_continuity_engine.graph",),
        tests=("tests/test_regressions_round4.py",))

    result = capabilities.verify([claim])[0]

    assert not result.ok
    assert "module:attribute" in result.problems[0]


@pytest.mark.parametrize(
    "argv",
    [
        ["--dir", "", "assumptions"],
        ["check", "--verify-receipt", ""],
        ["check", "--export-receipt", ""],
        ["migrate", "prepare", "--out", ""],
        ["audit", "anchor", "--out", ""],
    ],
    ids=["dir", "verify-receipt", "export-receipt", "capsule-out", "anchor-out"],
)
def test_cli_rejects_empty_paths_before_opening_engine(monkeypatch, argv):
    # Isolate argparse from output-target filesystem checks: every empty
    # token must be rejected by parsing, independent of the current checkout.
    monkeypatch.setattr(
        cli, "_validate_json_output_target", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        cli, "_engine",
        lambda _args: pytest.fail("empty CLI value reached engine"))

    with pytest.raises(SystemExit) as rejected:
        cli.main(argv)

    assert rejected.value.code == 2


def test_cli_verify_preserves_explicit_empty_statement(monkeypatch, capsys):
    observed = {}

    class StubEngine:
        def attest_action(self, project_id, **kwargs):
            observed["project_id"] = project_id
            observed.update(kwargs)
            return {
                "proof_id": "prf_round16",
                "status": "verified",
                "verifications": [],
            }

        def close(self):
            pass

    monkeypatch.setattr(
        cli, "_engine",
        lambda _args: (StubEngine(), {"project_id": PROJECT}))

    cli.main(["--json", "verify", "--statement", ""])

    assert json.loads(capsys.readouterr().out)["status"] == "verified"
    assert observed["intent_statement"] == ""
