"""Literal final-byte contracts exercised through the actual local adapters."""

from __future__ import annotations

import io
import json
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from causal_continuity_engine import cli, mcp
from causal_continuity_engine.core import Signer
from causal_continuity_engine.engine import Engine
from tests.authority_helpers import confirmed_task
from tests.test_api_contract import LocalAPI

ERROR = (b'{"error":{"code":"packet_budget_exceeded",'
         b'"message":"Complete packet exceeds max_response_bytes."}}')
DEFAULT = 131072
MAXIMUM = 1048576


def _near_limits(raw):
    # The declared cap changes its own digit count. Other fresh identifiers,
    # timestamps, digests and HMAC signatures retain their encoded widths.
    bound = len(raw)
    while True:
        resized = len(raw) - len(str(DEFAULT)) + len(str(bound))
        if resized == bound:
            return (bound - 1, bound, bound + 1)
        bound = resized


def _cli(directory, *arguments):
    return subprocess.run(
        [sys.executable, "-m", "causal_continuity_engine.cli",
         "--dir", str(directory), *arguments], capture_output=True, check=False)


def _dump(directory):
    connection = sqlite3.connect(directory / ".cce" / "cce.db")
    try:
        return tuple(connection.iterdump())
    finally:
        connection.close()


@pytest.fixture
def local(tmp_path):
    initialized = _cli(tmp_path, "--json", "init", "--capture-mode", "full",
                       "--repo", "octo/demo", "--repo-id", "123")
    assert initialized.returncode == 0, initialized.stderr
    engine, meta = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    engine.ingest_github(meta["project_id"], "issues", "terminal-context", {
        "action": "opened", "repository": {"id": 123, "full_name": "octo/demo"},
        "issue": {"number": 1, "state": "open", "title": "terminal context",
                  "body": "The terminal must display ESC\x1b[2J BEL\x07 and bidi\u202e safely",
                  "author_association": "OWNER", "created_at": "2026-08-04T12:00:00Z"},
    })
    task = confirmed_task(
        engine, meta["project_id"], text='Archive the café "雪" report safely')
    engine.resume_packet(meta["project_id"])
    engine.close()
    return tmp_path, meta["project_id"], task["node_id"]


def _mcp(directory, requests):
    initialization = {
        "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "byte-test", "version": "1"}}}
    source = io.StringIO("\n".join(json.dumps(item) for item in [
        initialization,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        *requests]) + "\n")
    raw = io.BytesIO()
    # Production must emit premeasured UTF-8/LF bytes even if a text wrapper
    # would otherwise translate LF. Ordinary StringIO callers remain supported.
    sink = io.TextIOWrapper(raw, encoding="utf-8", newline="\r\n")
    assert mcp.serve(str(directory), stdin=source, stdout=sink) == 0
    sink.flush()
    lines = raw.getvalue().splitlines(keepends=True)
    sink.detach()
    return lines[1:]


def _request(request_id, **arguments):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "resume_packet", "arguments": arguments}}


def _http(server, project_id, body):
    request = urllib.request.Request(
        server.base + f"/v1/projects/{project_id}/resume-packets:compose",
        data=json.dumps(body).encode("utf-8"), method="POST", headers={
            "Authorization": "Bearer contract-api-token-0123456789abcdef",
            "Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, response.read(), response.headers


@pytest.mark.parametrize("fmt", ["json", "markdown"])
def test_cli_exact_output_and_fixed_refusal_preserve_existing_watermark(local, fmt):
    directory, _, task_id = local
    args = ("resume", "--task-id", task_id, "--format", fmt)
    success = _cli(directory, *args)
    assert success.returncode == 0, success.stderr
    assert not success.stderr
    assert success.stdout.endswith(b"\n") and not success.stdout.endswith(b"\r\n")
    assert len(success.stdout) <= DEFAULT
    if fmt == "json":
        packet = json.loads(success.stdout)
        assert packet["scope"] == {"kind": "task", "task_id": task_id}
        assert packet["max_response_bytes"] == DEFAULT
        assert packet["response_format"] == "cli-json"
        assert success.stdout == (json.dumps(
            packet, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    else:
        assert b"cli-markdown" in success.stdout and b"131072" in success.stdout
        assert b"\\u202e" in success.stdout and "\u202e".encode() not in success.stdout
    for limit in _near_limits(success.stdout):
        before = _dump(directory)
        near = _cli(directory, *args, "--max-response-bytes", str(limit))
        if near.returncode == 0:
            assert len(near.stdout) <= limit and not near.stderr
            if fmt == "json":
                assert json.loads(near.stdout)["open_work"] == packet["open_work"]
        else:
            assert near.returncode == 2 and near.stdout == b""
            assert near.stderr == ERROR + b"\n"
            assert _dump(directory) == before
    before = _dump(directory)
    refused = _cli(directory, *args, "--max-response-bytes", "1")
    assert refused.returncode == 2
    assert refused.stdout == b""
    assert refused.stderr == ERROR + b"\n"
    assert len(refused.stderr) <= 1024
    assert _dump(directory) == before


@pytest.mark.parametrize("limit", ["0", "-1", "1048577", "true", "1.5"])
def test_cli_invalid_limit_refuses_before_opening_state(tmp_path, limit):
    result = _cli(tmp_path, "resume", "--max-response-bytes", limit)
    assert result.returncode == 2
    assert b"--max-response-bytes" in result.stderr
    assert not result.stdout and not (tmp_path / ".cce").exists()


def test_http_body_is_exact_bound_and_budget_error_is_fixed_422(local):
    directory, project_id, task_id = local
    engine, _ = cli._engine(SimpleNamespace(dir=str(directory)))
    server = LocalAPI(engine, project_id=project_id)
    try:
        status, raw, headers = _http(server, project_id, {"task_id": task_id})
        assert status == 200, raw
        packet = json.loads(raw)
        assert packet["max_response_bytes"] == DEFAULT
        assert packet["response_format"] == "http-json"
        assert packet["scope"] == {"kind": "task", "task_id": task_id}
        assert raw == json.dumps(packet, ensure_ascii=False, allow_nan=False,
                                 separators=(",", ":")).encode("utf-8")
        assert len(raw) <= DEFAULT and int(headers["Content-Length"]) == len(raw)
        for limit in _near_limits(raw):
            before = tuple(engine.store._conn.iterdump())
            code, near, _ = _http(server, project_id, {
                "task_id": task_id, "max_response_bytes": limit})
            if code == 200:
                assert len(near) <= limit
                assert json.loads(near)["open_work"] == packet["open_work"]
            else:
                assert code == 422 and near == ERROR
                assert tuple(engine.store._conn.iterdump()) == before
        before = tuple(engine.store._conn.iterdump())
        status, raw, _ = _http(server, project_id, {
            "task_id": task_id, "max_response_bytes": 1})
        assert status == 422 and raw == ERROR and len(raw) <= 1024
        assert tuple(engine.store._conn.iterdump()) == before
        assert _http(server, project_id, {"max_response_bytes": MAXIMUM})[0] == 200
    finally:
        server.close()
        engine.close()


@pytest.mark.parametrize("limit", [None, True, 0, -1, 1048577, 1.0, "1000"])
def test_http_invalid_limit_is_field_validation_not_unknown_field(local, limit):
    directory, project_id, _ = local
    engine, _ = cli._engine(SimpleNamespace(dir=str(directory)))
    server = LocalAPI(engine, project_id=project_id)
    try:
        before = tuple(engine.store._conn.iterdump())
        status, raw, _ = _http(server, project_id, {"max_response_bytes": limit})
        assert status == 400
        error = json.loads(raw)["error"]
        assert error["field"] == "max_response_bytes"
        assert error["code"] == "invalid_request"
        assert tuple(engine.store._conn.iterdump()) == before
    finally:
        server.close()
        engine.close()


@pytest.mark.parametrize("fmt", ["json", "markdown"])
@pytest.mark.parametrize("request_id", ["é" * 63, -(2**63), 2**63 - 1])
def test_mcp_whole_frame_bound_and_recovery_without_writes(local, fmt, request_id):
    directory, _, task_id = local
    before = _dump(directory)
    lines = _mcp(directory, [
        _request(request_id, task_id=task_id, format=fmt, max_response_bytes=1),
        _request(request_id, task_id=task_id, format=fmt),
    ])
    assert len(lines) == 2
    error, success = map(json.loads, lines)
    assert error == {"jsonrpc": "2.0", "id": request_id, "result": {
        "content": [{"type": "text", "text": ERROR.decode()}], "isError": True}}
    assert len(lines[0]) <= 1024
    assert success["id"] == request_id and success["result"]["isError"] is False
    assert len(lines[1]) <= DEFAULT
    assert all(line.endswith(b"\n") and not line.endswith(b"\r\n") for line in lines)
    assert lines[1] == (json.dumps(success, ensure_ascii=False) + "\n").encode()
    text = success["result"]["content"][0]["text"]
    if fmt == "json":
        packet = json.loads(text)
        assert packet["max_response_bytes"] == DEFAULT
        assert packet["response_format"] == "mcp-json"
        assert packet["scope"] == {"kind": "task", "task_id": task_id}
    else:
        assert "mcp-markdown" in text and "131072" in text
    for limit in _near_limits(lines[1]):
        (near,) = _mcp(directory, [_request(
            request_id, task_id=task_id, format=fmt, max_response_bytes=limit)])
        result = json.loads(near)["result"]
        if result["isError"]:
            assert result["content"][0]["text"] == ERROR.decode()
            assert len(near) <= 1024
        else:
            assert len(near) <= limit
            if fmt == "json":
                actual = json.loads(result["content"][0]["text"])
                assert actual["open_work"] == packet["open_work"]
    assert _dump(directory) == before


@pytest.mark.parametrize("request_id", [
    "x" * 127, "é" * 64, '"' * 64, "\\" * 64,
    2**63, -(2**63) - 1, None, True, 1.0, [], {},
])
def test_mcp_invalid_resume_id_is_bounded_before_opening_state(tmp_path, request_id):
    (raw,) = _mcp(tmp_path, [_request(request_id)])
    response = json.loads(raw)
    assert response["id"] is None and response["error"]["code"] == -32600
    assert len(raw) <= 1024
    assert not (tmp_path / ".cce").exists()


def test_mcp_resume_notifications_remain_silent_and_other_ids_unrestricted(tmp_path):
    notification = _request("unused", max_response_bytes=1)
    del notification["id"]
    lines = _mcp(tmp_path, [notification, {
        "jsonrpc": "2.0", "id": "x" * 512, "method": "ping"}])
    assert len(lines) == 1 and json.loads(lines[0])["id"] == "x" * 512
    assert not (tmp_path / ".cce").exists()


@pytest.mark.parametrize("limit", [None, True, 0, -1, 1048577, 1.0, "1000"])
def test_mcp_invalid_limit_is_specific_validation_before_opening(tmp_path, limit):
    (raw,) = _mcp(tmp_path, [_request(1, max_response_bytes=limit)])
    response = json.loads(raw)
    assert response["error"]["code"] == -32602
    assert response["error"]["message"] == (
        "max_response_bytes must be an integer from 1 to 1048576")
    assert not (tmp_path / ".cce").exists()


@pytest.mark.parametrize("target", ["absent", "foreign", "unconfirmed", "terminal"])
def test_unavailable_http_task_is_404_without_state_or_signing(tmp_path, monkeypatch, target):
    engine = Engine(tmp_path / "scope.db", tenant_id="ten_scope_http", workdir=tmp_path)
    project_id = "prj_scope_http"
    engine.create_project(
        "HTTP selector", project_id=project_id, capture_mode="full",
        config={"require_proof_for": []})
    good = confirmed_task(engine, project_id, text="Package the navigation image")
    if target == "absent":
        unavailable = "tsk_absent"
    elif target == "foreign":
        engine.create_project("Foreign selector", project_id="prj_foreign_scope")
        unavailable = confirmed_task(
            engine, "prj_foreign_scope", text="Index the marine field notes")["node_id"]
    elif target == "unconfirmed":
        report = engine.ingest_human_decision(
            project_id, actor="scope-source", request_id="scope-unconfirmed",
            decision="- [ ] Collate the forest survey results")
        unavailable, = [item["node_id"] for item in report["created"]
                        if item["kind"] == "claim" and not item.get("quarantined")]
    else:
        terminal = confirmed_task(engine, project_id, text="Archive the completed census")
        engine.complete_task(project_id, terminal["node_id"])
        unavailable = terminal["node_id"]
        assert engine.graph.get(unavailable)["status"] == "verified"
    engine.resume_packet(project_id)
    before = tuple(engine.store._conn.iterdump())
    calls = []
    original_sign = Signer.sign

    def observed_sign(self, packet):
        calls.append(packet.get("schema_version"))
        return original_sign(self, packet)

    monkeypatch.setattr(Signer, "sign", observed_sign)
    server = LocalAPI(engine, project_id=project_id)
    try:
        status, raw, _ = _http(server, project_id, {"task_id": unavailable})
        assert status == 404
        assert raw == b'{"error":{"code":"not_found","message":"task is unavailable"}}'
        assert unavailable.encode() not in raw
        assert tuple(engine.store._conn.iterdump()) == before
        assert calls == []
        status, raw, _ = _http(server, project_id, {"task_id": good["node_id"]})
        assert status == 200, raw
        assert calls == ["cce.resume.v2"]
    finally:
        server.close()
        engine.close()
