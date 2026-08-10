"""The MCP stdio surface: protocol conformance and the read-only boundary."""

from __future__ import annotations

import io
import json

import pytest

from causal_continuity_engine import mcp


def _drive(requests, directory="."):
    """Run the server over a canned request list, return parsed responses."""
    stdin = io.StringIO("\n".join(json.dumps(r) if isinstance(r, dict) else r
                                  for r in requests) + "\n")
    stdout = io.StringIO()
    mcp.serve(directory, stdin=stdin, stdout=stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines() if line]


def test_handshake_reports_the_protocol_and_the_package_version():
    from causal_continuity_engine import __version__

    (response,) = _drive([{"jsonrpc": "2.0", "id": 1, "method": "initialize"}])
    result = response["result"]
    assert result["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert result["serverInfo"] == {
        "name": mcp.SERVER_NAME, "version": __version__}


def test_a_notification_gets_no_response():
    """A request without an id is a notification; replying to one is a bug."""
    responses = _drive([
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    ])
    assert [r["id"] for r in responses] == [1]


def test_every_advertised_tool_declares_a_schema_and_is_dispatchable():
    (response,) = _drive([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
    tools = response["result"]["tools"]
    assert {t["name"] for t in tools} == set(mcp._TOOLS_BY_NAME)
    for tool in tools:
        assert tool["description"].strip()
        assert tool["inputSchema"]["type"] == "object"


def test_malformed_input_and_unknown_names_use_the_reserved_codes():
    responses = _drive([
        "this is not json",
        {"jsonrpc": "2.0", "id": 2, "method": "no/such/method"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "not_a_tool", "arguments": {}}},
        {"jsonrpc": "1.0", "id": 4, "method": "tools/list"},
    ])
    assert [r["error"]["code"] for r in responses] == [
        mcp._PARSE_ERROR, mcp._METHOD_NOT_FOUND,
        mcp._INVALID_PARAMS, mcp._INVALID_REQUEST]


def test_the_surface_is_read_only():
    """An MCP client is an untrusted caller. Nothing here may mutate state.

    Exposing verification, completion or policy over this transport would let
    a caller mint authority from outside the trust model, which is the failure
    AD-006 exists to prevent.
    """
    forbidden = ("verify", "complete", "policy", "grant", "ingest",
                 "quarantine", "promote", "attest")
    for name in mcp._TOOLS_BY_NAME:
        assert not any(word in name for word in forbidden), name


def test_a_tool_failure_is_a_result_not_a_protocol_error(tmp_path):
    """The call was well formed; the client needs to see why it failed."""
    (response,) = _drive(
        [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "list_assumptions", "arguments": {}}}],
        directory=str(tmp_path))          # no project here
    assert "error" not in response
    assert response["result"]["isError"] is True
    assert response["result"]["content"][0]["text"]


def test_tools_answer_from_a_real_project(tmp_path):
    from causal_continuity_engine.cli import main

    main(["--dir", str(tmp_path), "init", "--repo", "octo/demo",
          "--repo-id", "123"])
    issue = tmp_path / "issue.json"
    issue.write_text(json.dumps({
        "action": "opened",
        "repository": {"id": 123, "full_name": "octo/demo"},
        "issue": {"number": 1, "title": "exporter", "state": "open",
                  "body": "The exporter must stream rows instead of"
                          " buffering. We assume the feed is ordered by"
                          " timestamp.",
                  "author_association": "OWNER", "labels": [],
                  "created_at": "2026-08-01T00:00:00Z",
                  "updated_at": "2026-08-01T00:00:00Z"}}), encoding="utf-8")
    main(["--dir", str(tmp_path), "ingest", "--event", "issues",
          "--delivery-id", "d1", "--file", str(issue)])

    responses = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "list_assumptions", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "resume_packet",
                    "arguments": {"token_budget": 800}}},
    ], directory=str(tmp_path))
    assumptions, packet = (r["result"] for r in responses)
    assert assumptions["isError"] is False
    assert "ordered by timestamp" in assumptions["content"][0]["text"]
    assert packet["isError"] is False
    assert "CCE Resume Packet" in packet["content"][0]["text"]


@pytest.mark.parametrize("module", ["causal_continuity_engine.mcp"])
def test_the_server_adds_no_runtime_dependency(module):
    """Zero third-party imports is the property the hand-rolled server exists
    to keep; the official SDK would end it."""
    import importlib
    import sys

    before = set(sys.modules)
    importlib.import_module(module)
    for name in set(sys.modules) - before:
        root = name.split(".")[0]
        assert root in sys.stdlib_module_names or root == \
            "causal_continuity_engine", f"{module} pulled in {root}"
