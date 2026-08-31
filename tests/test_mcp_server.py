"""The MCP stdio surface: protocol conformance and the read-only boundary."""

from __future__ import annotations

import io
import json
import sqlite3
from types import SimpleNamespace

import pytest

from causal_continuity_engine import mcp


def _drive(requests, directory="."):
    """Run the server over a canned request list, return parsed responses."""
    stdin = io.StringIO("\n".join(json.dumps(r) if isinstance(r, dict) else r
                                  for r in requests) + "\n")
    stdout = io.StringIO()
    mcp.serve(directory, stdin=stdin, stdout=stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines() if line]


def _initialize(request_id=0, revision=mcp.PROTOCOL_VERSION):
    return {
        "jsonrpc": "2.0", "id": request_id, "method": "initialize",
        "params": {
            "protocolVersion": revision,
            "capabilities": {},
            "clientInfo": {"name": "cce-test", "version": "1.0"},
        },
    }


def _drive_ready(requests, directory="."):
    responses = _drive([
        _initialize(),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        *requests,
    ], directory=directory)
    assert responses[0]["id"] == 0
    return responses[1:]


def test_handshake_reports_the_protocol_and_the_package_version():
    from causal_continuity_engine import __version__

    (response,) = _drive([_initialize(1)])
    result = response["result"]
    assert result["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert result["serverInfo"] == {
        "name": mcp.SERVER_NAME, "version": __version__}


@pytest.mark.parametrize("revision", mcp.SUPPORTED_PROTOCOL_VERSIONS)
def test_the_handshake_answers_a_revision_it_speaks_with_that_revision(revision):
    (response,) = _drive([_initialize(1, revision)])
    assert response["result"]["protocolVersion"] == revision


@pytest.mark.parametrize("revision", ["2026-07-28", "banana"])
def test_an_unspoken_revision_falls_back_instead_of_being_echoed(revision):
    """Echoing the request would claim conformance to any string sent."""
    (response,) = _drive([_initialize(1, revision)])
    answered = response["result"]["protocolVersion"]
    assert answered != revision
    assert answered == mcp.PROTOCOL_VERSION


def test_no_advertised_revision_is_invented():
    """Regression: 0.1.4 advertised `2026-07-28`, which no client accepts.

    That value was guessed, not read, and nothing here caught it — the old
    handshake test compared the constant to itself. Only an external authority
    settles whether a revision is real, so this checks against the reference
    SDK's list when that SDK happens to be installed.

    It skips in this project's own CI, which has no dependencies by design.
    The check that does not skip is the manual client drive in docs/RELEASE.md;
    a date heuristic was tried here first and rejected, because the revision
    that actually shipped was in the past and sailed through it.
    """
    supported = pytest.importorskip(
        "mcp.shared.version",
        reason="reference MCP SDK not installed; RELEASE.md drives a real client",
    ).SUPPORTED_PROTOCOL_VERSIONS
    unknown = set(mcp.SUPPORTED_PROTOCOL_VERSIONS) - set(supported)
    assert not unknown, (
        f"advertised protocol revisions {sorted(unknown)} are unknown to the "
        f"reference SDK, which accepts {sorted(supported)}")


def test_a_notification_gets_no_response():
    """A request without an id is a notification; replying to one is a bug."""
    responses = _drive([
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    ])
    assert [r["id"] for r in responses] == [1]


def test_every_advertised_tool_declares_a_schema_and_is_dispatchable():
    (response,) = _drive_ready([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
    tools = response["result"]["tools"]
    assert {t["name"] for t in tools} == set(mcp._TOOLS_BY_NAME)
    for tool in tools:
        assert tool["description"].strip()
        assert tool["inputSchema"]["type"] == "object"


def test_malformed_input_and_unknown_names_use_the_reserved_codes():
    responses = _drive([
        "this is not json",
        _initialize(1),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "no/such/method"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "not_a_tool", "arguments": {}}},
        {"jsonrpc": "1.0", "id": 4, "method": "tools/list"},
    ])
    assert responses[1]["id"] == 1
    assert [responses[index]["error"]["code"] for index in (0, 2, 3, 4)] == [
        mcp._PARSE_ERROR, mcp._METHOD_NOT_FOUND,
        mcp._INVALID_PARAMS, mcp._INVALID_REQUEST]


@pytest.mark.parametrize("request_id", ["request-4", 0])
def test_invalid_jsonrpc_preserves_a_valid_request_identifier(request_id):
    (response,) = _drive([
        {"jsonrpc": "1.0", "id": request_id, "method": "tools/list"},
    ])
    assert response["error"]["code"] == mcp._INVALID_REQUEST
    assert response["id"] == request_id


@pytest.mark.parametrize("request_id", [None, False, 1.5, [], {}])
def test_invalid_jsonrpc_does_not_echo_an_invalid_request_identifier(request_id):
    (response,) = _drive([
        {"jsonrpc": "1.0", "id": request_id, "method": "tools/list"},
    ])
    assert response["error"]["code"] == mcp._INVALID_REQUEST
    assert response["id"] is None


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
    (response,) = _drive_ready(
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

    responses = _drive_ready([
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


def test_continuity_check_answers_the_question_without_the_receipt(tmp_path):
    """A status answer must not ship the signed receipt.

    The receipt was four fifths of the payload — 8,244 of 10,602 characters on
    a one-issue project — and it is cryptographic material for export, not
    something a client asking whether the project is continuous can act on.
    It remains available through `cce-engine check --export-receipt`.
    """
    from causal_continuity_engine.cli import main

    main(["--dir", str(tmp_path), "init", "--repo", "octo/demo",
          "--repo-id", "123"])
    (response,) = _drive_ready(
        [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "continuity_check", "arguments": {}}}],
        directory=str(tmp_path))
    body = response["result"]["content"][0]["text"]
    assert response["result"]["isError"] is False
    report = json.loads(body)
    assert "continuity_receipt" not in report
    # The fields a caller actually decides on are still present.
    assert "conclusion" in report and "open_invalidations" in report


def test_an_unknown_project_is_an_error_not_an_empty_answer(tmp_path):
    """Absence of success is never success — including here.

    A caller naming a project that does not exist received "No active
    assumptions.", a confident negative that conflates *none* with *not
    found*. An agent could reasonably conclude the project had no assumptions
    when it had no project.
    """
    from causal_continuity_engine.cli import main

    main(["--dir", str(tmp_path), "init", "--repo", "octo/demo",
          "--repo-id", "123"])
    responses = _drive_ready([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "list_assumptions",
                    "arguments": {"project_id": "prj_not_a_real_project"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "resume_packet",
                    "arguments": {"project_id": "prj_not_a_real_project"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "list_assumptions", "arguments": {}}},
    ], directory=str(tmp_path))
    unknown_a, unknown_b, real = (r["result"] for r in responses)
    assert unknown_a["isError"] is True
    assert unknown_b["isError"] is True
    # The project that does exist still answers.
    assert real["isError"] is False


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


def test_tools_are_unavailable_until_initialization_finishes():
    responses = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        _initialize(2),
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
    ])

    assert responses[0]["error"]["code"] == mcp._INVALID_REQUEST
    assert responses[1]["id"] == 2
    assert responses[2]["error"]["code"] == mcp._INVALID_REQUEST
    assert "tools" in responses[3]["result"]


def test_ping_is_prompt_and_preserves_the_request_identifier():
    responses = _drive([
        {"jsonrpc": "2.0", "id": "before-init", "method": "ping"},
        _initialize(2),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {}},
    ])
    assert responses[0] == {
        "jsonrpc": "2.0", "id": "before-init", "result": {}}
    assert responses[-1] == {"jsonrpc": "2.0", "id": 3, "result": {}}


@pytest.mark.parametrize("bad_id", [None, True, 1.5, [], {}])
def test_request_ids_are_strings_or_integers_but_never_null_or_bool(bad_id):
    (response,) = _drive([
        {"jsonrpc": "2.0", "id": bad_id, "method": "ping"},
    ])
    assert response["error"]["code"] == mcp._INVALID_REQUEST
    assert response["id"] is None


def test_invalid_parameter_shapes_are_protocol_errors():
    responses = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": []},
        _initialize(2),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": []},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "resume_packet", "arguments": []}},
    ])
    assert responses[1]["id"] == 2
    assert [responses[index]["error"]["code"] for index in (0, 2, 3)] == [
        mcp._INVALID_PARAMS, mcp._INVALID_PARAMS, mcp._INVALID_PARAMS]


@pytest.mark.parametrize(
    "arguments",
    [{"unexpected": True}, {"project_id": ""}, {"token_budget": True},
     {"token_budget": 0}, {"format": "xml"}],
)
def test_tool_arguments_are_validated_before_execution(arguments):
    (response,) = _drive_ready([{
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "resume_packet", "arguments": arguments},
    }])
    assert response["error"]["code"] == mcp._INVALID_PARAMS


def test_a_tool_notification_is_ignored_without_execution():
    def unexpected(*_args, **_kwargs):
        raise AssertionError("a notification must not execute a tool")

    session = SimpleNamespace(state="ready", call=unexpected)
    response = mcp._handle({
        "jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "resume_packet", "arguments": {}},
    }, session)
    assert response is None


def _database_dump(directory):
    connection = sqlite3.connect(directory / ".cce" / "cce.db")
    try:
        return tuple(connection.iterdump())
    finally:
        connection.close()


def test_resume_tool_is_a_logically_read_only_projection(tmp_path):
    from causal_continuity_engine.cli import _engine, main

    main(["--dir", str(tmp_path), "init", "--repo", "octo/demo",
          "--repo-id", "123"])
    engine, meta = _engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        collision = "the same quarantined payload " + "x" * 40
        engine.graph.put_node(
            entity_type="claim", tenant_id=engine.tenant_id,
            project_id=meta["project_id"], status="quarantined",
            data={"statement": collision})
        engine.graph.put_node(
            entity_type="constraint", tenant_id=engine.tenant_id,
            project_id=meta["project_id"], status="active",
            data={"statement": collision})
    finally:
        engine.close()
    before = _database_dump(tmp_path)

    (response,) = _drive_ready([{
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "resume_packet", "arguments": {}},
    }], directory=str(tmp_path))

    assert response["result"]["isError"] is False
    assert _database_dump(tmp_path) == before


def test_resume_tool_can_return_the_complete_canonical_packet(tmp_path):
    from causal_continuity_engine.cli import main
    from causal_continuity_engine.core import canonical_json
    from causal_continuity_engine.resume import ResumeComposer

    main(["--dir", str(tmp_path), "init", "--repo", "octo/demo",
          "--repo-id", "123"])
    (response,) = _drive_ready([{
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "resume_packet", "arguments": {"format": "json"}},
    }], directory=str(tmp_path))

    text = response["result"]["content"][0]["text"]
    packet = json.loads(text)
    assert text == canonical_json(packet)
    assert set(packet) >= ResumeComposer.MARKDOWN_RENDERED_TOP_LEVEL
    assert packet["schema_version"] == "cce.resume.v1"


def test_list_projections_read_canonical_status_and_nested_data(tmp_path):
    from causal_continuity_engine.cli import _engine, main

    main(["--dir", str(tmp_path), "init", "--repo", "octo/demo",
          "--repo-id", "123"])
    engine, meta = _engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        project_id = meta["project_id"]
        engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id,
            project_id=project_id, status="active",
            data={"statement": "the active feed is ordered"})
        engine.graph.put_node(
            entity_type="assumption", tenant_id=engine.tenant_id,
            project_id=project_id, status="invalidated",
            data={"statement": "the retired feed is ordered"})
        engine.graph.put_node(
            entity_type="invalidation", tenant_id=engine.tenant_id,
            project_id=project_id, status="open",
            data={"severity": "critical", "reason": "schema contradicted"})
    finally:
        engine.close()

    assumptions, invalidations = _drive_ready([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "list_assumptions", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "list_invalidations", "arguments": {}}},
    ], directory=str(tmp_path))
    assumptions_text = assumptions["result"]["content"][0]["text"]
    invalidations_text = invalidations["result"]["content"][0]["text"]
    assert "active feed" in assumptions_text
    assert "retired feed" not in assumptions_text
    assert "critical: schema contradicted" in invalidations_text
