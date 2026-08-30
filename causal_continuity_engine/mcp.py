"""Model Context Protocol server over stdio (JSON-RPC 2.0), standard library only.

Every editor that matters now speaks MCP — GitHub retired Copilot Extensions in
its favour, and Continue.dev deprecated its own context providers for it — so
this is the surface through which a client reads CCE without adopting anything.

Hand-rolled deliberately. The official SDK pulls sixteen dependencies including
starlette, uvicorn and pyjwt, which would end this package's zero-runtime-
dependency property to save a couple of hundred lines. `api.py` hand-rolls an
HTTP server on `http.server` for exactly the same reason.

The transport is newline-delimited JSON-RPC 2.0 on stdin/stdout, so nothing may
be printed to stdout except responses; diagnostics go to stderr.

Read-only by design. Every tool here answers questions about a project. Nothing
mutates state, mints a proof, or grants autonomy — an MCP client is an
untrusted caller in this project's authority model, and giving one a write path
would put the caller on the wrong side of AD-006.
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

from .core import canonical_json

# Protocol revisions this server answers, newest first. "Answers" is the whole
# claim: the methods it implements — initialize, ping, tools/list, tools/call
# and initialized notifications — are shaped identically across these revisions, and each is
# driven in tests/test_mcp_server.py. A revision is not listed until it is.
#
# A client asking for one of these gets it back unchanged; anything else is
# answered with the newest, which is what a server is required to do when it
# cannot speak the requested revision. Never echo the request blindly: that
# would claim conformance to any string a client happens to send.
SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
SERVER_NAME = "causal-continuity-engine"

# JSON-RPC 2.0 reserved codes.
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603

_PROJECT_ARG = {
    "project_id": {
        "type": "string",
        "description": "Project id; defaults to the project in --dir.",
    },
}

TOOLS = [
    {
        "name": "resume_packet",
        "description": (
            "Compose a Resume Packet: the control state a resuming agent "
            "receives instead of a summary. States its own omissions."),
        "inputSchema": {
            "type": "object",
            "properties": {
                **_PROJECT_ARG,
                "token_budget": {
                    "type": "integer",
                    "description": (
                        "Trimmable material is reduced to fit. Authority is "
                        "never dropped, so a large project may exceed this; "
                        "token_estimate reports the real size."),
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "json"],
                    "description": (
                        "Human Markdown view or the complete canonical packet. "
                        "Defaults to markdown."),
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "list_assumptions",
        "description": (
            "Active assumptions extracted from repository prose. These are "
            "proposals, not authority: an assumption is what the project "
            "currently believes, and may have been contradicted."),
        "inputSchema": {"type": "object", "properties": dict(_PROJECT_ARG),
                        "additionalProperties": False},
    },
    {
        "name": "list_invalidations",
        "description": (
            "Open invalidations: state contradicted by later evidence, with "
            "the blast radius computed over typed edges."),
        "inputSchema": {"type": "object", "properties": dict(_PROJECT_ARG),
                        "additionalProperties": False},
    },
    {
        "name": "continuity_check",
        "description": (
            "Whether the project is in a continuous state. Absence of success "
            "is never success: anything other than success is reported as "
            "such, never as a pass."),
        "inputSchema": {"type": "object", "properties": dict(_PROJECT_ARG),
                        "additionalProperties": False},
    },
]

_TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}


def _text(payload: str, *, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": payload}], "isError": is_error}


class _Session:
    """Holds the engine open across calls so a client is not paying for setup."""

    def __init__(self, directory: str) -> None:
        self._directory = directory
        self._engine = None
        self._meta = None
        self.state = "new"

    def _open(self):
        if self._engine is None:
            # Imported lazily so a failed handshake does not pay for opening a
            # database. `_engine` reads the project the CLI would have used,
            # so `cce-engine mcp` and `cce-engine resume` see the same state.
            from types import SimpleNamespace

            from .cli import _engine as open_engine

            self._engine, self._meta = open_engine(
                SimpleNamespace(dir=self._directory))
        return self._engine, self._meta

    def project(self, arguments: dict) -> str:
        engine, meta = self._open()
        requested = arguments.get("project_id")
        project_id = requested if requested else meta["project_id"]
        # An unknown project must not answer as an empty one. Returning "no
        # active assumptions" for a project that does not exist reports
        # absence as a finding, which is the confusion this project exists to
        # prevent. `_require_project` also refuses to say whether the id
        # exists in another tenant.
        engine._require_project(project_id)
        return project_id

    def call(self, name: str, arguments: dict) -> str:
        engine, _ = self._open()
        project_id = self.project(arguments)
        if name == "resume_packet":
            budget = arguments.get("token_budget", 4000)
            fmt = arguments.get("format", "markdown")
            packet = engine._resume_packet(
                project_id, token_budget=budget, fmt=fmt, record_state=False)
            if fmt == "json":
                return canonical_json(packet)
            return packet
        if name == "list_assumptions":
            nodes = engine.graph.current(
                project_id, "assumption", status=["active", "supported"],
                tenant_id=engine.tenant_id)
            if not nodes:
                return "No active assumptions."
            return "\n".join(
                f"- [{node.get('status')}] "
                f"{node.get('data', {}).get('statement', '')}"
                for node in nodes)
        if name == "list_invalidations":
            open_items = engine.invalidation.open_invalidations(project_id)
            if not open_items:
                return "No open invalidations."
            return "\n".join(
                f"- {item.get('data', {}).get('severity', '?')}: "
                f"{item.get('data', {}).get('reason', '')}"
                for item in open_items)
        if name == "continuity_check":
            report = engine.continuity_check(project_id)
            # The signed receipt is four fifths of this report and is
            # cryptographic material for export, not something a client
            # asking "is this project continuous?" can act on. It stays
            # available through `cce-engine check --export-receipt`.
            summary = {key: value for key, value in report.items()
                       if key != "continuity_receipt"}
            return json.dumps(summary, indent=2, sort_keys=True)
        raise KeyError(name)

    def close(self) -> None:
        if self._engine is not None:
            self._engine.close()
            self._engine = None


def _error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


def _valid_request_id(value) -> bool:
    return (isinstance(value, str)
            or isinstance(value, int) and not isinstance(value, bool))


def _valid_initialize(params: dict) -> bool:
    client = params.get("clientInfo")
    return bool(
        isinstance(params.get("protocolVersion"), str)
        and params["protocolVersion"]
        and isinstance(params.get("capabilities"), dict)
        and isinstance(client, dict)
        and isinstance(client.get("name"), str) and client["name"]
        and isinstance(client.get("version"), str) and client["version"]
    )


def _tool_argument_error(name: str, arguments: dict) -> str | None:
    allowed = set(_TOOLS_BY_NAME[name]["inputSchema"]["properties"])
    unknown = sorted(set(arguments) - allowed)
    if unknown:
        return f"unknown {name} argument(s): {unknown}"
    project_id = arguments.get("project_id")
    if project_id is not None and (
            not isinstance(project_id, str) or not project_id):
        return "project_id must be a non-empty string"
    if name == "resume_packet":
        budget = arguments.get("token_budget")
        if budget is not None and (
                isinstance(budget, bool) or not isinstance(budget, int)
                or not 1 <= budget <= 100_000):
            return "token_budget must be an integer from 1 to 100000"
        fmt = arguments.get("format")
        if fmt is not None and fmt not in ("markdown", "json"):
            return "format must be 'markdown' or 'json'"
    return None


def _handle(request: dict, session: _Session) -> dict | None:
    has_id = "id" in request
    notification = not has_id
    request_id = request.get("id") if has_id else None
    if request.get("jsonrpc") != "2.0":
        return _error(None, _INVALID_REQUEST, "jsonrpc must be '2.0'")
    if has_id and not _valid_request_id(request_id):
        return _error(None, _INVALID_REQUEST,
                      "request id must be a string or integer")
    method = request.get("method")
    if not isinstance(method, str) or not method:
        return None if notification else _error(
            request_id, _INVALID_REQUEST, "method must be a non-empty string")
    params = request.get("params", {})
    if not isinstance(params, dict):
        return None if notification else _error(
            request_id, _INVALID_PARAMS, "params must be an object")

    # Notifications are one-way. In particular, a tool-shaped notification
    # must never execute a read path that may be expensive or stateful.
    if notification:
        if method == "notifications/initialized" \
                and session.state == "initializing":
            session.state = "ready"
        return None

    # Ping is the sole request permitted during initialization and must not
    # pay the cost of opening project state.
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}

    if method == "initialize":
        if session.state != "new":
            return _error(request_id, _INVALID_REQUEST,
                          "connection is already initialized")
        if not _valid_initialize(params):
            return _error(
                request_id, _INVALID_PARAMS,
                "initialize requires protocolVersion, capabilities, and clientInfo")
        requested = params["protocolVersion"]
        session.state = "initializing"
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": (
                requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                else PROTOCOL_VERSION),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": _version()}}}

    if session.state != "ready":
        return _error(request_id, _INVALID_REQUEST,
                      "initialize the connection before normal operations")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return _error(request_id, _INVALID_PARAMS,
                          "tool arguments must be an object")
        if name not in _TOOLS_BY_NAME:
            return _error(request_id, _INVALID_PARAMS,
                          f"unknown tool: {name!r}")
        argument_error = _tool_argument_error(name, arguments)
        if argument_error:
            return _error(request_id, _INVALID_PARAMS, argument_error)
        try:
            body = session.call(name, arguments)
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            # A tool failure is a result with isError, not a protocol error:
            # the call was well formed and the client needs to see why.
            traceback.print_exc(file=sys.stderr)
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": _text(f"{type(exc).__name__}: {exc}",
                                    is_error=True)}
        return {"jsonrpc": "2.0", "id": request_id, "result": _text(body)}
    return _error(request_id, _METHOD_NOT_FOUND,
                  f"unknown method: {method!r}")


def _version() -> str:
    from . import __version__

    return __version__


def serve(directory: str = ".", *, stdin=None, stdout=None) -> int:
    """Read JSON-RPC requests until stdin closes. Returns a process exit code."""
    source = sys.stdin if stdin is None else stdin
    sink = sys.stdout if stdout is None else stdout
    session = _Session(str(Path(directory)))
    try:
        for line in source:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except ValueError:
                response = {"jsonrpc": "2.0", "id": None,
                            "error": {"code": _PARSE_ERROR,
                                      "message": "invalid JSON"}}
            else:
                if not isinstance(request, dict):
                    response = {"jsonrpc": "2.0", "id": None,
                                "error": {"code": _INVALID_REQUEST,
                                          "message": "request must be an object"}}
                else:
                    try:
                        response = _handle(request, session)
                    except Exception as exc:  # noqa: BLE001
                        traceback.print_exc(file=sys.stderr)
                        response = {"jsonrpc": "2.0", "id": request.get("id"),
                                    "error": {"code": _INTERNAL_ERROR,
                                              "message": str(exc)}}
            if response is not None:
                sink.write(json.dumps(response, ensure_ascii=False) + "\n")
                sink.flush()
    finally:
        session.close()
    return 0
