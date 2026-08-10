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

PROTOCOL_VERSION = "2026-07-28"
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
            },
        },
    },
    {
        "name": "list_assumptions",
        "description": (
            "Active assumptions extracted from repository prose. These are "
            "proposals, not authority: an assumption is what the project "
            "currently believes, and may have been contradicted."),
        "inputSchema": {"type": "object", "properties": dict(_PROJECT_ARG)},
    },
    {
        "name": "list_invalidations",
        "description": (
            "Open invalidations: state contradicted by later evidence, with "
            "the blast radius computed over typed edges."),
        "inputSchema": {"type": "object", "properties": dict(_PROJECT_ARG)},
    },
    {
        "name": "continuity_check",
        "description": (
            "Whether the project is in a continuous state. Absence of success "
            "is never success: anything other than success is reported as "
            "such, never as a pass."),
        "inputSchema": {"type": "object", "properties": dict(_PROJECT_ARG)},
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
        _, meta = self._open()
        requested = arguments.get("project_id")
        return requested if requested else meta["project_id"]

    def call(self, name: str, arguments: dict) -> str:
        engine, _ = self._open()
        project_id = self.project(arguments)
        if name == "resume_packet":
            budget = arguments.get("token_budget", 4000)
            return engine.resume_packet(
                project_id, token_budget=budget, fmt="markdown")
        if name == "list_assumptions":
            nodes = engine.graph.current(
                project_id, "assumption", tenant_id=engine.tenant_id)
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
                f"- {item.get('severity', '?')}: {item.get('reason', '')}"
                for item in open_items)
        if name == "continuity_check":
            report = engine.continuity_check(project_id)
            return json.dumps(report, indent=2, sort_keys=True)
        raise KeyError(name)

    def close(self) -> None:
        if self._engine is not None:
            self._engine.close()
            self._engine = None


def _handle(request: dict, session: _Session) -> dict | None:
    if request.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": request.get("id"),
                "error": {"code": _INVALID_REQUEST,
                          "message": "jsonrpc must be '2.0'"}}
    method = request.get("method")
    request_id = request.get("id")
    notification = request_id is None

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": _version()}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        if name not in _TOOLS_BY_NAME:
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": _INVALID_PARAMS,
                              "message": f"unknown tool: {name!r}"}}
        try:
            body = session.call(name, params.get("arguments") or {})
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            # A tool failure is a result with isError, not a protocol error:
            # the call was well formed and the client needs to see why.
            traceback.print_exc(file=sys.stderr)
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": _text(f"{type(exc).__name__}: {exc}",
                                    is_error=True)}
        return {"jsonrpc": "2.0", "id": request_id, "result": _text(body)}
    if notification:
        return None
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": _METHOD_NOT_FOUND,
                      "message": f"unknown method: {method!r}"}}


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
