"""Authenticated, fail-closed HTTP API for the PLT-001 endpoint contracts.

The production caveat remains explicit: ``http.server`` provides only basic
HTTP handling and is not a hosted-service boundary.  The local entry point
binds an IP loopback literal, requires a minimum-length bearer token, verifies
GitHub's HMAC over the untouched request bytes, bounds request size, socket I/O
timeout, and worker count, and never accepts executable verifier definitions.
It does not provide TLS, OS-user isolation, distributed rate limiting, or a
browser security boundary; a hosted service still needs a real gateway
(PLT-001).

``make_handler`` requires a syntactically valid, minimum-length API token even
when it is used as an embedding seam. ``serve`` additionally requires a
minimum-length webhook secret. Route metadata below is also the sole source for
the checked public API document.
"""

from __future__ import annotations

import hmac
import json
import math
import re
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .capsule import CapsuleError
from .core import strict_json_loads, validate_public_identifier
from .engine import AttestationInputError, GitHubDeliveryError
from .github import (
    WebhookError,
    WebhookPayloadError,
    validate_webhook_secret,
    verify_signature,
)
from .invalidation import ResolutionInputError
from .store import PayloadMismatchError

_MAX_BODY_BYTES = 1024 * 1024
_MAX_CONFIGURED_BODY_BYTES = 25 * 1024 * 1024
_MAX_TOKEN_BUDGET = 100_000
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 15.0
_MAX_REQUEST_TIMEOUT_SECONDS = 300.0
_DEFAULT_MAX_WORKERS = 8
_MAX_WORKERS = 64
_MIN_SECRET_BYTES = 32
_MAX_SECRET_BYTES = 4096
_BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*\Z")
_GITHUB_EVENT_HEADER = re.compile(r"[a-z][a-z_]{0,63}\Z", re.ASCII)
_ASSUMPTION_STATUSES = frozenset({
    "active", "supported", "uncertain", "resolved", "invalidated", "superseded",
})
_CONTINUITY_RELATIONS = frozenset({
    "task_ids", "requirement_ids", "decision_ids", "assumption_ids",
    "artifact_ids", "evidence_ids", "action_ids",
})
_VERIFICATION_RESULTS = frozenset({
    "passed", "failed", "skipped", "missing", "inconclusive", "stale",
})
_MISSING = object()


class RequestValidationError(Exception):
    """A caller-controlled request failed an explicit API contract check."""

    def __init__(self, field: str, message: str, *, code: str = "invalid_request"):
        super().__init__(message)
        self.field = field
        self.code = code
        self.message = message


class UnsupportedMediaTypeError(RequestValidationError):
    def __init__(self):
        super().__init__(
            "Content-Type", "Content-Type must be application/json",
            code="unsupported_media_type")


class APIResourceNotFound(Exception):
    """A deliberately scoped lookup found neither local nor disclosable state."""

    def __init__(self, resource: str):
        super().__init__(resource)
        self.resource = resource


class APIForbidden(Exception):
    """A request failed an API-owned tenant, project, or identity boundary."""


class RequestTooLarge(Exception):
    def __init__(self, limit: int):
        super().__init__(f"request body exceeds {limit}-byte limit")
        self.limit = limit


@dataclass(frozen=True)
class RouteSpec:
    method: str
    template: str
    pattern: re.Pattern[str]
    name: str
    auth: str
    request: str
    response: str
    success: int


def _route(method: str, template: str, pattern: str, name: str, auth: str,
           request: str, response: str, success: int) -> RouteSpec:
    return RouteSpec(
        method, template, re.compile(pattern), name, auth, request, response, success)


API_ROUTES = (
    _route("GET", "/v1/projects/{project_id}/assumptions",
           r"^/v1/projects/([^/]+)/assumptions$", "assumptions", "bearer",
           "Optional status query: comma-separated documented assumption statuses.",
           "Array of assumption summaries.", 200),
    _route("GET", "/v1/projects/{project_id}/invalidations",
           r"^/v1/projects/([^/]+)/invalidations$", "invalidations", "bearer",
           "No body.", "Array of open invalidation summaries.", 200),
    _route("GET", "/v1/evaluations", r"^/v1/evaluations$", "evaluations", "bearer",
           "No body.", "Array of evaluation summaries for the bound project.", 200),
    _route("GET", "/v1/health", r"^/v1/health$", "health", "public",
           "No body.", "Object with status=ok. This is the only unauthenticated route.", 200),
    _route("POST", "/v1/events:ingest", r"^/v1/events:ingest$", "events_ingest",
           "webhook", "Raw GitHub JSON payload; HMAC is checked before JSON parsing.",
           "Ingestion report, duplicate status, or ping health response.", 202),
    _route("POST", "/v1/traces:ingest", r"^/v1/traces:ingest$", "traces_ingest",
           "bearer", "Object: span_id; optional project_id, session_id, payload object.",
           "Ingestion report or duplicate status.", 202),
    _route("POST", "/v1/projects/{project_id}/resume-packets:compose",
           r"^/v1/projects/([^/]+)/resume-packets:compose$", "compose", "bearer",
           "Object: optional token_budget integer and target object.",
           "cce.resume.v1 object.", 200),
    _route("POST", "/v1/assumptions/{assumption_id}:resolve",
           r"^/v1/assumptions/([^/]+):resolve$", "resolve", "bearer",
           "Object selecting direct resolution or a typed invalidation that "
           "targets/affects the path resource.",
           "Resolved node or invalidation summary.", 200),
    _route("POST", "/v1/actions:attest", r"^/v1/actions:attest$", "attest", "bearer",
           "Object: intent_type plus optional statement, actor, action_type, "
           "verifications, continuity.",
           "cce.proof.v1 object.", 200),
    _route("POST", "/v1/verifications:run", r"^/v1/verifications:run$",
           "verifications_run", "bearer",
           "Object: optional intent fields and continuity; executable definitions are forbidden.",
           "cce.proof.v1 object.", 200),
    _route("POST", "/v1/projects/{project_id}/continuity-receipts:verify",
           r"^/v1/projects/([^/]+)/continuity-receipts:verify$",
           "continuity_receipt_verify", "bearer", "Object containing receipt object.",
           "CURRENT, AUTHENTIC_HISTORICAL, or INVALID verdict object.", 200),
    _route("POST", "/v1/migrations:prepare", r"^/v1/migrations:prepare$",
           "migrations_prepare", "bearer",
           "Object with optional scoped session and non-empty source/target strings.",
           "cce.capsule.v1 object.", 200),
    _route("POST", "/v1/migrations:validate", r"^/v1/migrations:validate$",
           "migrations_validate", "bearer",
           "Object containing capsule plus optional non-empty target model/runtime.",
           "Imported session, challenge, and validation object.", 200),
    _route("POST", "/v1/replays", r"^/v1/replays$", "replays", "bearer",
           "Object: from_event_id plus optional project_id and object-valued "
           "captured_inputs, mocks, fork.",
           "Replay node and fidelity object.", 201),
)


def render_api_document() -> str:
    """Render the complete public API contract from the live route registry."""
    auth_labels = {
        "public": "Public health check",
        "bearer": "Bearer token",
        "webhook": "GitHub HMAC",
    }
    lines = [
        "# Local HTTP API",
        "",
        "> Generated from `causal_continuity_engine.api.API_ROUTES`. Do not edit by hand.",
        "> Run `python .github/scripts/render_api_docs.py --write` after changing routes.",
        "",
        "CCE's built-in HTTP server is a loopback integration endpoint. It binds only",
        "`127.0.0.1`; it does not provide TLS, OS-user isolation, a browser security",
        "boundary, or distributed rate limiting. Put a deployment-grade authenticated",
        "gateway in front of it before any non-loopback exposure.",
        "",
        "## Authentication and requests",
        "",
        "Every route except `GET /v1/health` requires authentication. Ordinary routes",
        "use `Authorization: Bearer <api.token>`. `POST /v1/events:ingest` instead",
        "checks `X-Hub-Signature-256` over the untouched request bytes before parsing",
        "JSON, then requires `X-GitHub-Event` and `X-GitHub-Delivery`.",
        "",
        "Every POST requires `Content-Type: application/json` (parameters such as",
        "`charset=utf-8` are allowed). JSON must be an object, have no duplicate keys or",
        "non-finite numbers, and satisfy the route's typed field contract. The default",
        f"body limit is {_MAX_BODY_BYTES} bytes; configured limits must be between 1 and",
        f"{_MAX_CONFIGURED_BODY_BYTES} bytes. The socket I/O timeout must be finite,",
        "positive,",
        f"and at most {_MAX_REQUEST_TIMEOUT_SECONDS:g} seconds. Worker count is bounded",
        f"between 1 and {_MAX_WORKERS}.",
        "",
        "Every public resource identifier is one URI path segment: 1–128 ASCII",
        "unreserved characters, beginning with a letter or digit and continuing with",
        "letters, digits, `.`, `_`, `~`, or `-`. Slash, percent escapes, whitespace,",
        "controls, Unicode, dot segments, and longer values are rejected as",
        "`invalid_identifier`; clients must not encode an otherwise-invalid identity.",
        "",
        "GitHub sends `ping` when a webhook is created. A valid signed repository ping",
        "must carry `hook`, positive `hook_id`, `zen`, and the bound positive numeric",
        "`repository.id`; it returns 200 without persisting an event. GitHub's documented",
        "ping object does not declare `installation`, so absence does not fail setup. If",
        "installation is present it is checked, and every operational event still must",
        "match a configured installation id. See GitHub's [webhook payload reference]",
        "[github-webhook-payloads].",
        "",
        "## Routes",
        "",
        "| Method | Path | Authentication | Request | Success response | Status |",
        "|---|---|---|---|---|---:|",
    ]
    for route in API_ROUTES:
        lines.append(
            f"| {route.method} | `{route.template}` | {auth_labels[route.auth]} | "
            f"{route.request} | {route.response} | {route.success} |")
    lines.extend([
        "",
        "## Errors and method handling",
        "",
        "Every error uses the same JSON shape:",
        "",
        "```json",
        '{"error":{"code":"invalid_request","message":"...","field":"token_budget"}}',
        "```",
        "",
        "`field` is omitted when no request field applies. Explicit validation, including",
        "an `invalid_identifier`, is 400;",
        "missing/invalid bearer credentials are 401 with `WWW-Authenticate: Bearer`;",
        "project-scope denial is 403; an explicitly scoped missing resource is 404; a",
        "known route with the wrong method is 405 with exact `Allow`; idempotency-key",
        "payload conflict is 409; oversized input is 413; wrong media type is 415; and an",
        "authenticated unsupported GitHub event is 422. Unexpected implementation errors",
        "are generic 500 responses and disclose no exception detail.",
        "",
        "Unknown paths return JSON 404. GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS,",
        "TRACE, and CONNECT all pass through the same dispatcher; the standard-library",
        "HTML error pages and Python version banner are not part of this API.",
        "",
        "[github-webhook-payloads]: "
        "https://docs.github.com/en/webhooks/webhook-events-and-payloads#ping",
    ])
    return "\n".join(lines) + "\n"


def _error_body(code: str, message: str, field: str | None = None) -> dict:
    error = {"code": code, "message": message}
    if field is not None:
        error["field"] = field
    return {"error": error}


def _reject_unknown(body: dict, allowed) -> None:
    unknown = sorted(set(body) - set(allowed))
    if unknown:
        raise RequestValidationError(
            "body", f"unknown request field(s): {', '.join(unknown)}",
            code="unknown_field")


def _required_string(body: dict, field: str, *, allow_empty: bool = False) -> str:
    value = body.get(field, _MISSING)
    if value is _MISSING:
        raise RequestValidationError(field, f"{field} is required", code="missing_field")
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise RequestValidationError(field, f"{field} must be {qualifier}")
    return value


def _optional_string(
    body: dict,
    field: str,
    default: str | None = None,
    *,
    allow_none: bool = False,
    allow_empty: bool = False,
) -> str | None:
    if field not in body:
        return default
    if body[field] is None and allow_none:
        return None
    return _required_string(body, field, allow_empty=allow_empty)


def _identifier(value, field: str) -> str:
    try:
        return validate_public_identifier(value, field=field)
    except ValueError as exc:
        raise RequestValidationError(
            field, str(exc), code="invalid_identifier") from None


def _required_identifier(body: dict, field: str) -> str:
    return _identifier(_required_string(body, field), field)


def _optional_identifier(
    body: dict,
    field: str,
    default: str | None = None,
    *,
    allow_none: bool = False,
) -> str | None:
    value = _optional_string(
        body, field, default, allow_none=allow_none)
    if value is None:
        return None
    return _identifier(value, field)


def _required_object(body: dict, field: str) -> dict:
    value = body.get(field, _MISSING)
    if value is _MISSING:
        raise RequestValidationError(field, f"{field} is required", code="missing_field")
    if not isinstance(value, dict):
        raise RequestValidationError(field, f"{field} must be a JSON object")
    return value


def _optional_object(
    body: dict,
    field: str,
    default=None,
    *,
    allow_none: bool = False,
) -> dict | None:
    if field not in body:
        return default
    if body[field] is None and allow_none:
        return None
    return _required_object(body, field)


def _required_list(body: dict, field: str) -> list:
    value = body.get(field, _MISSING)
    if value is _MISSING:
        raise RequestValidationError(field, f"{field} is required", code="missing_field")
    if not isinstance(value, list):
        raise RequestValidationError(field, f"{field} must be a JSON array")
    return value


def _optional_list(body: dict, field: str, default=None, *, allow_none: bool = False):
    if field not in body:
        return default
    if body[field] is None and allow_none:
        return None
    return _required_list(body, field)


def _required_bool(body: dict, field: str) -> bool:
    value = body.get(field, _MISSING)
    if value is _MISSING:
        raise RequestValidationError(field, f"{field} is required", code="missing_field")
    if not isinstance(value, bool):
        raise RequestValidationError(field, f"{field} must be a boolean")
    return value


def _optional_bool(body: dict, field: str, default: bool | None = None) -> bool | None:
    if field not in body:
        return default
    return _required_bool(body, field)


def _required_int(
    body: dict,
    field: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    value = body.get(field, _MISSING)
    if value is _MISSING:
        raise RequestValidationError(field, f"{field} is required", code="missing_field")
    if isinstance(value, bool) or not isinstance(value, int):
        raise RequestValidationError(field, f"{field} must be an integer")
    if ((minimum is not None and value < minimum)
            or (maximum is not None and value > maximum)):
        if minimum is not None and maximum is not None:
            message = f"{field} must be between {minimum} and {maximum}"
        elif minimum is not None:
            message = f"{field} must be at least {minimum}"
        else:
            message = f"{field} must be at most {maximum}"
        raise RequestValidationError(field, message)
    return value


def _optional_int(
    body: dict,
    field: str,
    default: int | None = None,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if field not in body:
        return default
    return _required_int(body, field, minimum=minimum, maximum=maximum)


def _validate_continuity(body: dict, field: str = "continuity") -> dict | None:
    continuity = _optional_object(body, field)
    if continuity is None:
        return None
    unknown = sorted(set(continuity) - _CONTINUITY_RELATIONS)
    if unknown:
        raise RequestValidationError(
            field, f"{field} has unknown relation(s): {', '.join(unknown)}")
    for relation, targets in continuity.items():
        if (not isinstance(targets, list)
                or any(not isinstance(target, str) or not target for target in targets)):
            raise RequestValidationError(
                f"{field}.{relation}",
                f"{field}.{relation} must be an array of non-empty node ids")
        for index, target in enumerate(targets):
            _identifier(target, f"{field}.{relation}[{index}]")
        if len(targets) != len(set(targets)):
            raise RequestValidationError(
                f"{field}.{relation}", f"{field}.{relation} must not contain duplicates")
    return continuity


def _validate_verifications(body: dict) -> list[dict] | None:
    values = _optional_list(body, "verifications")
    if values is None:
        return None
    for index, value in enumerate(values):
        field = f"verifications[{index}]"
        if not isinstance(value, dict):
            raise RequestValidationError(field, f"{field} must be a JSON object")
        verifier = value.get("verifier")
        if not isinstance(verifier, str) or not verifier.strip():
            raise RequestValidationError(
                f"{field}.verifier", f"{field}.verifier must be a non-empty string")
        result = value.get("result")
        if (not isinstance(result, str)
                or result not in _VERIFICATION_RESULTS):
            raise RequestValidationError(
                f"{field}.result", f"{field}.result is not recognized")
    return values


def _bounded_int(name: str, value, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _validated_timeout(value) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value <= 0
            or value > _MAX_REQUEST_TIMEOUT_SECONDS):
        raise ValueError(
            "request_timeout_seconds must be finite and between 0 and "
            f"{_MAX_REQUEST_TIMEOUT_SECONDS}")
    return float(value)


def _validated_project_id(project_id) -> str:
    return validate_public_identifier(project_id, field="project_id")


def _validated_api_token(api_token) -> str:
    if not isinstance(api_token, str):
        raise ValueError("api_token must be an ASCII bearer-token string")
    try:
        encoded = api_token.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("api_token must contain only ASCII characters") from None
    if not _MIN_SECRET_BYTES <= len(encoded) <= _MAX_SECRET_BYTES:
        raise ValueError(
            f"api_token must be between {_MIN_SECRET_BYTES} and "
            f"{_MAX_SECRET_BYTES} ASCII bytes")
    if not _BEARER_TOKEN.fullmatch(api_token):
        raise ValueError("api_token contains characters forbidden in a bearer token")
    return api_token


def _validated_webhook_secret(webhook_secret, *, required: bool) -> bytes | None:
    return validate_webhook_secret(webhook_secret, required=required)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a fixed in-flight request ceiling."""

    daemon_threads = True
    request_queue_size = 16

    def __init__(
            self, server_address, handler, *, max_workers: int = _DEFAULT_MAX_WORKERS):
        max_workers = _bounded_int("max_workers", max_workers, 1, _MAX_WORKERS)
        self._request_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(server_address, handler)

    def process_request(self, request, client_address):
        self._request_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def make_handler(
    engine,
    project_id: str,
    *,
    api_token: str,
    webhook_secret: bytes | str | None = None,
    max_body_bytes: int = _MAX_BODY_BYTES,
    request_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
):
    project_id = _validated_project_id(project_id)
    api_token = _validated_api_token(api_token)
    webhook_secret = _validated_webhook_secret(webhook_secret, required=False)
    max_body_bytes = _bounded_int(
        "max_body_bytes", max_body_bytes, 1, _MAX_CONFIGURED_BODY_BYTES)
    request_timeout_seconds = _validated_timeout(request_timeout_seconds)

    class Handler(BaseHTTPRequestHandler):
        server_version = "CCE"
        sys_version = ""

        def setup(self):
            super().setup()
            self.request.settimeout(request_timeout_seconds)

        def log_message(self, *a):
            pass

        def version_string(self):
            return self.server_version

        def _send(self, code: int, obj, *, headers: dict | None = None):
            body = json.dumps(
                obj, allow_nan=False, ensure_ascii=False,
                separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_error(
                self, status: int, code: str, message: str, *,
                field: str | None = None, headers: dict | None = None):
            self._send(
                status, _error_body(code, message, field), headers=headers)

        def send_error(self, code, message=None, explain=None):
            # BaseHTTPRequestHandler otherwise emits an HTML page containing
            # its Python version. Keep even parser/fallback failures in the
            # same non-cacheable JSON contract.
            status = int(code)
            error_code = "unsupported_method" if status == 501 else "http_error"
            public = "unsupported HTTP method" if status == 501 else "HTTP request rejected"
            self._send_error(status, error_code, public)

        def _single_header(
                self, name: str, *, required: bool = False) -> str | None:
            values = self.headers.get_all(name) or []
            if len(values) > 1:
                raise RequestValidationError(
                    name, f"{name} must appear at most once")
            if not values:
                if required:
                    raise RequestValidationError(
                        name, f"{name} header is required",
                        code="missing_field")
                return None
            return values[0]

        def _require_json_media_type(self):
            media_type = (
                self._single_header("Content-Type") or "").split(";", 1)[0]
            if media_type.strip().lower() != "application/json":
                raise UnsupportedMediaTypeError()

        @staticmethod
        def _parse_object(raw: bytes, *, field: str = "body") -> dict:
            try:
                parsed = strict_json_loads(raw)
            except (ValueError, RecursionError):
                raise RequestValidationError(
                    field, "request body must be valid unambiguous JSON",
                    code="invalid_json") from None
            if not isinstance(parsed, dict):
                raise RequestValidationError(
                    field, "JSON request body must be an object")
            return parsed

        def _body(self, *, parse_json: bool = True) -> dict | bytes:
            if self.headers.get_all("Transfer-Encoding"):
                self.close_connection = True
                raise RequestValidationError(
                    "Transfer-Encoding",
                    "transfer encoding is unsupported; send Content-Length")
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1:
                self.close_connection = True
                raise RequestValidationError(
                    "Content-Length",
                    "POST requires exactly one Content-Length header")
            encoded_length = lengths[0]
            if re.fullmatch(r"(?:0|[1-9][0-9]*)", encoded_length) is None:
                self.close_connection = True
                raise RequestValidationError(
                    "Content-Length",
                    "Content-Length must be a canonical non-negative integer")
            encoded_limit = str(max_body_bytes)
            if (len(encoded_length) > len(encoded_limit)
                    or (len(encoded_length) == len(encoded_limit)
                        and encoded_length > encoded_limit)):
                # Compare the canonical decimal strings before int(). Python
                # deliberately rejects extremely long conversions; allowing
                # that interpreter guard to fire turned caller input into a
                # 500 instead of the documented request-size response.
                self.close_connection = True
                raise RequestTooLarge(max_body_bytes)
            length = int(encoded_length)
            if not length:
                self._raw_request_body = b""
                raise RequestValidationError(
                    "body", "request body must be a valid JSON object",
                    code="invalid_json")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise RequestValidationError(
                    "body", "request body ended before Content-Length")
            self._raw_request_body = raw
            if not parse_json:
                return raw
            return self._parse_object(raw)

        def _authorized(self) -> bool:
            header = self._single_header("Authorization") or ""
            scheme, _, supplied = header.partition(" ")
            return (
                scheme.lower() == "bearer"
                and _MIN_SECRET_BYTES <= len(supplied) <= _MAX_SECRET_BYTES
                and supplied.isascii()
                and _BEARER_TOKEN.fullmatch(supplied) is not None
                and hmac.compare_digest(supplied, api_token)
            )

        def _require_auth(self) -> bool:
            try:
                if self._authorized():
                    return True
            except RequestValidationError as exc:
                self._send_error(
                    400, exc.code, exc.message, field=exc.field)
                return False
            self._send_error(
                401, "unauthorized", "valid bearer token required",
                headers={"WWW-Authenticate": "Bearer"})
            return False

        @staticmethod
        def _project(pid: str) -> str:
            pid = _identifier(pid, "project_id")
            if pid != project_id:
                raise APIForbidden(
                    f"API is bound to project {project_id}, not {pid}")
            return pid

        @staticmethod
        def _require_session_in_project(session_id: str | None):
            """Validate a local session without probing outside API scope."""
            if session_id is None:
                return
            session_id = _identifier(session_id, "session_id")
            try:
                engine.graph.get(
                    session_id, tenant_id=engine.tenant_id,
                    project_id=project_id, entity_type="session")
            except KeyError:
                raise RequestValidationError(
                    "session_id",
                    "session_id is not a session in the bound project") from None

        @staticmethod
        def _parse_request_target(raw_target: str):
            message = (
                "request target must be an origin-form path without an "
                "authority or fragment")
            if (not isinstance(raw_target, str)
                    or not raw_target.startswith("/")
                    or "#" in raw_target
                    or any(ord(char) < 0x20 or ord(char) == 0x7F
                           for char in raw_target)):
                raise RequestValidationError(
                    "request_target", message)
            try:
                parsed = urlsplit(raw_target)
            except ValueError:
                raise RequestValidationError(
                    "request_target", message) from None
            if (parsed.scheme or parsed.netloc or parsed.fragment
                    or not parsed.path.startswith("/")):
                raise RequestValidationError(
                    "request_target", message)
            return parsed

        def _dispatch(self):
            try:
                target = self._parse_request_target(self.path)
                self._parsed_request_target = target
                path = target.path
                matches = [
                    (route, match)
                    for route in API_ROUTES
                    if (match := route.pattern.fullmatch(path)) is not None
                ]
                if not matches:
                    return self._send_error(
                        404, "not_found", "route not found")
                method_matches = [
                    item for item in matches if item[0].method == self.command]
                if not method_matches:
                    allow = ", ".join(sorted({
                        route.method for route, _ in matches}))
                    return self._send_error(
                        405, "method_not_allowed",
                        "method is not allowed for this route",
                        headers={"Allow": allow})

                route, match = method_matches[0]
                signed_webhook = (
                    route.auth == "webhook" and webhook_secret is not None)
                if (route.auth == "bearer"
                        or route.auth == "webhook" and not signed_webhook):
                    if not self._require_auth():
                        return None
                if target.query and route.name != "assumptions":
                    raise RequestValidationError(
                        "query", "query parameters are not supported for this route",
                        code="unknown_field")
                if route.method == "POST":
                    self._require_json_media_type()
                    body = self._body(parse_json=not signed_webhook)
                    return getattr(self, route.name)(body, *match.groups())
                return getattr(self, route.name)(*match.groups())
            except UnsupportedMediaTypeError as exc:
                return self._send_error(
                    415, exc.code, exc.message, field=exc.field)
            except RequestTooLarge as exc:
                return self._send_error(
                    413, "request_too_large",
                    f"request body exceeds {exc.limit}-byte limit", field="body")
            except RequestValidationError as exc:
                return self._send_error(
                    400, exc.code, exc.message, field=exc.field)
            except APIResourceNotFound as exc:
                return self._send_error(
                    404, "not_found", f"{exc.resource} was not found")
            except PayloadMismatchError:
                return self._send_error(
                    409, "idempotency_conflict",
                    "idempotency key was reused with different content")
            except WebhookPayloadError as exc:
                return self._send_error(
                    400, "invalid_webhook_payload", str(exc), field="body")
            except WebhookError as exc:
                return self._send_error(
                    422, "unsupported_webhook_event", str(exc), field="X-GitHub-Event")
            except CapsuleError as exc:
                return self._send_error(
                    400, "invalid_capsule", str(exc), field="capsule")
            except AttestationInputError as exc:
                return self._send_error(
                    400, "invalid_attestation", str(exc), field="attestation")
            except ResolutionInputError as exc:
                return self._send_error(
                    400, "invalid_resolution", str(exc), field="resolution")
            except (APIForbidden, GitHubDeliveryError):
                return self._send_error(
                    403, "forbidden", "request is outside the authorized project scope")
            except Exception:
                return self._send_error(
                    500, "internal_error", "internal server error")

        def do_GET(self):
            return self._dispatch()

        def do_POST(self):
            return self._dispatch()

        def do_HEAD(self):
            return self._dispatch()

        def do_PUT(self):
            return self._dispatch()

        def do_PATCH(self):
            return self._dispatch()

        def do_DELETE(self):
            return self._dispatch()

        def do_OPTIONS(self):
            return self._dispatch()

        def do_TRACE(self):
            return self._dispatch()

        def do_CONNECT(self):
            return self._dispatch()

        # ------------------------------------------------------------- GET

        def health(self):
            self._send(200, {"status": "ok"})

        def assumptions(self, pid):
            pid = self._project(pid)
            try:
                query = parse_qs(
                    self._parsed_request_target.query,
                    keep_blank_values=True, strict_parsing=True,
                    max_num_fields=2, separator="&")
            except ValueError:
                raise RequestValidationError(
                    "query", "query string is malformed") from None
            unknown = sorted(set(query) - {"status"})
            if unknown:
                raise RequestValidationError(
                    "query", f"unknown query parameter(s): {', '.join(unknown)}",
                    code="unknown_field")
            statuses = None
            if "status" in query:
                if len(query["status"]) != 1:
                    raise RequestValidationError(
                        "status", "status may be supplied only once")
                statuses = query["status"][0].split(",")
                if (not statuses or any(not status for status in statuses)
                        or len(statuses) != len(set(statuses))
                        or any(status not in _ASSUMPTION_STATUSES
                               for status in statuses)):
                    raise RequestValidationError(
                        "status", "status must be a comma-separated list of: "
                        + ", ".join(sorted(_ASSUMPTION_STATUSES)))
            nodes = engine.graph.current(
                pid, "assumption", status=statuses,
                tenant_id=engine.tenant_id)
            self._send(200, [
                {"node_id": n["node_id"], "status": n["status"],
                 "criticality": n["criticality"], "confidence": n["confidence"],
                 "statement": n["data"].get("statement")} for n in nodes])

        def invalidations(self, pid):
            pid = self._project(pid)
            invs = engine.invalidation.open_invalidations(pid)
            self._send(200, [
                {"node_id": i["node_id"], "status": i["status"], **i["data"]}
                for i in invs])

        def evaluations(self):
            evals = engine.graph.current(
                project_id, "evaluation", tenant_id=engine.tenant_id)
            self._send(200, [
                {"node_id": e["node_id"], "status": e["status"],
                 "kind": e["data"].get("kind")} for e in evals])

        # ------------------------------------------------------------ POST

        @staticmethod
        def _validate_ping(payload: dict):
            # GitHub's ping schema has repository for repository-scoped hooks,
            # but does not declare installation. Require the immutable repo id;
            # if an installation is present, bind it too. Operational events
            # still require an installation whenever project policy pins one.
            _required_object(payload, "hook")
            _required_int(payload, "hook_id", minimum=1)
            _required_string(payload, "zen")
            repository = _required_object(payload, "repository")
            delivered_id = _required_int(repository, "id", minimum=1)
            try:
                project = engine.graph.get(
                    project_id, tenant_id=engine.tenant_id,
                    project_id=project_id, entity_type="project")
            except KeyError:
                raise APIForbidden("bound project does not exist") from None
            configured_id = project["data"].get("repository_id")
            if (isinstance(configured_id, bool)
                    or not isinstance(configured_id, int)
                    or configured_id <= 0 or delivered_id != configured_id):
                raise APIForbidden("ping repository does not match the bound project")
            installation = payload.get("installation")
            configured_installation = project["data"].get(
                "github_installation_id")
            if (configured_installation is not None
                    and (isinstance(configured_installation, bool)
                         or not isinstance(configured_installation, int)
                         or configured_installation <= 0)):
                raise APIForbidden(
                    "bound project has an invalid installation identity")
            if installation is not None:
                if not isinstance(installation, dict):
                    raise RequestValidationError(
                        "installation", "installation must be a JSON object")
                delivered_installation = _required_int(
                    installation, "id", minimum=1)
                if (configured_installation is not None
                        and delivered_installation != configured_installation):
                    raise APIForbidden(
                        "ping installation does not match the bound project")

        def events_ingest(self, body):
            if webhook_secret is not None:
                raw = body
                signature = self._single_header("X-Hub-Signature-256")
                if (signature is None or not verify_signature(
                        webhook_secret, raw, signature)):
                    raise APIForbidden("GitHub webhook signature invalid")
                event_name = self._single_header(
                    "X-GitHub-Event", required=True)
                delivery_id = self._single_header(
                    "X-GitHub-Delivery", required=True)
                if (_GITHUB_EVENT_HEADER.fullmatch(event_name or "") is None):
                    raise RequestValidationError(
                        "X-GitHub-Event",
                        "X-GitHub-Event must be a bounded lowercase event name")
                try:
                    validate_public_identifier(
                        delivery_id, field="X-GitHub-Delivery")
                except ValueError as exc:
                    raise RequestValidationError(
                        "X-GitHub-Delivery", str(exc)) from None
                payload = self._parse_object(raw)
                pid = project_id
                if event_name == "ping":
                    self._validate_ping(payload)
                    return self._send(200, {"status": "ok", "event": "ping"})
            else:
                # Bearer-authenticated embedding compatibility. The shipped
                # server always configures a webhook secret.
                _reject_unknown(
                    body, {"project_id", "event_name", "delivery_id", "payload"})
                pid = self._project(
                    _optional_string(body, "project_id", project_id))
                event_name = _required_string(body, "event_name")
                delivery_id = _required_identifier(body, "delivery_id")
                payload = _required_object(body, "payload")
            signed_arguments = (
                {
                    "raw_body": raw,
                    "signature_header": signature,
                    "webhook_secret": webhook_secret,
                }
                if webhook_secret is not None else {}
            )
            report = engine.ingest_github(
                pid, event_name, delivery_id, payload, **signed_arguments)
            self._send(202, report or {"status": "duplicate"})

        def traces_ingest(self, body):
            _reject_unknown(body, {"project_id", "session_id", "span_id", "payload"})
            pid = self._project(_optional_identifier(
                body, "project_id", project_id))
            session_id = _optional_identifier(
                body, "session_id", allow_none=True)
            span_id = _required_identifier(body, "span_id")
            payload = _optional_object(body, "payload", {})
            if "message" in payload and not isinstance(payload["message"], str):
                raise RequestValidationError(
                    "payload.message", "payload.message must be a string")
            self._require_session_in_project(session_id)
            report = engine.ingest_agent_trace(
                pid, session_id=session_id, span_id=span_id, payload=payload)
            self._send(202, report or {"status": "duplicate"})

        def compose(self, body, pid):
            _reject_unknown(body, {"token_budget", "target"})
            pid = self._project(pid)
            budget = _optional_int(
                body, "token_budget", 4000,
                minimum=1, maximum=_MAX_TOKEN_BUDGET)
            target = _optional_object(body, "target")
            self._send(200, engine.resume_packet(
                pid, target=target, token_budget=budget))

        def resolve(self, body, assumption_id):
            assumption_id = _identifier(assumption_id, "assumption_id")
            try:
                node = engine.graph.get(
                    assumption_id, tenant_id=engine.tenant_id,
                    project_id=project_id)
            except KeyError:
                raise APIResourceNotFound("assumption") from None
            if node["project_id"] != project_id:
                raise APIForbidden("assumption belongs to another project")
            if node["entity_type"] not in ("assumption", "claim", "requirement",
                                           "constraint", "decision"):
                raise RequestValidationError(
                    "assumption_id",
                    f"cannot resolve a {node['entity_type']} through this endpoint",
                    code="invalid_resource_type")
            if "invalidation_id" in body:
                _reject_unknown(body, {
                    "invalidation_id", "mode", "actor", "replacement_node_id",
                    "narrowed_scope", "note",
                })
                inv_id = _required_identifier(body, "invalidation_id")
                mode = _optional_string(
                    body, "mode", "replacement_evidence")
                if mode not in {
                        "replacement_evidence", "narrowed_scope",
                        "superseding_decision"}:
                    raise RequestValidationError(
                        "mode", "mode must be replacement_evidence, "
                        "narrowed_scope, or superseding_decision")
                actor = _optional_string(body, "actor", "api")
                replacement = _optional_identifier(
                    body, "replacement_node_id", allow_none=True)
                narrowed_scope = _optional_object(
                    body, "narrowed_scope", allow_none=True)
                note = _optional_string(
                    body, "note", "", allow_empty=True)
                try:
                    invalidation = engine.graph.get(
                        inv_id, tenant_id=engine.tenant_id,
                        project_id=project_id, entity_type="invalidation")
                except KeyError:
                    raise APIResourceNotFound("invalidation") from None
                affected_ids = {
                    affected.get("node_id")
                    for affected in invalidation["data"].get("affected", [])
                    if isinstance(affected, dict)
                }
                if (invalidation["data"].get("target_node_id") != assumption_id
                        and assumption_id not in affected_ids):
                    raise RequestValidationError(
                        "invalidation_id",
                        "invalidation_id does not target or affect assumption_id",
                        code="resource_mismatch")
                if replacement is not None:
                    try:
                        engine.graph.get(
                            replacement, tenant_id=engine.tenant_id,
                            project_id=project_id)
                    except KeyError:
                        raise APIResourceNotFound("replacement node") from None
                out = engine.invalidation.resolve(
                    inv_id, mode=mode, actor=actor,
                    replacement_node_id=replacement,
                    narrowed_scope=narrowed_scope, note=note)
                return self._send(200, {"invalidation": out["node_id"],
                                        "status": out["status"]})
            _reject_unknown(body, {"action", "data"})
            # Scope the mutation. Without these two checks the endpoint
            # rewrites any node of any type in any project — a task, a proof
            # record, a project — because it reads the target's own
            # entity_type and never compares its project (ADR-052).
            action = _optional_string(body, "action", "accept")
            statuses = {"accept": "resolved", "reject": "invalidated",
                        "narrow": "active", "supersede": "superseded"}
            if action not in statuses:
                raise RequestValidationError(
                    "action",
                    "action must be accept, reject, narrow, or supersede")
            status = statuses[action]
            patch = _optional_object(body, "data")
            data = dict(node["data"])
            if patch is not None:
                data.update(patch)
            out = engine.graph.put_node(
                entity_type=node["entity_type"], tenant_id=node["tenant_id"],
                project_id=node["project_id"], node_id=assumption_id,
                data=data, status=status,
                authority="human_decision")
            self._send(200, {"node_id": out["node_id"], "status": out["status"]})

        def attest(self, body):
            _reject_unknown(body, {
                "project_id", "intent_type", "intent_statement", "actor",
                "action_type", "verifications", "continuity",
            })
            pid = self._project(
                _optional_identifier(body, "project_id", project_id))
            intent_type = _required_string(body, "intent_type")
            intent_statement = _optional_string(
                body, "intent_statement", "", allow_empty=True)
            actor = _optional_object(body, "actor", {"agent": "api"})
            action_type = _optional_string(
                body, "action_type", "run_verifier")
            verifications = _validate_verifications(body)
            continuity = _validate_continuity(body)
            proof = engine.attest_action(
                pid, intent_type=intent_type,
                intent_statement=intent_statement, actor=actor,
                action_type=action_type,
                verification_outcomes=verifications,
                continuity=continuity)
            self._send(200, proof)

        def verifications_run(self, body):
            if "verifiers" in body or "command" in body:
                raise RequestValidationError(
                    "verifiers",
                    "caller-supplied verifier definitions are forbidden; "
                    "configure pinned required_verifiers in project policy",
                    code="caller_verifier_forbidden")
            _reject_unknown(body, {
                "project_id", "intent_type", "intent_statement", "continuity",
            })
            pid = self._project(
                _optional_identifier(body, "project_id", project_id))
            intent_type = _optional_string(
                body, "intent_type", "verification_run")
            intent_statement = _optional_string(
                body, "intent_statement", "run policy-owned verifiers",
                allow_empty=True)
            continuity = _validate_continuity(body)
            proof = engine.attest_action(
                pid, intent_type=intent_type,
                intent_statement=intent_statement,
                actor={"agent": "api", "model": "n/a"},
                action_type="run_verifier",
                continuity=continuity)
            self._send(200, proof)

        def continuity_receipt_verify(self, body, pid):
            _reject_unknown(body, {"receipt"})
            pid = self._project(pid)
            receipt = _required_object(body, "receipt")
            self._send(
                200, engine.verify_continuity_receipt(pid, receipt))

        def migrations_prepare(self, body):
            _reject_unknown(body, {
                "project_id", "session_id", "source_model",
                "source_runtime", "target_adapter",
            })
            pid = self._project(
                _optional_identifier(body, "project_id", project_id))
            session_id = _optional_identifier(
                body, "session_id", allow_none=True)
            source_model = _optional_string(body, "source_model", "unknown")
            source_runtime = _optional_string(
                body, "source_runtime", "unknown")
            target_adapter = _optional_string(
                body, "target_adapter", "generic")
            self._require_session_in_project(session_id)
            capsule = engine.capsules.export(
                tenant_id=engine.tenant_id,
                project_id=pid, session_id=session_id,
                source_model=source_model,
                source_runtime=source_runtime,
                target_adapter=target_adapter,
                signer=engine.signer)
            self._send(200, capsule)

        def migrations_validate(self, body):
            _reject_unknown(body, {"capsule", "target_model", "target_runtime"})
            capsule = _required_object(body, "capsule")
            capsule_tenant = _identifier(
                _required_string(capsule, "tenant_id"), "capsule.tenant_id")
            capsule_project = _identifier(
                _required_string(capsule, "project_id"), "capsule.project_id")
            target_model = _optional_string(body, "target_model", "generic")
            target_runtime = _optional_string(
                body, "target_runtime", "generic")
            if capsule_tenant != engine.tenant_id:
                raise APIForbidden("migration capsule belongs to another tenant")
            self._project(capsule_project)
            result = engine.capsules.import_capsule(
                capsule, signer=engine.signer,
                target_model=target_model,
                target_runtime=target_runtime,
                expected_tenant_id=engine.tenant_id,
                expected_project_id=project_id)
            self._send(200, {"session_id": result["session"]["node_id"],
                             "challenge": result["challenge"],
                             "validation": result["validation"]})

        def replays(self, body):
            _reject_unknown(body, {
                "project_id", "from_event_id", "captured_inputs", "mocks", "fork",
            })
            pid = self._project(
                _optional_identifier(body, "project_id", project_id))
            from_event_id = _required_identifier(body, "from_event_id")
            captured_inputs = _optional_object(
                body, "captured_inputs", allow_none=True)
            mocks = _optional_object(body, "mocks", allow_none=True)
            fork = _optional_object(body, "fork", allow_none=True)
            try:
                engine.store.get_event(
                    from_event_id, tenant_id=engine.tenant_id, project_id=pid)
            except KeyError:
                raise APIForbidden(
                    "replay origin is outside the authorized project scope") from None
            node = engine.replay.start(
                tenant_id=engine.tenant_id,
                project_id=pid, from_event_id=from_event_id,
                captured_inputs=captured_inputs,
                mocks=mocks, fork=fork)
            self._send(201, {"replay_node": node["node_id"],
                             "fidelity": node["data"]["fidelity"]})

    return Handler


def serve(
    engine,
    project_id: str,
    port: int = 8199,
    *,
    api_token: str,
    webhook_secret: bytes | str,
    max_body_bytes: int = _MAX_BODY_BYTES,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    request_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
):
    project_id = _validated_project_id(project_id)
    port = _bounded_int("port", port, 1, 65_535)
    api_token = _validated_api_token(api_token)
    webhook_secret = _validated_webhook_secret(webhook_secret, required=True)
    max_body_bytes = _bounded_int(
        "max_body_bytes", max_body_bytes, 1, _MAX_CONFIGURED_BODY_BYTES)
    max_workers = _bounded_int("max_workers", max_workers, 1, _MAX_WORKERS)
    request_timeout_seconds = _validated_timeout(request_timeout_seconds)
    server = BoundedThreadingHTTPServer(
        ("127.0.0.1", port),
        make_handler(
            engine, project_id, api_token=api_token,
            webhook_secret=webhook_secret, max_body_bytes=max_body_bytes,
            request_timeout_seconds=request_timeout_seconds),
        max_workers=max_workers)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
