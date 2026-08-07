# Local HTTP API

> Generated from `causal_continuity_engine.api.API_ROUTES`. Do not edit by hand.
> Run `python .github/scripts/render_api_docs.py --write` after changing routes.

CCE's built-in HTTP server is a loopback integration endpoint. It binds only
`127.0.0.1`; it does not provide TLS, OS-user isolation, a browser security
boundary, or distributed rate limiting. Put a deployment-grade authenticated
gateway in front of it before any non-loopback exposure.

## Authentication and requests

Every route except `GET /v1/health` requires authentication. Ordinary routes
use `Authorization: Bearer <api.token>`. `POST /v1/events:ingest` instead
checks `X-Hub-Signature-256` over the untouched request bytes before parsing
JSON, then requires `X-GitHub-Event` and `X-GitHub-Delivery`.

Every POST requires `Content-Type: application/json` (parameters such as
`charset=utf-8` are allowed). JSON must be an object, have no duplicate keys or
non-finite numbers, and satisfy the route's typed field contract. The default
body limit is 1048576 bytes; configured limits must be between 1 and
26214400 bytes. The socket I/O timeout must be finite,
positive,
and at most 300 seconds. Worker count is bounded
between 1 and 64.

Every public resource identifier is one URI path segment: 1–128 ASCII
unreserved characters, beginning with a letter or digit and continuing with
letters, digits, `.`, `_`, `~`, or `-`. Slash, percent escapes, whitespace,
controls, Unicode, dot segments, and longer values are rejected as
`invalid_identifier`; clients must not encode an otherwise-invalid identity.

GitHub sends `ping` when a webhook is created. A valid signed repository ping
must carry `hook`, positive `hook_id`, `zen`, and the bound positive numeric
`repository.id`; it returns 200 without persisting an event. GitHub's documented
ping object does not declare `installation`, so absence does not fail setup. If
installation is present it is checked, and every operational event still must
match a configured installation id. See GitHub's [webhook payload reference]
[github-webhook-payloads].

## Routes

| Method | Path | Authentication | Request | Success response | Status |
|---|---|---|---|---|---:|
| GET | `/v1/projects/{project_id}/assumptions` | Bearer token | Optional status query: comma-separated documented assumption statuses. | Array of assumption summaries. | 200 |
| GET | `/v1/projects/{project_id}/invalidations` | Bearer token | No body. | Array of open invalidation summaries. | 200 |
| GET | `/v1/evaluations` | Bearer token | No body. | Array of evaluation summaries for the bound project. | 200 |
| GET | `/v1/health` | Public health check | No body. | Object with status=ok. This is the only unauthenticated route. | 200 |
| POST | `/v1/events:ingest` | GitHub HMAC | Raw GitHub JSON payload; HMAC is checked before JSON parsing. | Ingestion report, duplicate status, or ping health response. | 202 |
| POST | `/v1/traces:ingest` | Bearer token | Object: span_id; optional project_id, session_id, payload object. | Ingestion report or duplicate status. | 202 |
| POST | `/v1/projects/{project_id}/resume-packets:compose` | Bearer token | Object: optional token_budget integer and target object. | cce.resume.v1 object. | 200 |
| POST | `/v1/assumptions/{assumption_id}:resolve` | Bearer token | Object selecting direct resolution or a typed invalidation that targets/affects the path resource. | Resolved node or invalidation summary. | 200 |
| POST | `/v1/actions:attest` | Bearer token | Object: intent_type plus optional statement, actor, action_type, verifications, continuity. | cce.proof.v1 object. | 200 |
| POST | `/v1/verifications:run` | Bearer token | Object: optional intent fields and continuity; executable definitions are forbidden. | cce.proof.v1 object. | 200 |
| POST | `/v1/projects/{project_id}/continuity-receipts:verify` | Bearer token | Object containing receipt object. | CURRENT, AUTHENTIC_HISTORICAL, or INVALID verdict object. | 200 |
| POST | `/v1/migrations:prepare` | Bearer token | Object with optional scoped session and non-empty source/target strings. | cce.capsule.v1 object. | 200 |
| POST | `/v1/migrations:validate` | Bearer token | Object containing capsule plus optional non-empty target model/runtime. | Imported session, challenge, and validation object. | 200 |
| POST | `/v1/replays` | Bearer token | Object: from_event_id plus optional project_id and object-valued captured_inputs, mocks, fork. | Replay node and fidelity object. | 201 |

## Errors and method handling

Every error uses the same JSON shape:

```json
{"error":{"code":"invalid_request","message":"...","field":"token_budget"}}
```

`field` is omitted when no request field applies. Explicit validation, including
an `invalid_identifier`, is 400;
missing/invalid bearer credentials are 401 with `WWW-Authenticate: Bearer`;
project-scope denial is 403; an explicitly scoped missing resource is 404; a
known route with the wrong method is 405 with exact `Allow`; idempotency-key
payload conflict is 409; oversized input is 413; wrong media type is 415; and an
authenticated unsupported GitHub event is 422. Unexpected implementation errors
are generic 500 responses and disclose no exception detail.

Unknown paths return JSON 404. GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS,
TRACE, and CONNECT all pass through the same dispatcher; the standard-library
HTML error pages and Python version banner are not part of this API.

[github-webhook-payloads]: https://docs.github.com/en/webhooks/webhook-events-and-payloads#ping
