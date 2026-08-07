"""GitHub-native integration (GHI-001..GHI-008).

Webhook signature verification (X-Hub-Signature-256), delivery-ID
idempotency, and normalization of subscribed events into canonical CCE
events. This module is transport-free: it takes payload dicts (from a live
webhook receiver or fixtures) and returns normalized envelopes for the
engine. No network calls.

Source typing (R3/AD-006): issue and PR text is 'human_intent' — evidence
about work, never policy. README/docs/comments are 'untrusted_content'.
Commits/config are 'repository_authoritative'; check/workflow results are
'verifier_authoritative'. Check payloads retain their GitHub App slug and
sender identity for the policy layer to decide whether that producer is
trusted. ``workflow_run`` does not carry a Checks-App object; it retains the
stable workflow id/path plus actor, triggering actor, sender, and installation
id. Policy may pin the id/path. Transport authenticity proves GitHub sent the
identity fields; actor names alone never approve a verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from .core import is_rfc3339_datetime, validate_public_identifier

SUBSCRIBED_EVENTS = {
    "installation", "installation_repositories", "push", "pull_request",
    "pull_request_review", "issues", "issue_comment", "check_run",
    "check_suite", "workflow_run", "release", "repository",
}
WEBHOOK_SECRET_MIN_BYTES = 32
WEBHOOK_SECRET_MAX_BYTES = 4096
WEBHOOK_BODY_MAX_BYTES = 1024 * 1024


# GHI-005/AD-006: only these author associations carry project work intent.
# Anyone else commenting on a public repository is untrusted content, so their
# text can propose but never mandate (extraction demotes requirements and
# constraints from untrusted sources to claims).
TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
_SIGNATURE_HEADER = re.compile(r"sha256=[0-9a-f]{64}\Z", re.ASCII)


def validate_webhook_secret(
        webhook_secret: object, *, required: bool = True) -> bytes | None:
    """Return one bounded byte credential shared by HTTP and direct callers."""
    if webhook_secret is None and not required:
        return None
    if isinstance(webhook_secret, str):
        encoded = webhook_secret.encode("utf-8")
    elif isinstance(webhook_secret, bytes):
        encoded = webhook_secret
    else:
        raise ValueError("webhook_secret must be bytes or a string")
    if not WEBHOOK_SECRET_MIN_BYTES <= len(encoded) <= WEBHOOK_SECRET_MAX_BYTES:
        raise ValueError(
            f"webhook_secret must be between {WEBHOOK_SECRET_MIN_BYTES} and "
            f"{WEBHOOK_SECRET_MAX_BYTES} bytes")
    return encoded


def text_authority(author_association: str | None) -> str:
    """Source authority for text authored by a GitHub account.

    An issue or comment body is evidence about intent, never policy — and
    whose intent it is decides how much weight it carries.
    """
    if (isinstance(author_association, str)
            and author_association.upper() in TRUSTED_ASSOCIATIONS):
        return "human_intent"
    return "untrusted_content"


def verify_signature(secret: bytes | str, payload: bytes, signature_header: str | None) -> bool:
    """GHI-002: constant-time X-Hub-Signature-256 validation."""
    if (not isinstance(signature_header, str)
            or _SIGNATURE_HEADER.fullmatch(signature_header) is None):
        return False
    if isinstance(secret, str):
        secret = secret.encode()
    expected = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


class WebhookError(Exception):
    pass


class WebhookPayloadError(WebhookError):
    """A subscribed event carried a malformed JSON payload shape."""


def _object(
        container: dict, field: str, *, context: str = "payload",
        required: bool = False) -> dict:
    value = container.get(field)
    if value is None:
        if required:
            raise WebhookPayloadError(
                f"{context}.{field} must be an object")
        return {}
    if not isinstance(value, dict):
        raise WebhookPayloadError(
            f"{context}.{field} must be an object or null")
    return value


def _objects(
        container: dict, field: str, *, context: str,
        required: bool = False) -> list[dict]:
    value = container.get(field)
    if value is None:
        if required:
            raise WebhookPayloadError(
                f"{context}.{field} must be an array of objects")
        return []
    if (not isinstance(value, list)
            or any(not isinstance(item, dict) for item in value)):
        raise WebhookPayloadError(
            f"{context}.{field} must be an array of objects or null")
    return value


def _text(
        container: dict, field: str, *, context: str,
        required: bool = False) -> None:
    value = container.get(field)
    if ((required and (not isinstance(value, str) or not value))
            or (value is not None and not isinstance(value, str))):
        raise WebhookPayloadError(
            f"{context}.{field} must be "
            f"{'a non-empty string' if required else 'a string or null'}")


def _positive_integer(
        container: dict, field: str, *, context: str,
        required: bool = True) -> None:
    value = container.get(field)
    if value is None and not required:
        return
    if (isinstance(value, bool) or not isinstance(value, int)
            or not 1 <= value <= 9_223_372_036_854_775_807):
        raise WebhookPayloadError(
            f"{context}.{field} must be a positive 64-bit integer")


def _boolean(container: dict, field: str, *, context: str) -> None:
    if not isinstance(container.get(field), bool):
        raise WebhookPayloadError(f"{context}.{field} must be a boolean")


def _timestamp(
        container: dict, field: str, *, context: str,
        required: bool = False) -> None:
    value = container.get(field)
    if value is None and not required:
        return
    if not is_rfc3339_datetime(value):
        raise WebhookPayloadError(
            f"{context}.{field} must be an RFC 3339 date-time")


def _validate_payload_shape(event_name: str, payload: dict) -> None:
    """Validate every container/text operand before normalization persists it."""
    app_level = event_name in ("installation", "installation_repositories")
    if event_name != "push":
        _text(payload, "action", context="payload", required=True)
    repository = _object(
        payload, "repository", required=not app_level)
    if (not app_level
            or ("repository" in payload
                and payload.get("repository") is not None)):
        _positive_integer(repository, "id", context="payload.repository")
        _text(
            repository, "full_name", context="payload.repository",
            required=True)
    installation = _object(
        payload, "installation", required=app_level)
    if (app_level
            or ("installation" in payload
                and payload.get("installation") is not None)):
        _positive_integer(
            installation, "id", context="payload.installation")
    sender = _object(payload, "sender")
    for field in ("login", "type"):
        _text(sender, field, context="payload.sender")

    if event_name == "push":
        for field in ("ref", "before", "after"):
            _text(payload, field, context="payload", required=True)
        for field in ("forced", "deleted", "created"):
            _boolean(payload, field, context="payload")
        head = _object(payload, "head_commit")
        _timestamp(head, "timestamp", context="payload.head_commit")
        for index, commit in enumerate(
                _objects(
                    payload, "commits", context="payload", required=True)):
            context = f"payload.commits[{index}]"
            _text(commit, "id", context=context, required=True)
            _text(commit, "message", context=context, required=True)
    elif event_name == "pull_request":
        pull = _object(payload, "pull_request", required=True)
        _positive_integer(pull, "number", context="payload.pull_request")
        base = _object(
            pull, "base", context="payload.pull_request", required=True)
        head = _object(
            pull, "head", context="payload.pull_request", required=True)
        _text(base, "sha", context="payload.pull_request.base", required=True)
        _text(head, "sha", context="payload.pull_request.head", required=True)
        _boolean(pull, "merged", context="payload.pull_request")
        for field in ("title", "state"):
            _text(
                pull, field, context="payload.pull_request", required=True)
        _timestamp(
            pull, "updated_at", context="payload.pull_request", required=True)
        for field in (
                "author_association", "body"):
            _text(pull, field, context="payload.pull_request")
        _timestamp(pull, "created_at", context="payload.pull_request")
    elif event_name == "pull_request_review":
        review = _object(payload, "review", required=True)
        pull = _object(payload, "pull_request", required=True)
        _positive_integer(review, "id", context="payload.review")
        _positive_integer(pull, "number", context="payload.pull_request")
        _timestamp(
            review, "submitted_at", context="payload.review", required=True)
        _text(review, "state", context="payload.review", required=True)
        for field in ("author_association", "body"):
            _text(review, field, context="payload.review")
    elif event_name == "issues":
        issue = _object(payload, "issue", required=True)
        _positive_integer(issue, "number", context="payload.issue")
        for field in ("title", "state"):
            _text(issue, field, context="payload.issue", required=True)
        _timestamp(issue, "created_at", context="payload.issue", required=True)
        for field in (
                "author_association", "body"):
            _text(issue, field, context="payload.issue")
        _timestamp(issue, "updated_at", context="payload.issue")
        for index, label in enumerate(
                _objects(
                    issue, "labels", context="payload.issue")):
            _text(label, "name", context=f"payload.issue.labels[{index}]")
    elif event_name == "issue_comment":
        comment = _object(payload, "comment", required=True)
        issue = _object(payload, "issue", required=True)
        _positive_integer(comment, "id", context="payload.comment")
        _positive_integer(issue, "number", context="payload.issue")
        _text(comment, "body", context="payload.comment", required=True)
        _timestamp(
            comment, "created_at", context="payload.comment", required=True)
        for field in ("author_association",):
            _text(comment, field, context="payload.comment")
    elif event_name in ("check_run", "check_suite"):
        field = event_name
        context = f"payload.{field}"
        check = _object(payload, field, required=True)
        _positive_integer(check, "id", context=context)
        app = _object(check, "app", context=context, required=True)
        _positive_integer(app, "id", context=f"{context}.app")
        _text(app, "slug", context=f"{context}.app", required=True)
        for name in ("status", "head_sha"):
            _text(check, name, context=context, required=True)
        if event_name == "check_run":
            _text(check, "name", context=context, required=True)
        _text(check, "conclusion", context=context)
        for name in ("completed_at", "started_at", "updated_at"):
            _timestamp(check, name, context=context)
    elif event_name == "workflow_run":
        run = _object(payload, "workflow_run", required=True)
        _positive_integer(run, "id", context="payload.workflow_run")
        _positive_integer(
            run, "workflow_id", context="payload.workflow_run")
        actor = _object(run, "actor", context="payload.workflow_run")
        triggering = _object(
            run, "triggering_actor", context="payload.workflow_run")
        for context, identity in (
                ("payload.workflow_run.actor", actor),
                ("payload.workflow_run.triggering_actor", triggering)):
            for field in ("login", "type"):
                _text(identity, field, context=context)
        for field in ("name", "status", "head_sha", "path"):
            _text(run, field, context="payload.workflow_run", required=True)
        _timestamp(
            run, "updated_at", context="payload.workflow_run", required=True)
        for field in ("conclusion",):
            _text(run, field, context="payload.workflow_run")
    elif event_name == "installation_repositories":
        repositories = []
        for field in ("repositories_added", "repositories_removed"):
            for index, repository_item in enumerate(_objects(
                    payload, field, context="payload", required=True)):
                context = f"payload.{field}[{index}]"
                _positive_integer(repository_item, "id", context=context)
                _text(
                    repository_item, "full_name", context=context,
                    required=True)
                repositories.append(repository_item)
        if not repositories:
            raise WebhookPayloadError(
                "installation_repositories must identify at least one repository")
    elif event_name == "repository":
        changes = _object(payload, "changes")
        changed_repository = _object(
            changes, "repository", context="payload.changes")
        changed_name = _object(
            changed_repository, "name",
            context="payload.changes.repository",
            required="name" in changed_repository)
        _text(
            changed_name, "from",
            context="payload.changes.repository.name")
    elif event_name == "release":
        release = _object(payload, "release", required=True)
        _positive_integer(release, "id", context="payload.release")
        _text(
            release, "tag_name", context="payload.release", required=True)
        _text(release, "body", context="payload.release")
        _timestamp(release, "published_at", context="payload.release")


def normalize(event_name: str, delivery_id: str, payload: dict) -> dict:
    """Normalize a GitHub webhook into a canonical CCE event envelope.

    Returns {source_type, source_id, idempotency_key, authority, observed_at,
    payload, text_blocks: [{text, authority, ref}], flags}.
    """
    if not isinstance(event_name, str) or event_name not in SUBSCRIBED_EVENTS:
        raise WebhookError(f"unsubscribed event {event_name!r}")
    validate_public_identifier(delivery_id, field="delivery_id")
    if not isinstance(payload, dict):
        raise WebhookPayloadError("webhook payload must be an object")
    _validate_payload_shape(event_name, payload)
    repo = payload.get("repository", {}) or {}
    base = {
        "source_type": f"github:{event_name}",
        "idempotency_key": f"github:{delivery_id}",
        "repository": repo.get("full_name"),
        # ``full_name`` is mutable (repository transfers and renames). The
        # numeric id is GitHub's stable routing identity and is checked by
        # Engine before any canonical event is appended.
        "repository_id": repo.get("id"),
        "installation_id": (payload.get("installation") or {}).get("id"),
        "text_blocks": [],
        "flags": {},
    }
    handler = _HANDLERS.get(event_name, _default_handler)
    envelope = handler(payload, base)
    envelope.setdefault("authority", "repository_authoritative")
    envelope.setdefault("observed_at", None)
    envelope["payload"] = payload
    return envelope


def _default_handler(payload: dict, base: dict) -> dict:
    base["source_id"] = str(payload.get("action", ""))
    return base


def _push(payload: dict, base: dict) -> dict:
    base.update({
        "source_id": payload.get("after"),
        "authority": "repository_authoritative",
        "observed_at": (payload.get("head_commit") or {}).get("timestamp"),
    })
    base["flags"] = {
        "forced": bool(payload.get("forced")),
        "deleted": bool(payload.get("deleted")),
        "created": bool(payload.get("created")),
        "ref": payload.get("ref"),
        "before": payload.get("before"),
        "after": payload.get("after"),
    }
    for commit in payload.get("commits", []) or []:
        # The commit itself is authoritative repository state, but its MESSAGE
        # is free text written by whoever authored the commit — including a
        # fork contributor whose branch lands in a PR. Treat it as untrusted
        # content so it is injection-screened and cannot mandate anything.
        base["text_blocks"].append({
            "text": commit.get("message", ""),
            "authority": "untrusted_content",
            "ref": f"commit:{commit.get('id')}",
        })
    return base


def _pull_request(payload: dict, base: dict) -> dict:
    pr = payload.get("pull_request", {}) or {}
    association = pr.get("author_association")
    authority = text_authority(association)
    base.update({
        "source_id": f"pr:{pr.get('number')}",
        "authority": authority,
        "observed_at": pr.get("updated_at") or pr.get("created_at"),
    })
    base["flags"] = {
        "action": payload.get("action"),
        "merged": bool(pr.get("merged")),
        "base_sha": (pr.get("base") or {}).get("sha"),
        "head_sha": (pr.get("head") or {}).get("sha"),
        "state": pr.get("state"),
        "author_association": association,
    }
    for field in ("title", "body"):
        if pr.get(field):
            base["text_blocks"].append({
                "text": pr[field], "authority": authority,
                "ref": f"pr:{pr.get('number')}:{field}",
            })
    return base


def _pull_request_review(payload: dict, base: dict) -> dict:
    review = payload.get("review", {}) or {}
    pr = payload.get("pull_request", {}) or {}
    association = review.get("author_association")
    authority = text_authority(association)
    base.update({
        "source_id": f"pr:{pr.get('number')}:review:{review.get('id')}",
        "authority": authority,
        "observed_at": review.get("submitted_at"),
    })
    base["flags"] = {"state": review.get("state"), "action": payload.get("action"),
                     "author_association": association}
    if review.get("body"):
        base["text_blocks"].append({
            "text": review["body"], "authority": authority,
            "ref": f"review:{review.get('id')}",
        })
    return base


def _issues(payload: dict, base: dict) -> dict:
    issue = payload.get("issue", {}) or {}
    association = issue.get("author_association")
    authority = text_authority(association)
    base.update({
        "source_id": f"issue:{issue.get('number')}",
        "authority": authority,
        "observed_at": issue.get("updated_at") or issue.get("created_at"),
    })
    base["flags"] = {"action": payload.get("action"),
                     "state": issue.get("state"),
                     "author_association": association,
                     "labels": [lbl.get("name") for lbl in issue.get("labels", []) or []]}
    for field in ("title", "body"):
        if issue.get(field):
            base["text_blocks"].append({
                "text": issue[field], "authority": authority,
                "ref": f"issue:{issue.get('number')}:{field}",
            })
    return base


def _issue_comment(payload: dict, base: dict) -> dict:
    comment = payload.get("comment", {}) or {}
    issue = payload.get("issue", {}) or {}
    association = comment.get("author_association")
    authority = text_authority(association)
    base.update({
        "source_id": f"issue:{issue.get('number')}:comment:{comment.get('id')}",
        "authority": authority,
        "observed_at": comment.get("created_at"),
    })
    body = comment.get("body", "") or ""
    base["flags"] = {
        "action": payload.get("action"),
        "command": body.strip().split("\n")[0] if body.strip().startswith("/cce") else None,
        "author_association": association,
    }
    if body:
        base["text_blocks"].append({
            "text": body, "authority": authority,
            "ref": f"comment:{comment.get('id')}",
        })
    return base


def _check_run(payload: dict, base: dict) -> dict:
    check = payload.get("check_run", {}) or {}
    app = check.get("app", {}) or {}
    sender = payload.get("sender", {}) or {}
    base.update({
        "source_id": f"check:{check.get('id')}",
        "authority": "verifier_authoritative",
        "observed_at": check.get("completed_at") or check.get("started_at"),
    })
    base["flags"] = {
        "name": check.get("name"),
        "status": check.get("status"),
        "conclusion": check.get("conclusion"),
        "head_sha": check.get("head_sha"),
        "app": app.get("slug"),
        "app_id": app.get("id"),
        "sender": sender.get("login"),
        "sender_type": sender.get("type"),
        "installation_id": (payload.get("installation") or {}).get("id"),
    }
    return base


def _check_suite(payload: dict, base: dict) -> dict:
    suite = payload.get("check_suite", {}) or {}
    app = suite.get("app", {}) or {}
    sender = payload.get("sender", {}) or {}
    base.update({
        "source_id": f"suite:{suite.get('id')}",
        "authority": "verifier_authoritative",
        "observed_at": suite.get("updated_at"),
    })
    base["flags"] = {
        "status": suite.get("status"),
        "conclusion": suite.get("conclusion"),
        "head_sha": suite.get("head_sha"),
        "app": app.get("slug"),
        "app_id": app.get("id"),
        "sender": sender.get("login"),
        "sender_type": sender.get("type"),
        "installation_id": (payload.get("installation") or {}).get("id"),
    }
    return base


def _workflow_run(payload: dict, base: dict) -> dict:
    run = payload.get("workflow_run", {}) or {}
    actor = run.get("actor", {}) or {}
    triggering_actor = run.get("triggering_actor", {}) or {}
    sender = payload.get("sender", {}) or {}
    base.update({
        "source_id": f"workflow:{run.get('id')}",
        "authority": "verifier_authoritative",
        "observed_at": run.get("updated_at"),
    })
    base["flags"] = {
        "name": run.get("name"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "head_sha": run.get("head_sha"),
        "app": None,
        "workflow_id": run.get("workflow_id"),
        "workflow_path": run.get("path"),
        "actor": actor.get("login"),
        "actor_type": actor.get("type"),
        "triggering_actor": triggering_actor.get("login"),
        "sender": sender.get("login"),
        "sender_type": sender.get("type"),
        "installation_id": (payload.get("installation") or {}).get("id"),
    }
    return base


def _installation(payload: dict, base: dict) -> dict:
    inst = payload.get("installation", {}) or {}
    base.update({
        "source_id": f"installation:{inst.get('id')}",
        "authority": "repository_authoritative",
    })
    base["flags"] = {"action": payload.get("action")}
    return base


def _installation_repositories(payload: dict, base: dict) -> dict:
    inst = payload["installation"]
    added = payload["repositories_added"]
    removed = payload["repositories_removed"]
    base.update({
        "source_id": f"installation:{inst['id']}:{payload['action']}",
        "authority": "repository_authoritative",
        "repository_ids": [repo["id"] for repo in added + removed],
    })
    base["flags"] = {
        "action": payload["action"],
        "added_repository_ids": [repo["id"] for repo in added],
        "removed_repository_ids": [repo["id"] for repo in removed],
    }
    return base


def _repository(payload: dict, base: dict) -> dict:
    changes = payload.get("changes") or {}
    changed_repository = changes.get("repository") or {}
    changed_name = changed_repository.get("name") or {}
    base.update({
        "source_id": f"repository:{payload.get('action')}",
        "authority": "repository_authoritative",
    })
    base["flags"] = {
        "action": payload.get("action"),   # renamed | archived | ...
        "old_name": changed_name.get("from"),
    }
    return base


def _release(payload: dict, base: dict) -> dict:
    release = payload.get("release", {}) or {}
    base.update({
        "source_id": f"release:{release.get('id')}",
        "authority": "repository_authoritative",
        "observed_at": release.get("published_at"),
    })
    base["flags"] = {"tag": release.get("tag_name"), "action": payload.get("action")}
    if release.get("body"):
        base["text_blocks"].append({
            "text": release["body"], "authority": "untrusted_content",
            "ref": f"release:{release.get('tag_name')}",
        })
    return base


_HANDLERS = {
    "push": _push,
    "pull_request": _pull_request,
    "pull_request_review": _pull_request_review,
    "issues": _issues,
    "issue_comment": _issue_comment,
    "check_run": _check_run,
    "check_suite": _check_suite,
    "workflow_run": _workflow_run,
    "installation": _installation,
    "installation_repositories": _installation_repositories,
    "repository": _repository,
    "release": _release,
}


# Check-run conclusions CCE publishes (GHI-004). Cancellation and timeout
# never convert to success.
def continuity_conclusion(*, critical_invalidation: bool, proof_ok: bool,
                          packet_current: bool, authority_conflict: bool,
                          approval_needed: bool, trust_unavailable: bool) -> str:
    conditions = {
        "critical_invalidation": critical_invalidation,
        "proof_ok": proof_ok,
        "packet_current": packet_current,
        "authority_conflict": authority_conflict,
        "approval_needed": approval_needed,
        "trust_unavailable": trust_unavailable,
    }
    malformed = [
        name for name, value in conditions.items()
        if not isinstance(value, bool)
    ]
    if malformed:
        raise ValueError(
            "continuity conclusion inputs must be booleans: "
            + ", ".join(malformed))
    if trust_unavailable:
        return "cancelled"
    if critical_invalidation or authority_conflict or approval_needed:
        return "action_required"
    if not proof_ok:
        return "failure"
    if packet_current:
        return "success"
    return "neutral"
