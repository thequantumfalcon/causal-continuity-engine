#!/usr/bin/env python3
"""Build a CCE project from a repository's real history, without a webhook.

    GITHUB_TOKEN=$(gh auth token) python examples/backfill_github.py owner/repo

Webhook delivery is the live ingest path, but every event type the engine
understands is also retrievable from the REST API after the fact. This script
reads issues and issue comments through the public API, re-shapes them into the
webhook envelopes `ingest_github` already accepts, and feeds them in — so a
project can be populated from months of existing history in one pass, on a
laptop, with no App, tunnel, or public endpoint.

It then prints what the engine extracted and a Resume Packet built from that
real history. That packet is the thing worth reading: it is the product's
actual output on real data rather than on fixtures.

Standard library plus this package only. Read-only against GitHub; the project
is written to a directory you name (default: a temporary one).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if not (ROOT / "causal_continuity_engine").is_dir():  # pragma: no cover
    raise SystemExit("run this script from a checkout of the repository")
sys.path.append(str(ROOT))

from causal_continuity_engine.engine import Engine  # noqa: E402

API = "https://api.github.com"
PAGE_SIZE = 100


def _get(path: str, token: str | None) -> object:
    request = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "cce-backfill-example",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise SystemExit(
            f"GitHub returned {exc.code} for {path}: {detail}") from None
    except urllib.error.URLError as exc:
        raise SystemExit(f"cannot reach GitHub: {exc.reason}") from None


def _paged(path: str, token: str | None, *, pages: int) -> list[dict]:
    collected: list[dict] = []
    for page in range(1, pages + 1):
        joiner = "&" if "?" in path else "?"
        batch = _get(
            f"{path}{joiner}per_page={PAGE_SIZE}&page={page}", token)
        if not isinstance(batch, list) or not batch:
            break
        collected.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < PAGE_SIZE:
            break
    return collected


def _repository(meta: dict) -> dict:
    return {"id": meta["id"], "full_name": meta["full_name"]}


def _issue_event(issue: dict, meta: dict) -> dict:
    """Reshape a REST issue into the `issues` webhook envelope."""
    return {
        "action": "opened",
        "repository": _repository(meta),
        "issue": {
            "number": issue["number"],
            "title": issue.get("title") or "",
            "state": issue.get("state") or "open",
            "body": issue.get("body") or "",
            "author_association": issue.get("author_association") or "NONE",
            "created_at": issue["created_at"],
            "updated_at": issue.get("updated_at") or issue["created_at"],
            "labels": [{"name": label.get("name", "")}
                       for label in issue.get("labels", [])
                       if isinstance(label, dict)],
        },
    }


def _comment_event(comment: dict, issue_number: int, meta: dict) -> dict:
    """Reshape a REST issue comment into the `issue_comment` envelope."""
    return {
        "action": "created",
        "repository": _repository(meta),
        "issue": {"number": issue_number},
        "comment": {
            "id": comment["id"],
            "body": comment.get("body") or "",
            "author_association": comment.get("author_association") or "NONE",
            "created_at": comment["created_at"],
            "updated_at": comment.get("updated_at") or comment["created_at"],
        },
    }


def _frontier_event(head_sha: str, meta: dict) -> dict:
    """A tracked-ref event, so evidence has an observed commit to attach to."""
    return {
        "ref": f"refs/heads/{meta.get('default_branch', 'main')}",
        "before": "0" * 40,
        "after": head_sha,
        "created": True,
        "deleted": False,
        "forced": False,
        "commits": [],
        "repository": _repository(meta),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", help="owner/repo")
    parser.add_argument(
        "--dir", default=None,
        help="project directory (default: a temporary one, discarded)")
    parser.add_argument(
        "--pages", type=int, default=2,
        help=f"pages of {PAGE_SIZE} issues to read (default: 2)")
    parser.add_argument(
        "--token-env", default="GITHUB_TOKEN",
        help="environment variable holding a token (default: GITHUB_TOKEN)")
    args = parser.parse_args(argv)

    if "/" not in args.repository:
        raise SystemExit("repository must be owner/repo")
    token = os.environ.get(args.token_env)
    if not token:
        print(f"no {args.token_env} set — using unauthenticated requests,"
              " which are rate limited to 60/hour", file=sys.stderr)

    print(f"reading {args.repository} ...")
    meta = _get(f"/repos/{args.repository}", token)
    if not isinstance(meta, dict):
        raise SystemExit("unexpected repository response")
    head = _get(
        f"/repos/{args.repository}/commits/{meta['default_branch']}", token)
    head_sha = head["sha"] if isinstance(head, dict) else "0" * 40

    issues = _paged(
        f"/repos/{args.repository}/issues?state=all", token, pages=args.pages)
    # The issues endpoint returns pull requests too; they arrive again through
    # their own event type, so keep this pass to genuine issues.
    issues = [issue for issue in issues if "pull_request" not in issue]
    comments = _paged(
        f"/repos/{args.repository}/issues/comments", token, pages=args.pages)
    print(f"  {len(issues)} issues, {len(comments)} comments,"
          f" head {head_sha[:8]}")

    holder = args.dir or tempfile.mkdtemp(prefix="cce-backfill-")
    workdir = Path(holder)
    workdir.mkdir(parents=True, exist_ok=True)
    engine = Engine(workdir / "cce.db", tenant_id="ten_backfill",
                    workdir=workdir)
    try:
        project = engine.create_project(
            meta["name"], project_id="prj_backfill",
            repository=meta["full_name"], repository_id=meta["id"])
        project_id = project["project_id"] if isinstance(project, dict) \
            else "prj_backfill"

        events: list[tuple[str, str, dict]] = [
            ("push", f"backfill-frontier-{head_sha[:8]}",
             _frontier_event(head_sha, meta))]
        for issue in issues:
            events.append((
                "issues", f"backfill-issue-{issue['number']}",
                _issue_event(issue, meta)))
        for comment in comments:
            number = int(
                str(comment.get("issue_url", "")).rsplit("/", 1)[-1] or 0)
            if number:
                events.append((
                    "issue_comment", f"backfill-comment-{comment['id']}",
                    _comment_event(comment, number, meta)))

        nodes = invalidations = conflicts = 0
        for event_name, delivery_id, payload in events:
            report = engine.ingest_github(
                project_id, event_name, delivery_id, payload)
            if report:
                nodes += len(report.get("nodes", []))
                invalidations += len(report.get("invalidations", []))
                conflicts += len(report.get("conflicts", []))
        print(f"  ingested {len(events)} events -> {nodes} node(s),"
              f" {invalidations} invalidation(s), {conflicts} conflict(s)")

        print("\n== What the extractor typed as control state")
        for entity in ("assumption", "constraint", "requirement", "decision"):
            found = engine.graph.current(
                project_id, entity, tenant_id=engine.tenant_id)
            for node in found[:5]:
                statement = (node.get("data", {}).get("statement")
                             or node.get("data", {}).get("title") or "")
                print(f"  [{entity}/{node.get('status')}] {statement[:96]}")
            if found:
                print(f"  ... {len(found)} {entity}(s) total")

        print("\n== Resume Packet from real history")
        print(engine.resume_packet(
            project_id, token_budget=1500, fmt="markdown"))

        print(f"\nproject kept at {workdir}" if args.dir else
              f"\ntemporary project at {workdir} (delete when done)")
    finally:
        engine.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
