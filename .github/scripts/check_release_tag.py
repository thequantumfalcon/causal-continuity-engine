"""Bind a release tag exactly to the package version and current commit."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATHS = {
    "ci": ".github/workflows/ci.yml",
    "attribution": ".github/workflows/no-ai-attribution.yml",
    "secrets": ".github/workflows/secret-scan.yml",
}
# These branch requirements are intentionally excluded from the release
# quorum: neither is a reviewed push-event attestation for the squash commit.
# Any other extra context is rejected until its event/path semantics are added
# here deliberately rather than being ignored by accident.
PR_ONLY_BRANCH_CONTEXTS = frozenset({"dependency-review", "DCO"})
SIGNATURE_MARKERS = (
    "-----BEGIN PGP SIGNATURE-----",
    "-----BEGIN SSH SIGNATURE-----",
)
MAX_GITHUB_JSON_BYTES = 8 * 1024 * 1024
MAX_RULESET_BYTES = 256 * 1024
GITHUB_REQUIRED_CHECK_MAX_AGE = timedelta(days=7)
GITHUB_REQUIRED_CHECK_MAX_FUTURE_SKEW = timedelta(minutes=5)
_GITHUB_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z")
_GITHUB_REPOSITORY_COMPONENT = re.compile(r"[A-Za-z0-9_.-]{1,100}")


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


_GITHUB_OPENER = urllib.request.build_opener(_RejectRedirects())


def _strict_json_object(payload: bytes, *, label: str) -> dict:
    if len(payload) > MAX_GITHUB_JSON_BYTES:
        raise SystemExit(f"{label} exceeds the JSON size limit")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SystemExit(f"{label} must contain one JSON object")
    return document


def _release_version() -> str:
    """Use the exact-release verifier's non-executing dynamic-version contract."""
    verifier_path = ROOT / ".github" / "scripts" / "verify_distributions.py"
    spec = importlib.util.spec_from_file_location(
        "causal_continuity_engine_release_identity", verifier_path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release identity verifier")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    _, version = verifier._project_contract(ROOT)
    return version


def _verify_release_metadata(tag: str) -> str:
    path = ROOT / ".github" / "scripts" / "check_release_metadata.py"
    spec = importlib.util.spec_from_file_location(
        "causal_continuity_engine_release_metadata", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release metadata verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    version, _ = module.check(ROOT, release_tag=tag)
    return version


def _required_checks(source_root: Path = ROOT) -> dict[str, tuple[int, str]]:
    """Derive the fixed release quorum from the committed branch ruleset."""
    try:
        ruleset_bytes = (source_root / ".github" / "ruleset.json").read_bytes()
    except OSError as exc:
        raise SystemExit("cannot read the committed branch ruleset") from exc
    if len(ruleset_bytes) > MAX_RULESET_BYTES:
        raise SystemExit("committed branch ruleset exceeds the size limit")
    ruleset = _strict_json_object(
        ruleset_bytes, label="committed branch ruleset")
    if not isinstance(ruleset, dict) or ruleset.get("target") != "branch":
        raise SystemExit("committed branch ruleset has malformed identity")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise SystemExit("committed branch ruleset has malformed rules")
    status_rules = [rule for rule in rules if rule.get("type") == "required_status_checks"]
    if len(status_rules) != 1:
        raise SystemExit("branch ruleset must define exactly one required_status_checks rule")
    parameters = status_rules[0].get("parameters")
    if (
        not isinstance(parameters, dict)
        or parameters.get("strict_required_status_checks_policy") is not True
    ):
        raise SystemExit("branch required checks must use strict head synchronization")
    entries = parameters.get("required_status_checks")
    if not isinstance(entries, list) or not entries:
        raise SystemExit("branch ruleset has no required status contexts")
    derived: dict[str, tuple[int, str]] = {}
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"context", "integration_id"}:
            raise SystemExit("branch ruleset contains malformed required-check metadata")
        context = entry["context"]
        integration_id = entry["integration_id"]
        if (
            not isinstance(context, str)
            or not context
            or isinstance(integration_id, bool)
            or not isinstance(integration_id, int)
            or integration_id <= 0
            or context in seen
        ):
            raise SystemExit("branch ruleset contains invalid or duplicate check context")
        seen.add(context)
        expected_path = WORKFLOW_PATHS.get(context)
        if expected_path is not None:
            derived[context] = (integration_id, expected_path)
        elif context not in PR_ONLY_BRANCH_CONTEXTS:
            raise SystemExit(
                f"branch ruleset contains unclassified required context {context!r}")
    if set(derived) != set(WORKFLOW_PATHS):
        missing = sorted(set(WORKFLOW_PATHS) - set(derived))
        raise SystemExit(
            "branch ruleset omits core release context(s): " + ", ".join(missing))
    return derived


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "--no-replace-objects", *args], cwd=ROOT, text=True, timeout=30).strip()
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("release Git identity check timed out after 30s") from exc


def _git_bytes(*args: str) -> bytes:
    environment = dict(os.environ)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        return subprocess.check_output(
            ["git", "--no-replace-objects", *args],
            cwd=ROOT,
            env=environment,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("release Git object read timed out after 30s") from exc


def _verify_git_object_id(oid: str, kind: str, payload: bytes) -> None:
    algorithms = {40: hashlib.sha1, 64: hashlib.sha256}
    algorithm = algorithms.get(len(oid))
    if algorithm is None or any(character not in "0123456789abcdef" for character in oid):
        raise SystemExit("release Git object has an unsupported identifier")
    header = f"{kind} {len(payload)}\0".encode("ascii")
    if algorithm(header + payload).hexdigest() != oid:
        raise SystemExit("release Git object bytes do not match their identifier")


def _content_scanner():
    path = ROOT / ".github" / "scripts" / "check_content_marks.py"
    name = "causal_continuity_engine_release_content_marks"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the release content-integrity scanner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _scan_tag_object(tag: str, payload: bytes) -> None:
    scanner = _content_scanner()
    findings = scanner.scan_blob(f"<tag:{tag}>", payload, text_required=True)
    incomplete = [finding for finding in findings if finding.status == scanner.INCONCLUSIVE]
    if incomplete:
        raise SystemExit(
            f"release tag object content-integrity scan is incomplete: {incomplete[0].code}"
        )
    if findings:
        raise SystemExit(
            f"release tag object contains prohibited content: {findings[0].code}"
        )


def _validated_repository(repository: object) -> str:
    if not isinstance(repository, str) or repository != repository.strip():
        raise SystemExit("GitHub repository must be an owner/name slug")
    parts = repository.split("/")
    if (
        len(parts) != 2
        or any(_GITHUB_REPOSITORY_COMPONENT.fullmatch(part) is None for part in parts)
        or any(part in {".", ".."} for part in parts)
    ):
        raise SystemExit("GitHub repository must be an owner/name slug")
    return repository


def _github_repository() -> str:
    return _validated_repository(os.environ.get("GITHUB_REPOSITORY"))


def _validated_https_url(value: object, *, label: str, origin_only: bool) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SystemExit(f"{label} must be a canonical HTTPS URL")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise SystemExit(f"{label} must be a canonical HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
        or (origin_only and parsed.path not in {"", "/"})
    ):
        raise SystemExit(f"{label} must be a canonical HTTPS URL")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = "" if origin_only else parsed.path.rstrip("/")
    return urllib.parse.urlunsplit(("https", netloc, path, "", ""))


def _github_server_url() -> str:
    raw = os.environ.get("GITHUB_SERVER_URL")
    return _validated_https_url(
        "https://github.com" if raw is None else raw,
        label="GITHUB_SERVER_URL",
        origin_only=True,
    )


def _github_api_url() -> str:
    server = urllib.parse.urlsplit(_github_server_url())
    raw = os.environ.get("GITHUB_API_URL")
    if raw is None:
        raw = (
            "https://api.github.com"
            if server.hostname == "github.com"
            else urllib.parse.urlunsplit(
                ("https", server.netloc, "/api/v3", "", ""))
        )
    api = _validated_https_url(
        raw, label="GITHUB_API_URL", origin_only=False)
    parsed = urllib.parse.urlsplit(api)
    if server.hostname == "github.com":
        allowed = api == "https://api.github.com"
    else:
        allowed = (
            parsed.scheme == server.scheme
            and parsed.netloc == server.netloc
            and parsed.path == "/api/v3"
        )
    if not allowed:
        raise SystemExit(
            "GITHUB_API_URL is outside the server-bound GitHub API allowlist")
    return api


def _github_json(path: str) -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if (
        not isinstance(token, str)
        or not token
        or token != token.strip()
        or any(ord(char) < 33 or ord(char) == 127 for char in token)
    ):
        raise SystemExit("GitHub verification requires GITHUB_TOKEN or GH_TOKEN")
    api = _github_api_url()
    url = f"{api}/{path.lstrip('/')}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _GITHUB_OPENER.open(request, timeout=15) as response:
            if response.status != 200 or response.geturl() != url:
                raise SystemExit("GitHub verification response changed origin or status")
            payload = response.read(MAX_GITHUB_JSON_BYTES + 1)
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise SystemExit(f"GitHub verification request failed: {exc}") from exc
    return _strict_json_object(payload, label="GitHub response")


def _verification(payload: object, *, label: str) -> dict:
    required = {"verified", "reason", "signature", "payload", "verified_at"}
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise SystemExit(f"GitHub returned malformed {label} verification metadata")
    if (
        type(payload["verified"]) is not bool
        or not isinstance(payload["reason"], str)
        or not payload["reason"]
        or not isinstance(payload["signature"], (str, type(None)))
        or not isinstance(payload["payload"], (str, type(None)))
        or not isinstance(payload["verified_at"], (str, type(None)))
    ):
        raise SystemExit(f"GitHub returned malformed {label} verification metadata")
    if payload["verified"] is True and (
        not isinstance(payload["signature"], str)
        or not payload["signature"]
        or not isinstance(payload["payload"], str)
        or not payload["payload"]
        or not isinstance(payload["verified_at"], str)
        or not payload["verified_at"]
    ):
        raise SystemExit(f"GitHub returned malformed verified {label} metadata")
    return payload


def _verify_github_tag(tag_object: str, repository: str | None = None) -> None:
    repository = urllib.parse.quote(
        _validated_repository(repository) if repository is not None
        else _github_repository(),
        safe="/",
    )
    payload = _github_json(f"repos/{repository}/git/tags/{tag_object}")
    if payload.get("sha") != tag_object:
        raise SystemExit("GitHub returned tag verification for the wrong object")
    verification = _verification(
        payload.get("verification"), label="tag-object signature")
    if verification["verified"] is not True:
        reason = verification.get("reason", "unknown")
        raise SystemExit(f"GitHub did not verify the annotated tag signature: {reason}")


def _verify_github_commit(commit: str, repository: str | None = None) -> None:
    repository = urllib.parse.quote(
        _validated_repository(repository) if repository is not None
        else _github_repository(),
        safe="/",
    )
    payload = _github_json(f"repos/{repository}/commits/{commit}")
    commit_metadata = payload.get("commit")
    if payload.get("sha") != commit or not isinstance(commit_metadata, dict):
        raise SystemExit("GitHub returned commit verification for the wrong object")
    verification = _verification(
        commit_metadata.get("verification"), label="commit signature")
    if verification["verified"] is not True:
        reason = verification.get("reason", "unknown")
        raise SystemExit(f"GitHub did not verify the release commit signature: {reason}")


def _signed_tag_headers(tag_body: str) -> dict[str, str]:
    """Parse the signed annotated-tag headers, excluding message/signature."""
    header_block = tag_body.split("\n\n", 1)[0]
    headers: dict[str, str] = {}
    for line in header_block.splitlines():
        if not line or line[0].isspace():
            continue
        key, separator, value = line.partition(" ")
        if separator and key not in headers:
            headers[key] = value
    return headers


def _workflow_run_id(details_url: object, repository: str) -> str | None:
    if not isinstance(details_url, str):
        return None
    repository = _validated_repository(repository)
    server = _github_server_url()
    prefix = f"{server}/{repository}/actions/runs/"
    if not details_url.startswith(prefix):
        return None
    run_id = details_url[len(prefix):].split("/", 1)[0]
    return run_id if run_id.isdecimal() else None


def _workflow_path_matches(actual: object, expected: str) -> bool:
    """Match GitHub's exact workflow path, with its optional @ref suffix."""
    if not isinstance(actual, str):
        return False
    path, separator, ref = actual.partition("@")
    return path == expected and (not separator or bool(ref))


def _check_runs(repository: str, commit: str) -> list[dict]:
    repository = _validated_repository(repository)
    encoded = urllib.parse.quote(repository, safe="/")
    runs: list[dict] = []
    for page in range(1, 11):
        payload = _github_json(
            f"repos/{encoded}/commits/{commit}/check-runs?"
            f"filter=latest&per_page=100&page={page}")
        batch = payload.get("check_runs")
        if not isinstance(batch, list) or not all(isinstance(item, dict) for item in batch):
            raise SystemExit("GitHub returned malformed check-run metadata")
        runs.extend(batch)
        if len(batch) < 100:
            return runs
    raise SystemExit("release commit has more than 1,000 check runs; refusing ambiguity")


def _github_completed_at(value: object, *, check_name: str) -> datetime:
    if not isinstance(value, str) or _GITHUB_UTC_TIMESTAMP.fullmatch(value) is None:
        raise SystemExit(
            f"release check {check_name!r} has malformed completed_at metadata")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SystemExit(
            f"release check {check_name!r} has malformed completed_at metadata") from exc


def _latest_required_check(
        check_runs: list[dict], *, check_name: str, commit: str,
        integration_id: int, now: datetime, max_age: timedelta,
        future_skew: timedelta) -> dict | None:
    """Return the sole fresh latest exact-SHA check, irrespective of conclusion."""
    candidates: list[tuple[datetime, dict]] = []
    identifiers: set[int] = set()
    for check in check_runs:
        app = check.get("app") or {}
        if (
            check.get("name") != check_name
            or check.get("head_sha") != commit
            or not isinstance(app, dict)
            or app.get("id") != integration_id
        ):
            continue
        identifier = check.get("id")
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier <= 0:
            raise SystemExit(
                f"release check {check_name!r} has malformed check-run identity")
        if identifier in identifiers:
            raise SystemExit(
                f"release check {check_name!r} has duplicate check-run identity")
        identifiers.add(identifier)
        if check.get("status") != "completed":
            raise SystemExit(
                f"latest release check {check_name!r} is not completed")
        completed_at = _github_completed_at(
            check.get("completed_at"), check_name=check_name)
        if completed_at > now + future_skew:
            raise SystemExit(
                f"release check {check_name!r} completed_at is implausibly in the future")
        candidates.append((completed_at, check))

    if not candidates:
        return None
    latest_time = max(completed_at for completed_at, _ in candidates)
    latest = [check for completed_at, check in candidates if completed_at == latest_time]
    if len(latest) != 1:
        raise SystemExit(
            f"release check {check_name!r} has ambiguous latest completed runs")
    if latest_time < now - max_age:
        raise SystemExit(
            f"release check {check_name!r} is older than GitHub's seven-day "
            "required-check window")
    return latest[0]


def _verify_required_checks(
        commit: str, repository: str | None = None,
        source_root: Path = ROOT, *, now: datetime | None = None,
        max_age: timedelta = GITHUB_REQUIRED_CHECK_MAX_AGE,
        future_skew: timedelta = GITHUB_REQUIRED_CHECK_MAX_FUTURE_SKEW) -> None:
    """Require exact-SHA push checks from their expected Actions workflows."""
    if not isinstance(max_age, timedelta) or not (
            timedelta(0) < max_age <= GITHUB_REQUIRED_CHECK_MAX_AGE):
        raise SystemExit("required-check max_age must be positive and at most seven days")
    if not isinstance(future_skew, timedelta) or not (
            timedelta(0) <= future_skew <= GITHUB_REQUIRED_CHECK_MAX_FUTURE_SKEW):
        raise SystemExit(
            "required-check future_skew must be between zero and five minutes")
    now = now or datetime.now(timezone.utc)
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
    ):
        raise SystemExit("required-check reference time must be timezone-aware UTC")
    now = now.astimezone(timezone.utc)
    repository = (
        _validated_repository(repository) if repository is not None
        else _github_repository()
    )
    check_runs = _check_runs(repository, commit)
    workflow_cache: dict[str, dict] = {}
    missing: list[str] = []
    encoded = urllib.parse.quote(repository, safe="/")

    for check_name, (integration_id, expected_path) in _required_checks(
            source_root).items():
        trusted = False
        check = _latest_required_check(
            check_runs,
            check_name=check_name,
            commit=commit,
            integration_id=integration_id,
            now=now,
            max_age=max_age,
            future_skew=future_skew,
        )
        if check is not None and check.get("conclusion") == "success":
            run_id = _workflow_run_id(check.get("details_url"), repository)
            if run_id is not None and run_id not in workflow_cache:
                workflow_cache[run_id] = _github_json(
                    f"repos/{encoded}/actions/runs/{run_id}")
            run = workflow_cache.get(run_id) if run_id is not None else None
            if isinstance(run, dict) and (
                run.get("head_sha") == commit
                and _workflow_path_matches(run.get("path"), expected_path)
                and run.get("event") == "push"
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
            ):
                trusted = True
        if not trusted:
            missing.append(f"{check_name} from {expected_path}")

    if missing:
        raise SystemExit(
            "release commit lacks successful trusted exact-SHA checks: "
            + ", ".join(missing))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("--verify-github", action="store_true")
    parser.add_argument("--verify-required-checks", action="store_true")
    args = parser.parse_args(argv)
    version = _release_version()
    metadata_version = _verify_release_metadata(args.tag)
    if metadata_version != version:
        raise SystemExit(
            "release metadata and package identity disagree: "
            f"{metadata_version!r} != {version!r}")
    expected = f"v{version}"
    if args.tag != expected:
        raise SystemExit(f"release tag {args.tag!r} does not match package version {expected!r}")
    tag_type = _git("cat-file", "-t", f"refs/tags/{args.tag}")
    if tag_type != "tag":
        raise SystemExit("release tags must be annotated, not lightweight")
    tag_bytes = _git_bytes("cat-file", "tag", f"refs/tags/{args.tag}")
    _scan_tag_object(args.tag, tag_bytes)
    try:
        tag_body = tag_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("release tag object is not valid UTF-8") from exc
    headers = _signed_tag_headers(tag_body)
    if headers.get("type") != "commit":
        raise SystemExit("release tag object must directly name a commit")
    if headers.get("tag") != args.tag:
        raise SystemExit(
            f"signed tag object names {headers.get('tag')!r}, not "
            f"release ref {args.tag!r}")
    if not any(marker in tag_body for marker in SIGNATURE_MARKERS):
        raise SystemExit("release tags must carry a PGP or SSH signature")
    tag_object = _git("rev-parse", f"refs/tags/{args.tag}^{{tag}}")
    _verify_git_object_id(tag_object, "tag", tag_bytes)
    tagged = _git("rev-parse", f"refs/tags/{args.tag}^{{commit}}")
    if headers.get("object") != tagged:
        raise SystemExit(
            "signed tag object header does not exactly match its peeled commit")
    head = _git("rev-parse", "HEAD")
    if tagged != head:
        raise SystemExit(f"tag points to {tagged}, but the workflow checked out {head}")
    if args.verify_github:
        _verify_github_tag(tag_object)
        _verify_github_commit(tagged)
    if args.verify_required_checks:
        _verify_required_checks(tagged)
    print(f"{args.tag} is a signed annotated tag for package {version} at {head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
