"""Release-control regressions that do not create or push real tags."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_regressions_round10_release import _load_release_script

ROOT = Path(__file__).resolve().parent.parent
_POSIX_RELEASE_GIT = pytest.mark.skipif(
    os.name != "posix", reason="the release Git profile supports POSIX release hosts")


@pytest.fixture
def private_release_tmp():
    base = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    path = Path(tempfile.mkdtemp(prefix="cce-release-test-", dir=base))
    path.chmod(0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path)


def _metadata_fixture(
    root,
    *,
    version="0.1.0",
    release_state="2026-08-03",
    cff_date="2026-08-03",
    unreleased="No unreleased changes.",
    tail="",
):
    package = root / "causal_continuity_engine"
    package.mkdir()
    (package / "__init__.py").write_text(
        f'__version__ = "{version}"\n', encoding="utf-8")
    cff = f"cff-version: 1.2.0\nversion: {version}\n"
    if cff_date is not None:
        cff += f"date-released: {cff_date}\n"
    (root / "CITATION.cff").write_text(cff, encoding="utf-8")
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## Unreleased\n\n{unreleased}\n\n"
        f"## {version} — {release_state}\n\nRelease notes.\n{tail}",
        encoding="utf-8",
    )


def _verified(reason="valid"):
    return {
        "verified": True,
        "reason": reason,
        "signature": "signed",
        "payload": "payload",
        "verified_at": "2026-08-03T00:00:00Z",
    }


def test_current_metadata_is_consistent_but_not_pretending_to_be_released():
    metadata = _load_release_script("check_release_metadata")
    assert metadata.check(ROOT) == ("0.1.5", None)
    with pytest.raises(SystemExit, match="not yet released"):
        metadata.check(ROOT, release_tag="v0.1.5")


def test_release_metadata_requires_matching_dates_and_reset_unreleased(tmp_path):
    metadata = _load_release_script("check_release_metadata")
    _metadata_fixture(tmp_path)
    assert metadata.check(
        tmp_path, release_tag="v0.1.0") == ("0.1.0", "2026-08-03")

    (tmp_path / "CITATION.cff").write_text(
        "cff-version: 1.2.0\nversion: 0.1.0\ndate-released: 2026-08-02\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="release dates differ"):
        metadata.check(tmp_path, release_tag="v0.1.0")


@pytest.mark.parametrize(
    ("kwargs", "diagnostic"),
    [
        ({"release_state": "not yet released", "cff_date": None}, "not yet released"),
        ({"unreleased": "Pending work."}, "reset exactly"),
        ({"tail": "\nNo release has been tagged.\n"}, "stale pre-release"),
        ({"version": "0.1.0rc1"}, "stable X.Y.Z"),
    ],
)
def test_release_metadata_rejects_prerelease_state(tmp_path, kwargs, diagnostic):
    metadata = _load_release_script("check_release_metadata")
    _metadata_fixture(tmp_path, **kwargs)
    with pytest.raises(SystemExit, match=diagnostic):
        metadata.check(tmp_path, release_tag="v0.1.0")


def test_github_commit_verification_is_exact_and_well_formed(monkeypatch):
    checker = _load_release_script("check_release_tag")
    commit = "a" * 40
    paths = []

    def request(path):
        paths.append(path)
        return {"sha": commit, "commit": {"verification": _verified()}}

    monkeypatch.setattr(checker, "_github_json", request)
    checker._verify_github_commit(commit, "owner/repository")
    assert paths == [f"repos/owner/repository/commits/{commit}"]

    monkeypatch.setattr(
        checker,
        "_github_json",
        lambda path: {
            "sha": commit,
            "commit": {"verification": {**_verified(), "verified": False}},
        },
    )
    with pytest.raises(SystemExit, match="did not verify the release commit"):
        checker._verify_github_commit(commit, "owner/repository")


def test_release_tag_object_content_scan_is_exact_and_strict():
    checker = _load_release_script("check_release_tag")
    checker._scan_tag_object("v0.1.0", b"clean annotated tag\n")

    with pytest.raises(SystemExit, match="contains prohibited content"):
        checker._scan_tag_object(
            "v0.1.0",
            "tagger Hidden\u200bIdentity <tagger@example.test> 0 +0000\n".encode(),
        )

    with pytest.raises(SystemExit, match="scan is incomplete"):
        checker._scan_tag_object("v0.1.0", b"\xff")


def test_release_tag_object_bytes_must_match_their_object_id():
    checker = _load_release_script("check_release_tag")
    payload = b"object abc\ntype commit\ntag v0.1.0\n\nrelease\n"
    oid = hashlib.sha1(f"tag {len(payload)}\0".encode("ascii") + payload).hexdigest()

    checker._verify_git_object_id(oid, "tag", payload)
    with pytest.raises(SystemExit, match="bytes do not match"):
        checker._verify_git_object_id("0" * 40, "tag", payload)


def test_github_tag_verification_is_exact_and_well_formed(monkeypatch):
    checker = _load_release_script("check_release_tag")
    tag_object = "9" * 40
    paths = []

    def request(path):
        paths.append(path)
        return {"sha": tag_object, "verification": _verified()}

    monkeypatch.setattr(checker, "_github_json", request)
    checker._verify_github_tag(tag_object, "owner/repository")
    assert paths == [f"repos/owner/repository/git/tags/{tag_object}"]

    monkeypatch.setattr(
        checker,
        "_github_json",
        lambda path: {
            "sha": "8" * 40,
            "verification": _verified(),
        },
    )
    with pytest.raises(SystemExit, match="wrong object"):
        checker._verify_github_tag(tag_object, "owner/repository")


@pytest.mark.parametrize(
    "bad_verification",
    [
        {"verified": True},
        {**_verified(), "verified": 1},
        {**_verified(), "signature": None},
        {**_verified(), "verified_at": ""},
    ],
)
def test_github_commit_verification_rejects_malformed_payload(
        monkeypatch, bad_verification):
    checker = _load_release_script("check_release_tag")
    commit = "b" * 40
    monkeypatch.setattr(
        checker,
        "_github_json",
        lambda path: {
            "sha": commit,
            "commit": {"verification": bad_verification},
        },
    )
    with pytest.raises(SystemExit, match="malformed"):
        checker._verify_github_commit(commit, "owner/repository")


@pytest.mark.parametrize(
    "repository",
    [None, "", "owner", "/repository", "owner/", "owner/../repository",
     "owner/repository/extra", "owner/repo name", " owner/repository"],
)
def test_github_repository_slug_rejects_missing_or_ambiguous_values(repository):
    checker = _load_release_script("check_release_tag")
    with pytest.raises(SystemExit, match="owner/name slug"):
        checker._validated_repository(repository)


def test_github_api_url_defaults_to_the_fixed_public_service(monkeypatch):
    checker = _load_release_script("check_release_tag")
    monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    assert checker._github_server_url() == "https://github.com"
    assert checker._github_api_url() == "https://api.github.com"


@pytest.mark.parametrize(
    "server, api, diagnostic",
    [
        ("http://github.com", None, "canonical HTTPS"),
        ("https://user@github.com", None, "canonical HTTPS"),
        ("https://github.com/path", None, "canonical HTTPS"),
        ("https://github.com", "http://api.github.com", "canonical HTTPS"),
        ("https://github.com", "https://example.test", "allowlist"),
        (
            "https://github.example.test",
            None,
            "allowlist",
        ),
        (
            "https://github.example.test",
            "https://github.example.test/unreviewed",
            "allowlist",
        ),
    ],
)
def test_github_api_url_rejects_insecure_or_cross_origin_values(
        monkeypatch, server, api, diagnostic):
    checker = _load_release_script("check_release_tag")
    monkeypatch.setenv("GITHUB_SERVER_URL", server)
    if api is None:
        monkeypatch.delenv("GITHUB_API_URL", raising=False)
    else:
        monkeypatch.setenv("GITHUB_API_URL", api)
    with pytest.raises(SystemExit, match=diagnostic):
        checker._github_api_url()


def test_github_api_client_rejects_an_inherited_endpoint_before_sending_token(
        monkeypatch):
    checker = _load_release_script("check_release_tag")
    monkeypatch.setenv("GH_TOKEN", "owner-token")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://attacker.example")
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            raise AssertionError("the rejected endpoint must not receive a request")

    monkeypatch.setattr(checker, "_GITHUB_OPENER", Opener())
    with pytest.raises(SystemExit, match="public GitHub allowlist"):
        checker._github_json("repos/example/project")
    assert requests == []


@pytest.mark.parametrize(
    "payload, diagnostic",
    [
        (b'{"sha":"a","sha":"b"}', "duplicate JSON member"),
        (b'{"value":NaN}', "non-finite JSON number"),
        (b'[]', "must contain one JSON object"),
        (b'\xff', "strict UTF-8 JSON"),
    ],
)
def test_github_json_boundary_rejects_ambiguous_documents(payload, diagnostic):
    checker = _load_release_script("check_release_tag")
    with pytest.raises(SystemExit, match=diagnostic):
        checker._strict_json_object(payload, label="GitHub response")


def test_github_json_boundary_is_bounded_before_parsing():
    checker = _load_release_script("check_release_tag")
    checker.MAX_GITHUB_JSON_BYTES = 4
    with pytest.raises(SystemExit, match="JSON size limit"):
        checker._strict_json_object(b'{"x":1}', label="GitHub response")


def test_github_api_client_disables_proxies_and_prefers_the_explicit_owner_token(
        monkeypatch):
    checker = _load_release_script("check_release_tag")
    proxy_handlers = [
        handler for handler in checker._GITHUB_OPENER.handlers
        if isinstance(handler, checker.urllib.request.ProxyHandler)
    ]
    assert all(handler.proxies == {} for handler in proxy_handlers)
    monkeypatch.setenv("GH_TOKEN", "fresh-owner-token")
    monkeypatch.setenv("GITHUB_TOKEN", "stale-workflow-token")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    requests = []

    class Response:
        status = 200

        def __init__(self, url):
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            del exc_type, exc, traceback

        def geturl(self):
            return self.url

        def read(self, limit):
            assert limit == checker.MAX_GITHUB_JSON_BYTES + 1
            return b"{}"

    class Opener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            return Response(request.full_url)

    monkeypatch.setattr(checker, "_GITHUB_OPENER", Opener())
    assert checker._github_json("repos/example/project") == {}
    request, timeout = requests[0]
    assert timeout == 15
    assert request.get_header("Authorization") == "Bearer fresh-owner-token"


def test_required_check_contract_is_derived_from_committed_ruleset(tmp_path):
    checker = _load_release_script("check_release_tag")
    ruleset = json.loads((ROOT / ".github" / "ruleset.json").read_text(
        encoding="utf-8"))
    for rule in ruleset["rules"]:
        if rule["type"] == "required_status_checks":
            for entry in rule["parameters"]["required_status_checks"]:
                entry["integration_id"] = 4242
            # The committed ruleset already carries the PR-only DCO context;
            # dependency-review may later become a branch requirement the same
            # way without being a push-event release attestation.
            rule["parameters"]["required_status_checks"].append(
                {"context": "dependency-review", "integration_id": 4242})
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "ruleset.json").write_text(
        json.dumps(ruleset), encoding="utf-8")

    assert checker._required_checks(tmp_path) == {
        "ci": (4242, ".github/workflows/ci.yml"),
        "attribution": (4242, ".github/workflows/no-ai-attribution.yml"),
        "secrets": (4242, ".github/workflows/secret-scan.yml"),
    }


def test_required_check_contract_rejects_duplicate_extra_context(tmp_path):
    checker = _load_release_script("check_release_tag")
    ruleset = json.loads((ROOT / ".github" / "ruleset.json").read_text(
        encoding="utf-8"))
    for rule in ruleset["rules"]:
        if rule["type"] == "required_status_checks":
            rule["parameters"]["required_status_checks"].extend([
                {"context": "DCO", "integration_id": 1},
                {"context": "DCO", "integration_id": 2},
            ])
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "ruleset.json").write_text(
        json.dumps(ruleset), encoding="utf-8")

    with pytest.raises(SystemExit, match="invalid or duplicate"):
        checker._required_checks(tmp_path)


def test_required_check_contract_rejects_unclassified_extra_context(tmp_path):
    checker = _load_release_script("check_release_tag")
    ruleset = json.loads((ROOT / ".github" / "ruleset.json").read_text(
        encoding="utf-8"))
    for rule in ruleset["rules"]:
        if rule["type"] == "required_status_checks":
            rule["parameters"]["required_status_checks"].append(
                {"context": "new-policy", "integration_id": 1})
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "ruleset.json").write_text(
        json.dumps(ruleset), encoding="utf-8")

    with pytest.raises(SystemExit, match="unclassified required context"):
        checker._required_checks(tmp_path)


def _trusted_check_fixture(checker, commit, repository):
    checks = []
    workflow_runs = {}
    completed_at = (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        .replace("+00:00", "Z")
    )
    for index, (context, (app_id, path)) in enumerate(
            checker._required_checks(ROOT).items(), start=100):
        run_id = str(index)
        checks.append({
            "id": index,
            "name": context,
            "head_sha": commit,
            "status": "completed",
            "conclusion": "success",
            "completed_at": completed_at,
            "app": {"id": app_id},
            "details_url": (
                f"https://github.com/{repository}/actions/runs/{run_id}/job/{index}"
            ),
        })
        workflow_runs[run_id] = {
            "head_sha": commit,
            # GitHub's REST response may render the workflow path with the ref
            # that supplied it. The reviewed base path must still be exact.
            "path": f"{path}@main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
        }
    return checks, workflow_runs


def test_required_checks_bind_exact_sha_app_push_event_and_workflow(monkeypatch):
    checker = _load_release_script("check_release_tag")
    commit = "c" * 40
    repository = "owner/repository"
    checks, workflow_runs = _trusted_check_fixture(checker, commit, repository)
    requested = []

    def request(path):
        requested.append(path)
        run_id = path.rsplit("/", 1)[-1]
        return workflow_runs[run_id]

    monkeypatch.setattr(checker, "_check_runs", lambda repo, sha: checks)
    monkeypatch.setattr(checker, "_github_json", request)
    checker._verify_required_checks(commit, repository=repository, source_root=ROOT)
    assert requested == [
        f"repos/{repository}/actions/runs/{run_id}"
        for run_id in workflow_runs
    ]


@pytest.mark.parametrize(
    "tamper",
    [
        "check-sha",
        "check-app",
        "check-conclusion",
        "details-url",
        "run-sha",
        "run-path",
        "run-path-empty-ref",
        "run-event",
        "run-status",
    ],
)
def test_required_checks_reject_substitute_or_non_push_run(monkeypatch, tamper):
    checker = _load_release_script("check_release_tag")
    commit = "d" * 40
    repository = "owner/repository"
    checks, workflow_runs = _trusted_check_fixture(checker, commit, repository)
    target = checks[0]
    run_id = target["details_url"].split("/actions/runs/", 1)[1].split("/", 1)[0]

    if tamper == "check-sha":
        target["head_sha"] = "e" * 40
    elif tamper == "check-app":
        target["app"]["id"] += 1
    elif tamper == "check-conclusion":
        target["conclusion"] = "neutral"
    elif tamper == "details-url":
        target["details_url"] = f"https://example.test/actions/runs/{run_id}"
    elif tamper == "run-sha":
        workflow_runs[run_id]["head_sha"] = "e" * 40
    elif tamper == "run-path":
        workflow_runs[run_id]["path"] = ".github/workflows/substitute.yml@main"
    elif tamper == "run-path-empty-ref":
        expected = checker._required_checks(ROOT)[target["name"]][1]
        workflow_runs[run_id]["path"] = f"{expected}@"
    elif tamper == "run-event":
        workflow_runs[run_id]["event"] = "pull_request"
    else:
        workflow_runs[run_id]["status"] = "in_progress"

    monkeypatch.setattr(checker, "_check_runs", lambda repo, sha: checks)
    monkeypatch.setattr(
        checker,
        "_github_json",
        lambda path: workflow_runs[path.rsplit("/", 1)[-1]],
    )
    with pytest.raises(SystemExit, match="lacks successful trusted exact-SHA checks"):
        checker._verify_required_checks(
            commit, repository=repository, source_root=ROOT)


def _install_check_api(monkeypatch, checker, checks, workflow_runs):
    monkeypatch.setattr(checker, "_check_runs", lambda repo, sha: checks)
    monkeypatch.setattr(
        checker,
        "_github_json",
        lambda path: workflow_runs[path.rsplit("/", 1)[-1]],
    )


def _github_time(value):
    return value.isoformat().replace("+00:00", "Z")


def test_required_checks_reject_success_outside_github_seven_day_window(
        monkeypatch):
    checker = _load_release_script("check_release_tag")
    commit = "f" * 40
    repository = "owner/repository"
    now = datetime(2026, 8, 4, 12, tzinfo=timezone.utc)
    checks, workflow_runs = _trusted_check_fixture(checker, commit, repository)
    for check in checks:
        check["completed_at"] = _github_time(now - timedelta(minutes=1))
    checks[0]["completed_at"] = _github_time(
        now - timedelta(days=7, seconds=1))
    _install_check_api(monkeypatch, checker, checks, workflow_runs)

    with pytest.raises(SystemExit, match="older than GitHub's seven-day"):
        checker._verify_required_checks(
            commit, repository=repository, source_root=ROOT, now=now)


def test_required_checks_reject_newer_failure_over_older_success(monkeypatch):
    checker = _load_release_script("check_release_tag")
    commit = "1" * 40
    repository = "owner/repository"
    now = datetime(2026, 8, 4, 12, tzinfo=timezone.utc)
    checks, workflow_runs = _trusted_check_fixture(checker, commit, repository)
    for check in checks:
        check["completed_at"] = _github_time(now - timedelta(minutes=2))
    newer_failure = dict(checks[0])
    newer_failure.update({
        "id": 999,
        "conclusion": "failure",
        "completed_at": _github_time(now - timedelta(minutes=1)),
    })
    checks.append(newer_failure)
    _install_check_api(monkeypatch, checker, checks, workflow_runs)

    with pytest.raises(SystemExit, match="lacks successful trusted exact-SHA checks"):
        checker._verify_required_checks(
            commit, repository=repository, source_root=ROOT, now=now)


def test_required_checks_reject_ambiguous_latest_completion(monkeypatch):
    checker = _load_release_script("check_release_tag")
    commit = "2" * 40
    repository = "owner/repository"
    now = datetime(2026, 8, 4, 12, tzinfo=timezone.utc)
    checks, workflow_runs = _trusted_check_fixture(checker, commit, repository)
    for check in checks:
        check["completed_at"] = _github_time(now - timedelta(minutes=1))
    ambiguous = dict(checks[0])
    ambiguous["id"] = 998
    checks.append(ambiguous)
    _install_check_api(monkeypatch, checker, checks, workflow_runs)

    with pytest.raises(SystemExit, match="ambiguous latest completed runs"):
        checker._verify_required_checks(
            commit, repository=repository, source_root=ROOT, now=now)


@pytest.mark.parametrize(
    "completed_at, diagnostic",
    [
        ("2026-08-04 12:00:00Z", "malformed completed_at"),
        ("2026-02-30T12:00:00Z", "malformed completed_at"),
        ("2026-08-04T12:05:01Z", "implausibly in the future"),
    ],
)
def test_required_checks_reject_malformed_or_future_completion_time(
        monkeypatch, completed_at, diagnostic):
    checker = _load_release_script("check_release_tag")
    commit = "3" * 40
    repository = "owner/repository"
    now = datetime(2026, 8, 4, 12, tzinfo=timezone.utc)
    checks, workflow_runs = _trusted_check_fixture(checker, commit, repository)
    for check in checks:
        check["completed_at"] = _github_time(now - timedelta(minutes=1))
    checks[0]["completed_at"] = completed_at
    _install_check_api(monkeypatch, checker, checks, workflow_runs)

    with pytest.raises(SystemExit, match=diagnostic):
        checker._verify_required_checks(
            commit, repository=repository, source_root=ROOT, now=now)


@pytest.mark.parametrize(
    "override, diagnostic",
    [
        ({"max_age": timedelta(days=7, seconds=1)}, "at most seven days"),
        ({"future_skew": timedelta(minutes=5, seconds=1)}, "five minutes"),
    ],
)
def test_required_check_time_overrides_cannot_weaken_safety_bounds(
        override, diagnostic):
    checker = _load_release_script("check_release_tag")
    with pytest.raises(SystemExit, match=diagnostic):
        checker._verify_required_checks("4" * 40, **override)


def _schema_fixture(root, module, tag="v0.1.0", versions=None):
    versions = versions or module._runtime_schema_versions(ROOT)
    package = root / "causal_continuity_engine"
    package.mkdir()
    (package / "__init__.py").write_text(
        "SCHEMA_VERSIONS = " + repr(versions) + "\n",
        encoding="utf-8", newline="\n")
    schema_dir = root / "schemas"
    schema_dir.mkdir()
    served = {}
    for name in sorted(f"{value}.json" for value in versions.values()):
        url = f"{module.RAW_ORIGIN}/{tag}/schemas/{name}"
        payload = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                   "$id": url, "type": "object"}
        data = (json.dumps(payload, indent=2) + "\n").encode()
        (schema_dir / name).write_bytes(data)
        served[url] = data
    return served


def test_public_schema_verifier_compares_all_exact_tagged_bytes(tmp_path):
    verifier = _load_release_script("verify_public_schemas")
    served = _schema_fixture(tmp_path, verifier)
    requested = []

    def fetch(url):
        requested.append(url)
        return served[url]

    verifier.verify(tmp_path, "v0.1.0", fetch=fetch)
    assert requested == [
        verifier._schema_public_urls(tmp_path)[name]
        for name in verifier._schema_public_urls(tmp_path)
    ]


def test_public_schema_inventory_follows_runtime_registry_without_fixed_count(
        tmp_path):
    verifier = _load_release_script("verify_public_schemas")
    versions = verifier._runtime_schema_versions(ROOT)
    versions["future_fixture"] = "cce.future-fixture.v1"
    served = _schema_fixture(tmp_path, verifier, versions=versions)
    requested = []

    verifier.verify(
        tmp_path, "v0.1.0",
        fetch=lambda url: requested.append(url) or served[url])

    assert requested == list(verifier._schema_public_urls(tmp_path).values())
    assert len(requested) == len(versions)
    assert any(url.endswith("/schemas/cce.future-fixture.v1.json") for url in requested)


def test_public_schema_registry_rejects_duplicate_literal_keys(tmp_path):
    verifier = _load_release_script("verify_public_schemas")
    package = tmp_path / "causal_continuity_engine"
    package.mkdir()
    (package / "__init__.py").write_text(
        "SCHEMA_VERSIONS = {\n"
        "    'event': 'cce.event.v1',\n"
        "    'event': 'cce.resume.v1',\n"
        "}\n",
        encoding="utf-8", newline="\n")

    with pytest.raises(SystemExit, match="duplicated"):
        verifier._runtime_schema_versions(tmp_path)


def test_later_package_release_keeps_immutable_v1_schema_urls(tmp_path):
    verifier = _load_release_script("verify_public_schemas")
    served = _schema_fixture(tmp_path, verifier, tag="v0.1.0")
    requested = []

    def fetch(url):
        requested.append(url)
        return served[url]

    verifier.verify(tmp_path, "v0.2.0", fetch=fetch)
    assert requested == list(verifier._schema_public_urls(tmp_path).values())
    assert all("/v0.1.0/schemas/" in url for url in requested)


@pytest.mark.parametrize("failure", ["malformed", "mismatch"])
def test_public_schema_verifier_rejects_bad_served_content(tmp_path, failure):
    verifier = _load_release_script("verify_public_schemas")
    served = _schema_fixture(tmp_path, verifier)
    first = next(iter(served))
    if failure == "malformed":
        served[first] = b"{"
        diagnostic = "strict UTF-8 JSON"
    else:
        served[first] = served[first].replace(b'  "type"', b'   "type"')
        diagnostic = "bytes differ"
    with pytest.raises(SystemExit, match=diagnostic):
        verifier.verify(tmp_path, "v0.1.0", fetch=served.__getitem__)


def test_public_schema_verifier_rejects_wrong_id_and_inventory(tmp_path):
    verifier = _load_release_script("verify_public_schemas")
    served = _schema_fixture(tmp_path, verifier)
    first = verifier.SCHEMA_NAMES[0]
    path = tmp_path / "schemas" / first
    path.write_text('{"$id": "https://example.test/wrong"}\n', encoding="utf-8")
    with pytest.raises(SystemExit, match=r"has \$id"):
        verifier.verify(tmp_path, "v0.1.0", fetch=served.__getitem__)

    path.unlink()
    with pytest.raises(SystemExit, match="reviewed runtime contract"):
        verifier.verify(tmp_path, "v0.1.0", fetch=served.__getitem__)


def test_prepare_tag_preflight_is_fail_closed_and_orders_checks(monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    head = "c" * 40
    events = []
    monkeypatch.setattr(tool, "_require_clean_tree", lambda: events.append("clean"))
    monkeypatch.setattr(tool, "_require_origin_identity", lambda: events.append("origin"))
    monkeypatch.setattr(
        tool, "_require_current_origin_main",
        lambda: events.append("main") or head)
    monkeypatch.setattr(tool, "_local_tag_exists", lambda tag: False)
    monkeypatch.setattr(
        tool, "_require_remote_tag_absent",
        lambda tag: events.append("remote-tag"))
    monkeypatch.setattr(
        tool, "_verify_metadata", lambda tag: events.append("metadata") or "0.1.0")
    monkeypatch.setattr(
        tool, "_verify_commit_and_checks",
        lambda commit: events.append(("github", commit)))
    monkeypatch.setattr(tool, "_remote_main_sha", lambda: head)

    assert tool._preflight("v0.1.0") == (head, "0.1.0")
    assert events == [
        "clean", "origin", "main", "remote-tag", "metadata", ("github", head)]

    with pytest.raises(SystemExit, match="vX.Y.Z"):
        tool._preflight("release-0.1.0")


def test_prepare_tag_rejects_dirty_wrong_origin_branch_and_remote_tag(
        monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    monkeypatch.setattr(
        tool, "_run_git",
        lambda *args: "?? local.txt" if args[0] == "status" else "")
    with pytest.raises(SystemExit, match="clean working tree"):
        tool._require_clean_tree()

    monkeypatch.setattr(
        tool,
        "_release_git",
        lambda: SimpleNamespace(origin_url="https://example.test/wrong"),
    )
    with pytest.raises(SystemExit, match="origin fetch/push"):
        tool._require_origin_identity()

    monkeypatch.setattr(tool, "_run_git", lambda *args: "feature")
    with pytest.raises(SystemExit, match="main branch"):
        tool._require_current_origin_main()

    monkeypatch.setattr(
        tool, "_git_status",
        lambda *args: SimpleNamespace(returncode=0, stdout="exists", stderr=""))
    with pytest.raises(SystemExit, match="already exists"):
        tool._require_remote_tag_absent("v0.1.0")


@_POSIX_RELEASE_GIT
def test_prepare_tag_rejects_executable_local_config_before_git_sees_token(
        private_release_tmp, monkeypatch):
    tmp_path = private_release_tmp
    tool = _load_release_script("prepare_release_tag")
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "--quiet"], cwd=repository, check=True)
    sentinel = tmp_path / "captured-token"
    monitor = tmp_path / "capture_fsmonitor.py"
    monitor.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['CCE_R04_SENTINEL']).write_text(\n"
        "    os.environ.get('GH_TOKEN', '<missing>'), encoding='utf-8')\n",
        encoding="utf-8",
    )
    monitor.chmod(monitor.stat().st_mode | stat.S_IXUSR)
    subprocess.run(
        ["git", "config", "core.fsmonitor", os.fspath(monitor)],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        [
            "git", "remote", "add", "origin",
            "ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git",
        ],
        cwd=repository,
        check=True,
    )
    monkeypatch.setattr(tool, "ROOT", repository)
    monkeypatch.setenv("GH_TOKEN", "r04-planted-token")
    monkeypatch.setenv("CCE_R04_SENTINEL", os.fspath(sentinel))

    with pytest.raises(SystemExit, match="prohibited local Git configuration"):
        if hasattr(tool.CHECKER, "ReleaseGit"):
            tool.CHECKER.ReleaseGit.checker(
                root=repository, git_executable="/usr/bin/git")
        else:  # The pinned pre-fix helper executes the planted monitor here.
            tool._require_clean_tree()

    assert not sentinel.exists()


@_POSIX_RELEASE_GIT
def test_prepare_tag_never_runs_repository_pre_push_hook_with_api_token(
        private_release_tmp, monkeypatch):
    tmp_path = private_release_tmp
    tool = _load_release_script("prepare_release_tag")
    repository = tmp_path / "repository"
    remote = tmp_path / "remote.git"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "init", "--quiet", "--bare", os.fspath(remote)], check=True)
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
    subprocess.run(
        [
            "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
            "-c", "commit.gpgsign=false", "commit", "--quiet", "--message", "fixture",
        ],
        cwd=repository,
        check=True,
    )
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    sentinel = tmp_path / "captured-token"
    hook = hooks / "pre-push"
    hook.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['CCE_R04_SENTINEL']).write_text(\n"
        "    os.environ.get('GH_TOKEN', '<missing>'), encoding='utf-8')\n",
        encoding="utf-8",
    )
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
    subprocess.run(
        ["git", "config", "core.hooksPath", os.fspath(hooks)],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        [
            "git", "remote", "add", "origin",
            "ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git",
        ],
        cwd=repository,
        check=True,
    )
    monkeypatch.setattr(tool, "ROOT", repository)
    monkeypatch.setenv("GH_TOKEN", "r04-planted-token")
    monkeypatch.setenv("CCE_R04_SENTINEL", os.fspath(sentinel))

    with pytest.raises(SystemExit, match="prohibited local Git configuration"):
        if hasattr(tool.CHECKER, "ReleaseGit"):
            tool.CHECKER.ReleaseGit.checker(
                root=repository, git_executable="/usr/bin/git")
        else:  # The pinned pre-fix helper executes the planted hook here.
            tool._run_git(
                "push", "--dry-run", os.fspath(remote), "HEAD:refs/heads/probe")

    assert not sentinel.exists()


@_POSIX_RELEASE_GIT
def test_prepare_tag_rejects_a_repository_signing_program_before_execution(
        private_release_tmp, monkeypatch):
    tmp_path = private_release_tmp
    tool = _load_release_script("prepare_release_tag")
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
    subprocess.run(
        [
            "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
            "-c", "commit.gpgsign=false", "commit", "--quiet", "--message", "fixture",
        ],
        cwd=repository,
        check=True,
    )
    sentinel = tmp_path / "captured-token"
    signer = tmp_path / "capture-signer.py"
    signer.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "from pathlib import Path\n"
        "Path(os.environ['CCE_R04_SENTINEL']).write_text(\n"
        "    os.environ.get('GH_TOKEN', '<missing>'), encoding='utf-8')\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    signer.chmod(signer.stat().st_mode | stat.S_IXUSR)
    signing_key = tmp_path / "signing.pub"
    signing_key.write_text(
        "ssh-ed25519 Zml4dHVyZQ== fixture\n", encoding="utf-8")
    for key, value in (
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", os.fspath(signer)),
        ("user.signingkey", os.fspath(signing_key)),
    ):
        subprocess.run(
            ["git", "config", key, value], cwd=repository, check=True)
    subprocess.run(
        [
            "git", "remote", "add", "origin",
            "ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git",
        ],
        cwd=repository,
        check=True,
    )
    monkeypatch.setattr(tool, "ROOT", repository)
    monkeypatch.setenv("GH_TOKEN", "r04-planted-token")
    monkeypatch.setenv("CCE_R04_SENTINEL", os.fspath(sentinel))

    with pytest.raises(SystemExit):
        if hasattr(tool.CHECKER, "ReleaseGit"):
            tool.CHECKER.ReleaseGit.checker(
                root=repository, git_executable="/usr/bin/git")
        else:  # The pinned pre-fix helper executes the planted signer here.
            tool._run_git(
                "tag", "--sign", "--annotate", "v9.9.9",
                "--message", "Release v9.9.9",
            )

    assert not sentinel.exists()


@_POSIX_RELEASE_GIT
def test_prepare_tag_never_resolves_git_through_inherited_path(
        private_release_tmp, monkeypatch):
    tmp_path = private_release_tmp
    tool = _load_release_script("prepare_release_tag")
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["/usr/bin/git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        [
            "/usr/bin/git", "remote", "add", "origin",
            "ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git",
        ],
        cwd=repository,
        check=True,
    )
    shim_directory = tmp_path / "shim"
    shim_directory.mkdir()
    sentinel = tmp_path / "captured-token"
    shim = shim_directory / "git"
    shim.write_text(
        "#!/bin/sh\n"
        "printf '%s' \"$GH_TOKEN\" > \"$CCE_R04_SENTINEL\"\n"
        "exec /usr/bin/git \"$@\"\n",
        encoding="utf-8",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(tool, "ROOT", repository)
    monkeypatch.setenv("PATH", os.fspath(shim_directory))
    monkeypatch.setenv("GH_TOKEN", "r04-planted-token")
    monkeypatch.setenv("CCE_R04_SENTINEL", os.fspath(sentinel))

    if hasattr(tool.CHECKER, "ReleaseGit"):
        runner = tool.CHECKER.ReleaseGit.checker(
            root=repository, git_executable="/usr/bin/git")
        previous = tool._set_release_git(runner)
        try:
            tool._require_clean_tree()
        finally:
            tool._restore_release_git(previous)
            runner.close()
    else:  # The pinned pre-fix helper resolves and executes the planted shim.
        tool._require_clean_tree()

    assert not sentinel.exists()


def test_prepare_release_origin_is_exact_ssh_only():
    tool = _load_release_script("prepare_release_tag")
    assert tool._canonical_origin(
        "ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git")
    assert not tool._canonical_origin(
        "https://github.com/thequantumfalcon/causal-continuity-engine")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("credential.helper", "!capture-token"),
        ("gpg.program", "/tmp/capture-token"),
        ("gpg.ssh.program", "/tmp/capture-token"),
        ("core.sshCommand", "/tmp/capture-token"),
        ("url.ext::capture-token.insteadOf", "ssh://git@github.com/"),
        ("url.ext::capture-token.pushInsteadOf", "ssh://git@github.com/"),
        ("remote.origin.receivepack", "/tmp/capture-token"),
        ("remote.origin.uploadpack", "/tmp/capture-token"),
        ("include.path", "/tmp/capture-token"),
        ("includeIf.gitdir:/tmp/.path", "/tmp/capture-token"),
        ("protocol.ext.allow", "always"),
    ],
)
@_POSIX_RELEASE_GIT
def test_release_git_rejects_every_unadmitted_program_configuration(
        private_release_tmp, key, value):
    tmp_path = private_release_tmp
    checker = _load_release_script("check_release_tag")
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        [
            "git", "remote", "add", "origin",
            checker.RELEASE_SSH_ORIGIN,
        ],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", key, value], cwd=repository, check=True)

    with pytest.raises(SystemExit, match="prohibited local Git configuration"):
        checker.ReleaseGit.checker(
            root=repository, git_executable="/usr/bin/git")


@pytest.mark.parametrize("defect", ["duplicate", "worktree-config"])
@_POSIX_RELEASE_GIT
def test_release_git_rejects_ambiguous_or_per_worktree_configuration(
        private_release_tmp, defect):
    checker = _load_release_script("check_release_tag")
    repository = private_release_tmp / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", checker.RELEASE_SSH_ORIGIN],
        cwd=repository,
        check=True,
    )
    if defect == "duplicate":
        with (repository / ".git" / "config").open("a", encoding="utf-8") as handle:
            handle.write("\n[core]\n\tfilemode = true\n")
        diagnostic = "ambiguous"
    else:
        (repository / ".git" / "config.worktree").write_text(
            "[core]\n\tfsmonitor = /tmp/capture-token\n", encoding="utf-8")
        diagnostic = "per-worktree"

    with pytest.raises(SystemExit, match=diagnostic):
        checker.ReleaseGit.checker(
            root=repository, git_executable="/usr/bin/git")


@pytest.mark.parametrize(
    ("defect", "diagnostic"),
    [
        ("alternates", "object alternates"),
        ("grafts", "Git grafts"),
        ("shallow", "shallow Git history"),
        ("commondir", "redirected common Git directory"),
        ("loose-replace", "replacement refs"),
        ("packed-replace", "packed replacement refs"),
        ("exclude", "active info/exclude"),
        ("attributes", "active info/attributes"),
    ],
)
@_POSIX_RELEASE_GIT
def test_release_git_rejects_object_indirection_and_hidden_worktree_rules(
        private_release_tmp, defect, diagnostic):
    checker = _load_release_script("check_release_tag")
    repository = private_release_tmp / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", checker.RELEASE_SSH_ORIGIN],
        cwd=repository,
        check=True,
    )
    git_directory = repository / ".git"
    if defect == "alternates":
        path = git_directory / "objects" / "info" / "alternates"
        path.write_text("/tmp/untrusted-objects\n", encoding="utf-8")
    elif defect == "grafts":
        path = git_directory / "info" / "grafts"
        path.write_text("0" * 40 + " " + "1" * 40 + "\n", encoding="utf-8")
    elif defect == "shallow":
        path = git_directory / "shallow"
        path.write_text("0" * 40 + "\n", encoding="utf-8")
    elif defect == "commondir":
        path = git_directory / "commondir"
        path.write_text("../shared-git\n", encoding="utf-8")
    elif defect == "loose-replace":
        (git_directory / "refs" / "replace").mkdir()
    elif defect == "packed-replace":
        path = git_directory / "packed-refs"
        path.write_text(
            "# pack-refs with: peeled fully-peeled sorted\n"
            + "0" * 40
            + " refs/replace/"
            + "1" * 40
            + "\n",
            encoding="utf-8",
        )
    else:
        path = git_directory / "info" / defect
        path.write_text("*\n", encoding="utf-8")

    with pytest.raises(SystemExit, match=diagnostic):
        checker.ReleaseGit.checker(
            root=repository, git_executable="/usr/bin/git")


@_POSIX_RELEASE_GIT
def test_release_git_rejects_a_non_socket_agent_path(private_release_tmp):
    tmp_path = private_release_tmp
    checker = _load_release_script("check_release_tag")
    path = tmp_path / "not-a-socket"
    path.write_text("not a socket\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="owner-controlled"):
        checker._trusted_socket_path(
            os.fspath(path), root=tmp_path / "different-repository")


@_POSIX_RELEASE_GIT
def test_release_git_accepts_launchd_socket_permissions_only_behind_private_parent(
        private_release_tmp, monkeypatch):
    checker = _load_release_script("check_release_tag")
    private_parent = private_release_tmp / "com.apple.launchd.fixture"
    private_parent.mkdir(mode=0o700)
    target = private_parent / "Listeners"
    target.write_text("socket metadata seam\n", encoding="utf-8")
    alias_parent = private_release_tmp / "var" / "run"
    alias_parent.parent.mkdir()
    alias_parent.symlink_to(private_parent, target_is_directory=True)
    alias = alias_parent / "Listeners"
    original_stat = Path.stat

    def socket_stat(path, *, follow_symlinks=True):
        metadata = original_stat(path, follow_symlinks=follow_symlinks)
        if Path(path) != target:
            return metadata
        values = list(metadata)
        values[0] = stat.S_IFSOCK | 0o666
        return os.stat_result(values)

    monkeypatch.setattr(Path, "stat", socket_stat)
    resolved, _ = checker._trusted_socket_path(
        os.fspath(alias), root=private_release_tmp / "repository")
    assert resolved == target

    private_parent.chmod(0o770)
    with pytest.raises(SystemExit, match="group- or world-writable parent"):
        checker._trusted_socket_path(
            os.fspath(alias), root=private_release_tmp / "repository")
    private_parent.chmod(0o700)

    def wrong_owner_stat(path, *, follow_symlinks=True):
        metadata = socket_stat(path, follow_symlinks=follow_symlinks)
        if Path(path) != target:
            return metadata
        values = list(metadata)
        values[4] = os.getuid() + 1
        return os.stat_result(values)

    monkeypatch.setattr(Path, "stat", wrong_owner_stat)
    with pytest.raises(SystemExit, match="owner-controlled"):
        checker._trusted_socket_path(
            os.fspath(alias), root=private_release_tmp / "repository")


@_POSIX_RELEASE_GIT
def test_release_checker_accepts_only_the_exact_read_only_https_checkout(
        private_release_tmp):
    tmp_path = private_release_tmp
    checker = _load_release_script("check_release_tag")
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        [
            "git", "remote", "add", "origin",
            "https://github.com/thequantumfalcon/causal-continuity-engine",
        ],
        cwd=repository,
        check=True,
    )
    runner = checker.ReleaseGit.checker(
        root=repository, git_executable="/usr/bin/git")
    runner.close()


@_POSIX_RELEASE_GIT
def test_release_git_rejects_config_changed_after_admission(private_release_tmp):
    tmp_path = private_release_tmp
    checker = _load_release_script("check_release_tag")
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", checker.RELEASE_SSH_ORIGIN],
        cwd=repository,
        check=True,
    )
    runner = checker.ReleaseGit.checker(
        root=repository, git_executable="/usr/bin/git")
    try:
        subprocess.run(
            ["git", "config", "core.fsmonitor", "/tmp/capture-token"],
            cwd=repository,
            check=True,
        )
        with pytest.raises(SystemExit, match="changed after admission"):
            runner.output("status", "--porcelain=v1", "--untracked-files=all")
    finally:
        runner.close()


@_POSIX_RELEASE_GIT
def test_release_git_marks_a_completed_child_when_postflight_changes(
        private_release_tmp, monkeypatch):
    checker = _load_release_script("check_release_tag")
    repository = private_release_tmp / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", checker.RELEASE_SSH_ORIGIN],
        cwd=repository,
        check=True,
    )
    runner = checker.ReleaseGit.checker(
        root=repository, git_executable="/usr/bin/git")

    def completed_then_changed(*args, **kwargs):
        del args, kwargs
        with (repository / ".git" / "config").open("a", encoding="utf-8") as handle:
            handle.write("\n[core]\n\tfsmonitor = /tmp/capture-token\n")
        result = subprocess.CompletedProcess([], 0, "", "")
        result.output_limit_exceeded = False
        return result

    monkeypatch.setattr(checker, "_bounded_process", completed_then_changed)
    try:
        with pytest.raises(checker.ReleaseGitCompletedError) as captured:
            runner.output("status", "--porcelain=v1", "--untracked-files=all")
        assert captured.value.returncode == 0
        assert "postflight failed" in str(captured.value)
    finally:
        runner.close()


@_POSIX_RELEASE_GIT
def test_release_git_rejects_truncated_configuration_inspection(
        private_release_tmp, monkeypatch):
    checker = _load_release_script("check_release_tag")
    runner = object.__new__(checker.ReleaseGit)
    runner.git_executable = Path("/usr/bin/git")
    runner.root = private_release_tmp
    runner._private_home = private_release_tmp
    result = subprocess.CompletedProcess([], 0, b"core.bare\nfalse\0", b"")
    result.output_limit_exceeded = True
    monkeypatch.setattr(checker, "_bounded_process", lambda *args, **kwargs: result)
    monkeypatch.setattr(runner, "_base_environment", lambda: {})

    with pytest.raises(SystemExit, match="configuration output exceeds"):
        runner._run_config(private_release_tmp / "config")


@_POSIX_RELEASE_GIT
def test_bounded_git_child_stops_and_truncates_excess_output(private_release_tmp):
    checker = _load_release_script("check_release_tag")
    result = checker._bounded_process(
        [
            sys.executable,
            "-I",
            "-c",
            "import os; os.write(1, b'x' * 65536)",
        ],
        cwd=private_release_tmp,
        environment={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        temporary_directory=private_release_tmp,
        timeout=5,
        limit=64,
        text=False,
    )
    assert result.output_limit_exceeded is True
    assert result.stdout == b"x" * 64


def test_release_git_purpose_profiles_reject_side_effects_and_extra_arguments(
        monkeypatch):
    checker = _load_release_script("check_release_tag")
    read_only = object.__new__(checker.ReleaseGit)
    read_only.prepare = False
    owner = object.__new__(checker.ReleaseGit)
    owner.prepare = True
    child_calls = []
    monkeypatch.setattr(
        checker, "_bounded_process",
        lambda *args, **kwargs: child_calls.append((args, kwargs)),
    )

    with pytest.raises(SystemExit, match="tag operation"):
        read_only._purpose(("tag", "--delete", "v0.1.5"))
    with pytest.raises(SystemExit, match="unclassified read"):
        owner._purpose(("symbolic-ref", "--delete", "HEAD"))
    with pytest.raises(SystemExit, match="unclassified read"):
        owner._purpose(("status", "--help"))
    with pytest.raises(SystemExit, match="exact explicit SSH origin"):
        owner._purpose((
            "fetch", "--upload-pack=/tmp/capture", "--no-tags",
            checker.RELEASE_SSH_ORIGIN,
            "refs/heads/main:refs/remotes/origin/main",
        ))
    with pytest.raises(SystemExit, match="exact explicit SSH origin"):
        owner._purpose((
            "push", "--porcelain", "--no-verify", checker.RELEASE_SSH_ORIGIN,
            "refs/tags/v0.1.5:refs/tags/v0.1.5", "--force",
        ))
    for args in (
        ("tag", "--sign", "--annotate", "v0.1.5", "--message", "Release v0.1.5"),
        ("tag", "--delete", "v0.1.5"),
        ("verify-tag", "v0.1.5"),
        (
            "fetch", "--no-tags", checker.RELEASE_SSH_ORIGIN,
            "refs/heads/main:refs/remotes/origin/main",
        ),
        (
            "ls-remote", "--exit-code", "--heads", checker.RELEASE_SSH_ORIGIN,
            "refs/heads/main",
        ),
        (
            "push", "--porcelain", "--no-verify", checker.RELEASE_SSH_ORIGIN,
            "refs/tags/v0.1.5:refs/tags/v0.1.5",
        ),
    ):
        with pytest.raises(SystemExit):
            read_only.run(*args)
    assert child_calls == []


def test_release_git_wrappers_route_text_status_and_bytes_through_one_runner():
    tool = _load_release_script("prepare_release_tag")
    events = []

    class Runner:
        def output(self, *args):
            events.append(("output", args))
            return "text"

        def run(self, *args):
            events.append(("run", args))
            return SimpleNamespace(returncode=0)

        def output_bytes(self, *args):
            events.append(("bytes", args))
            return b"bytes"

    runner = Runner()
    previous = tool._set_release_git(runner)
    try:
        assert tool._run_git("rev-parse", "HEAD") == "text"
        assert tool._git_status("show-ref", "--verify", "refs/heads/main").returncode == 0
        assert tool.CHECKER._git("rev-parse", "HEAD") == "text"
        assert tool.CHECKER._git_bytes("cat-file", "commit", "HEAD") == b"bytes"
    finally:
        tool._restore_release_git(previous)
    assert events == [
        ("output", ("rev-parse", "HEAD")),
        ("run", ("show-ref", "--verify", "refs/heads/main")),
        ("output", ("rev-parse", "HEAD")),
        ("bytes", ("cat-file", "commit", "HEAD")),
    ]


@_POSIX_RELEASE_GIT
def test_release_git_rejects_a_private_key_where_a_public_key_is_required(
        private_release_tmp):
    checker = _load_release_script("check_release_tag")
    path = private_release_tmp / "private-key"
    path.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="one OpenSSH public key"):
        checker._require_public_key(path, label="signing key")


@_POSIX_RELEASE_GIT
def test_release_profile_rejects_symlinked_or_owner_mutable_programs(
        private_release_tmp):
    checker = _load_release_script("check_release_tag")
    symlink = private_release_tmp / "git-link"
    symlink.symlink_to("/usr/bin/git")
    with pytest.raises(SystemExit, match="canonical absolute path"):
        checker._trusted_regular_path(
            os.fspath(symlink),
            label="Git executable",
            root=private_release_tmp / "repository",
            executable=True,
        )

    program = private_release_tmp / "owner-program"
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(0o700)
    with pytest.raises(SystemExit, match="untrusted owner"):
        checker._trusted_regular_path(
            os.fspath(program),
            label="Git executable",
            root=private_release_tmp / "repository",
            executable=True,
        )

    writable_parent = private_release_tmp / "shared"
    writable_parent.mkdir(mode=0o770)
    writable_parent.chmod(0o770)
    key = writable_parent / "signing.pub"
    key.write_text("ssh-ed25519 Zml4dHVyZQ== fixture\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="group- or world-writable parent"):
        checker._trusted_regular_path(
            os.fspath(key),
            label="signing key",
            root=private_release_tmp / "repository",
            executable=False,
        )


@_POSIX_RELEASE_GIT
def test_release_git_profiles_are_absolute_and_token_free(
        private_release_tmp, monkeypatch):
    tmp_path = private_release_tmp
    checker = _load_release_script("check_release_tag")
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        [
            "git", "remote", "add", "origin",
            checker.RELEASE_SSH_ORIGIN,
        ],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "branch.main.remote", "origin"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "branch.main.merge", "refs/heads/main"],
        cwd=repository,
        check=True,
    )
    signing_key = tmp_path / "signing.pub"
    allowed_signers = tmp_path / "allowed_signers"
    known_hosts = tmp_path / "known_hosts"
    transport_key = tmp_path / "transport.pub"
    for path in (signing_key, transport_key):
        path.write_text(
            "ssh-ed25519 Zml4dHVyZQ== fixture\n", encoding="utf-8")
    for path in (allowed_signers, known_hosts):
        path.write_text("fixture\n", encoding="utf-8")
    agent_path = tmp_path / "agent.sock"
    agent_path.write_text("fixture socket seam\n", encoding="utf-8")
    monkeypatch.setattr(
        checker,
        "_trusted_socket_path",
        lambda value, *, root: (Path(value), checker._path_snapshot(Path(value))),
    )
    poison = {
        "DYLD_INSERT_LIBRARIES": "/tmp/capture",
        "GH_TOKEN": "api-token",
        "GITHUB_TOKEN": "api-token-2",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/objects",
        "GIT_ASKPASS": "/tmp/askpass",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_GLOBAL": "/tmp/global-config",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_SYSTEM": "/tmp/system-config",
        "GIT_CONFIG_VALUE_0": "/tmp/capture",
        "GIT_DIR": "/tmp/git-dir",
        "GIT_EXEC_PATH": "/tmp/git-exec",
        "GIT_INDEX_FILE": "/tmp/index",
        "GIT_SSH_COMMAND": "/tmp/capture",
        "LD_PRELOAD": "/tmp/capture",
        "PATH": "/tmp/path-shadow",
        "SSH_ASKPASS": "/tmp/capture",
    }
    for key, value in poison.items():
        monkeypatch.setenv(key, value)
    original_bounded_process = checker._bounded_process
    admission_calls = []

    def admission_run(command, **kwargs):
        admission_calls.append((command, kwargs))
        return original_bounded_process(command, **kwargs)

    monkeypatch.setattr(checker, "_bounded_process", admission_run)
    runner = checker.ReleaseGit.owner_profile(
        root=repository,
        git_executable="/usr/bin/git",
        tagger_name="Release Owner",
        tagger_email="owner@example.invalid",
        signing_key=os.fspath(signing_key),
        ssh_keygen_executable="/usr/bin/ssh-keygen",
        allowed_signers_file=os.fspath(allowed_signers),
        ssh_executable="/usr/bin/ssh",
        known_hosts_file=os.fspath(known_hosts),
        transport_key=os.fspath(transport_key),
        ssh_auth_sock=os.fspath(agent_path),
    )
    assert len(admission_calls) == 1
    admission_command, admission_kwargs = admission_calls[0]
    assert admission_command[0] == "/usr/bin/git"
    assert admission_kwargs["environment"]["GIT_CONFIG_COUNT"] == "0"
    assert admission_kwargs["environment"]["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert admission_kwargs["environment"]["GIT_CONFIG_SYSTEM"] == "/dev/null"
    admission_environment = admission_kwargs["environment"]
    expected_admission_overrides = {
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": "/usr/bin:/bin",
    }
    for key in poison:
        if key in expected_admission_overrides:
            assert admission_environment[key] == expected_admission_overrides[key]
        else:
            assert key not in admission_environment
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        value = "" if kwargs["text"] else b""
        result = subprocess.CompletedProcess(command, 0, value, value)
        result.output_limit_exceeded = False
        return result

    monkeypatch.setattr(checker, "_bounded_process", run)
    try:
        runner.output("status", "--porcelain=v1", "--untracked-files=all")
        runner.output(
            "tag", "--sign", "--annotate", "v0.1.5", "--message", "Release v0.1.5")
        runner.output("verify-tag", "v0.1.5")
        runner.output(
            "fetch", "--no-tags", checker.RELEASE_SSH_ORIGIN,
            "refs/heads/main:refs/remotes/origin/main")
        runner.output(
            "push", "--porcelain", "--no-verify", checker.RELEASE_SSH_ORIGIN,
            "refs/tags/v0.1.5:refs/tags/v0.1.5")
        runner.output("tag", "--delete", "v0.1.5")
    finally:
        runner.close()

    assert len(calls) == 6
    for command, kwargs in calls:
        environment = kwargs["environment"]
        assert command[0] == "/usr/bin/git"
        assert "--no-replace-objects" in command
        assert "core.hooksPath=/dev/null" in command
        assert "core.fsmonitor=false" in command
        assert "credential.helper=" in command
        assert environment["GIT_CONFIG_COUNT"] == "0"
        assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert environment["GIT_CONFIG_SYSTEM"] == "/dev/null"
        assert not (set(poison) - {"GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL",
                                    "GIT_CONFIG_SYSTEM", "GIT_SSH_COMMAND",
                                    "PATH"}) & set(environment)
        assert environment["PATH"] == "/usr/bin:/bin"
        assert environment.get("GIT_SSH_COMMAND") != poison["GIT_SSH_COMMAND"]
    assert "SSH_AUTH_SOCK" not in calls[0][1]["environment"]
    assert "GIT_SSH_COMMAND" not in calls[0][1]["environment"]
    assert "gpg.format=ssh" not in calls[0][0]
    assert calls[1][1]["environment"]["SSH_AUTH_SOCK"] == os.fspath(agent_path)
    assert "GIT_SSH_COMMAND" not in calls[1][1]["environment"]
    for setting in (
        "gpg.format=ssh",
        "user.name=Release Owner",
        "user.email=owner@example.invalid",
        f"user.signingKey={signing_key}",
        "gpg.ssh.program=/usr/bin/ssh-keygen",
        f"gpg.ssh.allowedSignersFile={allowed_signers}",
    ):
        assert setting in calls[1][0]
    assert "SSH_AUTH_SOCK" not in calls[2][1]["environment"]
    assert "GIT_SSH_COMMAND" not in calls[2][1]["environment"]
    assert "gpg.format=ssh" in calls[2][0]
    for command, kwargs in calls[3:5]:
        environment = kwargs["environment"]
        assert environment["SSH_AUTH_SOCK"] == os.fspath(agent_path)
        ssh_command = environment["GIT_SSH_COMMAND"]
        for fragment in (
            "/usr/bin/ssh -F /dev/null",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oClearAllForwardings=yes",
            "-oPermitLocalCommand=no",
            "-oProxyCommand=none",
            f"-oUserKnownHostsFile={known_hosts}",
            "-oGlobalKnownHostsFile=/dev/null",
            "-oIdentitiesOnly=yes",
            f"-oIdentityAgent={agent_path}",
            f"-oIdentityFile={transport_key}",
        ):
            assert fragment in ssh_command
        assert "protocol.ssh.allow=always" in command
        assert "gpg.format=ssh" not in command
    assert "SSH_AUTH_SOCK" not in calls[5][1]["environment"]
    assert "GIT_SSH_COMMAND" not in calls[5][1]["environment"]
    assert "gpg.format=ssh" not in calls[5][0]


def test_prepare_release_requires_every_explicit_ssh_profile_input():
    tool = _load_release_script("prepare_release_tag")
    with pytest.raises(SystemExit, match="explicit SSH release profile requires"):
        tool.main(["v0.1.5"])


def test_release_git_fails_closed_on_a_non_posix_release_host(
        tmp_path, monkeypatch):
    checker = _load_release_script("check_release_tag")
    monkeypatch.setattr(checker.os, "name", "nt")
    with pytest.raises(SystemExit, match="require a POSIX platform"):
        checker.ReleaseGit.checker(
            root=tmp_path, git_executable="C:/untrusted/git.exe")


def test_release_workflow_supplies_the_absolute_git_executable():
    workflow = (
        ROOT / ".github" / "workflows" / "release.yml"
    ).read_text(encoding="utf-8")
    assert workflow.count("check_release_tag.py") == 1
    start = workflow.index("      - name: Bind tag to package version")
    end = workflow.index("\n      #", start)
    step = workflow[start:end]
    assert "GITHUB_TOKEN: ${{ github.token }}" in step
    assert re.search(
        r'run: >-\n\s+python \.github/scripts/check_release_tag\.py '
        r'"\$GITHUB_REF_NAME"\n\s+--git-executable /usr/bin/git\n'
        r'\s+--verify-github --verify-required-checks',
        step,
    )


def test_prepare_tag_rejects_stale_origin_main(monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    head = "d" * 40

    def git(*args):
        if args[:2] == ("symbolic-ref", "--short"):
            return "main"
        if args[0] == "fetch":
            return ""
        if args == ("rev-parse", "HEAD"):
            return head
        if args == ("rev-parse", "refs/remotes/origin/main"):
            return head
        raise AssertionError(args)

    monkeypatch.setattr(tool, "_run_git", git)
    monkeypatch.setattr(tool, "_remote_main_sha", lambda: "e" * 40)
    with pytest.raises(SystemExit, match="freshly fetched"):
        tool._require_current_origin_main()


def test_prepare_tag_validates_annotated_signature_and_exact_peeling(monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    head = "f" * 40
    tag_object = "1" * 40
    verified = []
    tag_bytes = (
        f"object {head}\ntype commit\ntag v0.1.0\n\nrelease\n"
        "-----BEGIN SSH SIGNATURE-----"
    ).encode("utf-8")

    def git(*args):
        if args[:2] == ("cat-file", "-t"):
            return "tag"
        if args == ("rev-parse", "refs/tags/v0.1.0^{tag}"):
            return tag_object
        if args == ("rev-parse", "refs/tags/v0.1.0"):
            return tag_object
        if args == ("rev-parse", "refs/tags/v0.1.0^{commit}"):
            return head
        if args == ("verify-tag", "v0.1.0"):
            verified.append(args)
            return ""
        raise AssertionError(args)

    monkeypatch.setattr(tool, "_run_git", git)
    monkeypatch.setattr(tool.CHECKER, "_git_bytes", lambda *args: tag_bytes)
    monkeypatch.setattr(
        tool.CHECKER,
        "_scan_tag_object",
        lambda tag, payload: verified.append(("scan", tag, payload)),
    )
    monkeypatch.setattr(
        tool.CHECKER,
        "_verify_git_object_id",
        lambda oid, kind, payload: verified.append(("oid", oid, kind, payload)),
    )
    assert tool._validate_local_tag("v0.1.0", head) == tag_object
    assert verified == [
        ("scan", "v0.1.0", tag_bytes),
        ("oid", tag_object, "tag", tag_bytes),
        ("verify-tag", "v0.1.0"),
    ]


def test_prepare_tag_rejects_prohibited_raw_tag_before_push_and_cleans(
        monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    head = "7" * 40
    events = []
    monkeypatch.setattr(tool, "_preflight", lambda tag: (head, "0.1.0"))

    def git(*args):
        events.append(("git", args))
        if args[:2] == ("cat-file", "-t"):
            return "tag"
        return ""

    monkeypatch.setattr(tool, "_run_git", git)
    monkeypatch.setattr(
        tool.CHECKER,
        "_git_bytes",
        lambda *args: events.append(("raw", args)) or b"marked tag object",
    )
    monkeypatch.setattr(
        tool.CHECKER,
        "_scan_tag_object",
        lambda tag, payload: (_ for _ in ()).throw(SystemExit("prohibited content")),
    )
    monkeypatch.setattr(
        tool, "_cleanup_created_tag", lambda tag: events.append(("cleanup", tag)))

    with pytest.raises(SystemExit, match="prohibited content"):
        tool.main(["v0.1.0", "--push"], release_git=object())

    assert ("raw", ("cat-file", "tag", "refs/tags/v0.1.0")) in events
    assert ("cleanup", "v0.1.0") in events
    assert not any(
        event[0] == "git" and event[1][0] == "push"
        for event in events if isinstance(event, tuple)
    )


def test_prepare_tag_never_pushes_without_flag_and_rechecks_before_push(
        monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    head = "2" * 40
    events = []
    monkeypatch.setattr(tool, "_preflight", lambda tag: (head, "0.1.0"))
    monkeypatch.setattr(
        tool, "_run_git", lambda *args: events.append(("git", args)) or "")
    monkeypatch.setattr(
        tool, "_validate_local_tag",
        lambda tag, commit: events.append(("validate", tag, commit)) or "3" * 40)
    monkeypatch.setattr(
        tool, "_remote_main_sha",
        lambda: events.append("remote-main") or head)
    monkeypatch.setattr(
        tool, "_require_remote_tag_absent",
        lambda tag: events.append(("remote-absent", tag)))

    assert tool.main(["v0.1.0"], release_git=object()) == 0
    assert not any(
        event[0] == "git" and event[1][0] == "push"
        for event in events if isinstance(event, tuple))

    events.clear()
    assert tool.main(["v0.1.0", "--push"], release_git=object()) == 0
    push_index = events.index((
        "git",
        ("push", "--porcelain", "--no-verify", tool.RELEASE_SSH_ORIGIN,
         "refs/tags/v0.1.0:refs/tags/v0.1.0"),
    ))
    assert events[push_index - 1] == ("remote-absent", "v0.1.0")
    assert events[push_index - 2] == "remote-main"


def test_prepare_tag_cleans_only_a_tag_it_created_on_validation_failure(
        monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    cleaned = []
    monkeypatch.setattr(tool, "_preflight", lambda tag: ("4" * 40, "0.1.0"))
    monkeypatch.setattr(tool, "_run_git", lambda *args: "")
    monkeypatch.setattr(
        tool, "_validate_local_tag",
        lambda tag, head: (_ for _ in ()).throw(SystemExit("bad tag")))
    monkeypatch.setattr(
        tool, "_cleanup_created_tag", lambda tag: cleaned.append(tag))

    with pytest.raises(SystemExit, match="bad tag"):
        tool.main(["v0.1.0"], release_git=object())
    assert cleaned == ["v0.1.0"]

    cleaned.clear()
    monkeypatch.setattr(tool, "_preflight", lambda tag: ("4" * 40, "0.1.0"))
    monkeypatch.setattr(
        tool, "_validate_local_tag",
        lambda tag, head: (_ for _ in ()).throw(RuntimeError("unexpected failure")))
    with pytest.raises(RuntimeError, match="unexpected failure"):
        tool.main(["v0.1.0"], release_git=object())
    assert cleaned == ["v0.1.0"]

    cleaned.clear()
    monkeypatch.setattr(
        tool, "_preflight",
        lambda tag: (_ for _ in ()).throw(SystemExit("preflight failed")))
    with pytest.raises(SystemExit, match="preflight failed"):
        tool.main(["v0.1.0"], release_git=object())
    assert cleaned == []


@pytest.mark.parametrize("returncode", [0, 1])
def test_prepare_tag_cleans_when_creation_may_have_completed_before_failure(
        monkeypatch, returncode):
    tool = _load_release_script("prepare_release_tag")
    cleaned = []
    monkeypatch.setattr(tool, "_preflight", lambda tag: ("4" * 40, "0.1.0"))

    def git(*args):
        if args[:2] == ("tag", "--sign"):
            raise tool.CHECKER.ReleaseGitCompletedError(
                "tag completed but postflight failed", returncode=returncode)
        raise AssertionError(args)

    monkeypatch.setattr(tool, "_run_git", git)
    monkeypatch.setattr(tool, "_local_tag_exists", lambda tag: True)
    monkeypatch.setattr(
        tool, "_cleanup_created_tag", lambda tag: cleaned.append(tag))

    with pytest.raises(SystemExit, match="postflight failed"):
        tool.main(["v0.1.0"], release_git=object())
    assert cleaned == ["v0.1.0"]


def test_prepare_tag_cleans_when_creation_is_interrupted_after_ref_write(
        monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    cleaned = []
    monkeypatch.setattr(tool, "_preflight", lambda tag: ("4" * 40, "0.1.0"))

    def git(*args):
        if args[:2] == ("tag", "--sign"):
            raise KeyboardInterrupt
        raise AssertionError(args)

    monkeypatch.setattr(tool, "_run_git", git)
    monkeypatch.setattr(tool, "_local_tag_exists", lambda tag: True)
    monkeypatch.setattr(
        tool, "_cleanup_created_tag", lambda tag: cleaned.append(tag))

    with pytest.raises(KeyboardInterrupt):
        tool.main(["v0.1.0"], release_git=object())
    assert cleaned == ["v0.1.0"]


def test_prepare_tag_reports_unknown_local_state_when_cleanup_is_interrupted(
        monkeypatch):
    tool = _load_release_script("prepare_release_tag")
    monkeypatch.setattr(tool, "_preflight", lambda tag: ("4" * 40, "0.1.0"))
    monkeypatch.setattr(tool, "_run_git", lambda *args: "")
    monkeypatch.setattr(
        tool,
        "_validate_local_tag",
        lambda tag, head: (_ for _ in ()).throw(SystemExit("invalid tag")),
    )
    monkeypatch.setattr(
        tool,
        "_cleanup_created_tag",
        lambda tag: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(SystemExit, match="local tag may remain"):
        tool.main(["v0.1.0"], release_git=object())


@pytest.mark.parametrize("returncode", [0, 1])
def test_prepare_tag_reports_that_attempted_push_may_have_created_remote_ref(
        monkeypatch, returncode):
    tool = _load_release_script("prepare_release_tag")
    head = "4" * 40
    monkeypatch.setattr(tool, "_preflight", lambda tag: (head, "0.1.0"))
    monkeypatch.setattr(
        tool, "_validate_local_tag", lambda tag, commit: "5" * 40)
    monkeypatch.setattr(tool, "_remote_main_sha", lambda: head)
    monkeypatch.setattr(tool, "_require_remote_tag_absent", lambda tag: None)

    def git(*args):
        if args[0] == "tag":
            return ""
        if args[0] == "push":
            raise tool.CHECKER.ReleaseGitCompletedError(
                "push completed but postflight failed", returncode=returncode)
        raise AssertionError(args)

    monkeypatch.setattr(tool, "_run_git", git)

    with pytest.raises(SystemExit, match="remote tag may already exist"):
        tool.main(["v0.1.0", "--push"], release_git=object())


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, RuntimeError])
def test_prepare_tag_reports_unknown_remote_state_when_push_fails_unexpectedly(
        monkeypatch, failure_type):
    tool = _load_release_script("prepare_release_tag")
    head = "4" * 40
    monkeypatch.setattr(tool, "_preflight", lambda tag: (head, "0.1.0"))
    monkeypatch.setattr(
        tool, "_validate_local_tag", lambda tag, commit: "5" * 40)
    monkeypatch.setattr(tool, "_remote_main_sha", lambda: head)
    monkeypatch.setattr(tool, "_require_remote_tag_absent", lambda tag: None)

    def git(*args):
        if args[0] == "tag":
            return ""
        if args[0] == "push":
            raise failure_type()
        raise AssertionError(args)

    monkeypatch.setattr(tool, "_run_git", git)

    with pytest.raises(SystemExit, match="remote tag may already exist"):
        tool.main(["v0.1.0", "--push"], release_git=object())


def test_signature_audit_is_exact_sha_detective_control():
    workflow = (
        ROOT / ".github" / "workflows" / "commit-signature-audit.yml"
    ).read_text(encoding="utf-8")
    assert "branches:\n      - main" in workflow
    assert "detective, post-push control" in workflow
    assert "cannot prevent that commit from landing" in workflow
    assert "EXPECTED_SHA: ${{ github.sha }}" in workflow
    assert "commits/$EXPECTED_SHA" in workflow
    assert ".sha == $sha" in workflow
    assert ".verified == true" in workflow
    assert "actions/checkout@" not in workflow


def test_every_workflow_action_reference_uses_a_full_commit_sha():
    uses_pattern = re.compile(r"^\s*(?:-\s*)?uses:\s*([^#\s]+)")
    mutable = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1):
            match = uses_pattern.match(line)
            if match is None or match.group(1).startswith("./"):
                continue
            reference = match.group(1).rsplit("@", 1)
            if len(reference) != 2 or re.fullmatch(r"[0-9a-f]{40}", reference[1]) is None:
                mutable.append(f"{path.relative_to(ROOT)}:{line_number}")
    assert mutable == []


def test_release_verifies_public_schemas_before_any_draft_or_publish():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8")
    verify, publish = workflow.split("\n  publish:", 1)
    schema_check = "python .github/scripts/verify_public_schemas.py"
    assert schema_check in verify
    assert verify.index(schema_check) < verify.index(
        "Run every release gate and build twice")
    assert schema_check not in publish
    assert ".github/scripts/" not in publish
    assert "complete mutable ubuntu-latest runner/tool image" in publish
    assert "compromised gh could mutate release state" in publish
    assert "exact two-entry" in publish
    assert "three-file asset set" in publish


def test_checksum_rechecks_compare_the_manifest_in_filename_order():
    """SHA256SUMS is filename-ordered; a digest-ordered recheck is a coin flip.

    `build_distributions.py` writes the manifest from `sorted(hashes.items())`
    and `verify_distributions.py` rebuilds it with `key=lambda item: item.name`,
    so both define the order by filename. A shell recheck that sorts the whole
    line orders by the leading digest instead, which agrees only when the two
    digests happen to sort the same way their filenames do. v0.1.0 passed on
    that coincidence and v0.1.1 did not.
    """
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8")
    rechecks = [
        line.strip() for line in workflow.splitlines()
        if 'sort' in line and '"$expected_manifest"' in line
    ]
    assert len(rechecks) == 2
    for recheck in rechecks:
        assert "LC_ALL=C sort -k2 >" in recheck
