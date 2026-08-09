"""Release-control regressions that do not create or push real tags."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_regressions_round10_release import _load_release_script

ROOT = Path(__file__).resolve().parent.parent


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


def test_current_metadata_is_tag_ready_in_both_modes():
    metadata = _load_release_script("check_release_metadata")
    assert metadata.check(ROOT) == ("0.1.1", "2026-08-09")
    assert metadata.check(
        ROOT, release_tag="v0.1.1") == ("0.1.1", "2026-08-09")


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


def test_github_api_url_defaults_and_ghes_binding(monkeypatch):
    checker = _load_release_script("check_release_tag")
    monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    assert checker._github_server_url() == "https://github.com"
    assert checker._github_api_url() == "https://api.github.com"

    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.example.test")
    assert checker._github_api_url() == "https://github.example.test/api/v3"
    monkeypatch.setenv(
        "GITHUB_API_URL", "https://github.example.test/api/v3/")
    assert checker._github_api_url() == "https://github.example.test/api/v3"


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
            "https://api.example.test/api/v3",
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

    monkeypatch.setattr(tool, "_run_git", lambda *args: "https://example.test/wrong")
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

    def git(*args):
        if args[:2] == ("cat-file", "-t"):
            return "tag"
        if args[:2] == ("cat-file", "-p"):
            return (
                f"object {head}\ntype commit\ntag v0.1.0\n\nrelease\n"
                "-----BEGIN SSH SIGNATURE-----")
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
    assert tool._validate_local_tag("v0.1.0", head) == tag_object
    assert verified == [("verify-tag", "v0.1.0")]


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

    assert tool.main(["v0.1.0"]) == 0
    assert not any(
        event[0] == "git" and event[1][0] == "push"
        for event in events if isinstance(event, tuple))

    events.clear()
    assert tool.main(["v0.1.0", "--push"]) == 0
    push_index = events.index((
        "git",
        ("push", "--porcelain", "origin",
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
        tool.main(["v0.1.0"])
    assert cleaned == ["v0.1.0"]

    cleaned.clear()
    monkeypatch.setattr(tool, "_preflight", lambda tag: ("4" * 40, "0.1.0"))
    monkeypatch.setattr(
        tool, "_validate_local_tag",
        lambda tag, head: (_ for _ in ()).throw(RuntimeError("unexpected failure")))
    with pytest.raises(RuntimeError, match="unexpected failure"):
        tool.main(["v0.1.0"])
    assert cleaned == ["v0.1.0"]

    cleaned.clear()
    monkeypatch.setattr(
        tool, "_preflight",
        lambda tag: (_ for _ in ()).throw(SystemExit("preflight failed")))
    with pytest.raises(SystemExit, match="preflight failed"):
        tool.main(["v0.1.0"])
    assert cleaned == []


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
