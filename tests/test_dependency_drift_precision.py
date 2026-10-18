"""Dependency drift names its target and a rejected push cannot mute the next one.

The bot subjects below are quoted from the linked upstream commits or pull requests. Version
changes in the grouped-push bodies are deliberate breaking-change fixtures;
the subject names no package, so both pushes require their own human decision.
"""

import pytest

from causal_continuity_engine.engine import Engine
from tests.test_instrument_validation import PRJ as PROJECT
from tests.test_instrument_validation import REPOSITORY_ID, _confirmed, _good

REQUESTS = "the requests library version stays below 3"
# Dependabot: "Bump the minor-patch group across 1 directory with 3 updates"
# https://github.com/theupdateframework/tuf-js/commit/ea33919f9a602fc0e63c03c653c0751ea8128cab
GROUPED = "Bump the minor-patch group across 1 directory with 3 updates"


@pytest.fixture
def engine():
    engine = Engine()
    engine.create_project("dependency-drift", project_id=PROJECT,
                          repository_id=REPOSITORY_ID, capture_mode="full")
    try:
        yield engine
    finally:
        engine.close()


def _assume(engine, statement=REQUESTS, key="dependency"):
    return _confirmed(engine, PROJECT, "assumption", f"We assume {statement}.", key)


def _push(engine, message, delivery="push-1", *, before="a" * 40,
          after="b" * 40, paths=("requirements.txt",), commit_id=None, commits=None):
    if commits is None:
        commits = [{"id": after if commit_id is None else commit_id,
                    "message": message, "added": [], "modified": list(paths),
                    "removed": [], "timestamp": "2026-07-29T12:00:00Z"}]
    return engine.ingest_github(PROJECT, "push", delivery, {
        "ref": "refs/heads/main", "before": before, "after": after,
        "forced": False, "deleted": False, "created": False,
        "commits": commits, "head_commit": {"timestamp": "2026-07-29T12:00:00Z"},
        "repository": {"id": REPOSITORY_ID, "full_name": "o/r"}})


def _status(engine, node_id):
    return engine.graph.get(node_id, tenant_id=engine.tenant_id, project_id=PROJECT)["status"]


def _decide(engine, notice_id, operation, request_id):
    return engine.record_authority_decision(PROJECT, {
        "operation": operation, "request_id": request_id,
        "tenant_id": engine.tenant_id, "project_id": PROJECT,
        **engine.authority_invalidation(PROJECT, notice_id)})


def _attest(engine, task_id):
    return engine.attest_action(
        PROJECT, intent_type="task_complete", intent_statement="exporter done",
        actor={"agent": "test"}, action_type="run_verifier",
        continuity={"task_ids": [task_id]})


def _dependent_task(tmp_path):
    engine, task, _, _ = _good(tmp_path)
    assumption = _assume(engine)
    engine.graph.put_edge(
        edge_type="assumes", src_id=task.id, dst_id=assumption.id,
        tenant_id=engine.tenant_id, project_id=PROJECT)
    return engine, task, assumption


def test_named_bump_invalidates_only_one_of_four_confirmed_assumptions(engine):
    statements = [REQUESTS, "the public API version stays at v2",
                  "the exporter requires UTC timestamps", "the importer package only reads CSV"]
    assumptions = [_assume(engine, statement, f"assumption-{index}")
                   for index, statement in enumerate(statements)]
    report = _push(engine, "bump requests to 3.0")
    notices = [engine.graph.get(node_id) for node_id in report["invalidations"]]
    assert len(notices) == 4
    assert {notice["data"]["target_node_id"] for notice in notices
            if notice["status"] == "open"} == {assumptions[0].id}
    assert _status(engine, assumptions[0].id) == "invalidated"
    assert all(_status(engine, assumption.id) == "active" for assumption in assumptions[1:])
    assert {notice["data"]["target_node_id"] for notice in notices
            if notice["status"] == "pending_confirmation"} == {
                assumption.id for assumption in assumptions[1:]}


@pytest.mark.parametrize("subject,package,path", [
    # Dependabot: "Bump requests from 2.31.0 to 2.32.0"
    # https://github.com/krishnakuruvadi/portfoliomanager/pull/118
    ("Bump requests from 2.31.0 to 2.32.0", "requests", "requirements.txt"),
    # Renovate: "build(deps): update dependency cronstrue to v3.29.0 (main) (#46930)"
    # https://github.com/renovatebot/renovate/commit/69a4024480ba7116efb2a18918da1ffb91878eca
    ("build(deps): update dependency cronstrue to v3.29.0 (main) (#46930)",
     "cronstrue", "package.json"),
    # Renovate: "Update module github.com/stretchr/testify to v1.9.0"
    # https://github.com/minetest-go/mtauth/commit/f9a8dfc6f755231d85059c816b1f55d008b25c91
    ("Update module github.com/stretchr/testify to v1.9.0",
     "github.com/stretchr/testify", "go.mod"),
    # Renovate: "fix(deps): update rust crate serde to v1.0.226"
    # https://github.com/sterliakov/toggl/commit/b42d5930c269439ff7fa5ef37ece795fd9d4c05a
    ("fix(deps): update rust crate serde to v1.0.226", "serde", "Cargo.toml"),
    # Renovate: "chore(deps): update react monorepo to v19 (major)"
    # https://gitlab.com/biomedit/portal/-/merge_requests/1479
    ("chore(deps): update react monorepo to v19 (major)", "react", "package.json"),
])
def test_real_bot_subjects_name_the_dependency(engine, subject, package, path):
    assumption = _assume(engine, f"the {package} library remains compatible")
    (notice_id,) = _push(engine, subject, paths=(path,))["invalidations"]
    assert _status(engine, notice_id) == "open"
    assert _status(engine, assumption.id) == "invalidated"


def test_real_dependabot_subject_names_both_packages(engine):
    # Dependabot: "Bump OpenTelemetry and OpenTelemetry.Exporter.OpenTelemetryProtocol"
    # https://github.com/dependabot/dependabot-core/commit/a6e4af749dbba761ceb3f184e8657059c0ffcc14
    subject = "Bump OpenTelemetry and OpenTelemetry.Exporter.OpenTelemetryProtocol"
    packages = ("opentelemetry", "opentelemetry.exporter.opentelemetryprotocol")
    assumptions = [_assume(engine, f"the {package} library remains compatible", package)
                   for package in packages]
    report = _push(engine, subject)
    assert len(report["invalidations"]) == 2
    assert all(_status(engine, notice_id) == "open" for notice_id in report["invalidations"])
    assert all(_status(engine, assumption.id) == "invalidated" for assumption in assumptions)


@pytest.mark.parametrize("subject,statement", [
    ("Update app to 2.0", "the mobile app caches tokens for a day"),
    ("bump requests to 3.0, update ci to python 3.12", "the ci pipeline caches wheels"),
    ("Bump version to 0.4.0", "the public API version stays at v2"),
    ("update dependencies to latest", "the cli has no native dependencies"),
])
def test_common_words_are_never_automatic_package_matches(engine, subject, statement):
    assumption = _assume(engine, statement)
    report = _push(engine, subject)
    assert _status(engine, assumption.id) == "active"
    assert all(_status(engine, node_id) == "pending_confirmation"
               for node_id in report["invalidations"])


def test_a_body_cannot_supply_a_named_bump(engine):
    assumption = _assume(engine)
    (notice_id,) = _push(engine, "refresh dependency locks\n\nBump requests to 3.0")[
        "invalidations"]
    assert _status(engine, notice_id) == "pending_confirmation"
    assert _status(engine, assumption.id) == "active"


@pytest.mark.parametrize("subject", [
    "Do not bump requests to 3.0",
    "docs: explain how to bump requests to 3.0",
    'Revert "Bump requests from 2.31.0 to 2.32.0"',
])
def test_nonaffirmative_subjects_need_human_review(engine, subject):
    assumption = _assume(engine)
    (notice_id,) = _push(engine, subject)["invalidations"]
    assert _status(engine, notice_id) == "pending_confirmation"
    assert _status(engine, assumption.id) == "active"


@pytest.mark.parametrize("bumped,assumed", [
    ("@scope/foo-bar", "@scope/foo_bar"),
    ("foo-bar", "foo_bar"),
    ("foo.bar", "foo-bar"),
])
def test_python_name_normalization_does_not_equate_distinct_npm_packages(engine, bumped, assumed):
    assumption = _assume(engine, f"the {assumed} library remains compatible")
    (notice_id,) = _push(engine, f"Update dependency {bumped} to v2",
                         paths=("package.json",))["invalidations"]
    assert _status(engine, notice_id) == "pending_confirmation"
    assert _status(engine, assumption.id) == "active"


def test_scope_paths_from_narrowed_resolution_still_invalidate_automatically(engine):
    assumption = _assume(engine, "the upstream feed is ordered by timestamp")
    earlier = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT, target_node_id=assumption.id,
        trigger_type="dependency_drift", reason="integration found a mismatch")
    engine.invalidation.resolve(
        earlier["node_id"], mode="narrowed_scope", actor="owner",
        narrowed_scope={"paths": ["requirements.txt"]})
    assert _status(engine, assumption.id) == "active"
    (notice_id,) = _push(engine, "refresh locks")["invalidations"]
    assert _status(engine, notice_id) == "open"
    assert _status(engine, assumption.id) == "invalidated"


def test_a_different_commit_cannot_name_the_manifest_change(engine):
    assumption = _assume(engine)
    commits = [
        {"id": "b" * 40, "message": "refresh dependency locks", "added": [],
         "modified": ["requirements.txt"], "removed": []},
        {"id": "c" * 40, "message": "bump requests to 3.0", "added": [],
         "modified": ["docs/upgrade.md"], "removed": []},
    ]
    (notice_id,) = _push(engine, "", after="c" * 40, commits=commits)["invalidations"]
    assert _status(engine, notice_id) == "pending_confirmation"
    assert _status(engine, assumption.id) == "active"


@pytest.mark.parametrize("subject,package", [
    ("Bump Requests_OAuthlib to 2.0", "requests-oauthlib"),
    ("chore(deps): update dependency @types/node to v22", "@types/node"),
    ("bump requests[socks] from 2.32 to 3.0", "requests"),
])
def test_package_normalization_keeps_supported_names(engine, subject, package):
    assumption = _assume(engine, f"the {package} library remains compatible")
    (notice_id,) = _push(engine, subject)["invalidations"]
    assert _status(engine, notice_id) == "open"
    assert _status(engine, assumption.id) == "invalidated"


def test_package_prefixes_are_not_exact_names(engine):
    assumption = _assume(engine, "the requests-cache library remains compatible")
    (notice_id,) = _push(engine, "bump requests to 3.0")["invalidations"]
    assert _status(engine, notice_id) == "pending_confirmation"
    assert _status(engine, assumption.id) == "active"


def test_distinctive_shared_subject_word_requires_review(engine):
    assumption = _assume(engine, "the exporter accepts UTC timestamps")
    (notice_id,) = _push(engine, "refresh exporter pins")["invalidations"]
    assert _status(engine, notice_id) == "pending_confirmation"
    assert _status(engine, assumption.id) == "active"


def test_non_manifest_changes_raise_no_drift(engine):
    assumption = _assume(engine)
    assert _push(engine, "bump requests to 3.0", paths=("docs/upgrade.md",))["invalidations"] == []
    assert _status(engine, assumption.id) == "active"


def test_many_manifests_keep_the_reason_bounded_and_the_push_processed(engine):
    assumption = _assume(engine)
    paths = tuple(f"packages/{index:03d}/{'long-path-' * 8}/requirements.txt"
                  for index in range(100))
    (notice_id,) = _push(engine, "bump deps", paths=paths)["invalidations"]
    notice = engine.graph.get(notice_id)
    assert notice["status"] == "pending_confirmation"
    assert len(notice["data"]["reason"]) <= 4096
    assert _status(engine, assumption.id) == "active"
    assert engine.continuity_check(PROJECT)["conclusion"] == "action_required"


def test_a_later_push_gets_its_own_notice_even_while_the_first_is_pending(engine):
    _assume(engine)
    (first,) = _push(engine, "bump deps")["invalidations"]
    assert _status(engine, first) == "pending_confirmation"
    (second,) = _push(engine, "bump deps", "push-2", before="b" * 40,
                      after="c" * 40)["invalidations"]
    assert first != second
    assert _status(engine, second) == "pending_confirmation"


def test_redelivery_of_the_same_sha_does_not_raise_a_second_notice(engine):
    assumption = _assume(engine)
    (first,) = _push(engine, "bump deps")["invalidations"]
    assert _status(engine, first) == "pending_confirmation"
    assert _push(engine, "bump deps", "redelivery")["invalidations"] == []
    _decide(engine, first, "reject_invalidation", "reject-first")
    assert _push(engine, "bump deps", "rejected-redelivery")["invalidations"] == []
    assert _status(engine, assumption.id) == "active"


def test_completion_baseline_with_a_dependency_succeeds(tmp_path):
    engine, task, _ = _dependent_task(tmp_path)
    try:
        proof = _attest(engine, task.id)
        assert proof["status"] == "verified"
        assert engine.complete_task(PROJECT, task.id, proof=proof)["status"] == "verified"
    finally:
        engine.close()


def test_rejected_group_notice_cannot_mute_a_new_breaking_push_or_complete_task(tmp_path):
    engine, task, assumption = _dependent_task(tmp_path)
    try:
        (first,) = _push(engine, GROUPED + "\n\nUpdates `requests` from 2.31 to 2.32")[
            "invalidations"]
        assert _status(engine, first) == "pending_confirmation"
        _decide(engine, first, "reject_invalidation", "reject-first")
        assert _status(engine, assumption.id) == "active"
        later = _push(
            engine, GROUPED + "\n\nUpdates `requests` from 2.32 to 3.0", "push-2",
            before="b" * 40, after="c" * 40)
        proof = _attest(engine, task.id)
        assert proof["status"] == "verified"
        with pytest.raises(PermissionError, match="unresolved invalidation control state"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        assert _status(engine, task.id) != "verified"
        (second,) = later["invalidations"]
        assert second != first
        assert _status(engine, second) == "pending_confirmation"
        assert engine.continuity_check(PROJECT)["pending_confirmation"] == [second]
        _decide(engine, second, "confirm_invalidation", "confirm-second")
        assert _status(engine, assumption.id) == "invalidated"
    finally:
        engine.close()


def test_rejected_notice_cannot_mute_a_later_named_bump_or_complete_task(tmp_path):
    engine, task, assumption = _dependent_task(tmp_path)
    try:
        (first,) = _push(engine, "bump deps")["invalidations"]
        assert _status(engine, first) == "pending_confirmation"
        _decide(engine, first, "reject_invalidation", "reject-first")
        (second,) = _push(engine, "bump requests to 3.0", "push-2",
                          before="b" * 40, after="c" * 40)["invalidations"]
        assert _status(engine, second) == "open"
        assert _status(engine, assumption.id) == "invalidated"
        proof = _attest(engine, task.id)
        with pytest.raises(PermissionError, match="unresolved invalidation control state"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        assert _status(engine, task.id) != "verified"
    finally:
        engine.close()


@pytest.mark.parametrize("second_decision", [None, "reject_invalidation", "confirm_invalidation"])
def test_rebuild_reproduces_rejection_then_new_push_and_its_decision(engine, second_decision):
    _assume(engine)
    (first,) = _push(engine, "bump deps")["invalidations"]
    assert _status(engine, first) == "pending_confirmation"
    _decide(engine, first, "reject_invalidation", "reject-first")
    (second,) = _push(engine, "bump deps", "push-2", before="b" * 40,
                      after="c" * 40)["invalidations"]
    if second_decision is not None:
        _decide(engine, second, second_decision, "decide-second")
    fresh = engine.rebuild_projection(PROJECT)
    try:
        assert engine.projection_fingerprint(PROJECT) == fresh.projection_fingerprint(PROJECT)
        assert _status(fresh, first) == "rejected"
        assert _status(fresh, second) == _status(engine, second)
    finally:
        fresh.close()
