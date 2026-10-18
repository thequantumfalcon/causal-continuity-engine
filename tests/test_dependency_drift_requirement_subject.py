"""Dependabot requirement subjects name only the package before the label."""

import pytest

from tests.test_dependency_drift_precision import _assume, _push, _status
from tests.test_dependency_drift_precision import engine as engine


@pytest.mark.parametrize("subject,package,paths", [
    # Dependabot, with the actual changed manifest:
    # https://github.com/allure-framework/allure-ruby/pull/585.patch
    ("Update rubocop requirement from ~> 1.73.2 to ~> 1.74.0", "rubocop", ("Gemfile",)),
    # Dependabot, with the actual changed manifests:
    # https://github.com/berntpopp/stringdb-link/pull/61.patch
    ("deps: update uvicorn[standard] requirement", "uvicorn", ("pyproject.toml", "uv.lock")),
    # Synthetic boundary cases combine supported extras and version-range forms.
    ("Update uvicorn[standard] requirement from >=0.1 to >=0.2",
     "uvicorn[standard]", ("pyproject.toml",)),
    ("chore(deps): Update Requests_OAuthlib requirement to >=2",
     "requests-oauthlib", ("requirements.txt",)),
])
def test_requirement_subject_names_only_its_package(engine, subject, package, paths):
    target = _assume(engine, f"the {package} library remains compatible", "target")
    unrelated = _assume(engine, "the standard library remains compatible", "unrelated")
    label = _assume(engine, "the requirement library remains compatible", "label")
    report = _push(engine, subject, paths=paths)
    notices = [engine.graph.get(node_id) for node_id in report["invalidations"]]
    assert _status(engine, target.id) == "invalidated"
    assert _status(engine, unrelated.id) == "active"
    assert _status(engine, label.id) == "active"
    assert {notice["data"]["target_node_id"] for notice in notices
            if notice["status"] == "open"} == {target.id}
    assert {notice["data"]["target_node_id"] for notice in notices
            if notice["status"] == "pending_confirmation"} == {unrelated.id, label.id}
    assert len(notices) == 3


@pytest.mark.parametrize("word", [
    "ci", "app", "api", "version", "dependencies", "build", "requirement",
])
def test_requirement_subject_keeps_common_words_out_of_package_identity(engine, word):
    target = _assume(engine, f"the {word} library remains compatible")
    (notice_id,) = _push(engine, f"Update {word} requirement from 1.0 to 2.0")["invalidations"]
    assert _status(engine, target.id) == "active"
    assert _status(engine, notice_id) == "pending_confirmation"


def test_bare_requirement_is_a_common_word(engine):
    target = _assume(engine, "the requirement library remains compatible")
    (notice_id,) = _push(engine, "Update requirement from 1 to 2")["invalidations"]
    assert _status(engine, target.id) == "active"
    assert _status(engine, notice_id) == "pending_confirmation"


@pytest.mark.parametrize("subject", [
    "refresh dependency locks\n\nUpdate uvicorn requirement from 0.1 to 0.2",
    "docs: explain how to update uvicorn requirement from 0.1 to 0.2",
    'Revert "Update uvicorn requirement from 0.1 to 0.2"',
])
def test_requirement_names_in_bodies_or_nonaffirmative_subjects_need_review(engine, subject):
    target = _assume(engine, "the uvicorn library remains compatible")
    (notice_id,) = _push(engine, subject)["invalidations"]
    assert _status(engine, target.id) == "active"
    assert _status(engine, notice_id) == "pending_confirmation"
