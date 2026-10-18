"""Manifest scope coverage ends at a complete path segment."""

import pytest

from tests.test_dependency_drift_precision import PROJECT, _assume, _push, _status
from tests.test_dependency_drift_precision import engine as engine


def _narrow(engine, assumption, path):
    notice = engine.invalidation.fire(
        tenant_id=engine.tenant_id, project_id=PROJECT, target_node_id=assumption.id,
        trigger_type="dependency_drift", reason="integration found a mismatch")
    engine.invalidation.resolve(
        notice["node_id"], mode="narrowed_scope", actor="owner",
        narrowed_scope={"paths": [path]})
    assert _status(engine, assumption.id) == "active"


@pytest.mark.parametrize("scope,path", [
    ("packages/api/", "packages/api-other/requirements.txt"),
    ("packages/api/**", "packages/api-other/requirements.txt"),
    ("packages/api/*", "packages/api-other/requirements.txt"),
    ("packages/api", "packages/api-other/requirements.txt"),
    ("requirements.txt", "requirements.txt-other.txt"),
])
def test_scope_does_not_cover_a_sibling_prefix(engine, scope, path):
    assumption = _assume(engine, "the upstream feed is ordered by timestamp")
    _narrow(engine, assumption, scope)
    assert _push(engine, "refresh locks", paths=(path,))["invalidations"] == []
    assert _status(engine, assumption.id) == "active"


@pytest.mark.parametrize("scope,path", [
    ("requirements.txt", "requirements.txt"),
    ("packages/api/", "packages/api/requirements.txt"),
    ("packages/api/**", "packages/api/nested/requirements.txt"),
    ("packages/api/*", "packages/api/requirements.txt"),
    ("packages/api", "packages/api/nested/requirements.txt"),
])
def test_scope_still_covers_exact_files_and_directory_descendants(engine, scope, path):
    assumption = _assume(engine, "the upstream feed is ordered by timestamp")
    _narrow(engine, assumption, scope)
    (notice,) = _push(engine, "refresh locks", paths=(path,))["invalidations"]
    assert _status(engine, notice) == "open"
    assert _status(engine, assumption.id) == "invalidated"
