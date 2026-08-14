"""A named backfill must use the project layout every consumer opens."""

from __future__ import annotations

import importlib.util
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

import causal_continuity_engine.cli as cli_module

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "octo/demo"
REPOSITORY_ID = 4242
HEAD_SHA = "b" * 40


def _load_example():
    path = ROOT / "examples" / "backfill_github.py"
    spec = importlib.util.spec_from_file_location("cce_backfill_example", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def backfill(monkeypatch):
    module = _load_example()
    metadata = {
        "id": REPOSITORY_ID,
        "full_name": REPOSITORY,
        "name": "demo",
        "default_branch": "main",
    }

    def fake_get(path, token):
        if path == f"/repos/{REPOSITORY}":
            return dict(metadata)
        if path == f"/repos/{REPOSITORY}/commits/main":
            return {"sha": HEAD_SHA}
        raise AssertionError(f"unexpected GitHub read: {path}")

    monkeypatch.setattr(module, "_get", fake_get)
    monkeypatch.setattr(module, "_paged", lambda *args, **kwargs: [])
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    return module


def test_backfill_into_a_named_directory_produces_an_openable_project(
        backfill, tmp_path):
    assert backfill.main([REPOSITORY, "--dir", str(tmp_path)]) == 0

    assert (tmp_path / ".cce" / "meta.json").is_file()
    assert (tmp_path / ".cce" / "cce.db").is_file()
    assert not (tmp_path / "cce.db").exists()

    engine, meta = cli_module._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        engine._require_project(meta["project_id"])
    finally:
        engine.close()


def test_backfill_without_a_directory_keeps_the_ephemeral_layout(
        backfill, tmp_path, monkeypatch):
    holder = tmp_path / "temporary-project"

    def fake_mkdtemp(*_args, **_kwargs):
        holder.mkdir()
        return str(holder)

    monkeypatch.setattr(backfill.tempfile, "mkdtemp", fake_mkdtemp)

    assert backfill.main([REPOSITORY]) == 0
    assert (holder / "cce.db").is_file()
    assert not (holder / ".cce").exists()


@pytest.mark.parametrize(
    "destination",
    [
        "https://attacker.example/collect",
        "http://api.github.com/repos/o/r",
        "https://api.github.com:bad/repos/o/r",
        "https://someone@api.github.com/repos/o/r",
    ],
)
def test_github_authorization_cannot_cross_a_redirect_boundary(
        backfill, destination):
    request = urllib.request.Request(
        "https://api.github.com/repos/octo/demo",
        headers={"Authorization": "Bearer secret"})

    with pytest.raises(urllib.error.URLError, match="unsafe GitHub API redirect"):
        backfill._SameOriginRedirectHandler().redirect_request(
            request, None, 302, "Found", {}, destination)


def test_same_origin_https_redirect_remains_usable(backfill):
    request = urllib.request.Request(
        "https://api.github.com/repos/octo/demo",
        headers={"Authorization": "Bearer secret"})

    redirected = backfill._SameOriginRedirectHandler().redirect_request(
        request, None, 302, "Found", {},
        "https://api.github.com/repositories/4242")

    assert redirected.full_url == "https://api.github.com/repositories/4242"
    assert redirected.get_header("Authorization") == "Bearer secret"
