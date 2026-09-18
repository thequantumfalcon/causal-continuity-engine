"""A named backfill must use the project layout every consumer opens."""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

import causal_continuity_engine.cli as cli_module
from causal_continuity_engine.engine import Engine

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


@pytest.mark.parametrize("mode", ["named", "ephemeral"])
def test_backfill_closes_an_acquired_engine_when_setup_fails(
        backfill, tmp_path, monkeypatch, mode):
    class SetupError(RuntimeError):
        pass

    class CleanupError(RuntimeError):
        pass

    setup_error = SetupError(f"{mode} setup failed")
    cleanup_error = CleanupError("cleanup failed")
    engine = Engine(
        tmp_path / f"{mode}.db", tenant_id=f"ten_{mode}", workdir=tmp_path)
    connection = engine.store._conn
    real_close = engine.close
    close_count = 0

    def close_then_fail():
        nonlocal close_count
        close_count += 1
        real_close()
        raise cleanup_error

    monkeypatch.setattr(engine, "close", close_then_fail)
    if mode == "named":
        target = tmp_path / "target"
        (target / ".cce").mkdir(parents=True)

        class FailingMetadata(dict):
            def __getitem__(self, key):
                if key == "project_id":
                    raise setup_error
                return super().__getitem__(key)

        monkeypatch.setattr(
            cli_module, "_engine", lambda _args: (engine, FailingMetadata()))
        argv = [REPOSITORY, "--dir", str(target)]
    else:
        holder = tmp_path / "temporary-project"
        holder.mkdir()
        monkeypatch.setattr(
            backfill.tempfile, "mkdtemp", lambda *_args, **_kwargs: str(holder))
        monkeypatch.setattr(backfill, "Engine", lambda *_args, **_kwargs: engine)

        def fail_create_project(*_args, **_kwargs):
            raise setup_error

        monkeypatch.setattr(engine, "create_project", fail_create_project)
        argv = [REPOSITORY]

    try:
        with pytest.raises(SetupError) as caught:
            backfill.main(argv)

        assert caught.value is setup_error
        assert close_count == 1
        assert repr(cleanup_error) in " ".join(
            getattr(caught.value, "__notes__", []))
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
    finally:
        try:
            connection.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            pass
        else:
            real_close()


def test_backfill_propagates_close_failure_without_an_active_error(
        backfill, tmp_path, monkeypatch):
    class CleanupError(RuntimeError):
        pass

    holder = tmp_path / "temporary-project"
    holder.mkdir()
    engine = Engine(holder / "cce.db", tenant_id="ten_cleanup", workdir=holder)
    connection = engine.store._conn
    real_close = engine.close
    cleanup_error = CleanupError("cleanup failed")
    close_count = 0

    def close_then_fail():
        nonlocal close_count
        close_count += 1
        real_close()
        raise cleanup_error

    monkeypatch.setattr(
        backfill.tempfile, "mkdtemp", lambda *_args, **_kwargs: str(holder))
    monkeypatch.setattr(backfill, "Engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(engine, "close", close_then_fail)

    with pytest.raises(CleanupError) as caught:
        backfill.main([REPOSITORY])

    assert caught.value is cleanup_error
    assert close_count == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


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


@pytest.mark.parametrize(
    ("source", "destination", "allowed"),
    [
        ("https://api.github.com/repos/o/r",
         "https://api.github.com:443/repos/o/r", True),
        ("https://api.github.com:443/repos/o/r",
         "https://api.github.com/repos/o/r", True),
        ("https://api.github.com/repos/o/r",
         "https://api.github.com:0/repos/o/r", False),
        ("https://api.github.com:0/repos/o/r",
         "https://api.github.com/repos/o/r", False),
        ("https://api.github.com:8443/repos/o/r",
         "https://api.github.com:8443/repositories/4242", True),
        ("https://api.github.com:0/repos/o/r",
         "https://api.github.com:0/repositories/4242", True),
    ],
)
def test_redirect_port_identity_is_not_truthiness(
        backfill, source, destination, allowed):
    request = urllib.request.Request(
        source, headers={"Authorization": "Bearer secret"})

    if not allowed:
        with pytest.raises(
                urllib.error.URLError, match="unsafe GitHub API redirect"):
            backfill._SameOriginRedirectHandler().redirect_request(
                request, None, 302, "Found", {}, destination)
        return

    redirected = backfill._SameOriginRedirectHandler().redirect_request(
        request, None, 302, "Found", {}, destination)
    assert redirected.full_url == destination
    assert redirected.get_header("Authorization") == "Bearer secret"


def test_same_origin_https_redirect_remains_usable(backfill):
    request = urllib.request.Request(
        "https://api.github.com/repos/octo/demo",
        headers={"Authorization": "Bearer secret"})

    redirected = backfill._SameOriginRedirectHandler().redirect_request(
        request, None, 302, "Found", {},
        "https://api.github.com/repositories/4242")

    assert redirected.full_url == "https://api.github.com/repositories/4242"
    assert redirected.get_header("Authorization") == "Bearer secret"


def test_backfill_reports_the_nodes_it_created(backfill, monkeypatch, capsys):
    """The summary counted `report["nodes"]`, a key the ingest report does not
    have, so it always printed 0 nodes even when statements were extracted."""
    issue = {
        "number": 1, "title": "Exporter", "state": "open",
        "body": "The exporter must write CSV output.",
        "author_association": "OWNER", "created_at": "2026-07-29T10:00:00Z",
        "labels": [],
    }
    monkeypatch.setattr(
        backfill, "_paged",
        lambda path, token, **_kwargs: [issue] if path.endswith("/issues?state=all") else [])

    assert backfill.main([REPOSITORY]) == 0

    summary = next(line for line in capsys.readouterr().out.splitlines()
                   if "ingested" in line)
    created = int(summary.split("->")[1].split("node(s)")[0])
    assert created > 0, summary


@pytest.mark.parametrize(
    "suffix", ["\n", "\r", " ", "\t", "\x7f", "\u20ac", "\u00e9"])
def test_a_malformed_token_is_refused_without_being_echoed(
        monkeypatch, capsys, suffix):
    """A token read from a file with a stray newline made http.client raise
    `ValueError: Invalid header value b'Bearer <token>\\n'`, printing the
    whole credential to stderr before any request left the machine."""
    import socket

    module = _load_example()
    secret = "ghp_" + "S" * 36

    def refuse_network(*_args, **_kwargs):
        raise OSError("network is not available to this test")

    monkeypatch.setattr(socket.socket, "connect", refuse_network)
    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setenv("GITHUB_TOKEN", secret + suffix)

    with pytest.raises(SystemExit) as caught:
        module.main([REPOSITORY])

    captured = capsys.readouterr()
    assert secret not in str(caught.value.code)
    assert secret not in captured.out
    assert secret not in captured.err
    assert "GITHUB_TOKEN" in str(caught.value.code)
