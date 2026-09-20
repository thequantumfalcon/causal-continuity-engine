"""Compatibility refusal must not implicitly recover a rollback journal."""
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.cli import main
from causal_continuity_engine.engine import (
    PROCESSOR_VERSION,
    Engine,
    ProcessorProjectionCompatibilityError,
)
from tests.test_processor_compatibility import _ingested


def _snapshot(directory):
    return {p.name: (p.stat().st_mode, p.read_bytes())
            for p in directory.iterdir() if p.is_file()}


def _hot_pair(directory, *, incompatible):
    """Current producer plus explicit fixture-only marker rewrite; not an old binary."""
    directory.mkdir(mode=0o700)
    database = _ingested(directory)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
        if incompatible:
            connection.execute("UPDATE processed_events SET processor_version='fixture-old'")
        connection.execute("CREATE TABLE journal_probe_padding (body BLOB)")
        connection.executemany("INSERT INTO journal_probe_padding VALUES (?)",
                               [(b"a" * 8192,)] * 32)
        connection.commit()
    finally:
        connection.close()
    committed = database.read_bytes()
    child = r'''
import os, signal, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA cache_size=1")
connection.execute("PRAGMA cache_spill=1")
connection.execute("PRAGMA synchronous=FULL")
connection.execute("BEGIN IMMEDIATE")
connection.execute("UPDATE processed_events SET processor_version=?", (sys.argv[2],))
connection.execute("UPDATE journal_probe_padding SET body=?", (b"b" * 8192,))
assert connection.in_transaction
os.kill(os.getpid(), signal.SIGTERM if os.name == "nt" else signal.SIGKILL)
'''
    result = subprocess.run([sys.executable, "-I", "-c", child, str(database), PROCESSOR_VERSION],
                            capture_output=True, timeout=20)
    assert result.returncode != 0 and not result.stdout and not result.stderr
    journal = Path(str(database) + "-journal")
    assert journal.stat().st_size > 512
    assert journal.read_bytes()[:8].hex() == "d9d505f920a163d7"
    assert database.read_bytes() != committed, "no dirty-page spill"
    return database, committed


@pytest.mark.parametrize("incompatible", [False, True])
def test_genuine_hot_journal_refuses_before_recovery(tmp_path, incompatible):
    database, committed = _hot_pair(tmp_path / "original", incompatible=incompatible)
    before = _snapshot(database.parent)
    # A separate normal-SQLite read MUST recover, proving journal hotness and
    # real on-disk consequences independently of the compatibility checker.
    recovery = tmp_path / "recovery"
    shutil.copytree(database.parent, recovery)
    recovered = recovery / database.name
    connection = sqlite3.connect(recovered)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    assert recovered.read_bytes() == committed
    assert not Path(str(recovered) + "-journal").exists()
    if not incompatible:
        instance = Engine(recovered)
        instance.close()
    with pytest.raises(ProcessorProjectionCompatibilityError, match="rollback journal"):
        instance = Engine(database)
        instance.close()
    assert _snapshot(database.parent) == before


def test_journal_interposed_after_preflights_refuses_before_connection_reads(tmp_path, monkeypatch):
    hot, _ = _hot_pair(tmp_path / "hot", incompatible=True)
    target_dir = tmp_path / "target"
    target_dir.mkdir(mode=0o700)
    target = _ingested(target_dir)
    original = engine_module._assert_processor_projection_compatible_path
    snapshots = []

    def interpose(path):
        original(path)
        shutil.copy2(hot, target)
        shutil.copy2(Path(str(hot) + "-journal"), Path(str(target) + "-journal"))
        snapshots.append(_snapshot(target_dir))

    monkeypatch.setattr(engine_module, "_assert_processor_projection_compatible_path", interpose)
    with pytest.raises(ProcessorProjectionCompatibilityError, match="rollback journal"):
        instance = Engine(target)
        instance.close()
    assert len(snapshots) == 1
    assert _snapshot(target_dir) == snapshots[0]


@pytest.mark.parametrize("checker", [
    engine_module._assert_statement_identity_compatible_path,
    engine_module._assert_processor_projection_compatible_path,
])
@pytest.mark.parametrize("kind", ["empty", "directory", "dangling-link"])
def test_sidecar_presence_is_not_mistaken_for_a_hotness_classification(tmp_path, checker, kind):
    database = tmp_path / "absent.db"
    journal = Path(str(database) + "-journal")
    if kind == "empty":
        journal.touch()
    elif kind == "directory":
        journal.mkdir()
    else:
        if os.name == "nt":
            pytest.skip("creating symbolic links requires separate Windows privilege")
        journal.symlink_to(tmp_path / "absent-target")
    before = journal.lstat()
    with pytest.raises(ProcessorProjectionCompatibilityError, match="rollback journal"):
        checker(database)
    assert not database.exists()
    assert journal.lstat() == before


def test_cold_persist_journal_requires_explicit_copy_recovery(tmp_path):
    database = _ingested(tmp_path)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] == "persist"
        connection.execute("CREATE TABLE journal_probe_cold (value TEXT)")
        connection.commit()
    finally:
        connection.close()
    journal = Path(str(database) + "-journal")
    assert journal.exists() and journal.read_bytes()[:8] == b"\x00" * 8
    before = _snapshot(tmp_path)
    with pytest.raises(ProcessorProjectionCompatibilityError, match="rollback journal"):
        instance = Engine(database)
        instance.close()
    assert _snapshot(tmp_path) == before
    recovery = tmp_path / "recovery"
    recovery.mkdir()
    copied = recovery / "source.db"
    shutil.copy2(database, copied)
    shutil.copy2(journal, Path(str(copied) + "-journal"))
    source = sqlite3.connect(copied)
    clean = sqlite3.connect(recovery / "clean.db")
    try:
        source.backup(clean)
        assert clean.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        clean.close()
        source.close()
    instance = Engine(recovery / "clean.db")
    instance.close()
    assert _snapshot(tmp_path) == before


def test_cli_journal_refusal_leaves_real_project_state_unchanged(tmp_path, capsys):
    main(["--dir", str(tmp_path), "init", "--repo", "fixture/project", "--repo-id", "4242"])
    capsys.readouterr()
    (tmp_path / ".cce/cce.db-journal").touch()

    def snapshot():
        return {str(p.relative_to(tmp_path)): (p.stat().st_mode, p.read_bytes())
                for p in tmp_path.rglob("*") if p.is_file()}

    before = snapshot()
    with pytest.raises(SystemExit) as refusal:
        main(["--dir", str(tmp_path), "resume"])
    assert refusal.value.code == 2
    output = capsys.readouterr()
    assert output.out == "" and "rollback journal" in output.err
    assert str(tmp_path) not in output.err
    assert snapshot() == before


def test_memory_database_is_not_a_filesystem_journal_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path(":memory:-journal").touch()
    for path in (":memory:", Path(":memory:")):
        instance = Engine(path)
        instance.close()
