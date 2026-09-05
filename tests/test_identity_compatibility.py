"""Statement-identity upgrade regressions (ADR-106)."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path

import pytest

import causal_continuity_engine.engine as engine_module
from causal_continuity_engine.cli import main
from causal_continuity_engine.engine import Engine, stable_node_id

_KIND_PREFIX = {
    "assumption": "asm",
    "requirement": "req",
    "constraint": "cst",
    "decision": "dec",
    "claim": "clm",
    "task": "tsk",
}


def _v1_normalize_statement(statement: str) -> str:
    """Exact statement-key algorithm published in v0.1.2."""
    normalized = statement.lower()
    normalized = re.sub(r"[^a-z0-9 ]+", " ", normalized)
    normalized = re.sub(
        r"\b(the|a|an|is|are|was|were|be|been|that|this|it|its|of|to|in|on|for)\b",
        " ",
        normalized,
    )
    return re.sub(r"\s+", " ", normalized).strip()


def _v1_stable_node_id(project_id: str, kind: str, statement: str) -> str:
    key = f"{project_id}|{kind}|{_v1_normalize_statement(statement)}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:24]
    return f"{_KIND_PREFIX.get(kind, 'nod')}_{digest}"


def _write_identity_store(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    decisions: tuple[str, ...],
    *,
    legacy: bool,
) -> list[str]:
    def write() -> list[str]:
        engine = Engine(path)
        try:
            engine.create_project(
                "identity fixture",
                project_id="prj_identity",
                capture_mode="full",
                config={"require_proof_for": []},
            )
            for index, decision in enumerate(decisions):
                engine.ingest_human_decision(
                    "prj_identity",
                    actor="owner",
                    decision=decision,
                    request_id=f"evt_identity_{index}",
                )
            return [
                node["node_id"]
                for node in engine.graph.current("prj_identity")
                if node["data"].get("stable_key")
            ]
        finally:
            engine.close()

    if not legacy:
        return write()
    with monkeypatch.context() as fixture:
        fixture.setattr(engine_module, "stable_node_id", _v1_stable_node_id)
        return write()


def _snapshot_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.name.endswith(("-shm", "-wal"))
    }


def test_v1_only_identity_refuses_before_engine_storage_changes(tmp_path, monkeypatch):
    database = tmp_path / "legacy.sqlite3"
    legacy_ids = _write_identity_store(
        database,
        monkeypatch,
        ("We decided to use C++ for the €500 parser.",),
        legacy=True,
    )
    assert legacy_ids == ["dec_847d2d51c618e25d1fe0dded"]
    before = _snapshot_files(tmp_path)

    with pytest.raises(ValueError, match="statement identity.*v1") as refusal:
        Engine(database)

    assert type(refusal.value).__name__ == "StatementIdentityCompatibilityError"
    assert "C++" not in str(refusal.value)
    assert "€500" not in str(refusal.value)
    assert _snapshot_files(tmp_path) == before


def test_identity_check_reads_historical_node_versions(tmp_path, monkeypatch):
    database = tmp_path / "legacy-history.sqlite3"
    legacy_ids = _write_identity_store(
        database,
        monkeypatch,
        (
            "We decided to use C++ parser.",
            "We decided to use C parser.",
        ),
        legacy=True,
    )
    # Version 2's current statement is compatible with the v1 id. Only the
    # historical first statement proves that this store crossed the boundary.
    assert legacy_ids == [
        stable_node_id("prj_identity", "decision", "use C parser")
    ]

    with pytest.raises(ValueError, match="statement identity.*v1"):
        Engine(database)


def test_identity_check_reads_committed_wal_history(tmp_path, monkeypatch):
    database = tmp_path / "legacy-wal.sqlite3"
    writer = None
    with monkeypatch.context() as fixture:
        fixture.setattr(engine_module, "stable_node_id", _v1_stable_node_id)
        writer = Engine(database)
        writer.create_project(
            "identity fixture",
            project_id="prj_identity",
            capture_mode="full",
            config={"require_proof_for": []},
        )
        writer.ingest_human_decision(
            "prj_identity",
            actor="owner",
            decision="We decided to use C++ for the €500 parser.",
            request_id="evt_identity_wal",
        )

    try:
        wal_path = Path(str(database) + "-wal")
        assert wal_path.stat().st_size > 0
        immutable = sqlite3.connect(
            database.resolve().as_uri() + "?mode=ro&immutable=1", uri=True
        )
        try:
            table = immutable.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'nodes'"
            ).fetchone()
            if table is not None:
                assert immutable.execute(
                    "SELECT 1 FROM nodes WHERE node_id = ?",
                    ("dec_847d2d51c618e25d1fe0dded",),
                ).fetchone() is None
        finally:
            immutable.close()

        with pytest.raises(ValueError, match="statement identity.*v1"):
            Engine(database)
    finally:
        writer.close()


def test_actual_store_connection_rechecks_after_path_swap(tmp_path, monkeypatch):
    database = tmp_path / "candidate.sqlite3"
    _write_identity_store(
        database,
        monkeypatch,
        ("We decided to use C parser.",),
        legacy=False,
    )
    legacy = tmp_path / "replacement.sqlite3"
    _write_identity_store(
        legacy,
        monkeypatch,
        ("We decided to use C++ for the €500 parser.",),
        legacy=True,
    )
    legacy_digest = hashlib.sha256(legacy.read_bytes()).digest()
    original_store_init = engine_module.Store.__init__

    def swap_then_open(self, path, *args, **kwargs):
        for suffix in ("-shm", "-wal"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        legacy.replace(path)
        original_store_init(self, path, *args, **kwargs)

    monkeypatch.setattr(engine_module.Store, "__init__", swap_then_open)

    with pytest.raises(ValueError, match="statement identity.*v1"):
        Engine(database)

    assert hashlib.sha256(database.read_bytes()).digest() == legacy_digest


def test_precreated_empty_database_still_initializes(tmp_path):
    database = tmp_path / "empty.sqlite3"
    database.touch()

    engine = Engine(database)
    try:
        project = engine.create_project(
            "empty fixture",
            project_id="prj_empty_database",
            config={"require_proof_for": []},
        )
        assert project["node_id"] == "prj_empty_database"
    finally:
        engine.close()


@pytest.mark.parametrize("mutation", ["malformed", "unknown"])
def test_unclassifiable_self_bound_identity_fails_closed(
    tmp_path, monkeypatch, mutation
):
    database = tmp_path / f"{mutation}.sqlite3"
    node_id = _write_identity_store(
        database,
        monkeypatch,
        ("We decided to use the parser.",),
        legacy=False,
    )[0]
    connection = sqlite3.connect(database)
    try:
        if mutation == "malformed":
            connection.execute(
                "UPDATE nodes SET data = ? WHERE node_id = ?",
                (json.dumps({"stable_key": node_id, "statement": 7}), node_id),
            )
        else:
            unknown_id = "dec_000000000000000000000000"
            connection.execute(
                "UPDATE nodes SET node_id = ?, data = ? WHERE node_id = ?",
                (
                    unknown_id,
                    json.dumps({
                        "stable_key": unknown_id,
                        "statement": "use the parser",
                    }),
                    node_id,
                ),
            )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ValueError, match="cannot classify statement identity"):
        Engine(database)


def test_v1_v2_shared_identity_and_v013_style_v2_rebuild(tmp_path, monkeypatch):
    shared_database = tmp_path / "shared.sqlite3"
    shared_ids = _write_identity_store(
        shared_database,
        monkeypatch,
        ("We decided to use C parser.",),
        legacy=True,
    )
    shared = Engine(shared_database)
    try:
        assert shared_ids == [
            stable_node_id("prj_identity", "decision", "use C parser")
        ]
    finally:
        shared.close()

    v2_database = tmp_path / "v013-style.sqlite3"
    v2_ids = _write_identity_store(
        v2_database,
        monkeypatch,
        ("We decided to use C++ for the €500 parser.",),
        legacy=False,
    )
    upgraded = Engine(v2_database)
    rebuilt = upgraded.rebuild_projection("prj_identity")
    try:
        rebuilt_ids = [
            node["node_id"]
            for node in rebuilt.graph.current("prj_identity")
            if node["data"].get("stable_key")
        ]
        assert rebuilt_ids == v2_ids
    finally:
        rebuilt.close()
        upgraded.close()


def test_cli_refusal_precedes_legacy_secret_migration(
    tmp_path, monkeypatch, capsys
):
    main(["--dir", str(tmp_path), "--json", "init"])
    project_id = json.loads(capsys.readouterr().out)["project_id"]
    cce_dir = tmp_path / ".cce"
    database = cce_dir / "cce.db"

    with monkeypatch.context() as fixture:
        fixture.setattr(engine_module, "stable_node_id", _v1_stable_node_id)
        engine = Engine(database)
        try:
            engine.ingest_human_decision(
                project_id,
                actor="owner",
                decision="We decided to use C++ for the €500 parser.",
                request_id="evt_identity_cli",
            )
        finally:
            engine.close()

    meta_path = cce_dir / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    signing_key = cce_dir / meta.pop("signing_key_file")
    meta["signing_key_hex"] = signing_key.read_bytes().hex()
    signing_key.unlink()
    for field in ("api_token_file", "webhook_secret_file"):
        secret = cce_dir / meta.pop(field)
        secret.unlink()
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    before = _snapshot_files(cce_dir)

    with pytest.raises(SystemExit) as refusal:
        main(["--dir", str(tmp_path), "rebuild"])

    assert refusal.value.code == 2
    assert "statement identity" in capsys.readouterr().err
    assert _snapshot_files(cce_dir) == before
