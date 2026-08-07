"""Deterministic ownership tests for SQLite-backed startup failures."""

import sqlite3

import pytest

from causal_continuity_engine.engine import Engine
from causal_continuity_engine.store import Store


class StartupFailure(RuntimeError):
    """Deliberate initializer failure used to exercise cleanup ownership."""


def _assert_closed(connection: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


def test_store_closes_connection_when_schema_initialization_fails(
        monkeypatch):
    observed = []

    def fail_migration(store):
        observed.append(store._conn)
        raise StartupFailure("schema initialization failed")

    monkeypatch.setattr(
        Store, "_migrate_global_event_idempotency", fail_migration)

    with pytest.raises(StartupFailure, match="schema initialization failed"):
        Store()

    assert len(observed) == 1
    _assert_closed(observed[0])


def test_engine_closes_owned_store_when_component_initialization_fails(
        monkeypatch):
    observed = []

    def fail_backfill(engine):
        observed.append(engine.store._conn)
        raise StartupFailure("engine initialization failed")

    monkeypatch.setattr(Engine, "_backfill_spent_proofs", fail_backfill)

    with pytest.raises(StartupFailure, match="engine initialization failed"):
        Engine()

    assert len(observed) == 1
    _assert_closed(observed[0])
