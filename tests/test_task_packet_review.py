"""Independent deciding-path probes for the scoped packet implementation."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.core import digest_obj
from causal_continuity_engine.engine import Engine
from tests.test_task_packets import PROJECT, _confirm, _packet, _task
from tests.test_task_packets import engine as engine


@pytest.mark.parametrize("task_mode", [False, True])
def test_validity_frontier_cannot_bless_a_packet_omitting_newly_active_control(
        engine, monkeypatch, task_mode):
    task = _task(engine, "validity")
    requirement = _confirm(
        engine, "requirement", "The temporal exporter must preserve checksums.", "temporal")
    engine.graph.put_node(
        entity_type="requirement", tenant_id=engine.tenant_id, project_id=PROJECT,
        node_id=requirement.id, data={}, valid_from="2099-01-01T00:00:01Z")
    calls = []

    def crossed_frontier():
        calls.append(None)
        return "2099-01-01T00:00:00Z" if len(calls) == 1 else "2099-01-01T00:00:02Z"

    # Only time advances; producer authority and all database readers remain real.
    monkeypatch.setattr(engine_module, "utcnow", crossed_frontier)
    selected = task.id if task_mode else None
    packet = _packet(engine, selected)
    included = {member["node_id"] for member in packet["mandatory_control"]}
    stale = engine.packet_is_stale(PROJECT, task_id=selected)
    assert stale or requirement.id in included, (
        "watermark blesses a complete packet whose authority predates its control basis")


@pytest.mark.parametrize("status", ["active", "review_required", "uncertain"])
def test_live_selected_task_is_not_omitted_from_its_complete_work_packet(engine, status):
    task = _task(engine, "live")
    engine.graph.put_node(
        entity_type="task", tenant_id=engine.tenant_id, project_id=PROJECT,
        node_id=task.id, data={}, status=status)
    assert engine.graph.may_mandate(engine.graph.get(task.id))
    packet = _packet(engine, task.id)
    assert packet["complete"] is True
    assert task.id in {item["node_id"] for item in packet["open_work"]["tasks"]}, (
        "accepted live task scope became a complete packet with no selected work")
    if status in ("review_required", "uncertain"):
        assert task.id in {item["node_id"] for item in packet["open_work"]["blockers"]}
        assert packet["open_work"]["next_safe_action"].get("node_id") != task.id


@pytest.mark.parametrize("validity", [
    {"valid_from": "2099-01-01T00:00:00Z"},
    {"valid_from": "2000-01-01T00:00:00Z", "valid_to": "2001-01-01T00:00:00Z"},
])
def test_noncurrent_confirmed_task_cannot_be_actionable_project_work(engine, validity):
    task = _task(engine, "noncurrent")
    engine.graph.put_node(
        entity_type="task", tenant_id=engine.tenant_id, project_id=PROJECT,
        node_id=task.id, data={}, **validity)
    packet = _packet(engine)
    assert task.id not in {item["node_id"] for item in packet["open_work"]["tasks"]}
    assert packet["open_work"]["next_safe_action"].get("node_id") != task.id
    with pytest.raises(ValueError, match="current confirmed task"):
        _packet(engine, task.id)


@pytest.mark.parametrize("boundary", ["valid_from", "valid_to"])
def test_task_validity_transition_stales_prior_project_packet(engine, monkeypatch, boundary):
    task = _task(engine, "frontier")
    engine.graph.put_node(
        entity_type="task", tenant_id=engine.tenant_id, project_id=PROJECT,
        node_id=task.id, data={}, **{boundary: "2099-01-01T00:00:01Z"})
    monkeypatch.setattr(engine_module, "utcnow", lambda: "2099-01-01T00:00:00Z")
    first = _packet(engine)
    assert (task.id in {item["node_id"] for item in first["open_work"]["tasks"]}) == (
        boundary == "valid_to")
    assert not engine.packet_is_stale(PROJECT)
    monkeypatch.setattr(engine_module, "utcnow", lambda: "2099-01-01T00:00:02Z")
    assert engine.packet_is_stale(PROJECT)
    second = _packet(engine)
    assert (task.id in {item["node_id"] for item in second["open_work"]["tasks"]}) == (
        boundary == "valid_from")
    assert not engine.packet_is_stale(PROJECT)


def _legacy_store(path):
    instance = Engine(path)
    instance.create_project("Legacy packet", project_id=PROJECT, capture_mode="full")
    task = _task(instance, "legacy")
    packet = instance.resume_packet(PROJECT)
    row = dict(instance.store._conn.execute("SELECT * FROM packet_watermark").fetchone())
    instance.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute("ALTER TABLE packet_watermark RENAME TO scoped_watermark")
        connection.execute(
            "CREATE TABLE packet_watermark (project_id TEXT PRIMARY KEY, "
            "last_event_seq INTEGER NOT NULL, composed_at TEXT NOT NULL, packet_id TEXT, "
            "packet_digest TEXT, control_basis_digest TEXT, audit_entry_hash TEXT)")
        connection.execute(
            "INSERT INTO packet_watermark SELECT project_id,last_event_seq,composed_at,"
            "packet_id,packet_digest,control_basis_digest,audit_entry_hash FROM scoped_watermark")
        connection.execute("DROP TABLE scoped_watermark")
        connection.commit()
    finally:
        connection.close()
    return task.id, packet, row


def test_concurrent_legacy_reopen_preserves_history_as_stale(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    task_id, packet, legacy = _legacy_store(path)
    barrier = threading.Barrier(2)

    def reopen():
        barrier.wait(timeout=5)
        instance = Engine(path)
        try:
            row = dict(instance.store._conn.execute("SELECT * FROM packet_watermark").fetchone())
            assert row["scope_key"] == "project"
            assert row["packet_id"] == packet["packet_id"]
            for field in ("packet_digest", "control_basis_digest", "last_event_seq", "composed_at"):
                assert row[field] == legacy[field]
            assert row["audit_entry_hash"] is None
            assert instance.packet_is_stale(PROJECT)
            assert instance.packet_is_stale(PROJECT, task_id=task_id)
            return row
        finally:
            instance.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(reopen) for _ in range(2)]
        rows = [future.result(timeout=20) for future in futures]
    assert rows[0] == rows[1]
    instance = Engine(path)
    try:
        instance.resume_packet(PROJECT, task_id=task_id)
        assert instance.packet_is_stale(PROJECT)
        assert not instance.packet_is_stale(PROJECT, task_id=task_id)
        count = instance.store._conn.execute("SELECT COUNT(*) FROM packet_watermark").fetchone()[0]
        assert count == 2
    finally:
        instance.close()


def test_read_only_legacy_reopen_never_migrates_source_or_refreshes_watermark(tmp_path):
    path = tmp_path / "legacy-readonly.sqlite3"
    _legacy_store(path)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="read-only packet watermark schema is unsupported"):
        Engine(path, _read_only=True)
    assert path.read_bytes() == before
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()


def test_current_schema_read_only_composition_preserves_watermarks_and_source(tmp_path):
    path = tmp_path / "current-readonly.sqlite3"
    writer = Engine(path)
    writer.create_project("Current packet", project_id=PROJECT, capture_mode="full")
    task_id = _task(writer, "readonly").id
    packet = writer.resume_packet(PROJECT)
    writer.close()
    before = path.read_bytes()
    instance = Engine(path, _read_only=True)
    try:
        assert not instance.packet_is_stale(PROJECT)
        assert instance.packet_is_stale(PROJECT, task_id=task_id)
        row = dict(instance.store._conn.execute("SELECT * FROM packet_watermark").fetchone())
        assert row["packet_id"] == packet["packet_id"]
        snapshot = tuple(instance.store._conn.iterdump())
        returned = instance._resume_packet(PROJECT, task_id=task_id, record_state=False)
        assert returned["scope"] == {"kind": "task", "task_id": task_id}
        assert returned["authority_set_digest"] == digest_obj(returned["mandatory_control"])
        assert tuple(instance.store._conn.iterdump()) == snapshot
        assert not instance.packet_is_stale(PROJECT)
        assert instance.packet_is_stale(PROJECT, task_id=task_id)
    finally:
        instance.close()
    assert path.read_bytes() == before
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()


def test_read_snapshot_cannot_mix_later_confirmation_into_packet(engine, monkeypatch):
    task = _task(engine, "snapshot")
    prior = _packet(engine, task.id)
    writer = Engine(engine.store.path, tenant_id=engine.tenant_id)
    original = engine.composer.compose
    created = []

    def compose_after_other_writer(**kwargs):
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                _confirm, writer, "requirement",
                "The concurrent exporter must preserve archive checksums.", "concurrent")
            created.append(future.result(timeout=10))
        return original(**kwargs)

    monkeypatch.setattr(engine.composer, "compose", compose_after_other_writer)
    try:
        packet = engine._resume_packet(PROJECT, task_id=task.id, record_state=False)
        assert packet["project_state_basis"] == prior["project_state_basis"]
        assert packet["mandatory_control"] == prior["mandatory_control"]
        assert created[0].id not in {item["node_id"] for item in packet["mandatory_control"]}
        assert engine.graph.may_mandate(engine.graph.get(created[0].id))
        assert engine.packet_is_stale(PROJECT, task_id=task.id)
    finally:
        writer.close()
