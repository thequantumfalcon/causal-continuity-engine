"""Packets keep their selected validity instant without skipping target rechecks."""
from pathlib import Path

import pytest

from causal_continuity_engine import core, lamport
from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.core import Signer
from causal_continuity_engine.engine import Engine, ResumeTaskScopeError
from causal_continuity_engine.lamport import LamportSigner
from tests.test_task_packets import _task

PROJECT = "prj_validity_frontier"
BEFORE = "2099-01-01T00:00:00Z"
AFTER = "2099-01-01T00:00:01Z"


@pytest.fixture
def prepared(tmp_path, monkeypatch, request):
    assert Path(engine_module.__file__).resolve() == (
        Path.cwd() / "causal_continuity_engine/engine.py")

    def make(scheme):
        signer = Signer.generate() if scheme == "hmac" else LamportSigner()
        engine = Engine(tmp_path / (scheme + ".sqlite3"), signer=signer, workdir=tmp_path)
        request.addfinalizer(engine.close)
        engine.create_project("Validity frontier", project_id=PROJECT, capture_mode="full")
        task = _task(engine, "validity", project_id=PROJECT)
        engine.graph.put_node(
            node_id=task.id, entity_type="task", tenant_id=engine.tenant_id,
            project_id=PROJECT, data={}, valid_to="2099-01-01T00:00:01Z")
        clock = [BEFORE]
        monkeypatch.setattr(engine_module, "utcnow", lambda: clock[0])
        previous = engine.resume_packet(PROJECT, task_id=task.id)
        assert signer.verify(previous)
        assert not engine.packet_is_stale(PROJECT, task_id=task.id)
        return engine, task, clock, previous

    return make


def _dump(engine):
    return tuple(engine.store._conn.iterdump())


def _registries(signer):
    return (list(getattr(signer, "issued_fingerprints", [])),
            set(getattr(signer, "registered_fingerprints", set())))


def _observe(monkeypatch, scheme):
    module, name = (core.hmac, "new") if scheme == "hmac" else (lamport, "generate_keypair")
    original = getattr(module, name)
    calls = []

    def observed(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, observed)
    return calls


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
@pytest.mark.parametrize("record_state", [True, False], ids=["writer", "read-only"])
@pytest.mark.parametrize("crossing", [False, True], ids=["unchanged", "crossing"])
def test_packet_records_one_selected_validity_frontier(
        prepared, monkeypatch, scheme, record_state, crossing):
    engine, task, clock, previous = prepared(scheme)
    before = _dump(engine)
    canonical = tuple(engine.store._conn.execute("SELECT * FROM events"))
    nodes = tuple(engine.store._conn.execute("SELECT * FROM nodes"))
    basis = engine._packet_state_basis(PROJECT, task_id=task.id)
    registries = _registries(engine.signer)
    original = engine.composer.compose

    def interpose(**kwargs):
        if crossing:
            clock[0] = AFTER
        return original(**kwargs)

    monkeypatch.setattr(engine.composer, "compose", interpose)
    with monkeypatch.context() as patch:
        calls = _observe(patch, scheme)
        packet = engine._resume_packet(PROJECT, task_id=task.id, record_state=record_state)
        assert calls == [True]
    assert engine.signer.verify(packet)
    assert packet["scope"] == {"kind": "task", "task_id": task.id}
    assert packet["project_state_basis"] == basis
    assert task.id in {item["node_id"] for item in packet["open_work"]["tasks"]}
    assert tuple(engine.store._conn.execute("SELECT * FROM events")) == canonical
    assert tuple(engine.store._conn.execute("SELECT * FROM nodes")) == nodes
    row = engine.store._conn.execute(
        "SELECT packet_id FROM packet_watermark WHERE project_id=? AND scope_key=?",
        (PROJECT, "task:" + task.id)).fetchone()
    assert row[0] == (packet["packet_id"] if record_state else previous["packet_id"])
    if not record_state:
        assert _dump(engine) == before
    if scheme == "lamport":
        assert engine.signer.issued_fingerprints == (
            registries[0] + [packet["signature"]["fingerprint"]])
        assert engine.signer.registered_fingerprints == (
            registries[1] | {packet["signature"]["fingerprint"]})
    if crossing:
        # A returned as-of packet is not permission to use an expired task now.
        with pytest.raises(ResumeTaskScopeError, match="current confirmed task"):
            engine.packet_is_stale(PROJECT, task_id=task.id)
        after = _dump(engine)
        current_registries = _registries(engine.signer)
        with monkeypatch.context() as patch:
            calls = _observe(patch, scheme)
            with pytest.raises(ResumeTaskScopeError):
                engine.resume_packet(PROJECT, task_id=task.id)
            assert calls == []
        assert _dump(engine) == after
        assert _registries(engine.signer) == current_registries
    else:
        assert not engine.packet_is_stale(PROJECT, task_id=task.id)


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
def test_already_expired_target_refuses_before_signing(prepared, monkeypatch, scheme):
    engine, task, clock, _ = prepared(scheme)
    clock[0] = AFTER
    before, registries = _dump(engine), _registries(engine.signer)
    with monkeypatch.context() as patch:
        calls = _observe(patch, scheme)
        with pytest.raises(ResumeTaskScopeError, match="current confirmed task"):
            engine.resume_packet(PROJECT, task_id=task.id)
        assert calls == []
    assert _dump(engine) == before
    assert _registries(engine.signer) == registries


@pytest.mark.parametrize("defect", ["quarantine", "validity", "statement", "revoke", "terminal"])
def test_final_target_check_still_refuses_interposed_semantic_change(
        prepared, monkeypatch, defect):
    engine, task, clock, _ = prepared("hmac")
    before = _dump(engine)
    original = engine.composer.compose

    def interpose(**kwargs):
        packet = original(**kwargs)
        clock[0] = AFTER
        if defect == "revoke":
            binding = engine.authority_confirmation(PROJECT, task.id)
            engine.record_authority_decision(PROJECT, {
                "operation": "revoke", "request_id": "interposed-revoke",
                "tenant_id": engine.tenant_id, "project_id": PROJECT,
                **{key: value for key, value in binding.items() if key != "authority_scope"},
            })
        else:
            changes = {"quarantine": {"status": "quarantined"},
                       "terminal": {"status": "verified"},
                       "validity": {"valid_to": BEFORE},
                       "statement": {"data": {"statement": "Altered task instructions"}}}[defect]
            engine.graph.put_node(
                node_id=task.id, entity_type="task", tenant_id=engine.tenant_id,
                project_id=PROJECT, **({"data": {}} | changes))
        return packet

    monkeypatch.setattr(engine.composer, "compose", interpose)
    with pytest.raises(ResumeTaskScopeError, match="(?:current|live) confirmed task"):
        engine.resume_packet(PROJECT, task_id=task.id)
    assert _dump(engine) == before


@pytest.mark.parametrize("mutation", ["canonical-rescope", "validity"])
def test_still_eligible_mutation_cannot_bless_a_later_basis(prepared, monkeypatch, mutation):
    engine, task, clock, _ = prepared("hmac")
    basis = engine._packet_state_basis(PROJECT, task_id=task.id)
    original = engine.composer.compose

    def interpose(**kwargs):
        packet = original(**kwargs)
        if mutation == "canonical-rescope":
            binding = engine.authority_confirmation(PROJECT, task.id)
            engine.record_authority_decision(PROJECT, {
                "operation": "replace_scope", "request_id": "interposed-rescope",
                "tenant_id": engine.tenant_id, "project_id": PROJECT, **binding,
            })
        else:
            engine.graph.put_node(
                node_id=task.id, entity_type="task", tenant_id=engine.tenant_id,
                project_id=PROJECT, data={}, valid_to="2099-01-01T00:00:00.500000Z")
        return packet

    monkeypatch.setattr(engine.composer, "compose", interpose)
    packet = engine.resume_packet(PROJECT, task_id=task.id)
    assert engine.signer.verify(packet)
    assert packet["project_state_basis"] == basis
    watermark = engine.store._conn.execute(
        "SELECT last_event_seq, control_basis_digest FROM packet_watermark "
        "WHERE project_id=? AND scope_key=?", (PROJECT, "task:" + task.id)).fetchone()
    assert tuple(watermark) == (basis["event_seq"], basis["control_basis_digest"])
    assert engine.packet_is_stale(PROJECT, task_id=task.id)
    if mutation == "validity":
        clock[0] = AFTER
        with pytest.raises(ResumeTaskScopeError, match="current confirmed task"):
            engine.packet_is_stale(PROJECT, task_id=task.id)
