"""Open notices follow dependency edges recorded after the notice (ADR-135)."""

import pytest

from tests.test_dependency_drift_precision import (
    PROJECT,
    _assume,
    _attest,
    _decide,
    _push,
    _status,
)
from tests.test_instrument_validation import _confirmed, _good


def _edge(engine, src, dst, edge_type="assumes"):
    engine.graph.put_edge(
        edge_type=edge_type, src_id=src, dst_id=dst,
        tenant_id=engine.tenant_id, project_id=PROJECT)


def _bridge(engine):
    return engine.graph.put_node(
        entity_type="plan", tenant_id=engine.tenant_id, project_id=PROJECT,
        data={"title": "dependency bridge"}, status="active").id


@pytest.mark.parametrize("confirm", [False, True])
@pytest.mark.parametrize("transitive", [False, True])
def test_open_notice_blocks_late_dependency(tmp_path, confirm, transitive):
    engine, task, _, _ = _good(tmp_path)
    try:
        assumption = _assume(engine)
        notice, = _push(engine, "refresh dependency locks")["invalidations"]
        if confirm:
            _decide(engine, notice, "confirm_invalidation", "confirm-notice")
        dependency = assumption.id
        if transitive:
            dependency = _bridge(engine)
            _edge(engine, dependency, assumption.id, "depends_on")
        _edge(engine, task.id, dependency)
        proof = _attest(engine, task.id)
        assert proof["status"] == "verified"
        with pytest.raises(PermissionError, match="unresolved invalidation control state"):
            engine.complete_task(PROJECT, task.id, proof=proof)
        assert _status(engine, task.id) == "open"
    finally:
        engine.close()


@pytest.mark.parametrize("bound", ["max_depth", "max_nodes"])
def test_late_dependency_traversal_budget_fails_closed(tmp_path, bound):
    engine, task, _, _ = _good(tmp_path)
    try:
        assumption = _assume(engine)
        _push(engine, "refresh dependency locks")
        setattr(engine.invalidation, bound, 1)
        first, second = _bridge(engine), _bridge(engine)
        _edge(engine, first, assumption.id)
        _edge(engine, second, first)
        _edge(engine, task.id, second)
        proof = _attest(engine, task.id)
        assert proof["status"] == "verified"
        with pytest.raises(PermissionError, match="unresolved invalidation control state"):
            engine.complete_task(PROJECT, task.id, proof=proof)
    finally:
        engine.close()


@pytest.mark.parametrize("relationship", ["unrelated", "opposite", "untyped"])
def test_notice_does_not_block_unrelated_task(tmp_path, relationship):
    engine, task, _, _ = _good(tmp_path)
    try:
        assumption = _assume(engine)
        _push(engine, "refresh dependency locks")
        if relationship == "opposite":
            _edge(engine, assumption.id, task.id)
        elif relationship == "untyped":
            _edge(engine, task.id, assumption.id, "produces")
        proof = _attest(engine, task.id)
        assert engine.complete_task(PROJECT, task.id, proof=proof)["status"] == "verified"
    finally:
        engine.close()


@pytest.mark.parametrize("confirm", [False, True])
def test_closed_notice_does_not_hold_late_dependency(tmp_path, confirm):
    engine, task, _, _ = _good(tmp_path)
    try:
        assumption = _assume(engine)
        notice, = _push(engine, "refresh dependency locks")["invalidations"]
        if confirm:
            _decide(engine, notice, "confirm_invalidation", "confirm-notice")
        _edge(engine, task.id, assumption.id)
        if confirm:
            engine.invalidation.resolve(
                notice, mode="narrowed_scope", actor="owner",
                narrowed_scope=engine.graph.get(assumption.id)["scope"])
        else:
            _decide(engine, notice, "reject_invalidation", "reject-notice")
        proof = _attest(engine, task.id)
        assert engine.complete_task(PROJECT, task.id, proof=proof)["status"] == "verified"
    finally:
        engine.close()


@pytest.mark.parametrize("confirm", [False, True])
def test_late_dependency_on_disconnected_historical_dependent(tmp_path, confirm):
    engine, task, _, _ = _good(tmp_path)
    try:
        assumption = _assume(engine)
        held = _confirmed(engine, PROJECT, "task", "- [ ] prepare the exporter", "held-task")
        edge = engine.graph.put_edge(
            edge_type="assumes", src_id=held.id, dst_id=assumption.id,
            tenant_id=engine.tenant_id, project_id=PROJECT)
        notice, = _push(engine, "refresh dependency locks")["invalidations"]
        if confirm:
            _decide(engine, notice, "confirm_invalidation", "confirm-notice")
        engine.graph.end_edge(edge["edge_id"], tenant_id=engine.tenant_id, project_id=PROJECT)
        engine.graph.put_edge(
            edge_type="depends_on", src_id=task.id, dst_id=held.id,
            tenant_id=engine.tenant_id, project_id=PROJECT)
        assert engine.invalidation.blocking_invalidations(PROJECT, held.id)
        proof = _attest(engine, task.id)
        with pytest.raises(PermissionError, match="unresolved invalidation control state"):
            engine.complete_task(PROJECT, task.id, proof=proof)
    finally:
        engine.close()
