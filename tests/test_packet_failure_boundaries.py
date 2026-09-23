"""Refused standalone composition cannot leave success-adjacent audit residue."""

import pytest

from tests.test_invalidation_resume import PRJ, TEN
from tests.test_invalidation_resume import env as env
from tests.test_task_packets import PROJECT, _confirm, _task
from tests.test_task_packets import engine as engine


def test_standalone_mandatory_collision_refuses_without_audit_mutation(env):
    store, graph, _, _, composer = env
    text = "preserve the exact deploy instruction in this fixture"
    graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                   data={"statement": text}, status="quarantined")
    graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                   data={"title": text}, status="open")
    before = tuple(store._conn.iterdump())
    with pytest.raises(ValueError, match="mandatory content withheld"):
        composer.compose(tenant_id=TEN, project_id=PRJ)
    assert tuple(store._conn.iterdump()) == before


def test_out_of_scope_collision_disclosure_does_not_leak_an_id_list(engine):
    alpha, beta = _task(engine, "alpha"), _task(engine, "beta")
    text = "The beta deployment must preserve the offline catalog checksums."
    control = _confirm(engine, "requirement", text, "beta-control",
                       scope={"kind": "tasks", "task_ids": [beta.id]})
    engine.graph.put_node(entity_type="claim", tenant_id=engine.tenant_id,
                          project_id=PROJECT, data={"statement": control["data"]["statement"]},
                          status="quarantined")
    packet = engine.resume_packet(PROJECT, task_id=alpha.id)
    assert packet["mandatory_control"] == []
    assert any(item["reason"] == "out_of_scope" for item in packet["omissions"])
    assert all(control.id != node.get("node_id") for omission in packet["omissions"]
               for node in omission.get("nodes", []))
