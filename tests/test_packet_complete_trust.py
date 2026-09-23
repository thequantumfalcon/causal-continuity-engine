"""Complete packets disclose required trust state without the old ten-row cap."""

import shlex
import sys

from causal_continuity_engine.verifiers import VerifierSpec
from tests.test_task_packets import PROJECT, _packet, _task
from tests.test_task_packets import engine as engine


def test_complete_trust_contains_every_required_current_verifier(engine):
    task = _task(engine, "verifier-coverage")
    command = shlex.join([sys.executable, "-c", "print(1)"])
    definitions = [{"name": f"check-{index:02d}", "command": command}
                   for index in range(12)]
    engine.policy.set_project_config(PROJECT, {
        "required_verifiers": definitions, "min_evidence_grade": "C"})
    # Runtime verified records are a privileged input. This fixture does not
    # claim to have executed twelve independent verifiers or establish their adequacy.
    nodes = [engine.graph.put_node(
        entity_type="verification", tenant_id=engine.tenant_id, project_id=PROJECT,
        status="passed", authority="verifier_authoritative", data={
            "verifier": definition["name"], "source": "executed", "pinned": True,
            "definition_digest": VerifierSpec.from_policy(definition).definition_digest,
        }) for definition in engine.policy.required_verifier_defs(PROJECT)]
    packet = _packet(engine, task.id)
    assert packet["trust"]["gaps"] == []
    assert {node["node_id"] for node in packet["trust"]["completed_checks"]} == {
        node.id for node in nodes}


def test_packet_commits_complete_current_policy_not_only_verifier_names(engine):
    task = _task(engine, "policy-coverage")
    engine.policy.set_project_config(PROJECT, {
        "max_autonomy_level": 1, "min_evidence_grade": "B",
        "require_proof_for": ["task_complete"],
        "required_verifiers": [{"name": "review", "command": shlex.join([
            sys.executable, "-c", "print(1)"])}],
    })
    packet = _packet(engine, task.id)
    assert packet["trust"].get("policy") == engine.policy.project_config(PROJECT)
    assert engine.signer.verify(packet)
