"""Explicit fixture approval; ingest itself must never invoke this helper."""

from causal_continuity_engine.core import new_id


def confirm_proposal(engine, project_id, proposal_id):
    request = {"operation": "confirm", "request_id": "approve-" + proposal_id,
               "tenant_id": engine.tenant_id, "project_id": project_id,
               **engine.authority_proposal(project_id, proposal_id)}
    receipt = engine.record_authority_decision(project_id, request)
    node = engine.graph.get(receipt["confirmation_id"], tenant_id=engine.tenant_id,
                            project_id=project_id)
    assert engine.graph.may_mandate(node)
    return node


def confirmed_task(engine, project_id, *, text="Ship the verified deliverable"):
    key = new_id("event")
    report = engine.ingest_human_decision(
        project_id, actor="fixture-" + key, decision="- [ ] " + text,
        request_id="source-" + key)
    proposal_id, = [item["node_id"] for item in report["created"]
                    if item["kind"] == "claim" and not item.get("quarantined")]
    assert engine.authority_proposal(project_id, proposal_id)["proposed_kind"] == "task"
    return confirm_proposal(engine, project_id, proposal_id)
