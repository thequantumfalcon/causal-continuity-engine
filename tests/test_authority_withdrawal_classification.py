"""Source withdrawal must not masquerade as a dependency-version change."""

import pytest

from causal_continuity_engine.engine import Engine
from tests.authority_helpers import confirm_proposal
from tests.test_engine_e2e import _issue


@pytest.mark.parametrize("kind,text,trigger", [
    ("requirement", "The exporter must write CSV output.", "changed_requirement"),
    ("constraint", "The exporter must not delete records.", "changed_requirement"),
    ("assumption", "We assume the input is ordered.", "expired_approval"),
    ("decision", "We decided to use PostgreSQL for storage.", "expired_approval"),
    ("task", "- [ ] implement the exporter", "expired_approval"),
])
def test_withdrawal_names_the_lost_control_not_an_unrelated_dependency(kind, text, trigger):
    engine = Engine()
    project = "prj_withdrawal"
    try:
        engine.create_project("withdrawal", project_id=project, repository_id=1001)
        report = engine.ingest_github(project, "issues", "first", _issue(1, text))
        proposal, = [engine.graph.get(row["node_id"]) for row in report["created"]
                     if engine.graph.get(row["node_id"])["data"].get("proposed_kind") == kind]
        confirmed = confirm_proposal(engine, project, proposal.id)
        report = engine.ingest_github(
            project, "issues", "edited", _issue(1, "Background notes.", action="edited"))
        invalidation, = [engine.graph.get(node_id) for node_id in report["invalidations"]]
        assert invalidation["data"]["target_node_id"] == confirmed.id
        assert invalidation["data"]["reason"] == "confirmed source statement withdrawn"
        assert invalidation["data"]["trigger_type"] == trigger
        assert "dependency version" not in invalidation["data"]["recommended_action"]
        assert not engine.graph.may_mandate(engine.graph.get(confirmed.id))
        rebuilt = engine.rebuild_projection(project)
        try:
            restored, = rebuilt.invalidation.open_invalidations(project)
            assert restored["data"]["trigger_type"] == trigger
            assert restored["data"]["recommended_action"] == invalidation["data"][
                "recommended_action"]
        finally:
            rebuilt.close()
    finally:
        engine.close()


def test_expired_approval_does_not_claim_an_unperformed_autonomy_downgrade():
    engine = Engine()
    project = "prj_revoke_wording"
    try:
        engine.create_project("revoke", project_id=project, repository_id=1001,
                              config={"max_autonomy_level": 2})
        engine.policy.grant(project_id=project, level=2, granted_by="owner")
        report = engine.ingest_github(
            project, "issues", "first", _issue(1, "The exporter must write CSV output."))
        confirmed = confirm_proposal(engine, project, report["created"][0]["node_id"])
        binding = engine.authority_confirmation(project, confirmed.id)
        binding.pop("authority_scope")
        assert engine.policy.effective_level(project) == 2
        engine.record_authority_decision(project, {
            "operation": "revoke", "request_id": "revoke",
            "tenant_id": engine.tenant_id, "project_id": project, **binding})
        invalidation, = engine.invalidation.open_invalidations(project)
        assert invalidation["data"]["trigger_type"] == "expired_approval"
        assert engine.policy.effective_level(project) == 2
        assert invalidation["data"]["recommended_action"] == (
            "Request a fresh approval before relying on the affected authority.")
    finally:
        engine.close()
