"""Graceful partial progress (GPP-001..GPP-005).

A run may end completed, partially_completed, blocked, failed, cancelled, or
inconclusive — never a collapsed binary. Verified artifacts are retained,
ambiguous ones quarantined, and a recovery packet names the exact safe
boundary and rerun instructions. A failed action never invalidates
unrelated prior verified work.
"""

from __future__ import annotations

from .core import (
    canonical_json,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
)
from .ontology import FAILURE_TAXONOMY, RUN_OUTCOMES


def _outcome_items(value, *, field: str) -> list[dict]:
    if value is None:
        return []
    if (not isinstance(value, list)
            or any(not isinstance(item, dict) for item in value)):
        raise ValueError(f"{field} must be an array of outcome objects")
    try:
        normalized = strict_json_loads(canonical_json(value))
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError(
            f"{field} must contain only finite I-JSON outcome objects") from None
    return normalized


class PartialProgressManager:
    def __init__(
            self, store, graph, memory, *, tenant_id: str | None = None):
        self.store = store
        self.graph = graph
        self.memory = memory
        self.tenant_id = tenant_id

    def _tenant(self, tenant_id: str) -> str:
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise PermissionError(
                f"partial-progress tenant {tenant_id!r} is outside the "
                f"bound tenant {self.tenant_id!r}")
        return self.tenant_id or tenant_id

    def _project(self, project_id: str) -> None:
        if self.tenant_id is None:
            return
        try:
            self.graph.get(
                project_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="project")
        except KeyError:
            raise PermissionError(
                f"partial-progress project {project_id!r} is outside the "
                f"bound tenant {self.tenant_id!r}") from None

    def _node(self, node_id: str, *, entity_type: str | None = None) -> dict:
        try:
            return self.graph.get(
                node_id, tenant_id=self.tenant_id, entity_type=entity_type)
        except KeyError:
            raise PermissionError(
                f"partial-progress node {node_id!r} is outside the "
                "bound tenant") from None

    def record_outcome(
        self,
        *,
        tenant_id: str,
        project_id: str,
        session_id: str | None,
        status: str,
        completed: list[dict] | None = None,
        failed: list[dict] | None = None,
        blocked: list[dict] | None = None,
        skipped: list[dict] | None = None,
        unverified: list[dict] | None = None,
        failure_mode: str | None = None,
        event_id: str | None = None,
    ) -> dict:
        """GPP-002: record a truthful multi-state outcome."""
        completed = _outcome_items(completed, field="completed")
        failed = _outcome_items(failed, field="failed")
        blocked = _outcome_items(blocked, field="blocked")
        skipped = _outcome_items(skipped, field="skipped")
        unverified = _outcome_items(unverified, field="unverified")
        if session_id is not None:
            session_id = validate_public_identifier(
                session_id, field="partial-progress session_id")
        tenant_id = self._tenant(tenant_id)
        self._project(project_id)
        if not isinstance(status, str) or status not in RUN_OUTCOMES:
            raise ValueError(f"unknown run outcome {status!r}")
        if (failure_mode is not None
                and (not isinstance(failure_mode, str)
                     or failure_mode not in FAILURE_TAXONOMY)):
            raise ValueError(
                "failure_mode must be null or a known failure taxonomy value")
        if session_id is not None:
            session = self._node(session_id, entity_type="session")
            if session["project_id"] != project_id:
                raise PermissionError(
                    "partial-progress session belongs to another project")
        with self.store.transaction():
            outcome = self.graph.put_node(
                entity_type="outcome", tenant_id=tenant_id,
                project_id=project_id, status=status,
                data={
                    "session_id": session_id,
                    "completed": completed,
                    "failed": failed,
                    "blocked": blocked,
                    "skipped": skipped,
                    "unverified": unverified,
                    "failure_mode": failure_mode,
                    "recorded_at": utcnow(),
                },
                event_id=event_id,
            )
            if session_id is not None:
                self.graph.put_edge(
                    edge_type="produces", src_id=session_id, dst_id=outcome.id,
                    tenant_id=tenant_id, project_id=project_id, event_id=event_id)
        return outcome

    def quarantine(self, node_id: str, actor: str, reason: str,
                   event_id: str | None = None) -> dict:
        """GPP-004: quarantined artifacts cannot satisfy completion or reach L3."""
        node = self._node(node_id)
        # AD-006 bars quarantined content from every tier. Memory.promote
        # enforces that going forward, but a node already holding a tier kept
        # it — so a decision pinned to L0 and quarantined afterwards stayed
        # pinned control state, and stayed in the memory export as such
        # (ADR-062). Quarantine is a status change; the tier must follow it.
        with self.store.transaction():
            out = self.graph.put_node(
                entity_type=node["entity_type"], tenant_id=node["tenant_id"],
                project_id=node["project_id"], node_id=node_id,
                data={"quarantine_reason": reason, "quarantined_at": utcnow()},
                status="quarantined", event_id=event_id,
            )
            vacated = self.memory.demote_from_any_tier(
                node["project_id"], node_id, actor=actor,
                reason=f"quarantined: {reason}")
            self.store.audit(
                actor=actor, action="artifact.quarantine",
                object_id=node_id,
                detail=reason + (f" (demoted from {vacated})"
                                 if vacated else ""))
        return out

    def record_rollback(self, *, tenant_id: str, project_id: str, action_id: str,
                        compensating_action: str, status: str,
                        evidence_digest: str | None = None,
                        event_id: str | None = None) -> dict:
        """GPP-005: compensating action + rollback status with evidence."""
        if not isinstance(status, str) or status not in RUN_OUTCOMES:
            raise ValueError(f"unknown rollback outcome {status!r}")
        if (not isinstance(compensating_action, str)
                or not compensating_action.strip()):
            raise ValueError(
                "rollback compensating_action must be a non-empty string")
        compensating_action = validate_human_text(
            compensating_action, field="rollback compensating_action",
            max_length=4096)
        tenant_id = self._tenant(tenant_id)
        self._project(project_id)
        action = self._node(action_id, entity_type="action")
        if action["project_id"] != project_id:
            raise PermissionError("rollback action belongs to another project")
        with self.store.transaction():
            node = self.graph.put_node(
                entity_type="action", tenant_id=tenant_id,
                project_id=project_id, status=f"rollback_{status}",
                data={
                    "kind": "rollback",
                    "compensates": action_id,
                    "compensating_action": compensating_action,
                    "evidence_digest": evidence_digest,
                    "recorded_at": utcnow(),
                },
                event_id=event_id,
            )
            self.graph.put_edge(
                edge_type="supersedes", src_id=node.id, dst_id=action_id,
                tenant_id=tenant_id, project_id=project_id, event_id=event_id)
        return node

    def recovery_packet(self, project_id: str, session_id: str | None = None) -> dict:
        """GPP-003: machine- and human-readable recovery plan."""
        if session_id is not None:
            session_id = validate_public_identifier(
                session_id, field="recovery session_id")
        self._project(project_id)
        if session_id is not None:
            session = self._node(session_id, entity_type="session")
            if session["project_id"] != project_id:
                raise PermissionError(
                    "recovery session belongs to another project")
        outcomes = self.graph.current(
            project_id, "outcome", tenant_id=self.tenant_id)
        if session_id is not None:
            outcomes = [o for o in outcomes
                        if o["data"].get("session_id") == session_id]
        last = outcomes[-1] if outcomes else None
        checkpoint = self.memory.last_safe_checkpoint(project_id)
        open_tasks = [t for t in self.graph.current(
                      project_id, "task", tenant_id=self.tenant_id)
                      if t["status"] in ("open", "in_progress", "blocked", None)]
        verified = [n for n in self.graph.current(
                    project_id, tenant_id=self.tenant_id)
                    if n["status"] == "verified"
                    and n["entity_type"] in ("task", "action", "artifact", "checkpoint")]
        quarantined = [n["node_id"] for n in self.graph.current(
                       project_id, tenant_id=self.tenant_id)
                       if n["status"] == "quarantined"]
        verifications = self.graph.current(
            project_id, "verification", tenant_id=self.tenant_id)
        gaps = [v["data"].get("verifier") for v in verifications
                if v["status"] in ("failed", "stale", "inconclusive", "missing")]
        if any(not isinstance(gap, str) or not gap for gap in gaps):
            raise ValueError(
                "recovery packet cannot represent a malformed verifier gap")

        def summary(data: dict, *fields: str) -> str:
            for field in fields:
                value = data.get(field)
                if value is None:
                    continue
                if not isinstance(value, str):
                    raise ValueError(
                        f"recovery summary source {field!r} must be a string")
                return value
            return ""

        if last:
            if (not isinstance(last["status"], str)
                    or last["status"] not in RUN_OUTCOMES):
                raise ValueError(
                    "recovery packet cannot represent an invalid outcome status")
            last_failed = last["data"].get("failed")
            failure_mode = last["data"].get("failure_mode")
            if (not isinstance(last_failed, list)
                    or any(not isinstance(item, dict) for item in last_failed)
                    or failure_mode is not None
                    and (not isinstance(failure_mode, str)
                         or failure_mode not in FAILURE_TAXONOMY)):
                raise ValueError(
                    "recovery packet cannot represent malformed outcome data")
        if checkpoint:
            label = checkpoint["data"].get("label")
            if label is not None and not isinstance(label, str):
                raise ValueError(
                    "recovery checkpoint label must be a string or null")
        packet = {
            "schema_version": "cce.recovery.v1",
            "generated_at": utcnow(),
            "project_id": project_id,
            "last_outcome": {
                "status": last["status"],
                "failed": last["data"].get("failed"),
                "failure_mode": last["data"].get("failure_mode"),
            } if last else None,
            "last_safe_checkpoint": {
                "node_id": checkpoint["node_id"],
                "label": checkpoint["data"].get("label"),
                "working_state": checkpoint["data"].get("working_state"),
            } if checkpoint else None,
            "verified_work_to_keep": [
                {"node_id": n["node_id"],
                 "summary": summary(
                     n["data"], "statement", "label", "title")}
                for n in verified
            ],
            "quarantined": quarantined,
            "remaining_tasks": [
                {"node_id": t["node_id"], "status": t["status"],
                 "summary": summary(t["data"], "statement", "title")}
                for t in open_tasks
            ],
            "verifier_gaps": sorted({g for g in gaps if g}),
            "rerun_instructions": self._rerun(last, checkpoint),
        }
        return packet

    @staticmethod
    def _rerun(last: dict | None, checkpoint: dict | None) -> list[str]:
        steps = []
        if checkpoint:
            steps.append(
                f"Resume from checkpoint {checkpoint['node_id']}"
                f" ({checkpoint['data'].get('label')}); do not repeat work verified"
                " before it.")
        else:
            steps.append("No verified checkpoint exists; verify current state before"
                         " continuing.")
        if last and last["data"].get("failed"):
            for f in last["data"]["failed"]:
                steps.append(
                    f"Retry failed step {f.get('name') or f}: fix the recorded cause"
                    " before rerunning.")
        steps.append("Re-run required verifiers before claiming any completion.")
        return steps
