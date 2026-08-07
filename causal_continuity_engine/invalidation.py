"""Causal invalidation engine (CI-001..CI-008).

Direct triggers -> bounded typed-edge propagation -> deterministic impact
classification -> explanation with minimal causal path -> resolution that
preserves lineage.

ADR-008 / CI-005: a low-confidence, high-blast-radius invalidation cannot
silently rewrite control state; it demands human confirmation and marks
nodes review_required instead of blocked/invalidated.
"""

from __future__ import annotations

import math

from .core import (
    canonical_json,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
)
from .graph import TraversalBudgetExceeded
from .ontology import CRITICALITY_LEVELS, IMPACT_STATES, is_valid_transition

TRIGGER_TYPES = {
    "changed_requirement",
    "superseding_decision",
    "contradictory_evidence",
    "stale_verifier_input",
    "dependency_drift",
    "failed_check",
    "environment_mismatch",
    "expired_approval",
}


class ResolutionInputError(ValueError):
    """A typed invalidation-resolution request is invalid for current state."""


# Deterministic classification matrix (CI-003).
def classify(strength: float, criticality: str | None, trigger_confidence: float) -> str:
    for name, value in (("strength", strength),
                        ("trigger_confidence", trigger_confidence)):
        if (isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 <= value <= 1):
            raise ValueError(f"{name} must be finite and between 0 and 1")
    if criticality is not None and (
            not isinstance(criticality, str)
            or criticality not in CRITICALITY_LEVELS):
        raise ValueError("criticality must be a recognized level or null")
    crit = "medium" if criticality is None else criticality
    if strength >= 0.75 and crit in ("high", "critical"):
        return "blocked" if trigger_confidence >= 0.7 else "review_required"
    if strength >= 0.45:
        return "review_required"
    return "valid"


class InvalidationEngine:
    def __init__(self, store, graph, *, policy=None, max_depth: int = 6,
                 max_nodes: int = 500, tenant_id: str | None = None):
        for name, value in (("max_depth", max_depth), ("max_nodes", max_nodes)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if tenant_id is not None:
            tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        self.store = store
        self.graph = graph
        self.policy = policy
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.tenant_id = tenant_id

    def _require_tenant(self, tenant_id: str) -> None:
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise PermissionError(
                f"invalidation tenant {tenant_id!r} is outside the bound "
                f"tenant {self.tenant_id!r}")

    def _require_owned(self, node: dict) -> None:
        self._require_tenant(node.get("tenant_id"))

    def _require_project(self, project_id: str) -> None:
        if self.tenant_id is None:
            return
        try:
            self.graph.get(
                project_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="project")
        except KeyError:
            raise PermissionError(
                f"invalidation project {project_id!r} is outside the bound "
                f"tenant {self.tenant_id!r}") from None

    @staticmethod
    def _default_restored_status(node: dict) -> str:
        """Conservative fallback for invalidations written before receipts.

        A generic ``active`` is not a valid open-work state for tasks and
        caused released work to disappear from Resume Packets. New
        invalidations persist the exact status; this map is migration-only.
        """
        return {
            "task": "open", "decision": "accepted", "assumption": "active",
            "plan": "active", "action": "active",
        }.get(node["entity_type"], "active")

    def _held_restore_status(
            self, project_id: str, node_id: str,
            current_status: str | None, *, tenant_id: str | None = None
    ) -> str | None:
        """Original status carried through overlapping open invalidations."""
        for inv in self.graph.current(
                project_id, "invalidation", status=["open"],
                tenant_id=self.tenant_id or tenant_id):
            transition = inv["data"].get("target_transition") or {}
            if transition.get("node_id") == node_id:
                return transition.get("restore_status", transition.get("prior_status"))
            for affected in inv["data"].get("affected", []):
                if affected.get("node_id") == node_id:
                    return affected.get("restore_status", affected.get("prior_status"))
        return current_status

    def _restored_status(self, node: dict, receipt: dict | None) -> str:
        if receipt:
            prior = receipt.get("restore_status", receipt.get("prior_status"))
            if prior is not None:
                return prior
        return self._default_restored_status(node)

    def _restore_node(self, node: dict, receipt: dict | None,
                      event_id: str | None) -> str:
        """Retract an applied impact and restore its recorded predecessor.

        This is deliberately not an assumption lifecycle transition: it
        removes a justification that temporarily overlaid the status. Treating
        restoration as a new ``invalidated -> active`` assertion would either
        violate the lifecycle or force every entity into generic ``active``.
        """
        status = self._restored_status(node, receipt)
        self.graph.put_node(
            entity_type=node["entity_type"], tenant_id=node["tenant_id"],
            project_id=node["project_id"], node_id=node["node_id"],
            data={}, status=status, event_id=event_id,
        )
        return status

    @staticmethod
    def _validate_receipt_status(receipt: dict, field: str) -> None:
        value = receipt.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise ResolutionInputError(
                f"invalidation receipt {field} must be non-empty text or null")

    def _preflight_references(
            self, inv: dict) -> tuple[dict, dict, list[dict], dict[str, dict]]:
        """Resolve every receipt inside the invalidation's immutable scope.

        Confirmation and resolution apply several graph transitions. Resolving
        even one receipt lazily after the first transition lets a malformed
        invalidation redirect a later target across a tenant boundary. Bind the
        complete set, including its graph edges, before any mutation or audit.
        """
        if inv.get("entity_type") != "invalidation":
            raise ResolutionInputError("referenced node is not an invalidation")
        data = inv.get("data")
        if not isinstance(data, dict):
            raise ResolutionInputError("invalidation data must be an object")

        try:
            target_id = validate_public_identifier(
                data.get("target_node_id"), field="invalidation target_node_id")
        except ValueError as exc:
            raise ResolutionInputError(str(exc)) from None
        raw_transition = data.get("target_transition")
        if raw_transition is None:
            target_transition = {"node_id": target_id}
        elif isinstance(raw_transition, dict):
            target_transition = dict(raw_transition)
        else:
            raise ResolutionInputError(
                "invalidation target_transition must be an object or null")
        if target_transition.get("node_id") != target_id:
            raise ResolutionInputError(
                "invalidation target receipt does not match target_node_id")
        for field in ("prior_status", "restore_status", "applied_status"):
            self._validate_receipt_status(target_transition, field)
        if ("impact_applied" in target_transition
                and not isinstance(target_transition["impact_applied"], bool)):
            raise ResolutionInputError(
                "invalidation target impact_applied must be a boolean")

        try:
            target = self.graph.get(
                target_id, tenant_id=inv["tenant_id"],
                project_id=inv["project_id"])
        except KeyError:
            raise ResolutionInputError(
                "invalidation target is not bound to this invalidation tenant and project"
            ) from None
        target_edges = self.graph.out_edges(inv["node_id"], {"invalidates"})
        if len(target_edges) != 1 or target_edges[0]["dst_id"] != target_id:
            raise ResolutionInputError(
                "invalidation target is not bound to this invalidation tenant and project")

        raw_affected = data.get("affected", [])
        if not isinstance(raw_affected, list):
            raise ResolutionInputError("invalidation affected receipts must be a list")
        affected: list[dict] = []
        nodes: dict[str, dict] = {target_id: target}
        for raw_receipt in raw_affected:
            if not isinstance(raw_receipt, dict):
                raise ResolutionInputError(
                    "each invalidation affected receipt must be an object")
            receipt = dict(raw_receipt)
            try:
                node_id = validate_public_identifier(
                    receipt.get("node_id"), field="affected node_id")
            except ValueError as exc:
                raise ResolutionInputError(str(exc)) from None
            if node_id in nodes:
                raise ResolutionInputError(
                    "invalidation receipts contain a duplicate or target node")
            entity_type = receipt.get("entity_type")
            if not isinstance(entity_type, str) or not entity_type:
                raise ResolutionInputError(
                    "affected receipt entity_type must be non-empty text")
            impact = receipt.get("impact")
            if not isinstance(impact, str) or impact not in IMPACT_STATES:
                raise ResolutionInputError(
                    "affected receipt impact must be a recognized impact state")
            for field in ("prior_status", "restore_status", "applied_status"):
                self._validate_receipt_status(receipt, field)
            if ("impact_applied" in receipt
                    and not isinstance(receipt["impact_applied"], bool)):
                raise ResolutionInputError(
                    "affected receipt impact_applied must be a boolean")
            path = receipt.get("path")
            if path is not None:
                if (not isinstance(path, list) or not path
                        or path[0] != target_id or path[-1] != node_id):
                    raise ResolutionInputError(
                        "affected receipt path must bind the target to its node")
                try:
                    for path_id in path:
                        validate_public_identifier(
                            path_id, field="affected receipt path identifier")
                except ValueError as exc:
                    raise ResolutionInputError(str(exc)) from None
            try:
                node = self.graph.get(
                    node_id, tenant_id=inv["tenant_id"],
                    project_id=inv["project_id"], entity_type=entity_type)
            except KeyError:
                raise ResolutionInputError(
                    "affected receipt is not bound to this invalidation tenant and project"
                ) from None
            nodes[node_id] = node
            affected.append(receipt)

        affected_edges = self.graph.out_edges(inv["node_id"], {"affects"})
        edge_targets = [edge["dst_id"] for edge in affected_edges]
        receipt_targets = [receipt["node_id"] for receipt in affected]
        if (len(edge_targets) != len(set(edge_targets))
                or set(edge_targets) != set(receipt_targets)):
            raise ResolutionInputError(
                "affected receipts are not bound to this invalidation tenant and project")
        if inv.get("status") == "pending_confirmation":
            for receipt in [target_transition, *affected]:
                if (receipt.get("impact_applied") not in (None, False)
                        or receipt.get("applied_status") is not None):
                    raise ResolutionInputError(
                        "a pending invalidation cannot contain an applied receipt")
        return target, target_transition, affected, nodes

    def _resolution_inputs(self, inv: dict, mode: str,
                           replacement_node_id: str | None,
                           narrowed_scope: dict | None) -> dict | None:
        """Validate the typed evidence a resolution mode promises.

        Validation happens before the invalidation is marked resolved. A
        missing, cross-project, self-referential, quarantined, or semantically
        unrelated node is not a resolution receipt merely because a human
        supplied its id.
        """
        target_id = inv["data"].get("target_node_id")
        if mode == "narrowed_scope":
            if replacement_node_id is not None:
                raise ResolutionInputError(
                    "narrowed_scope does not accept a replacement node")
            if not isinstance(narrowed_scope, dict) or not narrowed_scope:
                raise ResolutionInputError(
                    "narrowed_scope requires a non-empty scope object")
            return None
        if narrowed_scope is not None:
            raise ResolutionInputError(f"{mode} does not accept narrowed_scope")
        if replacement_node_id is None:
            raise ResolutionInputError(f"{mode} requires replacement_node_id")
        if replacement_node_id in (target_id, inv["node_id"]):
            raise ResolutionInputError(
                "a resolution replacement cannot refer to itself or its target")
        try:
            replacement = self.graph.get(
                replacement_node_id,
                tenant_id=inv["tenant_id"], project_id=inv["project_id"])
        except KeyError as exc:
            raise ResolutionInputError(
                "resolution replacement does not exist in this tenant and project") \
                from exc
        expected_type = "evidence" if mode == "replacement_evidence" else "decision"
        if replacement["entity_type"] != expected_type:
            raise ResolutionInputError(
                f"{mode} requires a {expected_type} node, got "
                f"{replacement['entity_type']!r}")
        if replacement.get("status") in ("quarantined", "invalidated", "superseded",
                                           "rejected", "failed"):
            raise ResolutionInputError(
                f"resolution replacement is not live: {replacement.get('status')!r}")
        if mode == "replacement_evidence" and (
                replacement.get("status") != "verified"
                or replacement.get("authority") not in (
                    "verifier_authoritative", "human_decision")):
            raise ResolutionInputError(
                "replacement_evidence requires verified authoritative evidence")
        if mode == "superseding_decision" and replacement.get("status") not in (
                "accepted", "active"):
            raise ResolutionInputError(
                "superseding_decision requires an accepted decision")
        if (mode == "superseding_decision"
                and replacement.get("authority") != "human_decision"):
            raise ResolutionInputError(
                "superseding_decision requires human-decision authority")
        binding_field = (
            "subject_node_id" if mode == "replacement_evidence"
            else "supersedes_node_id")
        if replacement.get("data", {}).get(binding_field) != target_id:
            raise ResolutionInputError(
                f"{mode} node must explicitly bind target {target_id!r} "
                f"through {binding_field}")
        return replacement

    # ----------------------------------------------------------------- fire

    def fire(
        self,
        *,
        tenant_id: str,
        project_id: str,
        target_node_id: str,
        trigger_type: str,
        trigger_evidence_id: str | None = None,
        trigger_confidence: float = 0.9,
        reason: str = "",
        event_id: str | None = None,
        actor: str = "cce",
    ) -> dict:
        """Atomically create and apply an invalidation."""
        tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        project_id = validate_public_identifier(project_id, field="project_id")
        target_node_id = validate_public_identifier(
            target_node_id, field="target_node_id")
        if trigger_evidence_id is not None:
            trigger_evidence_id = validate_public_identifier(
                trigger_evidence_id, field="trigger_evidence_id")
        if event_id is not None:
            event_id = validate_public_identifier(event_id, field="event_id")
        if not isinstance(trigger_type, str) or trigger_type not in TRIGGER_TYPES:
            raise ValueError(f"unknown trigger type {trigger_type!r}")
        if (isinstance(trigger_confidence, bool)
                or not isinstance(trigger_confidence, (int, float))
                or not math.isfinite(trigger_confidence)
                or not 0 <= trigger_confidence <= 1):
            raise ValueError("trigger confidence must be finite and between 0 and 1")
        actor = validate_human_text(actor, field="invalidation actor")
        if not isinstance(reason, str):
            raise ValueError("invalidation reason must be a string")
        if reason:
            reason = validate_human_text(
                reason, field="invalidation reason", max_length=4096)
        self._require_tenant(tenant_id)
        with self.store.transaction():
            return self._fire(
                tenant_id=tenant_id, project_id=project_id,
                target_node_id=target_node_id, trigger_type=trigger_type,
                trigger_evidence_id=trigger_evidence_id,
                trigger_confidence=trigger_confidence, reason=reason,
                event_id=event_id, actor=actor)

    def _fire(
        self,
        *,
        tenant_id: str,
        project_id: str,
        target_node_id: str,
        trigger_type: str,
        trigger_evidence_id: str | None = None,
        trigger_confidence: float = 0.9,
        reason: str = "",
        event_id: str | None = None,
        actor: str = "cce",
    ) -> dict:
        """Invalidate target_node_id and propagate bounded impact.

        Returns the invalidation node (with explanation in data).
        """
        if not isinstance(trigger_type, str) or trigger_type not in TRIGGER_TYPES:
            raise ValueError(f"unknown trigger type {trigger_type!r}")
        if (isinstance(trigger_confidence, bool)
                or not isinstance(trigger_confidence, (int, float))
                or not math.isfinite(trigger_confidence)
                or not 0 <= trigger_confidence <= 1):
            raise ValueError("trigger confidence must be finite and between 0 and 1")
        try:
            target = self.graph.get(
                target_node_id, tenant_id=tenant_id, project_id=project_id)
        except KeyError:
            raise ValueError(
                "invalidation target does not exist in this tenant and project"
            ) from None
        target_criticality = target.get("criticality")
        if target_criticality is not None and (
                not isinstance(target_criticality, str)
                or target_criticality not in CRITICALITY_LEVELS):
            raise ValueError("invalidation target has malformed criticality")
        if trigger_evidence_id is not None:
            try:
                trigger = self.graph.get(
                    trigger_evidence_id, tenant_id=tenant_id,
                    project_id=project_id)
            except KeyError as exc:
                raise ValueError(
                    f"trigger evidence {trigger_evidence_id!r} does not exist "
                    "in this tenant and project") from exc
            if trigger["entity_type"] not in ("evidence", "verification"):
                raise ValueError(
                    "trigger evidence must be an evidence or verification node")
            if trigger.get("status") in (
                    "quarantined", "invalidated", "superseded", "rejected"):
                raise ValueError("trigger evidence is not live")

        try:
            affected = self.graph.dependents(
                target_node_id, max_depth=self.max_depth, max_nodes=self.max_nodes
            )
            truncated = False
        except TraversalBudgetExceeded:
            affected = self.graph.dependents(
                target_node_id, max_depth=2, max_nodes=self.max_nodes * 10
            )
            truncated = True

        high_blast = len(affected) >= 10 or truncated
        low_confidence = trigger_confidence < 0.6
        requires_human = (low_confidence and high_blast) or (
            (target.get("criticality") in ("high", "critical")) and low_confidence
        )

        classified = []
        for dep in affected:
            try:
                node = self.graph.get(
                    dep["node_id"], tenant_id=tenant_id,
                    project_id=project_id)
            except KeyError:
                continue
            impact = classify(dep["strength"], node.get("criticality"), trigger_confidence)
            if requires_human and impact in ("blocked", "invalidated"):
                impact = "review_required"    # CI-005 conservative downgrade
            prior_status = node.get("status")
            classified.append({
                "node_id": dep["node_id"],
                "entity_type": node["entity_type"],
                "depth": dep["depth"],
                "strength": dep["strength"],
                "impact": impact,
                "path": dep["path"],
                # A status change is a retractable belief justified by this
                # invalidation, not a permanent rewrite. Carry the oldest
                # status through overlapping holders so the last resolution
                # can restore exactly what existed before the first one.
                "prior_status": prior_status,
                "restore_status": self._held_restore_status(
                    project_id, dep["node_id"], prior_status,
                    tenant_id=tenant_id),
                "impact_applied": False,
                "applied_status": None,
            })

        minimal_path = min(
            (c["path"] for c in classified), key=len, default=[target_node_id]
        )
        severity = self._severity(target, classified)
        target_prior_status = target.get("status")
        target_transition = {
            "node_id": target_node_id,
            "prior_status": target_prior_status,
            "restore_status": self._held_restore_status(
                project_id, target_node_id, target_prior_status,
                tenant_id=tenant_id),
            "impact_applied": False,
            "applied_status": None,
        }
        explanation = {
            "trigger_type": trigger_type,
            "trigger_evidence_id": trigger_evidence_id,
            "trigger_confidence": trigger_confidence,
            "reason": reason,
            "target_node_id": target_node_id,
            "target_summary": target["data"].get("statement") or target["data"].get("title"),
            "minimal_causal_path": minimal_path,
            "affected_count": len(classified),
            "truncated": truncated,
            "severity": severity,
            "requires_human_confirmation": requires_human,
            "recommended_action": self._recommend(trigger_type, severity, requires_human),
            "target_transition": target_transition,
        }

        inv = self.graph.put_node(
            entity_type="invalidation",
            tenant_id=tenant_id,
            project_id=project_id,
            status="open" if not requires_human else "pending_confirmation",
            criticality=target.get("criticality") or "medium",
            confidence=trigger_confidence,
            data={**explanation, "affected": classified, "fired_at": utcnow()},
            event_id=event_id,
        )
        self.graph.put_edge(
            edge_type="invalidates", src_id=inv.id, dst_id=target_node_id,
            tenant_id=tenant_id, project_id=project_id, event_id=event_id,
        )
        if trigger_evidence_id is not None:
            self.graph.put_edge(
                edge_type="derived_from", src_id=inv.id, dst_id=trigger_evidence_id,
                tenant_id=tenant_id, project_id=project_id, event_id=event_id,
            )

        # Apply state changes only when no human gate is pending (ADR-008).
        refused: list[str] = []
        if not requires_human:
            target_before = target.get("status")
            if not self._transition(target, "invalidated", event_id):
                refused.append(target_node_id)
            else:
                target_after = self.graph.get(
                    target_node_id, tenant_id=tenant_id,
                    project_id=project_id,
                    entity_type=target["entity_type"]).get("status")
                target_transition["impact_applied"] = target_after != target_before
                target_transition["applied_status"] = target_after
            for c in classified:
                if c["impact"] in ("review_required", "blocked"):
                    node = self.graph.get(
                        c["node_id"], tenant_id=tenant_id,
                        project_id=project_id,
                        entity_type=c["entity_type"])
                    before = node.get("status")
                    if not self._apply_impact(c, event_id, node=node):
                        refused.append(c["node_id"])
                    else:
                        after = self.graph.get(
                            c["node_id"], tenant_id=tenant_id,
                            project_id=project_id,
                            entity_type=c["entity_type"]).get("status")
                        c["impact_applied"] = after != before
                        c["applied_status"] = after
                self.graph.put_edge(
                    edge_type="affects", src_id=inv.id, dst_id=c["node_id"],
                    tenant_id=tenant_id, project_id=project_id,
                    strength=c["strength"], event_id=event_id,
                    data={"impact": c["impact"]},
                )
            self.graph.put_node(
                entity_type="invalidation", tenant_id=tenant_id,
                project_id=project_id, node_id=inv.id,
                data={"affected": classified,
                      "target_transition": target_transition},
                event_id=event_id,
            )
        else:
            for c in classified:
                self.graph.put_edge(
                    edge_type="affects", src_id=inv.id, dst_id=c["node_id"],
                    tenant_id=tenant_id, project_id=project_id,
                    strength=c["strength"], event_id=event_id,
                    data={"impact": "pending_confirmation"},
                )
        # A node whose lifecycle refused the transition is still standing.
        # Recording it is the difference between "this was invalidated" and
        # "this could not be invalidated and nobody was told" — the second is
        # how a contradicted assumption keeps driving work (ADR-060).
        if refused:
            # Status stays 'open': it must remain in open_invalidations() and
            # stay resolvable. The refusal is recorded, not hidden in a state
            # the queries do not look at.
            self.graph.put_node(
                entity_type="invalidation", tenant_id=tenant_id,
                project_id=project_id, node_id=inv.id,
                data={"unapplied_nodes": refused,
                      "target_status_applied": target_node_id not in refused,
                      "unapplied_reason":
                          "the lifecycle of these nodes forbids the transition;"
                          " their status is unchanged"},
                event_id=event_id,
            )
        # AUT-005: a major invalidation downgrades autonomy until reviewed.
        if severity == "critical" and self.policy is not None:
            self.policy.downgrade(project_id, "major_invalidation", ceiling=1,
                                  actor=actor)
        self.store.audit(
            actor=actor, action="invalidation.fire", object_id=inv.id,
            authority="verifier_authoritative",
            detail=f"{trigger_type} -> {target_node_id} ({len(classified)} affected,"
                   f" human={requires_human}"
                   + (f", {len(refused)} UNAPPLIED" if refused else "") + ")",
        )
        return self.graph.get(
            inv.id, tenant_id=tenant_id, project_id=project_id,
            entity_type="invalidation")

    def _transition(self, node: dict, new_status: str, event_id: str | None) -> bool:
        """Apply a status change. Returns whether it actually happened.

        The assumption lifecycle legitimately forbids some transitions (a
        superseded assumption is not re-invalidated; its successor is). The
        return value exists so a caller cannot report a state change the
        graph refused — a control that declines to act must say so.
        """
        current = node.get("status") or "proposed"
        if node["entity_type"] == "assumption" and not is_valid_transition(current, new_status):
            return False
        self.graph.put_node(
            entity_type=node["entity_type"], tenant_id=node["tenant_id"],
            project_id=node["project_id"], node_id=node["node_id"],
            data={}, status=new_status, event_id=event_id,
        )
        return True

    def _apply_impact(
            self, c: dict, event_id: str | None, *, node: dict) -> bool:
        """False only when a transition was attempted and the graph refused.
        A node type that carries no impact status claims nothing, so there is
        nothing to refuse."""
        if node["entity_type"] in ("assumption", "decision", "plan", "task", "action"):
            status = {"review_required": "uncertain", "blocked": "blocked"}.get(c["impact"])
            if not status:
                return True
            if node["entity_type"] == "assumption" and status == "blocked":
                status = "uncertain"
            return self._transition(node, status, event_id)
        return True

    @staticmethod
    def _severity(target: dict, classified: list[dict]) -> str:
        crit = target.get("criticality") or "medium"
        blocked = sum(1 for c in classified if c["impact"] == "blocked")
        if crit == "critical" or blocked >= 3:
            return "critical"
        if crit == "high" or blocked >= 1:
            return "high"
        if any(c["impact"] == "review_required" for c in classified):
            return "medium"
        return "low"

    @staticmethod
    def _recommend(trigger_type: str, severity: str, requires_human: bool) -> str:
        if requires_human:
            return "Confirm or reject this invalidation; no state was changed automatically."
        base = {
            "changed_requirement": "Revise affected plans/tasks against the new requirement.",
            "superseding_decision": "Re-link dependents to the superseding decision.",
            "contradictory_evidence": "Review the contradiction and resolve the conflict.",
            "stale_verifier_input": "Re-run the affected verifiers against current inputs.",
            "dependency_drift": "Re-validate assumptions against the new dependency version.",
            "failed_check": "Fix the failing check before relying on dependent work.",
            "environment_mismatch": "Reconcile the environment fingerprint before resuming.",
            "expired_approval": "Request a fresh approval; autonomy is downgraded meanwhile.",
        }.get(trigger_type, "Review affected nodes.")
        if severity in ("high", "critical"):
            base += " Blocked nodes must not drive actions until resolved."
        return base

    # ------------------------------------------------------------ confirmation

    def confirm(self, invalidation_id: str, actor: str, accept: bool,
                event_id: str | None = None) -> dict:
        """Atomically apply or reject a human-gated invalidation."""
        invalidation_id = validate_public_identifier(
            invalidation_id, field="invalidation_id")
        if event_id is not None:
            event_id = validate_public_identifier(event_id, field="event_id")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError(
                "invalidation confirmation actor must be a non-empty string")
        actor = validate_human_text(
            actor, field="invalidation confirmation actor")
        if not isinstance(accept, bool):
            raise ValueError("invalidation confirmation accept must be a boolean")
        with self.store.transaction():
            return self._confirm(invalidation_id, actor, accept, event_id)

    def _confirm(self, invalidation_id: str, actor: str, accept: bool,
                 event_id: str | None = None) -> dict:
        """Human confirmation for gated invalidations (CI-005)."""
        inv = self.graph.get(invalidation_id, tenant_id=self.tenant_id)
        self._require_owned(inv)
        if inv["status"] != "pending_confirmation":
            raise ValueError(f"{invalidation_id} is not pending confirmation")
        target, target_transition, affected, nodes = (
            self._preflight_references(inv))
        refused: list[str] = []
        if accept:
            before = target.get("status")
            if not self._transition(target, "invalidated", event_id):
                refused.append(target["node_id"])
            else:
                after = self.graph.get(
                    target["node_id"], tenant_id=inv["tenant_id"],
                    project_id=inv["project_id"],
                    entity_type=target["entity_type"]).get("status")
                target_transition["impact_applied"] = after != before
                target_transition["applied_status"] = after
            for c in affected:
                if c["impact"] in ("review_required", "blocked"):
                    node = nodes[c["node_id"]]
                    before = node.get("status")
                    if not self._apply_impact(c, event_id, node=node):
                        refused.append(c["node_id"])
                    else:
                        after = self.graph.get(
                            c["node_id"], tenant_id=inv["tenant_id"],
                            project_id=inv["project_id"],
                            entity_type=c["entity_type"]).get("status")
                        c["impact_applied"] = after != before
                        c["applied_status"] = after
            new_status = "open"
        else:
            new_status = "rejected"
        confirmation = {"confirmed_by": actor, "confirmed_at": utcnow(),
                        "accepted": accept, "affected": affected,
                        "target_transition": target_transition}
        if refused:
            # The human said yes and the graph said no. Saying so is the whole
            # point: an approval that quietly did nothing is worse than a
            # refusal, because the reviewer believes it took effect.
            confirmation["unapplied_nodes"] = refused
            confirmation["unapplied_reason"] = (
                "confirmed, but the lifecycle of these nodes forbids the"
                " transition; their status is unchanged")
        out = self.graph.put_node(
            entity_type="invalidation", tenant_id=inv["tenant_id"],
            project_id=inv["project_id"], node_id=invalidation_id,
            data=confirmation,
            status=new_status, authority="human_decision", event_id=event_id,
        )
        released = []
        if not accept:
            # Rejecting must not strand anything: sweep the nodes this
            # invalidation named and release any no open invalidation holds.
            released = self._release_unheld(
                inv["project_id"],
                affected + [target_transition],
                excluding_id=invalidation_id, event_id=event_id,
                tenant_id=inv["tenant_id"], nodes_by_id=nodes)
        self.store.audit(actor=actor, action="invalidation.confirm",
                         object_id=invalidation_id,
                         detail=f"accepted={accept}; released {len(released)}"
                                + (f"; {len(refused)} UNAPPLIED" if refused else ""))
        return out

    # -------------------------------------------------------------- resolution

    def resolve(
        self,
        invalidation_id: str,
        *,
        mode: str,
        actor: str,
        replacement_node_id: str | None = None,
        narrowed_scope: dict | None = None,
        note: str = "",
        event_id: str | None = None,
    ) -> dict:
        """CI-007: resolve by replacement evidence, narrowed scope, or a
        superseding decision. History is preserved.

        Only an *open* invalidation is resolvable. A pending_confirmation
        invalidation must pass the human gate first (CI-005), and a rejected
        or already-resolved one must not mutate its target — otherwise a
        human 'reject' would be silently converted into a state change.
        """
        if (not isinstance(mode, str)
                or mode not in (
                    "replacement_evidence", "narrowed_scope",
                    "superseding_decision")):
            raise ResolutionInputError(f"unknown resolution mode {mode!r}")
        invalidation_id = validate_public_identifier(
            invalidation_id, field="invalidation_id")
        if replacement_node_id is not None:
            replacement_node_id = validate_public_identifier(
                replacement_node_id, field="replacement_node_id")
        if event_id is not None:
            event_id = validate_public_identifier(event_id, field="event_id")
        actor = validate_human_text(actor, field="invalidation resolution actor")
        if not isinstance(note, str):
            raise ResolutionInputError("resolution note must be a string")
        if note:
            note = validate_human_text(
                note, field="invalidation resolution note", max_length=4096)
        if narrowed_scope is not None:
            if not isinstance(narrowed_scope, dict):
                raise ResolutionInputError(
                    "narrowed_scope must be an object or null")
            try:
                narrowed_scope = strict_json_loads(canonical_json(narrowed_scope))
            except (TypeError, ValueError, OverflowError, RecursionError) as exc:
                raise ResolutionInputError(
                    f"narrowed_scope must be finite canonical JSON: {exc}"
                ) from None
        with self.store.transaction():
            inv = self.graph.get(invalidation_id, tenant_id=self.tenant_id)
            self._require_owned(inv)
            if inv["entity_type"] != "invalidation":
                raise ResolutionInputError(
                    f"{invalidation_id} is not an invalidation")
            if inv["status"] != "open":
                raise ResolutionInputError(
                    f"cannot resolve invalidation {invalidation_id} in status"
                    f" {inv['status']!r}; only 'open' invalidations are resolvable"
                    + (" (confirm the human gate first)"
                       if inv["status"] == "pending_confirmation" else ""))
            target, target_receipt, affected, nodes = (
                self._preflight_references(inv))
            target_id = target["node_id"]
            replacement = self._resolution_inputs(
                inv, mode, replacement_node_id, narrowed_scope)

            # Release ONLY nodes that no other open invalidation still
            # justifies holding. This includes the direct target: resolving
            # one of two contradictions must not clear the other one.
            still_held = self._nodes_held_by_others(
                inv["project_id"], excluding_id=invalidation_id,
                tenant_id=inv["tenant_id"])
            released: list[str] = []
            held: list[str] = []
            if replacement is not None:
                self.graph.put_edge(
                    edge_type=("supports" if mode == "replacement_evidence"
                               else "supersedes"),
                    src_id=replacement["node_id"], dst_id=target_id,
                    tenant_id=inv["tenant_id"], project_id=inv["project_id"],
                    event_id=event_id,
                )

            target_before = target.get("status")
            if target_id in still_held:
                held.append(target_id)
                if mode == "narrowed_scope":
                    # Scope can be narrowed while another invalidation keeps
                    # the status held; clearing that status waits for the last
                    # justification to close.
                    self.graph.put_node(
                        entity_type=target["entity_type"], tenant_id=target["tenant_id"],
                        project_id=target["project_id"], node_id=target_id,
                        data={"narrowed_scope": narrowed_scope}, scope=narrowed_scope,
                        authority="human_decision", event_id=event_id,
                    )
            elif mode == "superseding_decision":
                if not self._transition(target, "superseded", event_id):
                    raise ResolutionInputError(
                        "target lifecycle refused superseding decision")
            elif mode == "replacement_evidence":
                if not self._transition(target, "resolved", event_id):
                    raise ResolutionInputError(
                        "target lifecycle refused replacement evidence")
            else:
                restored = self._restored_status(target, target_receipt)
                self.graph.put_node(
                    entity_type=target["entity_type"], tenant_id=target["tenant_id"],
                    project_id=target["project_id"], node_id=target_id,
                    data={"narrowed_scope": narrowed_scope}, status=restored,
                    scope=narrowed_scope, authority="human_decision", event_id=event_id,
                )
                released.append(target_id)

            for receipt in affected:
                node = nodes[receipt["node_id"]]
                if node.get("status") not in ("uncertain", "blocked"):
                    continue
                if receipt["node_id"] in still_held:
                    held.append(receipt["node_id"])
                    continue
                self._restore_node(node, receipt, event_id)
                released.append(receipt["node_id"])

            target_after = self.graph.get(
                target_id, tenant_id=inv["tenant_id"],
                project_id=inv["project_id"],
                entity_type=target["entity_type"]).get("status")
            resolution = {
                "resolved_by": actor, "resolved_at": utcnow(), "mode": mode,
                "note": note, "replacement_node_id": replacement_node_id,
                "narrowed_scope": narrowed_scope,
                "replacement": ({
                    "node_id": replacement["node_id"],
                    "entity_type": replacement["entity_type"],
                    "status": replacement.get("status"),
                } if replacement is not None else None),
                "target_result": {
                    "node_id": target_id, "from_status": target_before,
                    "to_status": target_after, "still_held": target_id in still_held,
                },
                "released_nodes": sorted(set(released)),
                "still_held_nodes": sorted(set(held)),
            }
            self.graph.put_node(
                entity_type="invalidation", tenant_id=inv["tenant_id"],
                project_id=inv["project_id"], node_id=invalidation_id,
                data={"resolution": resolution,
                      "released_nodes": resolution["released_nodes"],
                      "still_held_nodes": resolution["still_held_nodes"]},
                status="resolved", authority="human_decision", event_id=event_id,
            )
            self.store.audit(
                actor=actor, action="invalidation.resolve", object_id=invalidation_id,
                detail=f"{mode}; released {len(set(released))}, still held by other open"
                       f" invalidations: {len(set(held))}")
        return self.graph.get(
            invalidation_id, tenant_id=inv["tenant_id"],
            project_id=inv["project_id"], entity_type="invalidation")

    def _nodes_held_by_others(
            self, project_id: str, excluding_id: str, *,
            tenant_id: str | None = None) -> set[str]:
        """Node ids still constrained by another invalidation that ACTUALLY
        applied its impact.

        Only 'open' invalidations count. A pending_confirmation invalidation
        deliberately changes no state (CI-005), so treating it as a holder
        would let a human's later rejection strand a node: rejecting releases
        nothing, and a rejected invalidation can no longer be resolved, so
        the node would stay blocked with nothing left to clear it.
        """
        held: set[str] = set()
        for other in self.graph.current(
                project_id, "invalidation", status=["open"],
                tenant_id=self.tenant_id or tenant_id):
            if other["node_id"] == excluding_id:
                continue
            for c in other["data"].get("affected", []):
                if c.get("impact") in ("review_required", "blocked"):
                    held.add(c["node_id"])
            held.add(other["data"].get("target_node_id"))
        held.discard(None)
        return held

    def _release_unheld(self, project_id: str, receipts, excluding_id: str,
                        event_id: str | None = None, *,
                        tenant_id: str | None = None,
                        nodes_by_id: dict[str, dict] | None = None) -> list[str]:
        """Restore listed nodes that this invalidation actually changed."""
        held = self._nodes_held_by_others(
            project_id, excluding_id, tenant_id=tenant_id)
        released = []
        for item in receipts:
            receipt = item if isinstance(item, dict) else {"node_id": item}
            node_id = receipt.get("node_id")
            if not node_id or receipt.get("impact_applied") is not True:
                continue
            if node_id in held:
                continue
            if nodes_by_id is not None:
                node = nodes_by_id.get(node_id)
                if node is None:
                    raise ResolutionInputError(
                        "release receipt is not bound to this invalidation "
                        "tenant and project")
            else:
                try:
                    node = self.graph.get(
                        node_id, tenant_id=self.tenant_id or tenant_id,
                        project_id=project_id)
                except KeyError:
                    raise ResolutionInputError(
                        "release receipt is not bound to this invalidation "
                        "tenant and project") from None
            if node.get("status") in ("uncertain", "blocked"):
                self._restore_node(node, receipt, event_id)
                released.append(node_id)
        return released

    # ----------------------------------------------------------------- query

    def open_invalidations(self, project_id: str) -> list[dict]:
        self._require_project(project_id)
        return self.graph.current(project_id, "invalidation",
                                  status=["open", "pending_confirmation"],
                                  tenant_id=self.tenant_id)

    def blocking_invalidations(
            self, project_id: str, node_id: str) -> list[dict]:
        """Current invalidations that make a node unsafe to promote.

        An unresolved invalidation is control state, not merely history.  A
        later proof cannot silently price in a human confirmation that has
        never happened.  Direct/propagated invalidations therefore follow the
        named node, while a critical invalidation remains a project-wide
        stop.  Resolved and rejected invalidations are absent from
        :meth:`open_invalidations` and cannot keep work blocked.
        """
        blockers = []
        for invalidation in self.open_invalidations(project_id):
            data = invalidation.get("data") or {}
            touched = {
                item.get("node_id")
                for item in data.get("affected", [])
                if isinstance(item, dict)
            }
            touched.add(data.get("target_node_id"))
            if node_id in touched or data.get("severity") == "critical":
                blockers.append(invalidation)
        return blockers

    def metrics(self, project_id: str) -> dict:
        """CI-008 raw counters; precision/recall come from ContinuityBench."""
        self._require_project(project_id)
        all_inv = self.graph.current(
            project_id, "invalidation", tenant_id=self.tenant_id)
        by_status: dict[str, int] = {}
        by_trigger: dict[str, int] = {}
        for inv in all_inv:
            by_status[inv["status"]] = by_status.get(inv["status"], 0) + 1
            t = inv["data"].get("trigger_type", "unknown")
            by_trigger[t] = by_trigger.get(t, 0) + 1
        return {"total": len(all_inv), "by_status": by_status, "by_trigger": by_trigger}
