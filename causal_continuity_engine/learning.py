"""Learning layer: trace replay, failure composting, eval generation, skill
proposals (TR-*, FC-*, AE-*, SD-*).

Replay states its fidelity honestly (TR-003): LLM output is never assumed
deterministic, so a replay that includes model calls without captured
outputs is at best 'mocked' and may be 'non_reproducible'. Skill
distillation is proposal-only (SD-001/002): nothing here activates a skill.
"""

from __future__ import annotations

from .core import (
    canonical_json,
    digest_obj,
    new_id,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
)
from .extraction import normalize_statement
from .ontology import FAILURE_TAXONOMY, REPLAY_FIDELITY


def _optional_json_object(value, *, field: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a finite I-JSON object or null")
    try:
        normalized = strict_json_loads(canonical_json(value))
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError(
            f"{field} must be a finite I-JSON object or null") from None
    return normalized


def _safe_nonempty_text(value, *, field: str, max_length: int = 8192) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return validate_human_text(value, field=field, max_length=max_length)


def _optional_distinct_ids(value, *, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array of distinct identifiers")
    normalized = [
        validate_public_identifier(item, field=f"{field} item")
        for item in value
    ]
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field} must not contain duplicate identifiers")
    return normalized


class _TenantBoundManager:
    def __init__(self, store, graph, *, tenant_id: str | None = None):
        self.store = store
        self.graph = graph
        self.tenant_id = tenant_id

    def _tenant(self, tenant_id: str) -> str:
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise PermissionError(
                f"manager tenant {tenant_id!r} is outside the bound tenant "
                f"{self.tenant_id!r}")
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
                f"manager project {project_id!r} is outside the bound tenant "
                f"{self.tenant_id!r}") from None

    def _node(self, node_id: str, *, entity_type: str | None = None) -> dict:
        try:
            return self.graph.get(
                node_id, tenant_id=self.tenant_id, entity_type=entity_type)
        except KeyError:
            raise PermissionError(
                f"manager node {node_id!r} is outside the bound tenant") from None

    def _event(self, event_id: str, *, tenant_id: str,
               project_id: str) -> dict:
        """Resolve an event without disclosing cross-scope existence/state."""
        try:
            return self.store.get_event(
                event_id, tenant_id=tenant_id, project_id=project_id)
        except KeyError:
            raise PermissionError(
                "manager event is outside the requested tenant/project") from None


# ------------------------------------------------------------------- replay


class ReplayManager(_TenantBoundManager):

    def start(
        self,
        *,
        tenant_id: str,
        project_id: str,
        from_event_id: str,
        captured_inputs: dict | None = None,
        mocks: dict | None = None,
        fork: dict | None = None,
    ) -> dict:
        """TR-001/TR-002: create a sandboxed replay descriptor from an event
        boundary. Replays never touch production graph state: results attach
        to a dedicated replay node."""
        captured_inputs = _optional_json_object(
            captured_inputs, field="replay captured_inputs")
        mocks = _optional_json_object(mocks, field="replay mocks")
        fork = _optional_json_object(fork, field="replay fork")
        tenant_id = self._tenant(tenant_id)
        self._project(project_id)
        origin = self._event(
            from_event_id, tenant_id=tenant_id, project_id=project_id)
        events = [
            event for event in self.store.events(
                project_id, tenant_id=tenant_id)
            if event["seq"] <= origin["seq"]]
        fidelity = self._classify(captured_inputs, mocks)
        with self.store.transaction():
            node = self.graph.put_node(
                entity_type="evaluation", tenant_id=tenant_id,
                project_id=project_id, status="replay_ready",
                data={
                    "kind": "replay",
                    "replay_id": new_id("replay"),
                    "from_event_id": from_event_id,
                    "event_count": len(events),
                    "captured_inputs": sorted(captured_inputs),
                    "mocks": sorted(mocks),
                    "fork": fork,
                    "fidelity": fidelity,
                    "created_at": utcnow(),
                },
            )
            self.graph.put_edge(
                edge_type="replay_of", src_id=node.id, dst_id=from_event_id,
                tenant_id=tenant_id, project_id=project_id)
        return node

    @staticmethod
    def _classify(captured_inputs: dict | None, mocks: dict | None) -> str:
        """TR-003: honest fidelity. 'exact' requires every external input
        captured AND no model call outside captured outputs — which the local
        engine cannot prove, so it never claims better than
        environment_equivalent on its own."""
        if mocks:
            return "mocked"
        if captured_inputs:
            return "environment_equivalent"
        return "non_reproducible"

    def record_result(self, replay_node_id: str, *, diff: dict,
                      outcome: str) -> dict:
        with self.store.transaction():
            node = self._node(replay_node_id, entity_type="evaluation")
            if (node["data"].get("kind") != "replay"
                    or node.get("status") != "replay_ready"):
                raise ValueError(
                    "replay result requires a replay evaluation in "
                    "replay_ready state")
            fidelity = node["data"].get("fidelity")
            if (not isinstance(fidelity, str)
                    or fidelity not in REPLAY_FIDELITY):
                fidelity = "non_reproducible"
            return self.graph.put_node(
                entity_type="evaluation", tenant_id=node["tenant_id"],
                project_id=node["project_id"], node_id=replay_node_id,
                status="replay_done",
                data={"result_outcome": outcome, "diff": diff,
                      "fidelity": fidelity, "finished_at": utcnow()},
            )


# ---------------------------------------------------------------- composting

_FAILURE_RULES = [
    ("stale_assumption", ("stale", "assumption", "invalidat", "outdated")),
    ("verification", ("test fail", "assert", "verification", "check fail", "proof")),
    ("environment", ("env", "dependency", "version", "missing module", "install",
                     "not found", "permission denied")),
    ("tool", ("tool", "command", "subprocess", "timeout", "crash", "exit code")),
    ("retrieval", ("retriev", "context", "memory", "missing information")),
    ("planning", ("plan", "wrong order", "skipped step", "scope")),
    ("policy", ("policy", "denied", "authoriz", "autonomy", "blocked by")),
    ("coordination", ("conflict", "concurrent", "race", "merge conflict", "handoff")),
]


class FailureComposter(_TenantBoundManager):

    def classify(self, description: str) -> str:
        """FC-001: deterministic taxonomy assignment (correctable by humans)."""
        text = description.lower()
        for label, needles in _FAILURE_RULES:
            if any(n in text for n in needles):
                return label
        return "unknown"

    def compost(
        self,
        *,
        tenant_id: str,
        project_id: str,
        description: str,
        failing_step: str,
        session_id: str | None = None,
        trace_event_ids: list[str] | None = None,
        taxonomy_override: str | None = None,
    ) -> dict:
        """FC-002: produce a diagnosis with minimal failing boundary, causal
        path, and a concrete recovery candidate."""
        description = _safe_nonempty_text(
            description, field="failure description")
        failing_step = _safe_nonempty_text(
            failing_step, field="failure failing_step")
        trace_event_ids = _optional_distinct_ids(
            trace_event_ids, field="failure trace_event_ids")
        tenant_id = self._tenant(tenant_id)
        self._project(project_id)
        if session_id is not None:
            session = self._node(session_id, entity_type="session")
            if session["project_id"] != project_id:
                raise PermissionError(
                    "failure session belongs to another project")
        events = []
        for event_id in trace_event_ids:
            self._event(
                event_id, tenant_id=tenant_id, project_id=project_id)
            events.append(event_id)
        if taxonomy_override is not None and not isinstance(
                taxonomy_override, str):
            raise ValueError("failure taxonomy override must be a string or null")
        taxonomy = (
            self.classify(description)
            if taxonomy_override is None else taxonomy_override)
        if taxonomy not in FAILURE_TAXONOMY:
            raise ValueError(f"unknown failure taxonomy {taxonomy!r}")
        cluster_key = f"{taxonomy}:{normalize_statement(failing_step)[:80]}"
        with self.store.transaction():
            node = self.graph.put_node(
                entity_type="failure", tenant_id=tenant_id,
                project_id=project_id, status="diagnosed",
                data={
                    "description": description,
                    "taxonomy": taxonomy,
                    "minimal_failing_boundary": failing_step,
                    "session_id": session_id,
                    "trace_event_ids": events,
                    "cluster_key": cluster_key,
                    "recovery_candidate": self._recovery(
                        taxonomy, failing_step),
                    "diagnosed_at": utcnow(),
                },
            )
            for event_id in events:
                self.graph.put_edge(
                    edge_type="derived_from", src_id=node.id, dst_id=event_id,
                    tenant_id=tenant_id, project_id=project_id)
        return node

    @staticmethod
    def _recovery(taxonomy: str, failing_step: str) -> str:
        return {
            "stale_assumption": "Re-validate the assumption against current evidence"
                                " before retrying.",
            "verification": "Fix the failing check; do not mark complete until the"
                            " verifier passes.",
            "environment": "Pin/restore the environment fingerprint, then rerun"
                           f" {failing_step!r}.",
            "tool": f"Retry {failing_step!r} with captured inputs; if it recurs,"
                    " wrap with timeout/retry.",
            "retrieval": "Add the missing context to the resume packet composition"
                         " query.",
            "planning": "Insert an explicit verification step before this boundary.",
            "policy": "Request the required grant or reduce the action's scope.",
            "coordination": "Serialize the conflicting operations or add a lock.",
            "unknown": "Escalate for human diagnosis; insufficient signal.",
        }[taxonomy]

    def clusters(self, project_id: str) -> dict[str, list[str]]:
        """FC-003: recurring clusters within one project (tenant isolation is
        structural: queries are project-scoped)."""
        self._project(project_id)
        out: dict[str, list[str]] = {}
        for f in self.graph.current(
                project_id, "failure", tenant_id=self.tenant_id):
            out.setdefault(f["data"]["cluster_key"], []).append(f["node_id"])
        return {k: v for k, v in out.items() if len(v) >= 1}


# ------------------------------------------------------------------ eval gen


class EvalGenerator(_TenantBoundManager):

    def from_failure(self, failure_node_id: str, *, withheld: bool = False) -> dict:
        """AE-001/AE-002: convert a diagnosed failure into a versioned eval
        candidate with hidden ground truth and split assignment."""
        if not isinstance(withheld, bool):
            raise ValueError("evaluation withheld must be a boolean")
        with self.store.transaction():
            # Read and claim under one write snapshot. The former
            # read-then-insert sequence let two connections both observe no
            # match and create duplicate evaluation cases.
            failure = self._node(failure_node_id, entity_type="failure")
            data = failure["data"]
            content = {
                "setup": {
                    "project_id": failure["project_id"],
                    "trace_event_ids": data.get("trace_event_ids", []),
                    "failing_step": data.get("minimal_failing_boundary"),
                },
                "expected_properties": [
                    f"System detects/handles: {data.get('description')}",
                    f"Recovery action available: {data.get('recovery_candidate')}",
                ],
                "ground_truth": {
                    "taxonomy": data.get("taxonomy"),
                    "minimal_failing_boundary": data.get(
                        "minimal_failing_boundary"),
                },
                "scoring": [
                    "detected", "classified_correctly", "recovery_offered"],
            }
            dedup_key = digest_obj({
                "boundary": data.get("minimal_failing_boundary"),
                "taxonomy": data.get("taxonomy"),
            })
            split = "withheld" if withheld else "development"
            identity_digest = digest_obj({
                "tenant_id": failure["tenant_id"],
                "project_id": failure["project_id"],
                "kind": "generated_eval",
                "split": split,
                "dedup_key": dedup_key,
            }).removeprefix("sha256:")
            eval_node_id = f"evl_{identity_digest[:24]}"
            try:
                existing = self.graph.get(
                    eval_node_id, tenant_id=failure["tenant_id"],
                    project_id=failure["project_id"],
                    entity_type="evaluation")
            except KeyError:
                existing = None
            if existing is not None:
                existing_data = existing["data"]
                if not (
                        existing_data.get("kind") == "generated_eval"
                        and existing_data.get("split") == split
                        and existing_data.get("dedup_key") == dedup_key):
                    raise RuntimeError(
                        "deterministic evaluation identity collision")
                sources = {
                    edge["dst_id"] for edge in self.graph.out_edges(
                        eval_node_id, {"derived_from"})
                }
                if failure_node_id not in sources:
                    self.graph.put_edge(
                        edge_type="derived_from", src_id=eval_node_id,
                        dst_id=failure_node_id,
                        tenant_id=failure["tenant_id"],
                        project_id=failure["project_id"])
                return existing
            node = self.graph.put_node(
                entity_type="evaluation", tenant_id=failure["tenant_id"],
                project_id=failure["project_id"], node_id=eval_node_id,
                status="candidate",
                data={
                    "kind": "generated_eval",
                    "version": 1,
                    "split": split,
                    "dedup_key": dedup_key,
                    "case": content,
                    "provenance": {"failure_node_id": failure_node_id,
                                   "generated_at": utcnow()},
                },
            )
            self.graph.put_edge(
                edge_type="derived_from", src_id=node.id,
                dst_id=failure_node_id, tenant_id=failure["tenant_id"],
                project_id=failure["project_id"])
        return node


# ---------------------------------------------------------------- skills


class SkillProposer(_TenantBoundManager):
    """SD-001/SD-002: proposal-only. Activation requires human approval and
    passing evals — neither of which this class can do."""

    def propose(
        self,
        *,
        tenant_id: str,
        project_id: str,
        name: str,
        description: str,
        source_failure_ids: list[str],
        tests: list[str],
        rollback_plan: str,
    ) -> dict:
        tenant_id = self._tenant(tenant_id)
        self._project(project_id)
        for failure_id in source_failure_ids:
            failure = self._node(failure_id, entity_type="failure")
            if failure["project_id"] != project_id:
                raise PermissionError(
                    "skill provenance belongs to another project")
        with self.store.transaction():
            node = self.graph.put_node(
                entity_type="skill", tenant_id=tenant_id,
                project_id=project_id, status="proposed",
                data={
                    "name": name, "description": description, "version": 1,
                    "provenance": source_failure_ids, "tests": tests,
                    "rollback_plan": rollback_plan, "proposed_at": utcnow(),
                    "gate_results": {
                        "sandbox_eval": "not_run",
                        "human_approval": "pending"},
                },
            )
            for failure_id in source_failure_ids:
                self.graph.put_edge(
                    edge_type="derived_from", src_id=node.id,
                    dst_id=failure_id,
                    tenant_id=tenant_id, project_id=project_id)
        return node

    def approve(self, skill_id: str, actor: str, sandbox_eval_passed: bool) -> dict:
        """Approval moves proposed -> approved, never -> active: activation,
        canary, and rollback (SD-003) belong to a deployment layer."""
        actor = _safe_nonempty_text(
            actor, field="skill approval actor", max_length=256)
        with self.store.transaction():
            skill = self._node(skill_id, entity_type="skill")
            if skill.get("status") != "proposed":
                raise ValueError(
                    "skill approval requires the proposed source state")
            if sandbox_eval_passed is not True:
                raise ValueError(
                    "cannot approve a skill without a passing sandbox eval")
            out = self.graph.put_node(
                entity_type="skill", tenant_id=skill["tenant_id"],
                project_id=skill["project_id"], node_id=skill_id,
                status="approved", authority="human_decision",
                data={"gate_results": {"sandbox_eval": "passed",
                                       "human_approval": actor}},
            )
            self.store.audit(
                actor=actor, action="skill.approve", object_id=skill_id)
        return out
