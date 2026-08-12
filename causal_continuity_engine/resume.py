"""Resume Packet composer (MIG-001, MIG-002, MIG-007).

Deterministic-first: mandatory L0 and active-state content is selected before
any compression; lower-priority material is trimmed against the token budget
with explicit omissions (never silently). Composition is decision-sufficient,
not chronological.
"""

from __future__ import annotations

import json

from .capsule import CapsuleError, CapsuleManager
from .core import (
    digest_obj,
    new_id,
    utcnow,
    validate_public_identifier,
)
from .policy import proof_policy_verifier_gaps


# Rough token estimate: 4 chars/token keeps the budget model-neutral.
def _tokens(obj) -> int:
    try:
        encoded = json.dumps(
            obj, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError(
            f"resume packet must contain finite JSON values: {exc}") from None
    return max(len(encoded) // 4, 1)


def _matches(value: str, texts: set[str], substring_patterns: list[str]) -> bool:
    """Whether a packet string carries quarantined content.

    Whole-value equality catches a field copied verbatim; substring matching
    catches the realistic case, an injected block embedded inside a longer
    statement. Only long patterns are matched as substrings — see
    ResumeComposer._MIN_SUBSTRING_PATTERN.
    """
    if value in texts:
        return True
    return any(pattern in value for pattern in substring_patterns)


SECTION_ORDER = [
    "mission", "authority", "invalidations", "accepted_decisions",
    "verified_progress", "open_work", "environment", "trust", "recent_context",
]
# Sections that may be trimmed under budget pressure, least critical first.
TRIMMABLE = ["recent_context", "environment_detail", "verified_progress_detail",
             "open_work_detail"]


class ResumeComposer:
    def __init__(
            self, store, graph, memory, policy=None, *,
            tenant_id: str | None = None):
        self.store = store
        self.graph = graph
        self.memory = memory
        self.policy = policy
        self.tenant_id = tenant_id

    def compose(
        self,
        *,
        tenant_id: str,
        project_id: str,
        target: dict | None = None,
        token_budget: int = 4000,
        signer=None,
        session_id: str | None = None,
        state_basis: dict | None = None,
    ) -> dict:
        """Compose a model-neutral Resume Packet. Never drops L0 (MIG-002)."""
        if target is not None and not isinstance(target, dict):
            raise ValueError("resume target must be an object or null")
        if (isinstance(token_budget, bool)
                or not isinstance(token_budget, int)
                or not 1 <= token_budget <= 100_000):
            raise ValueError(
                "resume token_budget must be an integer from 1 to 100000")
        if state_basis is not None and not isinstance(state_basis, dict):
            raise ValueError("resume state_basis must be an object or null")
        target = dict(target or {})
        state_basis = dict(state_basis) if state_basis is not None else None
        try:
            digest_obj({"target": target, "state_basis": state_basis})
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"resume inputs must contain finite canonical JSON: {exc}") from None
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise PermissionError(
                f"resume tenant {tenant_id!r} is outside the bound tenant "
                f"{self.tenant_id!r}")
        try:
            self.graph.get(
                project_id, tenant_id=tenant_id, project_id=project_id,
                entity_type="project")
        except KeyError:
            raise PermissionError(
                f"resume project {tenant_id}/{project_id} does not exist or "
                "belongs to another tenant") from None
        if session_id is not None:
            try:
                session_id = validate_public_identifier(
                    session_id, field="session_id")
                self.graph.get(
                    session_id, tenant_id=tenant_id, project_id=project_id,
                    entity_type="session")
            except ValueError:
                raise
            except KeyError:
                raise PermissionError(
                    "resume session_id is not a session in the bound project"
                ) from None
        omissions: list[dict] = []
        scope_query = " ".join(str(v) for v in target.values())
        policy_config = (
            self.policy.project_config(project_id)
            if self.policy is not None else {})
        prose_may_mandate = policy_config.get("prose_may_mandate", True)

        def may_mandate(node: dict) -> bool:
            # Extraction provenance distinguishes prose-derived control from
            # tasks and requirements created through an explicit API. Apply
            # the policy in force at projection so tightening it also closes
            # already-stored prose, while the graph retains its history.
            if not node.get("extractor"):
                return True
            if node.get("authority") in (
                    "untrusted_content", "agent_inference"):
                return False
            return bool(
                prose_may_mandate
                or node.get("entity_type") not in (
                    "requirement", "constraint", "decision", "task"))

        l0_candidates = self.memory.l0(project_id, tenant_id=tenant_id)
        l0_nodes = [node for node in l0_candidates if may_mandate(node)]
        current_constraints = [n for n in self.graph.current(
            project_id, "constraint", tenant_id=tenant_id)
            if n["status"] not in ("invalidated", "superseded")]
        current_requirements = [n for n in self.graph.current(
            project_id, "requirement", tenant_id=tenant_id)
            if n["status"] not in ("invalidated", "superseded")]
        constraints = self._section(
            [n for n in current_constraints if may_mandate(n)],
            kind="constraint")
        requirements = self._section(
            [n for n in current_requirements if may_mandate(n)],
            kind="requirement")
        current_decisions = [n for n in self.graph.current(
            project_id, "decision", tenant_id=tenant_id)
            if n["status"] in ("accepted", "active", None)]
        decisions = self._section(
            [n for n in current_decisions if may_mandate(n)],
            kind="decision")
        assumptions_active = self.graph.current(
            project_id, "assumption", status=["active", "supported"],
            tenant_id=tenant_id)
        assumptions_uncertain = self.graph.current(
            project_id, "assumption", status=["uncertain"],
            tenant_id=tenant_id)
        open_invalidations = self.graph.current(
            project_id, "invalidation", status=["open", "pending_confirmation"],
            tenant_id=tenant_id)
        tasks = self.graph.current(project_id, "task", tenant_id=tenant_id)
        verified = [n for n in self.graph.current(
            project_id, tenant_id=tenant_id)
                    if n["entity_type"] in ("task", "action", "artifact")
                    and n["status"] == "verified"]
        candidate_tasks = [t for t in tasks if t["status"] in
                           ("open", "in_progress", "blocked", None)]
        open_tasks = [t for t in candidate_tasks if may_mandate(t)]
        demoted_authority = (
            len(current_constraints) - len(constraints["nodes"])
            + len(current_requirements) - len(requirements["nodes"])
        )
        demoted_decisions = len(current_decisions) - len(decisions["nodes"])
        demoted_l0 = len(l0_candidates) - len(l0_nodes)
        demoted_tasks = len(candidate_tasks) - len(open_tasks)
        if demoted_authority:
            omissions.append({
                "reason": "policy_demoted_prose", "section": "authority",
                "count": demoted_authority,
                "note": "prose-derived control is retained as history but is "
                        "not authority under the current project policy"})
        if demoted_decisions:
            omissions.append({
                "reason": "policy_demoted_prose",
                "section": "accepted decisions", "count": demoted_decisions,
                "note": "prose-derived decisions are proposals under the "
                        "current authority boundary"})
        if demoted_l0:
            omissions.append({
                "reason": "policy_demoted_prose",
                "section": "mission control state", "count": demoted_l0,
                "note": "an existing memory assignment cannot elevate prose "
                        "above its current source and policy authority"})
        if demoted_tasks:
            omissions.append({
                "reason": "policy_demoted_prose", "section": "open work",
                "count": demoted_tasks,
                "note": "prose-derived checklist items are proposals, not "
                        "actionable work under the current authority boundary"})
        env_nodes = self.graph.current(
            project_id, "artifact", tenant_id=tenant_id)
        env = [n for n in env_nodes if n["data"].get("kind") == "environment"]
        sessions = self.graph.current(
            project_id, "session", tenant_id=tenant_id)
        checkpoints = self.graph.current(
            project_id, "checkpoint", tenant_id=tenant_id)

        evidence_index = []
        material_nodes = (assumptions_active + assumptions_uncertain
                          + decisions["nodes"] + open_invalidations + verified)
        covered = 0
        for node in material_nodes:
            ev = self._evidence_for(node)
            if ev:
                covered += 1
                evidence_index.append({"claim_id": node["node_id"], "evidence_ids": ev})
        evidence_coverage = round(covered / len(material_nodes), 3) if material_nodes else 1.0

        mission = self._mission(
            project_id, l0_nodes, target, tenant_id=tenant_id)
        packet = {
            "schema_version": "cce.resume.v1",
            "packet_id": new_id("packet"),
            "generated_at": utcnow(),
            "project_state_at": self._watermark(
                project_id, tenant_id=tenant_id),
            "project_state_basis": state_basis,
            "target": target,
            "mission": mission,
            "authority": {
                "instruction_precedence": [
                    "tenant_policy", "human_decision", "repository_authoritative",
                    "agent_inference", "untrusted_content",
                ],
                "active_requirements": requirements["items"],
                "active_constraints": constraints["items"],
            },
            "accepted_decisions": decisions["items"],
            "verified_progress": [self._summ(n) for n in verified],
            "invalidations": [self._inv_summ(n) for n in open_invalidations],
            "assumptions": {
                "active": [self._summ(n) for n in assumptions_active],
                "uncertain": [self._summ(n) for n in assumptions_uncertain],
            },
            "open_work": self._open_work(open_tasks, open_invalidations),
            "environment": ([n["data"] for n in env]
                            or {"note": "no environment fingerprint recorded"}),
            "trust": self._trust(project_id, tenant_id=tenant_id),
            "continuity_lineage": {
                "source_session": (
                    sessions[-1]["node_id"] if session_id is None and sessions
                    else session_id),
                "checkpoints": [c["node_id"] for c in checkpoints[-3:]],
                "packet_generation_time": utcnow(),
            },
            "evidence_index": evidence_index,
            "evidence_coverage": evidence_coverage,
            "omissions": omissions,
            "recent_context": [
                {"node_id": s["node"]["node_id"],
                 "entity_type": s["node"]["entity_type"],
                 "summary": self._summ(s["node"])["summary"],
                 "score": s["score"]}
                for s in self.memory.retrieve(
                    project_id, query=scope_query, limit=10,
                    tenant_id=tenant_id)
                if s["signals"]["pinned"] == 0
            ],
        }

        # Token budget: trim trimmable material, never L0/mission/constraints.
        packet = self._fit_budget(packet, token_budget, omissions)
        # Defence in depth (AD-006): whatever any section selected, nothing
        # quarantined leaves in a packet. Every earlier barrier is a filter on
        # one path; this one is on the only exit.
        packet = self._strip_quarantined(
            project_id, packet, tenant_id=tenant_id)
        packet["token_estimate"] = _tokens(packet)
        # The digest is part of the signed packet. Signing first and then
        # appending this field made every packet fail Signer.verify(): the
        # verifier quite correctly included packet_digest in the body that
        # the producer had signed without it.
        packet["packet_digest"] = digest_obj(
            {k: v for k, v in packet.items() if k not in ("signature", "packet_digest")})
        try:
            CapsuleManager._validate_resume_packet(packet)
        except CapsuleError as exc:
            raise ValueError(
                f"resume composer produced an invalid packet: {exc}") from None
        if signer is not None:
            packet["signature"] = signer.sign(packet)
            try:
                CapsuleManager._validate_resume_packet(packet)
            except CapsuleError as exc:
                raise ValueError(
                    f"resume signer produced an invalid packet: {exc}") from None
        return packet

    # ------------------------------------------------------------------ parts

    def _mission(
            self, project_id: str, l0_nodes: list[dict], target: dict, *,
            tenant_id: str | None = None) -> dict:
        objective = None
        for n in l0_nodes:
            if n["data"].get("kind") == "mission" or n["entity_type"] == "plan":
                objective = n["data"].get("statement") or n["data"].get("title")
                break
        projects = self.graph.current(
            project_id, "project", tenant_id=tenant_id)
        name = projects[0]["data"].get("name") if projects else project_id
        live = [n for n in l0_nodes
                if n.get("status") not in ("invalidated", "superseded",
                                           "quarantined", "rejected")]
        retired = [n for n in l0_nodes if n not in live]
        return {
            "project": name,
            "objective": objective or "No explicit mission pinned; see open work.",
            "target": target,
            # Only live items are control state. A superseded constraint left
            # in this list reads as binding to anything skimming the packet,
            # which is the opposite of what invalidating it meant (ADR-053).
            "pinned_control_state": [self._summ(n) for n in live],
            "retired_control_state": [self._summ(n) for n in retired],
        }

    def _section(self, nodes: list[dict], kind: str) -> dict:
        return {"nodes": nodes, "items": [self._summ(n) for n in nodes]}

    def _summ(self, node: dict) -> dict:
        summary = (
            node["data"].get("statement") or node["data"].get("title")
            or node["data"].get("label") or node["data"].get("name") or "")
        if not isinstance(summary, str):
            raise ValueError(
                f"resume summary for node {node.get('node_id')!r} must be a string")
        return {
            "node_id": node["node_id"],
            "entity_type": node["entity_type"],
            "status": node.get("status"),
            "criticality": node.get("criticality"),
            "confidence": node.get("confidence"),
            "authority": node.get("authority"),
            "summary": summary,
        }

    def _inv_summ(self, inv: dict) -> dict:
        d = inv["data"]
        return {
            "invalidation_id": inv["node_id"],
            "status": inv["status"],
            "trigger_type": d.get("trigger_type"),
            "target": d.get("target_summary") or d.get("target_node_id"),
            "severity": d.get("severity"),
            "affected_count": d.get("affected_count"),
            "minimal_causal_path": d.get("minimal_causal_path"),
            "recommended_action": d.get("recommended_action"),
        }

    def _open_work(self, open_tasks: list[dict], open_invalidations: list[dict]) -> dict:
        prioritized = sorted(
            open_tasks,
            key=lambda t: (
                0 if t.get("status") == "blocked" else 1,
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                    t.get("criticality") or "medium", 2),
            ),
        )
        next_safe = None
        for t in prioritized:
            if t.get("status") != "blocked":
                next_safe = self._summ(t)
                break
        blockers = [self._summ(t) for t in prioritized if t.get("status") == "blocked"]
        if open_invalidations and next_safe is None:
            next_safe = {
                "summary": "Resolve open invalidations before continuing implementation.",
            }
        return {
            "tasks": [self._summ(t) for t in prioritized],
            "blockers": blockers,
            "next_safe_action": next_safe
            or {"summary": "No open tasks; verify project state and await instruction."},
        }

    def _trust(
            self, project_id: str, *, tenant_id: str | None = None) -> dict:
        verifications = self.graph.current(
            project_id, "verification", tenant_id=tenant_id)
        projects = self.graph.current(
            project_id, "project", tenant_id=tenant_id)
        project_data = projects[-1]["data"] if projects else {}

        policy_config = (
            self.policy.project_config(project_id)
            if self.policy is not None else {})
        definitions = (
            self.policy.required_verifier_defs(project_id)
            if self.policy is not None else [])
        frontier = (
            self.policy.tracked_ref_frontier(project_id, project_data)
            if self.policy is not None else {})
        # External checks are revision-bound.  A head retained from an older
        # protected-ref policy epoch, or an out-of-order/uncertain frontier,
        # cannot be presented as a completed current check.
        trusted_external_head = frontier.get("trusted_external_head_sha")

        def satisfies(v: dict, definition: dict) -> bool:
            if v.get("status") != "passed":
                return False
            data = v.get("data") or {}
            if data.get("verifier") != definition["name"]:
                return False
            source = str(data.get("source") or "")
            if source == "executed":
                if not definition.get("pinned") or not data.get("pinned"):
                    return False
                from .verifiers import VerifierSpec
                return data.get("definition_digest") == \
                    VerifierSpec.from_policy(definition).definition_digest
            if source.startswith("github:"):
                return bool(
                    not definition.get("pinned")
                    and self.policy.external_verifier_trusted(
                        project_id, source, data)
                    and trusted_external_head
                    and data.get("head_sha") == trusted_external_head
                )
            return False

        completed = []
        gaps = proof_policy_verifier_gaps(policy_config, definitions)
        for definition in definitions:
            matches = [v for v in verifications if satisfies(v, definition)]
            if matches:
                completed.append(matches[-1])
            else:
                gaps.append(definition["name"])
        failed = [v for v in verifications if v["status"] in ("failed", "stale")]
        level = None
        required = [definition["name"] for definition in definitions]
        if self.policy is not None:
            level = self.policy.effective_level(project_id)
        return {
            "autonomy_level": level,
            "required_verifiers": required,
            "completed_checks": [self._summ(v) for v in completed[-10:]],
            "failed_or_stale_checks": [self._summ(v) for v in failed],
            "gaps": gaps,
        }

    #: Keys the ENGINE writes on a quarantined node. Everything else in its
    #: data came from outside and is treated as payload — allow-listing
    #: content keys instead would leak any field a future extractor adds
    #: (ADR-061: the payload arrived under `title`, not `statement`).
    _BOOKKEEPING_KEYS = frozenset({
        "span", "source_ref", "suspected_injection", "quarantine_reason",
        "quarantined_at", "extractor", "extractor_version", "node_id",
        "event_id", "kind",
    })

    #: A pattern shorter than this matches only as a whole value. Substring
    #: matching on a short string is a wildcard: "ok" would strip every
    #: section containing it, which hands an outsider an erase button. Long
    #: patterns are matched inside larger strings because the realistic leak
    #: is an injected block embedded in a longer, legitimate-looking one.
    _MIN_SUBSTRING_PATTERN = 24

    def _strip_quarantined(
            self, project_id: str, packet: dict, *,
            tenant_id: str | None = None) -> dict:
        """Remove any reference to a quarantined node from a composed packet.

        Suspected-injection text must not reach an agent's context by ANY
        route — a section that forgets to filter, a retrieval score, an
        evidence id. Removals are disclosed as omissions rather than silently
        dropped, so the packet never hides that something was withheld.

        Text matching cannot tell the payload from a legitimate node that
        quotes it, and the safe direction is to withhold both. That gives an
        outsider a denial of service: quote a critical constraint inside
        content that gets quarantined and the constraint stops reaching the
        agent. The removal is kept — a leak is worse — but the collision is
        detected, named and disclosed, so the loss is visible and attributable
        rather than a section that quietly goes missing (ADR-061).
        """
        current = self.graph.current(project_id, tenant_id=tenant_id)
        quarantined = {n["node_id"] for n in current
                       if n.get("status") == "quarantined"}
        if not quarantined:
            return packet
        removed = 0

        texts: set[str] = set()
        for nid in quarantined:
            for key, value in (self.graph.get(
                    nid, tenant_id=tenant_id,
                    project_id=project_id)["data"] or {}).items():
                if key not in self._BOOKKEEPING_KEYS and isinstance(value, str) \
                        and value.strip():
                    texts.add(value)
        substring_patterns = [t for t in texts
                              if len(t) >= self._MIN_SUBSTRING_PATTERN]

        # Legitimate nodes carrying the same text: stripping takes them out
        # too, so say which ones rather than leaving a hole.
        collisions = []
        for node in current:
            if node["node_id"] in quarantined:
                continue
            for value in (node.get("data") or {}).values():
                if isinstance(value, str) and _matches(value, texts,
                                                       substring_patterns):
                    collisions.append({"node_id": node["node_id"],
                                       "entity_type": node["entity_type"],
                                       "status": node.get("status")})
                    break

        def scrub(value):
            nonlocal removed
            if isinstance(value, dict):
                ident = value.get("node_id") or value.get("claim_id")
                if ident in quarantined:
                    removed += 1
                    return None
                # A dict carrying the quarantined TEXT under some other key
                # (a summary, a mission objective, a next-safe-action) leaks
                # the payload even with the id gone (ADR-053).
                if any(isinstance(v, str) and _matches(v, texts,
                                                       substring_patterns)
                       for v in value.values()):
                    removed += 1
                    return None
                return {k: scrub(v) for k, v in value.items()}
            if isinstance(value, list):
                kept = [scrub(v) for v in value]
                return [v for v in kept if v is not None]
            if isinstance(value, str) and (
                    value in quarantined
                    or _matches(value, texts, substring_patterns)):
                removed += 1
                return None
            return value

        packet = {k: (scrub(v) if k not in ("omissions",) else v)
                  for k, v in packet.items()}
        if removed:
            packet["omissions"].append({
                "reason": "quarantined_content", "section": "all",
                "count": removed,
                "note": "content flagged as suspected prompt injection is "
                        "withheld from agent-facing state (AD-006)"})
        if collisions:
            packet["omissions"].append({
                "reason": "quarantined_text_collision", "section": "all",
                "count": len(collisions), "nodes": collisions,
                "note": "these NON-quarantined nodes carry text that also "
                        "appears in quarantined content, so they were withheld "
                        "too. Either an injection was copied into live state, "
                        "or someone quoted live state to get it suppressed. "
                        "Both need a human."})
            self.store.audit(
                actor="resume", action="packet.quarantine_collision",
                object_id=project_id, authority="verifier_authoritative",
                detail=f"{len(collisions)} live node(s) withheld for matching "
                       f"quarantined text: "
                       f"{','.join(c['node_id'] for c in collisions[:10])}")
        return packet

    def _evidence_for(self, node: dict) -> list[str]:
        """Evidence ids a reader can actually follow.

        Every id is resolved before it is counted: a dangling edge endpoint or
        an event id with no row behind it is not evidence, and letting such
        ids through would inflate the very coverage metric that is supposed
        to detect unsupported claims. A node never counts as its own evidence.
        """
        node_id = node["node_id"]
        candidates = (
            [e["dst_id"] for e in self.graph.out_edges(node_id, {"derived_from"})]
            + [e["src_id"] for e in self.graph.in_edges(node_id,
                                                        {"supports", "verifies"})]
        )
        out = set()
        for other_id in candidates:
            if other_id == node_id:
                continue
            try:
                self.graph.get(other_id)
                out.add(other_id)
            except KeyError:
                try:                       # edges may also point at raw events
                    self.store.get_event(other_id)
                    out.add(other_id)
                except KeyError:
                    continue
        for v in self.graph.history(node_id):
            if not v["event_id"]:
                continue
            try:
                self.store.get_event(v["event_id"])
                out.add(v["event_id"])
            except KeyError:
                continue
        # Inline digest evidence (signed proofs, verifier outputs) is
        # inspectable evidence too.
        for key in ("proof_id", "proof_digest", "completion_evidence",
                    "evidence_digest", "output_digest"):
            if node["data"].get(key):
                out.add(str(node["data"][key]))
        return sorted(out)

    def _watermark(
            self, project_id: str, *,
            tenant_id: str | None = None) -> str | None:
        events = self.store.events(project_id, tenant_id=tenant_id)
        return f"event:{events[-1]['event_id']}" if events else None

    # ----------------------------------------------------------------- budget

    def _fit_budget(self, packet: dict, budget: int, omissions: list[dict]) -> dict:
        """Trim trimmable material until the budget is met, and say so if it is not.

        Trimming to a fixed cap made `token_budget` a trigger rather than a
        bound: once each section had been cut to its cap the loop stopped,
        however far over budget the packet still was, so a large project
        returned the same oversized packet at every budget. Sections are now
        reduced progressively.

        Authority — mission, L0 and constraints — is still never dropped, which
        is the point of the design. When authority alone exceeds the budget the
        packet is emitted over budget, and `token_estimate` reports its real
        size so a caller comparing that against the budget it asked for can
        tell. This is deliberately not recorded as an omission: nothing was
        withheld, and saying otherwise would itself be a false statement.
        """
        trim_order = [
            ("recent_context", "recent context"),
            ("verified_progress", "verified progress detail"),
            ("open_work", "open work detail"),
            ("environment", "environment detail"),
        ]
        for key, label in trim_order:
            if _tokens(packet) <= budget:
                break
            section = packet.get(key)
            if isinstance(section, list) and section:
                kept = list(section)
                while kept and _tokens({**packet, key: kept}) > budget:
                    kept.pop()
                if len(kept) != len(section):
                    packet[key] = kept
                    omissions.append({
                        "reason": "token_budget", "section": label,
                        "count": len(section) - len(kept)})
            elif key == "open_work" and isinstance(section, dict):
                tasks = section.get("tasks", [])
                kept = list(tasks)
                while kept and _tokens(
                        {**packet, key: {**section, "tasks": kept}}) > budget:
                    kept.pop()
                if len(kept) != len(tasks):
                    omissions.append({
                        "reason": "token_budget", "section": label,
                        "count": len(tasks) - len(kept)})
                    section["tasks"] = kept
        packet["omissions"] = omissions
        return packet

    # ----------------------------------------------------------------- render

    @staticmethod
    def render_markdown(packet: dict) -> str:
        lines = [
            "# CCE Resume Packet",
            f"Packet `{packet['packet_id']}` | generated {packet['generated_at']}"
            f" | state at {packet.get('project_state_at')}",
            "",
            "## Mission",
            f"**Project:** {packet['mission']['project']}",
            f"**Objective:** {packet['mission']['objective']}",
            "",
            "## Authority",
        ]
        for c in packet["authority"]["active_constraints"]:
            lines.append(f"- [constraint] {c['summary']} ({c.get('criticality')})")
        for r in packet["authority"]["active_requirements"]:
            lines.append(f"- [requirement] {r['summary']}")
        lines += ["", "## Accepted decisions"]
        for d in packet["accepted_decisions"]:
            lines.append(f"- {d['summary']} ({d['node_id']})")
        lines += ["", "## Invalidated state"]
        if packet["invalidations"]:
            for inv in packet["invalidations"]:
                lines.append(
                    f"- [{inv['severity']}] {inv['trigger_type']}: {inv['target']}"
                    f" -> {inv['recommended_action']}")
        else:
            lines.append("- none open")
        lines += ["", "## Verified progress"]
        for v in packet["verified_progress"]:
            lines.append(f"- {v['summary']} ({v['node_id']})")
        lines += ["", "## Open work"]
        for t in packet["open_work"]["tasks"]:
            lines.append(f"- [{t.get('status')}] {t['summary']}")
        nsa = packet["open_work"]["next_safe_action"]
        lines.append(f"\n**Next safe action:** {nsa['summary']}")
        lines += ["", "## Trust"]
        trust = packet["trust"]
        lines.append(f"- autonomy level: {trust.get('autonomy_level')}")
        required = ", ".join(trust.get("required_verifiers") or []) or "none"
        lines.append(f"- required verifiers: {required}")
        gaps = trust.get("gaps") or []
        lines.append(f"- verification gaps: {', '.join(gaps) or 'none'}")
        if packet["omissions"]:
            lines += ["", "## Omissions"]
            for o in packet["omissions"]:
                lines.append(f"- {o['section']}: {o['count']} item(s) dropped ({o['reason']})")
        lines.append("")
        lines.append(f"Evidence coverage: {packet['evidence_coverage']:.0%}"
                     f" | ~{packet.get('token_estimate', '?')} tokens")
        return "\n".join(lines)
