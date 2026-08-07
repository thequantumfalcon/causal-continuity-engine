"""Temporal memory tiers L0-L4 (TM-001..TM-008).

L0  pinned control state   — mission, non-negotiable constraints, accepted
                             decisions, critical invalidations. Always in
                             packets; human/policy controlled.
L1  working state          — durable checkpoints of plan/task-queue state.
L2  episodic memory        — events/decisions/failures retrieved by causal,
                             temporal, lexical signals.
L3  distilled knowledge    — stable facts with mandatory provenance.
L4  raw archive            — events + evidence blobs under retention policy
                             (lives in Store).

Tier assignments are append-only and therefore observable and reversible
(TM-001). Decay re-weights retrieval without deleting anything (TM-007).
"""

from __future__ import annotations

import json
import math
import re

from .core import (
    canonical_json,
    parse_ts,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
)
from .store import serialized_access


def _finite_json_object(value, *, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a finite I-JSON object")
    try:
        normalized = strict_json_loads(canonical_json(value))
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError(f"{field} must be a finite I-JSON object") from None
    return normalized

_MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_assignments (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    tier       TEXT NOT NULL,          -- L0 | L1 | L2 | L3
    op         TEXT NOT NULL,          -- promote | demote
    actor      TEXT NOT NULL,
    reason     TEXT,
    at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mem_proj ON memory_assignments(project_id, node_id);
"""

TIERS = {"L0", "L1", "L2", "L3"}


class Memory:
    def __init__(self, store, graph, *, tenant_id: str | None = None):
        self.store = store
        self.graph = graph
        self.tenant_id = tenant_id
        self._conn = store._conn
        self._lock = store._lock
        with self._lock, self._conn:
            self._conn.executescript(_MEMORY_SCHEMA)

    def _effective_tenant(self, tenant_id: str | None = None) -> str | None:
        if (self.tenant_id is not None and tenant_id is not None
                and tenant_id != self.tenant_id):
            raise PermissionError(
                f"memory tenant {tenant_id!r} is outside the bound tenant "
                f"{self.tenant_id!r}")
        return self.tenant_id or tenant_id

    def _require_project(self, project_id: str) -> None:
        if self.tenant_id is None:
            return
        try:
            self.graph.get(
                project_id, tenant_id=self.tenant_id,
                project_id=project_id, entity_type="project")
        except KeyError:
            raise PermissionError(
                f"memory project {project_id!r} is outside the bound tenant "
                f"{self.tenant_id!r}") from None

    def _require_node(self, project_id: str, node_id: str) -> dict:
        self._require_project(project_id)
        try:
            return self.graph.get(
                node_id, tenant_id=self.tenant_id,
                project_id=project_id)
        except KeyError:
            raise PermissionError(
                f"memory node {node_id!r} is outside project "
                f"{project_id!r}") from None

    # ---------------------------------------------------------------- tiers

    def promote(self, project_id: str, node_id: str, tier: str, actor: str,
                reason: str | None = None):
        if not isinstance(tier, str) or tier not in TIERS:
            raise ValueError(f"unknown tier {tier}")
        node = self._require_node(project_id, node_id)
        # AD-006: quarantined content is barred from EVERY tier, not just L3.
        # L0 is pinned control state that lands in every resume packet, so it
        # is the most damaging destination for suspected injection, not the
        # least.
        if node["status"] == "quarantined":
            raise ValueError(
                f"quarantined node {node_id} cannot be promoted to any tier"
                f" (requested {tier})")
        if tier == "L3":
            # TM-005: distillation requires provenance that actually resolves.
            if not self._has_real_provenance(project_id, node_id):
                raise ValueError(
                    f"cannot distill {node_id} to L3 without provenance or evidence"
                )
        self._record(project_id, node_id, tier, "promote", actor, reason)

    @serialized_access
    def _has_real_provenance(self, project_id: str, node_id: str) -> bool:
        """Require a bounded trust path to a real provenance root.

        Merely finding another node is not provenance: two unsupported agent
        claims can point at one another, or form a longer cycle, and thereby
        vouch for themselves. A valid path must terminate in a canonical
        event, typed evidence, a passed authoritative verification, or an
        explicit human decision. Traversal is cycle-safe and bounded so a
        hostile graph cannot turn promotion into unbounded work.
        """
        node = self._require_node(project_id, node_id)
        tenant_id = node["tenant_id"]

        memo: dict[str, bool] = {}
        discovered: set[str] = set()
        max_nodes = 256

        def canonical_event_exists(candidate_id: str) -> bool:
            try:
                self.store.get_event(
                    candidate_id, tenant_id=tenant_id,
                    project_id=project_id)
                return True
            except KeyError:
                return False

        def is_terminal(candidate: dict) -> bool:
            if candidate.get("status") == "quarantined":
                return False
            if candidate.get("authority") == "human_decision":
                return True
            if (candidate.get("entity_type") == "verification"
                    and candidate.get("authority") == "verifier_authoritative"
                    and candidate.get("status") in ("passed", "verified")):
                return True
            # Evidence is itself a typed source. Quarantined or failed
            # evidence is excluded above/below; recorded and verified are the
            # two affirmative lifecycle states used by the reference engine.
            return (
                candidate.get("entity_type") == "evidence"
                and candidate.get("status") in ("recorded", "verified")
            )

        def walk(candidate_id: str, visiting: set[str]) -> bool:
            if candidate_id in memo:
                return memo[candidate_id]
            if candidate_id in visiting or len(discovered) >= max_nodes:
                return False
            try:
                candidate = self.graph.get(
                    candidate_id, tenant_id=tenant_id,
                    project_id=project_id)
            except KeyError:
                # A derived_from edge may point straight at a canonical raw
                # event that has not itself been projected into the graph.
                # Only use this fallback when no graph node owns the id: once
                # a node exists, its current event_id must bind its semantics.
                result = canonical_event_exists(candidate_id)
                memo[candidate_id] = result
                return result
            discovered.add(candidate_id)
            if is_terminal(candidate):
                memo[candidate_id] = True
                return True
            # Provenance belongs to the semantics of the CURRENT node
            # version. A prior version's event_id cannot keep vouching for
            # materially changed content, and a node whose identifier merely
            # equals an event id is not event-backed provenance.
            current_event_id = candidate.get("event_id")
            if (current_event_id
                    and canonical_event_exists(current_event_id)):
                memo[candidate_id] = True
                return True

            next_visiting = visiting | {candidate_id}
            sources = {
                edge["dst_id"] for edge in self.graph.out_edges(
                    candidate_id, {"derived_from"})
            } | {
                edge["src_id"] for edge in self.graph.in_edges(
                    candidate_id, {"supports", "verifies"})
            }
            result = any(
                walk(source_id, next_visiting)
                for source_id in sorted(sources)
                if source_id != candidate_id
            )
            memo[candidate_id] = result
            return result

        return walk(node_id, set())

    def demote(self, project_id: str, node_id: str, tier: str, actor: str,
               reason: str | None = None) -> bool:
        """Remove a node from `tier`. Returns whether it was in that tier.

        The tier is CHECKED, not merely recorded. A demotion row used to
        unassign the node whichever tier it named, so a sweep over L3 — or a
        typo naming no tier at all — silently unpinned L0 control state, the
        one thing a resume packet is never allowed to drop (ADR-062).
        """
        if not isinstance(tier, str) or tier not in TIERS:
            raise ValueError(f"unknown tier {tier}")
        self._require_node(project_id, node_id)
        actual = self.tier_of(project_id, node_id)
        if actual is None:
            return False                      # already unassigned; idempotent
        if actual != tier:
            raise ValueError(
                f"{node_id} is in {actual}, not {tier}: demoting it from"
                f" {tier} would unassign it from {actual}")
        self._record(project_id, node_id, tier, "demote", actor, reason)
        return True

    def demote_from_any_tier(self, project_id: str, node_id: str, actor: str,
                             reason: str) -> str | None:
        """Unassign a node from whatever tier holds it. Returns that tier.

        For callers acting on the node's status rather than on a tier they
        already know — quarantine is the case that matters (AD-006).
        """
        self._require_node(project_id, node_id)
        actual = self.tier_of(project_id, node_id)
        if actual is None:
            return None
        self._record(project_id, node_id, actual, "demote", actor, reason)
        return actual

    def _record(self, project_id, node_id, tier, op, actor, reason):
        with self.store.transaction():
            self._conn.execute(
                "INSERT INTO memory_assignments (project_id, node_id, tier, op, actor,"
                " reason, at) VALUES (?,?,?,?,?,?,?)",
                (project_id, node_id, tier, op, actor, reason, utcnow()),
            )
            self.store.audit(
                actor=actor, action=f"memory.{op}", object_id=node_id,
                detail=f"{tier}: {reason or ''}")

    @serialized_access
    def tier_of(self, project_id: str, node_id: str) -> str | None:
        self._require_project(project_id)
        row = self._conn.execute(
            "SELECT tier, op FROM memory_assignments WHERE project_id = ? AND node_id = ?"
            " ORDER BY seq DESC LIMIT 1",
            (project_id, node_id),
        ).fetchone()
        if row is None or row["op"] == "demote":
            return None
        return row["tier"]

    @serialized_access
    def tier_members(
            self, project_id: str, tier: str, *,
            tenant_id: str | None = None) -> list[str]:
        """Nodes currently in `tier`.

        Quarantined nodes are excluded here, not only where they are pinned:
        AD-006 must hold whichever route set the status. PartialProgressManager
        .quarantine() records the demotion so the history shows it, but a node
        whose status was changed by any other path must not stay in a tier
        because that path forgot to call it (ADR-062). tier_of() is
        deliberately NOT filtered — it reports the raw assignment, which is
        what demote_from_any_tier() needs to record the vacated tier.
        """
        tenant_id = self._effective_tenant(tenant_id)
        self._require_project(project_id)
        rows = self._conn.execute(
            "SELECT node_id, tier, op FROM memory_assignments WHERE project_id = ?"
            " ORDER BY seq",
            (project_id,),
        ).fetchall()
        state: dict[str, str | None] = {}
        for r in rows:
            state[r["node_id"]] = r["tier"] if r["op"] == "promote" else None
        members = []
        for node_id, held in state.items():
            if held != tier:
                continue
            try:
                node = self.graph.get(
                    node_id, tenant_id=tenant_id, project_id=project_id)
                if node["status"] == "quarantined":
                    continue
            except KeyError:
                # A dangling or foreign-scope assignment cannot become
                # packet control state merely because project ids collide.
                continue
            members.append(node_id)
        return members

    @serialized_access
    def l0(
            self, project_id: str, *,
            tenant_id: str | None = None) -> list[dict]:
        """Pinned control state; never dropped from packets (TM-002, MIG-002)."""
        tenant_id = self._effective_tenant(tenant_id)
        self._require_project(project_id)
        out = []
        for node_id in self.tier_members(
                project_id, "L0", tenant_id=tenant_id):
            try:
                out.append(self.graph.get(
                    node_id, tenant_id=tenant_id, project_id=project_id))
            except KeyError:
                continue
        return out

    # ----------------------------------------------------------- checkpoints

    def checkpoint(
        self,
        *,
        tenant_id: str,
        project_id: str,
        session_id: str | None,
        label: str,
        working_state: dict,
        event_id: str | None = None,
        verified: bool = False,
    ) -> dict:
        """Durable L1 checkpoint at a task boundary or before a risky action
        (TM-003, GPP-001)."""
        if not isinstance(verified, bool):
            raise ValueError("checkpoint verified must be a boolean")
        if not isinstance(label, str) or not label.strip():
            raise ValueError("checkpoint label must be a non-empty string")
        label = validate_human_text(
            label, field="checkpoint label", max_length=1024)
        working_state = _finite_json_object(
            working_state, field="checkpoint working_state")
        if session_id is not None:
            session_id = validate_public_identifier(
                session_id, field="checkpoint session_id")
        effective_tenant = self._effective_tenant(tenant_id)
        self._require_project(project_id)
        if session_id is not None:
            session = self._require_node(project_id, session_id)
            if session.get("entity_type") != "session":
                raise ValueError(
                    "checkpoint session_id must identify a session")
        with self.store.transaction():
            node = self.graph.put_node(
                entity_type="checkpoint",
                tenant_id=effective_tenant,
                project_id=project_id,
                status="verified" if verified else "unverified",
                data={
                    "label": label,
                    "session_id": session_id,
                    "working_state": working_state,
                    "checkpoint_at": utcnow(),
                },
                event_id=event_id,
            )
            if session_id is not None:
                self.graph.put_edge(
                    edge_type="produces", src_id=session_id, dst_id=node.id,
                    tenant_id=effective_tenant, project_id=project_id,
                    event_id=event_id,
                )
            self.promote(
                project_id, node.id, "L1", actor="cce",
                reason=f"checkpoint {label}")
        return node

    @serialized_access
    def last_safe_checkpoint(self, project_id: str) -> dict | None:
        self._require_project(project_id)
        cps = [n for n in self.graph.current(
            project_id, "checkpoint", tenant_id=self.tenant_id)
               if n["status"] == "verified"]
        return cps[-1] if cps else None

    # -------------------------------------------------------------- retrieval

    @serialized_access
    def retrieve(
        self,
        project_id: str,
        query: str = "",
        anchor_node_ids: list[str] | None = None,
        limit: int = 20,
        now: str | None = None,
        half_life_days: float = 14.0,
        *,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Rank episodic (L2-eligible) memories by combined causal, temporal,
        and lexical signal (TM-004). Pinned L0 nodes always rank first.
        Returns [{node, score, signals}].
        """
        if not isinstance(query, str):
            raise ValueError("memory query must be a string")
        if query:
            query = validate_human_text(
                query, field="memory query", max_length=8192)
        if (isinstance(limit, bool) or not isinstance(limit, int)
                or not 0 <= limit <= 10_000):
            raise ValueError(
                "memory limit must be an integer from 0 to 10000")
        if (isinstance(half_life_days, bool)
                or not isinstance(half_life_days, (int, float))
                or not math.isfinite(half_life_days)
                or half_life_days <= 0):
            raise ValueError(
                "memory half_life_days must be a finite positive number")
        if now is None:
            now = utcnow()
        elif not isinstance(now, str) or not now:
            raise ValueError("memory now must be an ISO-8601 timestamp or null")
        try:
            now_dt = parse_ts(now)
        except (TypeError, ValueError, OverflowError):
            raise ValueError(
                "memory now must be an ISO-8601 timestamp or null") from None
        if anchor_node_ids is None:
            anchor_node_ids = []
        elif not isinstance(anchor_node_ids, list):
            raise ValueError(
                "memory anchor_node_ids must be an array of identifiers or null")
        else:
            anchor_node_ids = [
                validate_public_identifier(
                    anchor, field="memory anchor_node_id")
                for anchor in anchor_node_ids
            ]
            if len(anchor_node_ids) != len(set(anchor_node_ids)):
                raise ValueError(
                    "memory anchor_node_ids must not contain duplicates")
        tenant_id = self._effective_tenant(tenant_id)
        self._require_project(project_id)
        l0_ids = set(self.tier_members(
            project_id, "L0", tenant_id=tenant_id))
        query_terms = _terms(query)
        anchor_near: dict[str, float] = {}
        for anchor in anchor_node_ids:
            try:
                for dep in self.graph.dependents(anchor, max_depth=3, max_nodes=200):
                    anchor_near[dep["node_id"]] = max(
                        anchor_near.get(dep["node_id"], 0.0), dep["strength"]
                    )
                for edge in self.graph.out_edges(anchor):
                    anchor_near[edge["dst_id"]] = max(anchor_near.get(edge["dst_id"], 0), 0.8)
            except KeyError:
                continue

        scored = []
        for node in self.graph.current(project_id, tenant_id=tenant_id):
            if node["entity_type"] in ("project", "actor"):
                continue
            # AD-006: quarantined content is barred from every tier, and
            # retrieval is a tier in all but name — a suspected injection
            # surfaced here lands verbatim in the resume packet, which is the
            # outcome the quarantine exists to prevent.
            if node.get("status") == "quarantined":
                continue
            temporal = _decay(node["tx_from"], now_dt, half_life_days)
            lexical = _lexical(query_terms, node)
            causal = anchor_near.get(node.id, 0.0)
            pinned = 1.0 if node.id in l0_ids else 0.0
            authority_boost = 0.1 if node.get("authority") in (
                "tenant_policy", "human_decision", "verifier_authoritative") else 0.0
            score = pinned * 10 + causal * 2.0 + lexical * 1.5 + temporal + authority_boost
            if score <= 0.05:
                continue
            scored.append({
                "node": node,
                "score": round(score, 4),
                "signals": {
                    "pinned": pinned, "causal": round(causal, 4),
                    "lexical": round(lexical, 4), "temporal": round(temporal, 4),
                },
            })
        scored.sort(key=lambda s: -s["score"])
        return scored[:limit]

    # ---------------------------------------------------- inspection & export

    @serialized_access
    def export(self, project_id: str) -> dict:
        """TM-008: full inspectable memory export."""
        self._require_project(project_id)
        tiers = {
            tier: self.tier_members(
                project_id, tier, tenant_id=self.tenant_id)
            for tier in sorted(TIERS)}
        return {
            "project_id": project_id,
            "exported_at": utcnow(),
            "tiers": tiers,
            "nodes": self.graph.current(
                project_id, tenant_id=self.tenant_id),
        }

    def correct(self, project_id: str, node_id: str, corrections: dict, actor: str,
                event_id: str | None = None) -> dict:
        """Human correction: a new node version, never an overwrite (TM-008)."""
        corrections = _finite_json_object(
            corrections, field="memory corrections")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("memory correction actor must be a non-empty string")
        actor = validate_human_text(
            actor, field="memory correction actor", max_length=256)
        node = self._require_node(project_id, node_id)
        with self.store.transaction():
            new = self.graph.put_node(
                entity_type=node["entity_type"], tenant_id=node["tenant_id"],
                project_id=project_id, node_id=node_id, data=corrections,
                authority="human_decision", event_id=event_id,
            )
            self.store.audit(
                actor=actor, action="memory.correct", object_id=node_id,
                before_ref=str(node["version"]),
                after_ref=str(new["version"]))
        return new

    def sweep_retention(self, *, raw_days: int = 30, now: str | None = None,
                        actor: str = "retention-job") -> int:
        """TM-006/SEC-006: delete raw event payloads older than the retention
        window. Metadata (digests, ids, times) is always retained."""
        if (isinstance(raw_days, bool) or not isinstance(raw_days, int)
                or raw_days < 0):
            raise ValueError(
                "retention raw_days must be a non-negative integer")
        if now is None:
            now = utcnow()
        elif not isinstance(now, str) or not now:
            raise ValueError(
                "retention now must be an ISO-8601 timestamp or null")
        try:
            now_dt = parse_ts(now)
        except (TypeError, ValueError, OverflowError):
            raise ValueError(
                "retention now must be an ISO-8601 timestamp or null") from None
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("retention actor must be a non-empty string")
        actor = validate_human_text(
            actor, field="retention actor", max_length=256)
        deleted = 0
        # The deletion and the record that explains it are one state change.
        # An audit failure must leave the recoverable payload intact.
        with self.store.transaction():
            if self.tenant_id is None:
                rows = self._conn.execute(
                    "SELECT event_id, recorded_at FROM events "
                    "WHERE payload IS NOT NULL").fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT event_id, recorded_at FROM events "
                    "WHERE payload IS NOT NULL AND tenant_id = ?",
                    (self.tenant_id,)).fetchall()
            for r in rows:
                age = (now_dt - parse_ts(r["recorded_at"])).days
                if age >= raw_days:
                    self._conn.execute(
                        "UPDATE events SET payload = NULL WHERE event_id = ?",
                        (r["event_id"],),
                    )
                    deleted += 1
            if deleted:
                self.store.audit(actor=actor, action="retention.sweep",
                                 detail=f"cleared {deleted} raw payloads > {raw_days}d")
        return deleted


def _terms(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9_]+", text.lower()) if len(t) > 2}


def _lexical(query_terms: set[str], node: dict) -> float:
    if not query_terms:
        return 0.0
    hay = _terms(json.dumps(node["data"]))
    if not hay:
        return 0.0
    overlap = len(query_terms & hay)
    return overlap / max(len(query_terms), 1)


def _decay(ts: str, now_dt, half_life_days: float) -> float:
    try:
        age_days = max((now_dt - parse_ts(ts)).total_seconds() / 86400.0, 0.0)
    except Exception:
        return 0.0
    return 0.5 ** (age_days / half_life_days)
