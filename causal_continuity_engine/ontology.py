"""Causal ontology: entity types, relations, authority, state machines.

CCG-002 and CCG-004. The graph is typed; every mutable project fact is bi-temporal
(ADR-003): valid time (true in the project world) and transaction time
(when CCE recorded it).
"""

from __future__ import annotations

ENTITY_TYPES = {
    "project", "event", "artifact", "claim", "assumption", "requirement",
    "constraint", "decision", "plan", "task", "action", "evidence",
    "verification", "session", "outcome", "failure", "skill", "evaluation",
    "actor", "invalidation", "checkpoint",
}

EDGE_TYPES = {
    "derived_from", "supports", "contradicts", "assumes", "depends_on",
    "invalidates", "supersedes", "affects", "produces", "verifies",
    "accepted_by", "rejected_by", "resumed_from", "migrated_from", "replay_of",
}

# Edges along which invalidation impact propagates, with default strength.
# Propagation follows dependency direction: if X is invalidated, anything that
# assumes / depends_on / derived_from X is affected.
PROPAGATION_EDGES = {
    "assumes": 1.0,
    "depends_on": 0.9,
    "derived_from": 0.8,
    "supports": 0.6,
    "verifies": 0.7,
}

# Source authority ordering (CCG-005): higher wins conflicts.
AUTHORITY_ORDER = [
    "untrusted_content",          # README, docs, code comments, arbitrary text
    "agent_inference",            # model-derived claims
    "agent_observed",             # observable agent traces
    "human_intent",               # issue/PR bodies: work intent, never policy
    "repository_authoritative",   # commits, config, tests as recorded by GitHub
    "verifier_authoritative",     # CI/check results
    "human_decision",             # explicit human approval via CCE
    "tenant_policy",              # tenant/system policy
]

AUTHORITY_RANK = {name: i for i, name in enumerate(AUTHORITY_ORDER)}


def authority_rank(authority: str) -> int:
    return AUTHORITY_RANK.get(authority, 0)


# Assumption state machine (AD-005).
ASSUMPTION_STATES = {
    "proposed", "supported", "active", "uncertain",
    "invalidated", "resolved", "superseded",
}

ASSUMPTION_TRANSITIONS = {
    "proposed": {"supported", "active", "uncertain", "invalidated", "superseded", "resolved"},
    "supported": {"active", "uncertain", "invalidated", "superseded", "resolved"},
    "active": {"uncertain", "invalidated", "superseded", "resolved"},
    "uncertain": {"active", "supported", "invalidated", "superseded", "resolved"},
    "invalidated": {"resolved", "superseded"},
    # A resolution is not a permanent acquittal: evidence that arrives later
    # contradicts the assumption, not the paperwork that closed it. Without
    # these, re-firing on a resolved assumption is refused and — before the
    # refusal was made visible — reported as an invalidation that happened.
    "resolved": {"invalidated", "uncertain", "superseded"},
    "superseded": set(),          # genuinely replaced; invalidate the successor
}

# Node impact classification after invalidation propagation (CI-003).
IMPACT_STATES = {"valid", "review_required", "blocked", "invalidated"}

# Run outcome states (GPP-002).
RUN_OUTCOMES = {
    "completed", "partially_completed", "blocked", "failed", "cancelled", "inconclusive",
}

# Verification results (PA-005): absence of success is never success.
VERIFICATION_RESULTS = {"passed", "failed", "skipped", "missing", "inconclusive", "stale"}

# Failure taxonomy (FC-001).
FAILURE_TAXONOMY = {
    "planning", "retrieval", "stale_assumption", "tool", "environment",
    "verification", "policy", "coordination", "unknown",
}

# Replay fidelity classes (TR-003).
REPLAY_FIDELITY = {"exact", "environment_equivalent", "mocked", "non_reproducible"}

# Autonomy levels (AUT-001).
AUTONOMY_LEVELS = {
    0: "observe",
    1: "recommend",
    2: "reversible_execution",
    3: "guarded_repository_action",
    4: "irreversible_external_action",
}
MVP_MAX_AUTONOMY = 3          # level 4 prohibited in MVP (ADR-009)
CRITICALITY_LEVELS = {"low", "medium", "high", "critical"}


def is_valid_transition(current: str, new: str) -> bool:
    if current == new:
        return True
    return new in ASSUMPTION_TRANSITIONS.get(current, set())
