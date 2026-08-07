"""Causal Continuity Engine (CCE).

GitHub-native continuity, causal invalidation, and proof for long-running
coding agents. Canonical truth is an immutable event/evidence log. Event-derived
graph state is rebuildable only while retained source payloads remain available;
authenticated runtime records are not replay-derived (ADR-001). Storage is
SQLite implementing the PostgreSQL-first relational adjacency design (ADR-011).
"""

__version__ = "0.1.0"

SCHEMA_VERSIONS = {
    "anchor": "cce.anchor.v1",
    "recovery_packet": "cce.recovery.v1",
    "event": "cce.event.v1",
    "resume_packet": "cce.resume.v1",
    "proof": "cce.proof.v1",
    "proof_predicate": "cce.proof-predicate.v1",
    "capsule": "cce.capsule.v1",
    "continuity_receipt": "cce.continuity-receipt.v1",
}
