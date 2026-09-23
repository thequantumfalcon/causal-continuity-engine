"""Causal Continuity Engine (CCE).

GitHub-native continuity, causal invalidation, and proof for long-running
coding agents. Canonical truth is an immutable event/evidence log. Event-derived
graph state is rebuildable only while retained source payloads remain available;
authenticated runtime records are not replay-derived (ADR-001). Storage is
SQLite implementing the PostgreSQL-first relational adjacency design (ADR-011).
"""

__version__ = "0.2.0"

SCHEMA_VERSIONS = {
    "anchor": "cce.anchor.v1",
    "recovery_packet": "cce.recovery.v1",
    "event": "cce.event.v1",
    "resume_packet": "cce.resume.v2",
    "historical_resume_packet": "cce.resume.v1",
    "proof": "cce.proof.v2",
    "proof_predicate": "cce.proof-predicate.v2",
    # Shipped for historical interpretation, never current proof spending.
    "historical_proof": "cce.proof.v1",
    "historical_proof_predicate": "cce.proof-predicate.v1",
    "capsule": "cce.capsule.v2",
    "historical_capsule": "cce.capsule.v1",
    "continuity_receipt": "cce.continuity-receipt.v2",
    "historical_continuity_receipt": "cce.continuity-receipt.v1",
}
