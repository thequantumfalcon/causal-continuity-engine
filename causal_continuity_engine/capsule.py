"""Session Capsules: signed, portable, model-neutral state (MIG-003..005, 008).

A capsule carries observable state only — packets, decisions, assumptions,
environment, lineage. Hidden chain-of-thought is structurally excluded
(MIG-008/ADR-005): known hidden-reasoning keys are stripped defensively at
export, and the capsule schema has no field for them.

Import verifies schema version, content digests, and signature (tamper
detection), then runs a deterministic challenge step (MIG-005) whose result
gates autonomy above level 1.
"""

from __future__ import annotations

import copy
import math
import re

from .core import (
    digest_obj,
    is_canonical_utc_timestamp,
    is_public_identifier,
    new_id,
    utcnow,
    validate_human_text,
)

CAPSULE_SCHEMA = "cce.capsule.v1"

_HIDDEN_KEYS = {"chain_of_thought", "hidden_reasoning", "reasoning_trace",
                "internal_monologue", "scratchpad", "thinking"}

_CAPSULE_ID = re.compile(r"^cap_[0-9a-f]{24}$")
_PACKET_ID = re.compile(r"^rsp_[0-9a-f]{24}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")

_PACKET_REQUIRED = {
    "schema_version", "packet_id", "generated_at", "project_state_at",
    "project_state_basis", "target", "mission", "authority",
    "accepted_decisions", "verified_progress", "invalidations",
    "assumptions", "open_work", "environment", "trust",
    "continuity_lineage", "evidence_index", "evidence_coverage",
    "omissions", "recent_context", "token_estimate", "packet_digest",
}
_PACKET_ALLOWED = _PACKET_REQUIRED | {"signature"}


def _nonempty(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_capsule_text(value, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CapsuleError(f"{field} must be a non-empty string")
    try:
        return validate_human_text(value, field=field)
    except ValueError as exc:
        raise CapsuleError(str(exc)) from None


def _timestamp(value) -> bool:
    return is_canonical_utc_timestamp(value)


def _finite_probability(value) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0 <= value <= 1
    )


def _finite_number(value) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def _string_or_none(value) -> bool:
    return value is None or isinstance(value, str)


def _string_list(value) -> bool:
    return (
        isinstance(value, list)
        and all(_nonempty(item) for item in value)
    )


def _summary(value) -> bool:
    required = {
        "node_id", "entity_type", "status", "criticality", "confidence",
        "authority", "summary",
    }
    return (
        isinstance(value, dict)
        and set(value) == required
        and is_public_identifier(value.get("node_id"))
        and _nonempty(value.get("entity_type"))
        and _string_or_none(value.get("status"))
        and _string_or_none(value.get("criticality"))
        and (
            value.get("confidence") is None
            or _finite_probability(value.get("confidence"))
        )
        and _string_or_none(value.get("authority"))
        and isinstance(value.get("summary"), str)
    )


def _summary_list(value) -> bool:
    return isinstance(value, list) and all(_summary(item) for item in value)


def _invalidation(value) -> bool:
    required = {
        "invalidation_id", "status", "trigger_type", "target", "severity",
        "affected_count", "minimal_causal_path", "recommended_action",
    }
    affected = value.get("affected_count") if isinstance(value, dict) else None
    path = value.get("minimal_causal_path") if isinstance(value, dict) else None
    return (
        isinstance(value, dict)
        and set(value) == required
        and is_public_identifier(value.get("invalidation_id"))
        and _string_or_none(value.get("status"))
        and _string_or_none(value.get("trigger_type"))
        and _string_or_none(value.get("target"))
        and _string_or_none(value.get("severity"))
        and (
            affected is None
            or not isinstance(affected, bool)
            and isinstance(affected, int)
            and affected >= 0
        )
        and (
            path is None
            or isinstance(path, list)
            and all(is_public_identifier(item) for item in path)
        )
        and _string_or_none(value.get("recommended_action"))
    )


def _evidence_index_item(value) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"claim_id", "evidence_ids"}
        and is_public_identifier(value.get("claim_id"))
        and _string_list(value.get("evidence_ids"))
    )


def _recent_context_item(value) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"node_id", "entity_type", "summary", "score"}
        and is_public_identifier(value.get("node_id"))
        and _nonempty(value.get("entity_type"))
        and isinstance(value.get("summary"), str)
        and _finite_number(value.get("score"))
    )


def _strip_hidden(obj):
    if isinstance(obj, dict):
        return {k: _strip_hidden(v) for k, v in obj.items() if k not in _HIDDEN_KEYS}
    if isinstance(obj, list):
        return [_strip_hidden(v) for v in obj]
    return obj


def _contains_hidden(obj) -> bool:
    """Whether a capsule carries a field the portable schema forbids."""
    if isinstance(obj, dict):
        return any(k in _HIDDEN_KEYS or _contains_hidden(v)
                   for k, v in obj.items())
    if isinstance(obj, list):
        return any(_contains_hidden(v) for v in obj)
    return False


class CapsuleError(Exception):
    pass


class CapsuleManager:
    def __init__(
            self, store, graph, composer, policy=None, tenant_id=None,
            state_basis_provider=None):
        self.store = store
        self.graph = graph
        self.composer = composer
        self.policy = policy
        self.tenant_id = tenant_id
        self.state_basis_provider = state_basis_provider

    def _state_basis(self, project_id: str) -> dict | None:
        if self.state_basis_provider is None:
            return None
        basis = self.state_basis_provider(project_id)
        if not isinstance(basis, dict):
            raise CapsuleError("capsule state-basis provider returned malformed state")
        return basis

    def _require_project(self, tenant_id: str, project_id: str) -> dict:
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise CapsuleError(
                f"capsule tenant {tenant_id!r} is not this engine's tenant")
        try:
            return self.graph.get(
                project_id, tenant_id=tenant_id, project_id=project_id,
                entity_type="project")
        except KeyError as exc:
            raise CapsuleError(
                f"capsule project {tenant_id}/{project_id} does not exist") from exc

    @staticmethod
    def _authenticator_valid(capsule: dict, signer) -> bool:
        signature = capsule.get("signature")
        if not isinstance(signature, dict):
            return False
        if signature.get("algorithm") != getattr(signer, "algorithm", None):
            return False
        try:
            if not signer.verify(capsule):
                return False
        except (KeyError, TypeError, ValueError):
            return False
        if bool(getattr(signer, "self_authenticating", False)):
            return True
        derive = getattr(signer, "derive_fingerprint", None)
        registry = getattr(signer, "registered_fingerprints", None)
        if not callable(derive) or registry is None:
            return False
        actual = derive(signature)
        return bool(
            actual
            and signature.get("fingerprint") == actual
            and actual in set(registry))

    @staticmethod
    def _validate_signature_shape(signature, *, label: str) -> None:
        if not isinstance(signature, dict):
            raise CapsuleError(f"{label} signature must be an object")
        algorithm = signature.get("algorithm")
        if algorithm == "hmac-sha256":
            if set(signature) != {"key_id", "algorithm", "value"}:
                raise CapsuleError(f"{label} HMAC signature shape is malformed")
            if (not _nonempty(signature.get("key_id"))
                    or not isinstance(signature.get("value"), str)
                    or _HEX_256.fullmatch(signature["value"]) is None):
                raise CapsuleError(f"{label} HMAC signature fields are malformed")
            return
        if algorithm == "lamport-sha256/1":
            required = {
                "key_id", "algorithm", "fingerprint", "public_key", "value"}
            if set(signature) != required:
                raise CapsuleError(f"{label} Lamport signature shape is malformed")
            public = signature.get("public_key")
            value = signature.get("value")
            valid_public = (
                isinstance(public, list)
                and len(public) == 256
                and all(
                    isinstance(pair, list)
                    and len(pair) == 2
                    and all(
                        isinstance(block, str)
                        and _HEX_256.fullmatch(block) is not None
                        for block in pair)
                    for pair in public)
            )
            valid_value = (
                isinstance(value, list)
                and len(value) == 256
                and all(
                    isinstance(block, str)
                    and _HEX_256.fullmatch(block) is not None
                    for block in value)
            )
            if (not _nonempty(signature.get("key_id"))
                    or not isinstance(signature.get("fingerprint"), str)
                    or _SHA256.fullmatch(signature["fingerprint"]) is None
                    or not valid_public or not valid_value):
                raise CapsuleError(f"{label} Lamport signature fields are malformed")
            return
        raise CapsuleError(f"{label} signature algorithm is unsupported")

    @staticmethod
    def _validate_resume_packet(packet) -> None:
        if not isinstance(packet, dict):
            raise CapsuleError("capsule resume_packet must be an object")
        missing = _PACKET_REQUIRED - set(packet)
        unknown = set(packet) - _PACKET_ALLOWED
        if missing or unknown:
            raise CapsuleError(
                "capsule resume_packet has missing or unknown fields: "
                f"missing={sorted(missing)}, unknown={sorted(unknown)}")
        if packet.get("schema_version") != "cce.resume.v1":
            raise CapsuleError("capsule resume_packet schema_version is unsupported")
        packet_id = packet.get("packet_id")
        if not isinstance(packet_id, str) or _PACKET_ID.fullmatch(packet_id) is None:
            raise CapsuleError("capsule resume_packet packet_id is malformed")
        if not _timestamp(packet.get("generated_at")):
            raise CapsuleError("capsule resume_packet generated_at is malformed")
        watermark = packet.get("project_state_at")
        if watermark is not None and not _nonempty(watermark):
            raise CapsuleError("capsule resume_packet project_state_at is malformed")

        basis = packet.get("project_state_basis")
        if basis is not None:
            if not isinstance(basis, dict) or set(basis) != {
                    "event_seq", "control_basis_digest", "artifact_inputs"}:
                raise CapsuleError(
                    "capsule resume_packet project_state_basis is malformed")
            event_seq = basis.get("event_seq")
            artifacts = basis.get("artifact_inputs")
            if (isinstance(event_seq, bool) or not isinstance(event_seq, int)
                    or event_seq < 0
                    or not isinstance(basis.get("control_basis_digest"), str)
                    or _SHA256.fullmatch(
                        basis["control_basis_digest"]) is None
                    or not isinstance(artifacts, dict)
                    or any(
                        not _nonempty(path)
                        or not isinstance(digest, str)
                        or _SHA256.fullmatch(digest) is None
                        for path, digest in artifacts.items())):
                raise CapsuleError(
                    "capsule resume_packet project_state_basis is malformed")

        mission = packet.get("mission")
        authority = packet.get("authority")
        assumptions = packet.get("assumptions")
        open_work = packet.get("open_work")
        trust = packet.get("trust")
        lineage = packet.get("continuity_lineage")
        if (not isinstance(packet.get("target"), dict)
                or not isinstance(mission, dict)
                or set(mission) != {
                    "project", "objective", "target", "pinned_control_state",
                    "retired_control_state"}
                or not _nonempty(mission.get("project"))
                or not isinstance(mission.get("objective"), str)
                or not isinstance(mission.get("target"), dict)
                or not _summary_list(mission.get("pinned_control_state"))
                or not _summary_list(mission.get("retired_control_state"))):
            raise CapsuleError("capsule resume_packet mission shape is malformed")

        precedence = (
            authority.get("instruction_precedence")
            if isinstance(authority, dict) else None
        )
        if (not isinstance(authority, dict)
                or set(authority) != {
                    "instruction_precedence", "active_requirements",
                    "active_constraints"}
                or not _string_list(precedence)
                or len(precedence) != len(set(precedence))
                or not _summary_list(authority.get("active_requirements"))
                or not _summary_list(authority.get("active_constraints"))):
            raise CapsuleError("capsule resume_packet authority shape is malformed")

        if (not isinstance(assumptions, dict)
                or set(assumptions) != {"active", "uncertain"}
                or not _summary_list(assumptions.get("active"))
                or not _summary_list(assumptions.get("uncertain"))):
            raise CapsuleError("capsule resume_packet assumptions shape is malformed")

        next_safe = (
            open_work.get("next_safe_action")
            if isinstance(open_work, dict) else None
        )
        next_safe_valid = _summary(next_safe) or (
            isinstance(next_safe, dict)
            and set(next_safe) == {"summary"}
            and isinstance(next_safe.get("summary"), str)
        )
        if (not isinstance(open_work, dict)
                or set(open_work) != {"tasks", "blockers", "next_safe_action"}
                or not _summary_list(open_work.get("tasks"))
                or not _summary_list(open_work.get("blockers"))
                or not next_safe_valid):
            raise CapsuleError("capsule resume_packet open_work shape is malformed")

        summary_fields = ("accepted_decisions", "verified_progress")
        if any(not _summary_list(packet.get(field)) for field in summary_fields):
            raise CapsuleError(
                "capsule resume_packet decision/progress summaries are malformed")
        invalidations = packet.get("invalidations")
        if (not isinstance(invalidations, list)
                or any(not _invalidation(item) for item in invalidations)):
            raise CapsuleError("capsule resume_packet invalidations are malformed")
        evidence_index = packet.get("evidence_index")
        if (not isinstance(evidence_index, list)
                or any(not _evidence_index_item(item) for item in evidence_index)):
            raise CapsuleError("capsule resume_packet evidence_index is malformed")
        omissions = packet.get("omissions")
        if (not isinstance(omissions, list)
                or any(not isinstance(item, dict) for item in omissions)):
            raise CapsuleError("capsule resume_packet omissions are malformed")
        recent_context = packet.get("recent_context")
        if (not isinstance(recent_context, list)
                or any(not _recent_context_item(item) for item in recent_context)):
            raise CapsuleError("capsule resume_packet recent_context is malformed")
        environment = packet.get("environment")
        if not (
                isinstance(environment, dict)
                or isinstance(environment, list)
                and all(isinstance(item, dict) for item in environment)):
            raise CapsuleError(
                "capsule resume_packet environment must be an object or "
                "an array of objects")
        autonomy = trust.get("autonomy_level") if isinstance(trust, dict) else None
        if (not isinstance(trust, dict)
                or set(trust) != {
                    "autonomy_level", "required_verifiers", "completed_checks",
                    "failed_or_stale_checks", "gaps"}
                or autonomy is not None
                and (
                    isinstance(autonomy, bool)
                    or not isinstance(autonomy, int)
                    or not 0 <= autonomy <= 3
                )
                or not _string_list(trust.get("required_verifiers"))
                or not _summary_list(trust.get("completed_checks"))
                or not _summary_list(trust.get("failed_or_stale_checks"))
                or not _string_list(trust.get("gaps"))):
            raise CapsuleError("capsule resume_packet trust shape is malformed")
        if (not isinstance(lineage, dict)
                or set(lineage) != {
                    "source_session", "checkpoints", "packet_generation_time"}
                or lineage.get("source_session") is not None
                and not is_public_identifier(lineage.get("source_session"))
                or not isinstance(lineage.get("checkpoints"), list)
                or any(not is_public_identifier(item)
                       for item in lineage.get("checkpoints", []))
                or not _timestamp(lineage.get("packet_generation_time"))):
            raise CapsuleError(
                "capsule resume_packet continuity_lineage is malformed")
        coverage = packet.get("evidence_coverage")
        tokens = packet.get("token_estimate")
        if not _finite_probability(coverage):
            raise CapsuleError(
                "capsule resume_packet evidence_coverage must be finite "
                "and between zero and one")
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise CapsuleError(
                "capsule resume_packet token_estimate must be a non-negative integer")

        digest = packet.get("packet_digest")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise CapsuleError("capsule resume_packet packet_digest is malformed")
        unsigned = {
            key: value for key, value in packet.items()
            if key not in ("packet_digest", "signature")}
        try:
            expected = digest_obj(unsigned)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise CapsuleError(
                f"capsule resume_packet is not finite canonical JSON: {exc}") from None
        if digest != expected:
            raise CapsuleError(
                "capsule resume_packet digest mismatch: internal digest is inconsistent")
        if "signature" in packet:
            CapsuleManager._validate_signature_shape(
                packet["signature"], label="resume packet")

    # ----------------------------------------------------------------- export

    def _observable_state(self, tenant_id: str, project_id: str) -> dict:
        return {
            "active_assumptions": [
                {"node_id": n["node_id"],
                 "statement": n["data"].get("statement"),
                 "status": n["status"], "criticality": n["criticality"],
                 "confidence": n["confidence"]}
                for n in self.graph.current(
                    project_id, "assumption",
                    status=["active", "supported", "uncertain"],
                    tenant_id=tenant_id)
            ],
            "open_invalidations": [
                n["node_id"] for n in self.graph.current(
                    project_id, "invalidation",
                    status=["open", "pending_confirmation"],
                    tenant_id=tenant_id)
            ],
        }

    def export(
        self,
        *,
        tenant_id: str,
        project_id: str,
        session_id: str | None,
        source_model: str,
        source_runtime: str,
        target_adapter: str,
        signer,
        token_budget: int = 8000,
    ) -> dict:
        """Export one transaction-consistent, signed portable snapshot."""
        with self.store.transaction():
            return self._export_locked(
                tenant_id=tenant_id, project_id=project_id,
                session_id=session_id, source_model=source_model,
                source_runtime=source_runtime, target_adapter=target_adapter,
                signer=signer, token_budget=token_budget)

    def _export_locked(
        self,
        *,
        tenant_id: str,
        project_id: str,
        session_id: str | None,
        source_model: str,
        source_runtime: str,
        target_adapter: str,
        signer,
        token_budget: int = 8000,
    ) -> dict:
        source_model = _safe_capsule_text(
            source_model, field="capsule source model")
        source_runtime = _safe_capsule_text(
            source_runtime, field="capsule source runtime")
        target_adapter = _safe_capsule_text(
            target_adapter, field="capsule target adapter")
        self._require_project(tenant_id, project_id)
        if session_id is not None and not _nonempty(session_id):
            raise CapsuleError(
                "capsule source session must be a non-empty string when present")
        if session_id is not None:
            try:
                self.graph.get(
                    session_id, tenant_id=tenant_id, project_id=project_id,
                    entity_type="session")
            except KeyError:
                raise CapsuleError(
                    "capsule source session is not a session in the requested scope"
                ) from None
        packet = self.composer.compose(
            tenant_id=tenant_id, project_id=project_id,
            token_budget=token_budget, session_id=session_id,
            state_basis=self._state_basis(project_id),
        )
        body = {
            "schema_version": CAPSULE_SCHEMA,
            "capsule_id": new_id("capsule"),
            "created_at": utcnow(),
            "tenant_id": tenant_id,
            "project_id": project_id,
            "source": {
                "session_id": session_id,
                "model": source_model,
                "runtime": source_runtime,
            },
            "target": {"adapter": target_adapter},
            "resume_packet": packet,
            "observable_state": self._observable_state(
                tenant_id, project_id),
            "lineage": {
                "exported_from_session": session_id,
                "event_watermark": packet.get("project_state_at"),
            },
        }
        body = _strip_hidden(body)
        body["content_digest"] = digest_obj(
            {k: v for k, v in body.items() if k not in ("content_digest", "signature")})
        body["signature"] = signer.sign(body)
        self.store.audit(actor="cce", action="capsule.export",
                         object_id=body["capsule_id"],
                         detail=f"{source_model}/{source_runtime} -> {target_adapter}")
        return body

    # ----------------------------------------------------------------- import

    def validate(
            self, capsule: dict, signer, *, expected_tenant_id: str | None = None,
            expected_project_id: str | None = None) -> dict:
        """Schema + digest + signature validation. Raises CapsuleError on
        tampering; returns a validation report."""
        top_fields = {
            "schema_version", "capsule_id", "created_at", "tenant_id",
            "project_id", "source", "target", "resume_packet",
            "observable_state", "lineage", "content_digest", "signature",
        }
        if not isinstance(capsule, dict):
            raise CapsuleError("capsule must be an object")
        if capsule.get("schema_version") != CAPSULE_SCHEMA:
            raise CapsuleError(
                f"unsupported capsule schema {capsule.get('schema_version')!r}")
        if _contains_hidden(capsule):
            raise CapsuleError(
                "capsule contains hidden-reasoning fields forbidden by the portable schema")
        missing = top_fields - set(capsule)
        unknown = set(capsule) - top_fields
        if "signature" in missing:
            raise CapsuleError("capsule signature is missing")
        if missing or unknown:
            raise CapsuleError(
                f"capsule has missing or unknown top-level fields: "
                f"missing={sorted(missing)}, unknown={sorted(unknown)}")
        capsule_id = capsule.get("capsule_id")
        if (not isinstance(capsule_id, str)
                or _CAPSULE_ID.fullmatch(capsule_id) is None):
            raise CapsuleError("capsule_id is malformed")
        if not _timestamp(capsule.get("created_at")):
            raise CapsuleError("capsule created_at is malformed")
        tenant_id = capsule.get("tenant_id")
        project_id = capsule.get("project_id")
        if (not is_public_identifier(tenant_id)
                or not is_public_identifier(project_id)):
            raise CapsuleError(
                "capsule tenant_id and project_id are malformed identifiers")
        if expected_tenant_id is not None and tenant_id != expected_tenant_id:
            raise CapsuleError("capsule belongs to another tenant")
        if expected_project_id is not None and project_id != expected_project_id:
            raise CapsuleError("capsule belongs to another project")
        self._require_project(tenant_id, project_id)
        source = capsule.get("source")
        target = capsule.get("target")
        state = capsule.get("observable_state")
        lineage = capsule.get("lineage")
        if (not isinstance(source, dict)
                or set(source) != {"session_id", "model", "runtime"}
                or source.get("session_id") is not None
                and not is_public_identifier(source.get("session_id"))
                or not _nonempty(source.get("model"))
                or not _nonempty(source.get("runtime"))
                or not isinstance(target, dict)
                or set(target) != {"adapter"}
                or not _nonempty(target.get("adapter"))
                or not isinstance(state, dict)
                or set(state) != {"active_assumptions", "open_invalidations"}
                or not isinstance(state.get("active_assumptions"), list)
                or not isinstance(state.get("open_invalidations"), list)
                or not isinstance(lineage, dict)
                or set(lineage) != {"exported_from_session", "event_watermark"}
                or lineage.get("exported_from_session") !=
                source.get("session_id")):
            raise CapsuleError("capsule portable-state shape is malformed")
        self._validate_resume_packet(capsule.get("resume_packet"))
        if (lineage.get("event_watermark") is not None
                and not _nonempty(lineage.get("event_watermark"))):
            raise CapsuleError("capsule lineage event_watermark is malformed")
        if (
            lineage.get("event_watermark")
            != capsule["resume_packet"].get("project_state_at")
        ):
            raise CapsuleError(
                "capsule lineage event_watermark does not match resume_packet")
        assumption_fields = {
            "node_id", "statement", "status", "criticality", "confidence"}
        assumptions = state["active_assumptions"]
        if any(
                not isinstance(item, dict)
                or set(item) != assumption_fields
                or not is_public_identifier(item.get("node_id"))
                or item.get("statement") is not None
                and not isinstance(item.get("statement"), str)
                or not isinstance(item.get("status"), str)
                or item.get("status") not in {
                    "active", "supported", "uncertain"}
                or item.get("criticality") is not None
                and not _nonempty(item.get("criticality"))
                or item.get("confidence") is not None
                and not _finite_probability(item.get("confidence"))
                for item in assumptions):
            raise CapsuleError("capsule assumption state is malformed")
        assumption_ids = [item["node_id"] for item in assumptions]
        invalidation_ids = state["open_invalidations"]
        if len(set(assumption_ids)) != len(assumption_ids):
            raise CapsuleError("capsule assumption ids must be unique")
        if (any(not is_public_identifier(node_id)
                for node_id in invalidation_ids)
                or len(set(invalidation_ids)) != len(invalidation_ids)):
            raise CapsuleError(
                "capsule invalidation ids must be non-empty and unique")
        content_digest = capsule.get("content_digest")
        if (not isinstance(content_digest, str)
                or _SHA256.fullmatch(content_digest) is None):
            raise CapsuleError("capsule content_digest is malformed")
        self._validate_signature_shape(
            capsule.get("signature"), label="capsule")
        body = {k: v for k, v in capsule.items()
                if k not in ("content_digest", "signature")}
        try:
            expected = digest_obj(body)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise CapsuleError(
                f"capsule is not finite canonical JSON: {exc}") from None
        if content_digest != expected:
            raise CapsuleError("content digest mismatch: capsule was modified")
        # Import is a trust transition, so an absent trust root cannot turn
        # signature verification into an optional check. A content digest
        # detects accidental change; it authenticates no producer.
        if signer is None:
            raise CapsuleError("a trusted signer is required to import a capsule")
        if not self._authenticator_valid(capsule, signer):
            raise CapsuleError(
                "signature authenticity could not be established")
        return {"valid": True, "capsule_id": capsule["capsule_id"],
                "content_digest": expected}

    def challenge(self, capsule: dict) -> dict:
        """Deterministic challenge step (MIG-005): the importing runtime must
        confront uncertainty before acting. Autonomy above level 1 requires
        challenge.passed."""
        if not isinstance(capsule, dict):
            raise CapsuleError("capsule challenge input must be an object")
        packet = capsule.get("resume_packet")
        state = capsule.get("observable_state")
        self._validate_resume_packet(packet)
        if (not isinstance(state, dict)
                or set(state) != {
                    "active_assumptions", "open_invalidations"}
                or not isinstance(state.get("active_assumptions"), list)
                or not isinstance(state.get("open_invalidations"), list)):
            raise CapsuleError(
                "capsule challenge observable_state is malformed")
        assumption_fields = {
            "node_id", "statement", "status", "criticality", "confidence"}
        assumptions = state["active_assumptions"]
        if any(
                not isinstance(item, dict)
                or set(item) != assumption_fields
                or not is_public_identifier(item.get("node_id"))
                or item.get("statement") is not None
                and not isinstance(item.get("statement"), str)
                or not isinstance(item.get("status"), str)
                or item.get("status") not in {
                    "active", "supported", "uncertain"}
                or item.get("criticality") is not None
                and not _nonempty(item.get("criticality"))
                or item.get("confidence") is not None
                and not _finite_probability(item.get("confidence"))
                for item in assumptions):
            raise CapsuleError(
                "capsule challenge assumption state is malformed")
        assumption_ids = [item["node_id"] for item in assumptions]
        invalidation_ids = state["open_invalidations"]
        if len(set(assumption_ids)) != len(assumption_ids):
            raise CapsuleError(
                "capsule challenge assumption ids must be unique")
        if (any(not is_public_identifier(node_id)
                for node_id in invalidation_ids)
                or len(set(invalidation_ids)) != len(invalidation_ids)):
            raise CapsuleError(
                "capsule challenge invalidation ids must be non-empty and unique")
        uncertainties = []
        conflicts = []
        for a in assumptions:
            if a.get("status") == "uncertain":
                uncertainties.append({
                    "kind": "uncertain_assumption", "node_id": a["node_id"],
                    "statement": a.get("statement"),
                })
            else:
                confidence = a.get("confidence")
                # `0.0 or 1.0` used to turn the least-confident possible
                # assumption into certainty. Missing/non-numeric confidence
                # is unresolved too; absence of a measure is not a high one.
                if isinstance(confidence, bool) or not isinstance(
                        confidence, (int, float)):
                    uncertainties.append({
                        "kind": "missing_confidence_assumption",
                        "node_id": a["node_id"], "statement": a.get("statement"),
                    })
                elif confidence < 0.5:
                    uncertainties.append({
                        "kind": "low_confidence_assumption", "node_id": a["node_id"],
                        "statement": a.get("statement"),
                    })
        for inv in invalidation_ids:
            conflicts.append({"kind": "open_invalidation", "node_id": inv})
        gaps = packet.get("trust", {}).get("gaps", [])
        missing_env = packet.get("environment") in (None, {}, []) or (
            isinstance(packet.get("environment"), dict)
            and "note" in packet.get("environment", {}))
        questions = (
            [f"Assumption {u['node_id']} is uncertain: {u.get('statement')!r}."
             f" Confirm, narrow, or reject before relying on it."
             for u in uncertainties]
            + [f"Invalidation {c['node_id']} is open; its blast radius must be"
               f" reviewed before dependent work continues." for c in conflicts]
            + ([f"Required verifier(s) not yet passed: {', '.join(gaps)}."] if gaps else [])
            + (["No environment fingerprint present; re-derive the toolchain before"
                " executing anything."] if missing_env else [])
        )
        # Every item that produces a challenge question is a gate. Previously
        # uncertainty and a missing environment were reported to the reader
        # while `passed=True` granted unrestricted autonomy anyway.
        passed = not uncertainties and not conflicts and not gaps and not missing_env
        score = max(0.0, 1.0 - 0.15 * len(uncertainties) - 0.3 * len(conflicts)
                    - 0.2 * len(gaps) - (0.2 if missing_env else 0.0))
        return {
            "passed": passed,
            "migration_score": round(score, 3),
            "uncertainties": uncertainties,
            "conflicts": conflicts,
            "verifier_gaps": gaps,
            "environment_missing": missing_env,
            "questions": questions,
            "max_autonomy_until_resolved": 1 if not passed else None,
        }

    def _challenge_against_live_target(
            self, capsule: dict, tenant_id: str, project_id: str) -> dict:
        """Challenge the signed source state plus the current target state.

        A capsule authenticates what was exported; it does not freeze the
        target project. New invalidations and verifier gaps that appear after
        export must therefore participate in the migration gate.
        """
        source_session = capsule["source"].get("session_id")
        if source_session is not None:
            try:
                self.graph.get(
                    source_session, tenant_id=tenant_id,
                    project_id=project_id, entity_type="session")
            except KeyError:
                # A portable source id need not exist in the target graph.
                # Missing and foreign-scoped values are deliberately
                # equivalent and neither may become local packet lineage.
                source_session = None
        live_packet = self.composer.compose(
            tenant_id=tenant_id, project_id=project_id,
            token_budget=8000,
            session_id=source_session,
            state_basis=self._state_basis(project_id))
        source_packet = capsule.get("resume_packet") or {}
        # Presentation is budget-dependent: verified/open-work detail and
        # environment lists may be shortened without the project changing.
        # The embedded state basis commits the complete semantic control
        # surface before rendering, so it is the only sound drift comparator.
        source_basis = source_packet.get("project_state_basis")
        target_basis = live_packet.get("project_state_basis")
        source_control_digest = (
            source_basis.get("control_basis_digest")
            if isinstance(source_basis, dict) else None)
        target_control_digest = (
            target_basis.get("control_basis_digest")
            if isinstance(target_basis, dict) else None)
        source_watermark = (
            capsule.get("lineage") or {}).get("event_watermark")
        target_watermark = live_packet.get("project_state_at")
        source_gaps = (source_packet.get("trust") or {}).get("gaps") or []
        live_trust = live_packet.setdefault("trust", {})
        live_gaps = live_trust.get("gaps") or []
        live_trust["gaps"] = sorted(set(source_gaps) | set(live_gaps))
        live_packet["packet_digest"] = digest_obj({
            key: value for key, value in live_packet.items()
            if key not in ("signature", "packet_digest")})
        source_omissions = copy.deepcopy(source_packet.get("omissions") or [])
        target_omissions = copy.deepcopy(live_packet.get("omissions") or [])

        source_state = capsule["observable_state"]
        live_state = self._observable_state(tenant_id, project_id)
        assumptions = {
            item["node_id"]: copy.deepcopy(item)
            for item in source_state["active_assumptions"]}
        # Current state wins for the same stable node id; source-only state is
        # retained so migration cannot erase a warning by omission.
        assumptions.update({
            item["node_id"]: item
            for item in live_state["active_assumptions"]})
        challenge_input = {
            "resume_packet": live_packet,
            "observable_state": {
                "active_assumptions": [
                    assumptions[node_id] for node_id in sorted(assumptions)],
                "open_invalidations": sorted(set(
                    source_state["open_invalidations"])
                    | set(live_state["open_invalidations"])),
            },
        }
        result = self.challenge(challenge_input)
        drift = []
        if source_watermark != target_watermark:
            drift.append({
                "kind": "target_event_frontier_changed",
                "node_id": project_id,
                "source": source_watermark,
                "target": target_watermark,
            })
        if source_basis != target_basis:
            drift.append({
                "kind": "target_control_state_changed",
                "node_id": project_id,
                "source_digest": source_control_digest,
                "target_digest": target_control_digest,
            })
        if drift:
            result["conflicts"].extend(drift)
            result["questions"].append(
                "The target project changed after capsule export. Review the "
                "new event frontier and control state before restoring autonomy.")
            result["passed"] = False
            result["migration_score"] = round(max(
                0.0, result["migration_score"] - 0.3 * len(drift)), 3)
            result["max_autonomy_until_resolved"] = 1
        result["control_drift"] = drift
        result["live_state_reconciled"] = True
        result["source_event_watermark"] = source_watermark
        result["target_event_watermark"] = target_watermark
        result["source_control_digest"] = source_control_digest
        result["target_control_digest"] = target_control_digest
        # Source warnings remain visible even when a fresh target rendering
        # has a larger budget.  Keep provenance separate while the challenge
        # itself operates on the conservative union of verifier gaps and
        # observable uncertainty above.
        result["source_verifier_gaps"] = sorted(set(source_gaps))
        result["target_verifier_gaps"] = sorted(set(live_gaps))
        result["source_packet_omissions"] = source_omissions
        result["target_packet_omissions"] = target_omissions
        return result

    def import_capsule(
        self,
        capsule: dict,
        *,
        signer,
        target_model: str,
        target_runtime: str,
        actor: str = "cce",
        expected_tenant_id: str | None = None,
        expected_project_id: str | None = None,
    ) -> dict:
        """Validate, challenge, and create the migrated session with lineage
        (MIG-004). Returns {session, challenge, validation}."""
        target_model = _safe_capsule_text(
            target_model, field="capsule target model")
        target_runtime = _safe_capsule_text(
            target_runtime, field="capsule target runtime")
        actor = _safe_capsule_text(actor, field="capsule import actor")
        validation = self.validate(
            capsule, signer, expected_tenant_id=expected_tenant_id,
            expected_project_id=expected_project_id)
        tenant_id = capsule["tenant_id"]
        project_id = capsule["project_id"]
        # Fresh target challenge, session, lineage, enforced downgrade, and
        # audit are one snapshot/write unit. A concurrent invalidation cannot
        # land between the migration gate and the session it authorizes.
        with self.store.transaction():
            challenge = self._challenge_against_live_target(
                capsule, tenant_id, project_id)
            source_session = capsule["source"].get("session_id")
            if source_session:
                try:
                    self.graph.get(
                        source_session, tenant_id=tenant_id,
                        project_id=project_id, entity_type="session")
                except KeyError:
                    # A portable source id need not exist in the target graph.
                    # Never probe globally: doing so distinguishes a foreign
                    # session from an absent one and turns import into a scope
                    # oracle. Both mean that no local lineage edge can be made.
                    source_session = None
            session = self.graph.put_node(
                entity_type="session", tenant_id=tenant_id,
                project_id=project_id, status="active",
                data={
                    "model": target_model, "runtime": target_runtime,
                    "started_at": utcnow(),
                    "migrated_from_capsule": capsule["capsule_id"],
                    "source_model": capsule["source"].get("model"),
                    "source_runtime": capsule["source"].get("runtime"),
                    "challenge": challenge,
                },
            )
            if source_session:
                self.graph.put_edge(
                    edge_type="migrated_from", src_id=session.id,
                    dst_id=source_session, tenant_id=tenant_id,
                    project_id=project_id,
                )
            # AUT-005/MIG-005: the challenge is a real gate, not a report.
            if not challenge["passed"] and self.policy is not None:
                self.policy.downgrade(
                    project_id, "migration",
                    ceiling=challenge["max_autonomy_until_resolved"] or 1,
                    actor=actor)
                challenge["enforced_ceiling"] = \
                    self.policy.active_downgrade_ceiling(project_id)
            self.store.audit(
                actor=actor, action="capsule.import",
                object_id=capsule["capsule_id"],
                detail=f"-> {target_model}/{target_runtime}"
                       f" challenge_passed={challenge['passed']}")
        return {"session": session, "challenge": challenge, "validation": validation}
