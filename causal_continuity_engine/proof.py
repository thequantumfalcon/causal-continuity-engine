"""Proof-carrying actions (PA-001..PA-006, EV-005).

A proof envelope links intent, inputs, environment, execution, verification,
policy, and continuity lineage for one action claim, digest-addressed and
signed. Missing/skipped/failed/inconclusive verification is represented
truthfully and never treated as success (PA-005). Envelopes can be exported
as in-toto-compatible statements and re-imported without loss (PA-006).
"""

from __future__ import annotations

import math
import re
from datetime import datetime

from .core import (
    canonical_json,
    digest_obj,
    is_public_identifier,
    new_id,
    strict_json_loads,
    utcnow,
    validate_human_text,
    validate_public_identifier,
)

PROOF_SCHEMA = "cce.proof.v1"
INTOTO_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/thequantumfalcon/"
    "causal-continuity-engine/v0.1.0/schemas/cce.proof-predicate.v1.json"
)

FINAL_STATUSES = {"verified", "failed", "incomplete", "inconclusive", "stale", "invalid"}

_PROOF_STATUSES = FINAL_STATUSES | {"draft"}
_VERIFICATION_RESULTS = {
    "passed", "failed", "skipped", "missing", "inconclusive", "stale",
}
_REQUIRED_FIELDS = {
    "schema_version", "proof_id", "created_at", "tenant_id", "project_id",
    "action_id",
    "subject", "action_intent", "actor", "inputs", "environment", "execution",
    "verifications", "policy_decision", "continuity_links", "evidence_context",
    "status", "verification_summary", "proof_digest", "signature",
}
_PROOF_ID = re.compile(r"prf_[0-9a-f]{24}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CANONICAL_CREATED_AT = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{6}Z\Z")
_ACTION_INTENT_FIELDS = {"type", "statement", "requirement_ids"}
_SUBJECT_FIELDS = {"name", "digest"}
_INPUT_FIELDS = {"name", "digest", "kind"}
_SUMMARY_FIELDS = {
    "unbacked_self_assertions", "required", "missing", "failed",
    "inconclusive", "skipped", "passed",
}
_EXECUTION_FIELDS = {
    "tool", "command_digest", "exit_code", "started_at", "output_digest",
}
_VERIFICATION_FIELDS = {
    "source", "pinned", "command_digest", "definition_digest", "verifier",
    "kind", "result", "started_at", "duration_seconds", "exit_code",
    "output_digest", "evidence_digest", "coverage", "control", "observed",
    "details", "network",
}
_CONTROL_FIELDS = {"command_present", "status", "exit_code", "details"}
_POLICY_DECISION_FIELDS = {
    "decision", "reason", "action_type", "required_level", "effective_level",
    "action_scope", "applicable_grant_ids", "reasons", "policy_config",
    "decided_at", "action_scopes", "scope_decisions",
}
_CONTINUITY_FIELDS = {
    "task_ids", "requirement_ids", "decision_ids", "assumption_ids",
    "artifact_ids", "evidence_ids", "action_ids", "proof_node_id",
}
_EVIDENCE_CONTEXT_FIELDS = {
    "unpinned_required", "policy_pinned", "mutation", "determinism",
}
_VERIFICATION_SOURCES = {
    "executed", "verifier_authoritative", "self_asserted",
}
_CONTROL_STATUSES = {"held", "unmet", "absent", "inconclusive"}
_SIGNATURE_FIELDS = {
    "key_id", "algorithm", "value", "fingerprint", "public_key",
}

# Fail-closed precedence when one verifier reports more than once (a retry, or
# a caller-supplied history). The WORST result stands: a recorded failure is
# evidence that the property did not hold, and a later green run does not
# retract it (PA-005). Re-attest for a clean claim instead.
_RESULT_SEVERITY = {
    "failed": 0, "inconclusive": 1, "stale": 1,
    "missing": 2, "skipped": 3, "passed": 4,
}


def _worst(results: list[str]) -> str:
    return min(results, key=lambda r: _RESULT_SEVERITY.get(r, 0))


def _is_canonical_created_at(value: str) -> bool:
    """Whether value is CCE's one canonical RFC-3339 UTC representation."""
    if not _CANONICAL_CREATED_AT.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


# Only results CCE observed itself, or that came from an authoritative
# external verifier (a GitHub check run), can satisfy a REQUIRED verifier.
# An agent asserting "tests passed" with no execution behind it is the
# misleading-success-claim case the trust layer exists to reject: it is
# recorded truthfully in the envelope, but it satisfies nothing.
AUTHORITATIVE_SOURCES = {"executed", "verifier_authoritative"}
SELF_ASSERTED = "self_asserted"


class ProofEnvelope:
    """Builder + evaluator for one action claim."""

    def __init__(
        self,
        *,
        tenant_id: str,
        project_id: str,
        action_id: str | None = None,
        intent_type: str,
        intent_statement: str,
        actor: dict,
        requirement_ids: list[str] | None = None,
    ):
        tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        project_id = validate_public_identifier(project_id, field="project_id")
        action_id = (
            new_id("action") if action_id is None
            else validate_public_identifier(action_id, field="action_id")
        )
        validate_human_text(intent_type, field="intent_type")
        if not isinstance(intent_statement, str):
            raise ValueError("intent_statement must be a string")
        if not isinstance(actor, dict):
            raise ValueError("actor must be an object")
        try:
            canonical_json({"statement": intent_statement, "actor": actor})
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"intent_statement and actor must be finite canonical JSON: {exc}"
            ) from None
        requirement_ids = [] if requirement_ids is None else requirement_ids
        if not isinstance(requirement_ids, list):
            raise ValueError("requirement_ids must be an array of identifiers")
        requirement_ids = [
            validate_public_identifier(value, field="requirement_id")
            for value in requirement_ids
        ]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("requirement_ids must not contain duplicates")
        self.body = {
            "schema_version": PROOF_SCHEMA,
            "proof_id": new_id("proof"),
            "created_at": utcnow(),
            "tenant_id": tenant_id,
            "project_id": project_id,
            "action_id": action_id,
            "subject": [],
            "action_intent": {
                "type": intent_type,
                "statement": intent_statement,
                "requirement_ids": requirement_ids,
            },
            "actor": actor,
            "inputs": [],
            "environment": {},
            "execution": [],
            "verifications": [],
            # A standalone builder has not passed through PolicyEngine.  Say
            # that explicitly instead of emitting a value that violates the
            # public proof schema.  Engine.attest_action replaces this with
            # the actual allow/deny record before finalization.
            "policy_decision": {
                "decision": "deny",
                "reason": "proof constructed outside the policy engine",
            },
            "continuity_links": {},
            "evidence_context": {},
            "status": "draft",
        }

    def _preflight_candidate(
        self,
        *,
        update_field: str | None = None,
        update_value: object = None,
        required_verifiers: list[str] | None = None,
    ) -> dict:
        """Return one normalized, structurally valid candidate envelope.

        Builder methods use the same whole-envelope check as ``finalize`` so
        malformed nested values are rejected atomically at the public
        mutation boundary.  The synthetic signature exists only to exercise
        the public envelope shape before any signing implementation is called.
        """
        draft = dict(self.body)
        if update_field is not None:
            draft[update_field] = update_value
        try:
            candidate = strict_json_loads(canonical_json(draft))
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"proof draft must be finite canonical JSON: {exc}") from None
        try:
            status, summary = evaluate_status(
                candidate.get("verifications"), required_verifiers)
        except ValueError as exc:
            raise ValueError(f"proof draft is invalid: {exc}") from None
        candidate["status"] = status
        candidate["verification_summary"] = summary
        candidate["proof_digest"] = digest_obj({
            key: value for key, value in candidate.items()
            if key not in ("signature", "proof_digest")
        })
        candidate["signature"] = {
            "key_id": "preflight",
            "algorithm": "preflight",
            "value": "preflight",
        }
        errors = validate_envelope_shape(candidate)
        if errors:
            raise ValueError("proof draft is invalid: " + "; ".join(errors))
        return candidate

    def _apply_validated_update(self, field: str, value: object):
        candidate = self._preflight_candidate(
            update_field=field, update_value=value)
        candidate["status"] = "draft"
        candidate.pop("verification_summary", None)
        candidate.pop("proof_digest", None)
        candidate.pop("signature", None)
        self.body = candidate
        return self

    def add_subject(self, name: str, digest: str):
        validate_human_text(name, field="subject name")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ValueError("subject digest must be a sha256 content address")
        subjects = list(self.body.get("subject", []))
        subjects.append({"name": name, "digest": digest})
        return self._apply_validated_update("subject", subjects)

    def add_input(self, name: str, digest: str, kind: str = "artifact"):
        validate_human_text(name, field="input name")
        validate_human_text(kind, field="input kind")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ValueError("input digest must be a sha256 content address")
        inputs = list(self.body.get("inputs", []))
        inputs.append({"name": name, "digest": digest, "kind": kind})
        return self._apply_validated_update("inputs", inputs)

    def set_environment(self, **env):
        current = self.body.get("environment")
        if not isinstance(current, dict):
            raise ValueError("proof draft environment must be an object")
        environment = dict(current)
        environment.update(env)
        return self._apply_validated_update("environment", environment)

    def add_execution(self, *, tool: str, command_digest: str | None = None,
                      exit_code: int | None = None, started_at: str | None = None,
                      output_digest: str | None = None):
        validate_human_text(tool, field="execution tool")
        executions = list(self.body.get("execution", []))
        executions.append({
            "tool": tool, "command_digest": command_digest, "exit_code": exit_code,
            "started_at": utcnow() if started_at is None else started_at,
            "output_digest": output_digest,
        })
        return self._apply_validated_update("execution", executions)

    def add_verification(self, outcome: dict):
        outcomes = list(self.body.get("verifications", []))
        outcomes.append(outcome)
        return self._apply_validated_update("verifications", outcomes)

    def set_policy_decision(self, decision: dict):
        return self._apply_validated_update("policy_decision", decision)

    def set_continuity(self, **links):
        current = self.body.get("continuity_links")
        if not isinstance(current, dict):
            raise ValueError("proof draft continuity_links must be an object")
        continuity = dict(current)
        continuity.update(links)
        return self._apply_validated_update("continuity_links", continuity)

    def set_evidence_context(self, **context):
        """Signed record of how the evidence was obtained: which required
        verifiers the policy pinned, and which the claimant chose."""
        current = self.body.get("evidence_context")
        if not isinstance(current, dict):
            raise ValueError("proof draft evidence_context must be an object")
        evidence_context = dict(current)
        evidence_context.update(context)
        return self._apply_validated_update(
            "evidence_context", evidence_context)

    # --------------------------------------------------------------- finalize

    def finalize(self, signer, required_verifiers: list[str] | None = None) -> dict:
        """Evaluate and shape-check the complete proof before signing it."""
        candidate = self._preflight_candidate(
            required_verifiers=required_verifiers)
        try:
            signable = strict_json_loads(canonical_json(candidate))
            candidate["signature"] = signer.sign(signable)
            candidate = strict_json_loads(canonical_json(candidate))
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(
                f"signer returned a non-canonical signature: {exc}") from None
        errors = validate_envelope_shape(candidate)
        if errors:
            raise ValueError(
                "signed proof is invalid: " + "; ".join(errors))
        self.body = candidate
        return strict_json_loads(canonical_json(candidate))


def evaluate_status(verifications: list[dict],
                    required_verifiers: list[str] | None = None
                    ) -> tuple[str, dict]:
    """Recompute status from verification results alone (PA-005, SPEC §7).

    verified     — every required verifier ran and passed
    failed       — any required verifier failed
    inconclusive — no failure, but a required verifier was inconclusive
    incomplete   — a required verifier is missing or skipped

    Separate from finalize() so a holder of an envelope can ask whether its
    recorded status follows from its own contents without signing anything.
    finalize() remains the only writer; this is the only rule.
    """
    if not isinstance(verifications, list) or any(
            not isinstance(value, dict) for value in verifications):
        raise ValueError("verifications must be an array of objects")
    required_values = (
        [] if required_verifiers is None else required_verifiers)
    if (not isinstance(required_values, list)
            or any(not isinstance(name, str) or not name.strip()
                   for name in required_values)):
        raise ValueError(
            "required_verifiers must be an array of non-empty strings")
    required = set(required_values)
    by_verifier: dict[str, list[str]] = {}
    self_asserted: set[str] = set()
    for v in verifications:
        name = v.get("verifier")
        result = v.get("result")
        source = v.get("source", SELF_ASSERTED)
        if not isinstance(name, str) or not name.strip():
            raise ValueError("verification verifier must be a non-empty string")
        if result not in _VERIFICATION_RESULTS:
            raise ValueError(f"unknown verification result {result!r}")
        if source not in _VERIFICATION_SOURCES:
            raise ValueError(f"unknown verification source {source!r}")
        if source in AUTHORITATIVE_SOURCES:
            by_verifier.setdefault(name, []).append(result)
        else:
            self_asserted.add(name)
    results = {name: _worst(rs) for name, rs in by_verifier.items()}
    # A self-assertion is preserved in the body but is not an observation. It
    # can neither satisfy a missing verifier nor poison an authoritative pass
    # under the same display name (a cheap denial-of-service against proof).
    unbacked = sorted(
        name for name in required
        if name in self_asserted and name not in results)
    missing = sorted({r for r in required if r not in results}
                     | {n for n, r in results.items()
                        if r == "missing" and n in required})
    failed = sorted(n for n, r in results.items() if r == "failed"
                    and (not required or n in required))
    inconclusive = sorted(
        n for n, r in results.items() if r in ("inconclusive", "stale")
        and (not required or n in required))
    skipped = sorted(
        n for n, r in results.items() if r == "skipped" and n in required)
    backed_pass = sorted(n for n, r in results.items() if r == "passed")
    if failed:
        status = "failed"
    elif missing or skipped:
        status = "incomplete"
    elif inconclusive:
        status = "inconclusive"
    elif required and all(results.get(r) == "passed" for r in required):
        status = "verified"
    elif not required and backed_pass and \
            all(r == "passed" for r in results.values()):
        # No declared requirement set: still needs at least one result CCE
        # actually observed. An envelope of pure self-assertion is not proof.
        status = "verified"
    else:
        status = "incomplete"
    return status, {
        "unbacked_self_assertions": unbacked,
        "required": sorted(required), "missing": missing, "failed": failed,
        "inconclusive": inconclusive, "skipped": skipped,
        "passed": backed_pass,
    }


def validate_envelope_shape(envelope: object) -> list[str]:
    """Validate the security-relevant cce.proof.v1 structure with stdlib only.

    Cryptographic validity and structural validity are separate properties.
    Signing a dictionary with no proof id, intent, or policy record does not
    manufacture those semantics.  This mirrors the shipped JSON Schema while
    keeping the runtime dependency-free and returning every useful defect to
    callers rather than stopping at the first missing key.
    """
    if not isinstance(envelope, dict):
        return ["envelope must be an object"]

    errors: list[str] = []
    missing = sorted(_REQUIRED_FIELDS - set(envelope))
    errors.extend(f"missing required field {name!r}" for name in missing)
    unknown = sorted(set(envelope) - _REQUIRED_FIELDS)
    if unknown:
        errors.append(f"unknown top-level field(s): {unknown}")

    if envelope.get("schema_version") != PROOF_SCHEMA:
        errors.append(f"schema_version must be {PROOF_SCHEMA!r}")

    for name in ("proof_id", "tenant_id", "project_id", "action_id",
                 "created_at"):
        value = envelope.get(name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{name} must be a non-empty string")
    for name in ("tenant_id", "project_id", "action_id"):
        if not is_public_identifier(envelope.get(name)):
            errors.append(f"{name} must be a public resource identifier")
    proof_id = envelope.get("proof_id")
    if isinstance(proof_id, str) and not _PROOF_ID.fullmatch(proof_id):
        errors.append("proof_id must be 'prf_' followed by 24 lowercase hex digits")
    created_at = envelope.get("created_at")
    if (isinstance(created_at, str) and created_at.strip()
            and not _is_canonical_created_at(created_at)):
        errors.append(
            "created_at must be a valid UTC timestamp in canonical "
            "YYYY-MM-DDTHH:MM:SS.ffffffZ form")

    status = envelope.get("status")
    if not isinstance(status, str) or status not in _PROOF_STATUSES:
        errors.append(f"status {status!r} is not a cce.proof.v1 status")

    for name in ("subject", "inputs", "execution", "verifications"):
        if not isinstance(envelope.get(name), list):
            errors.append(f"{name} must be an array")
    for name in ("actor", "environment", "policy_decision",
                 "continuity_links", "evidence_context",
                 "verification_summary", "signature"):
        if not isinstance(envelope.get(name), dict):
            errors.append(f"{name} must be an object")

    intent = envelope.get("action_intent")
    if not isinstance(intent, dict):
        errors.append("action_intent must be an object")
    else:
        missing_intent = sorted(_ACTION_INTENT_FIELDS - set(intent))
        unknown_intent = sorted(set(intent) - _ACTION_INTENT_FIELDS)
        if missing_intent:
            errors.append(
                f"action_intent missing field(s): {missing_intent}")
        if unknown_intent:
            errors.append(
                f"action_intent has unknown field(s): {unknown_intent}")
        if not isinstance(intent.get("type"), str) or not intent["type"].strip():
            errors.append("action_intent.type must be a non-empty string")
        if not isinstance(intent.get("statement"), str):
            errors.append("action_intent.statement must be a string")
        requirements = intent.get("requirement_ids")
        if not isinstance(requirements, list) or not all(
                isinstance(item, str) for item in requirements):
            errors.append("action_intent.requirement_ids must be an array of strings")
        elif not all(is_public_identifier(item) for item in requirements):
            errors.append(
                "action_intent.requirement_ids must contain public identifiers")

    policy = envelope.get("policy_decision")
    if isinstance(policy, dict):
        unknown_policy = sorted(set(policy) - _POLICY_DECISION_FIELDS)
        if unknown_policy:
            errors.append(
                f"policy_decision has unknown field(s): {unknown_policy}")
        decision = policy.get("decision")
        if not isinstance(decision, str) or decision not in {"allow", "deny"}:
            errors.append("policy_decision.decision must be 'allow' or 'deny'")
        for field in ("action_type", "reason", "decided_at"):
            if field in policy and not isinstance(policy[field], str):
                errors.append(f"policy_decision.{field} must be a string")
        for field in ("required_level", "effective_level"):
            if field in policy and (
                    isinstance(policy[field], bool)
                    or not isinstance(policy[field], int)):
                errors.append(f"policy_decision.{field} must be an integer")
        if "action_scope" in policy and policy["action_scope"] is not None and \
                not isinstance(policy["action_scope"], str):
            errors.append("policy_decision.action_scope must be a string or null")
        for field in ("applicable_grant_ids", "reasons", "action_scopes"):
            if field in policy and (
                    not isinstance(policy[field], list)
                    or not all(isinstance(value, str) for value in policy[field])):
                errors.append(
                    f"policy_decision.{field} must be an array of strings")
        for field in ("policy_config",):
            if field in policy and not isinstance(policy[field], dict):
                errors.append(f"policy_decision.{field} must be an object")
        if "scope_decisions" in policy and (
                not isinstance(policy["scope_decisions"], list)
                or not all(isinstance(value, dict)
                           for value in policy["scope_decisions"])):
            errors.append("policy_decision.scope_decisions must be an array of objects")

    subjects = envelope.get("subject")
    if isinstance(subjects, list):
        for index, subject in enumerate(subjects):
            if not isinstance(subject, dict):
                errors.append(f"subject[{index}] must be an object")
                continue
            if set(subject) != _SUBJECT_FIELDS:
                errors.append(
                    f"subject[{index}] must contain exactly name and digest")
            if (not isinstance(subject.get("name"), str)
                    or not subject.get("name", "").strip()):
                errors.append(f"subject[{index}].name must be a non-empty string")
            if not isinstance(subject.get("digest"), str) or not _DIGEST.fullmatch(
                    subject.get("digest", "")):
                errors.append(f"subject[{index}].digest must be a sha256 digest")

    inputs = envelope.get("inputs")
    if isinstance(inputs, list):
        for index, item in enumerate(inputs):
            if not isinstance(item, dict):
                errors.append(f"inputs[{index}] must be an object")
                continue
            if set(item) != _INPUT_FIELDS:
                errors.append(
                    f"inputs[{index}] must contain exactly name, digest and kind")
            for field in ("name", "kind"):
                if (not isinstance(item.get(field), str)
                        or not item.get(field, "").strip()):
                    errors.append(
                        f"inputs[{index}].{field} must be a non-empty string")
            if not isinstance(item.get("digest"), str) or not _DIGEST.fullmatch(
                    item.get("digest", "")):
                errors.append(f"inputs[{index}].digest must be a sha256 digest")

    execution = envelope.get("execution")
    if isinstance(execution, list):
        for index, item in enumerate(execution):
            if not isinstance(item, dict):
                errors.append(f"execution[{index}] must be an object")
                continue
            if set(item) != _EXECUTION_FIELDS:
                errors.append(
                    f"execution[{index}] must contain exactly "
                    f"{sorted(_EXECUTION_FIELDS)}")
            if not isinstance(item.get("tool"), str) or not item.get("tool", "").strip():
                errors.append(f"execution[{index}].tool must be a non-empty string")
            if not isinstance(item.get("started_at"), str) or not item.get(
                    "started_at", "").strip():
                errors.append(
                    f"execution[{index}].started_at must be a non-empty string")
            for field in ("command_digest", "output_digest"):
                value = item.get(field)
                if value is not None and (
                        not isinstance(value, str) or not _DIGEST.fullmatch(value)):
                    errors.append(
                        f"execution[{index}].{field} must be a sha256 digest or null")
            if item.get("exit_code") is not None and (
                    isinstance(item.get("exit_code"), bool)
                    or not isinstance(item.get("exit_code"), int)):
                errors.append(
                    f"execution[{index}].exit_code must be an integer or null")

    verifications = envelope.get("verifications")
    if isinstance(verifications, list):
        for index, outcome in enumerate(verifications):
            if not isinstance(outcome, dict):
                errors.append(f"verifications[{index}] must be an object")
                continue
            unknown_outcome = sorted(set(outcome) - _VERIFICATION_FIELDS)
            if unknown_outcome:
                errors.append(
                    f"verifications[{index}] has unknown field(s): "
                    f"{unknown_outcome}")
            if (not isinstance(outcome.get("verifier"), str)
                    or not outcome.get("verifier", "").strip()):
                errors.append(
                    f"verifications[{index}].verifier must be a non-empty string")
            result = outcome.get("result")
            if (not isinstance(result, str)
                    or result not in _VERIFICATION_RESULTS):
                errors.append(
                    f"verifications[{index}].result is not recognized")
            source = outcome.get("source", SELF_ASSERTED)
            if (not isinstance(source, str)
                    or source not in _VERIFICATION_SOURCES):
                errors.append(f"verifications[{index}].source is not recognized")
            if "pinned" in outcome and not isinstance(outcome["pinned"], bool):
                errors.append(f"verifications[{index}].pinned must be a boolean")
            for field in ("command_digest", "definition_digest",
                          "output_digest", "evidence_digest"):
                value = outcome.get(field)
                if field in outcome and value is not None and (
                        not isinstance(value, str) or not _DIGEST.fullmatch(value)):
                    errors.append(
                        f"verifications[{index}].{field} must be a sha256 "
                        f"digest or null")
            control = outcome.get("control")
            if "control" in outcome and control is not None:
                if not isinstance(control, dict):
                    errors.append(
                        f"verifications[{index}].control must be an object or null")
                elif (not isinstance(control.get("status"), str)
                      or control.get("status") not in _CONTROL_STATUSES):
                    errors.append(
                        f"verifications[{index}].control.status is not recognized")
                elif set(control) != _CONTROL_FIELDS:
                    errors.append(
                        f"verifications[{index}].control must contain exactly "
                        f"{sorted(_CONTROL_FIELDS)}")
                else:
                    if not isinstance(control["command_present"], bool):
                        errors.append(
                            f"verifications[{index}].control.command_present "
                            f"must be a boolean")
                    if (control["exit_code"] is not None and (
                            isinstance(control["exit_code"], bool)
                            or not isinstance(control["exit_code"], int))):
                        errors.append(
                            f"verifications[{index}].control.exit_code must be "
                            f"an integer or null")
                    if not isinstance(control["details"], str):
                        errors.append(
                            f"verifications[{index}].control.details must be a string")
            for field in ("coverage", "observed"):
                value = outcome.get(field)
                if field in outcome and value is not None and not isinstance(value, dict):
                    errors.append(
                        f"verifications[{index}].{field} must be an object or null")
            if "duration_seconds" in outcome:
                duration = outcome["duration_seconds"]
                if (isinstance(duration, bool)
                        or not isinstance(duration, (int, float))
                        or not math.isfinite(duration) or duration < 0):
                    errors.append(
                        f"verifications[{index}].duration_seconds must be a "
                        f"finite non-negative number")
            if "exit_code" in outcome and outcome["exit_code"] is not None and (
                    isinstance(outcome["exit_code"], bool)
                    or not isinstance(outcome["exit_code"], int)):
                errors.append(
                    f"verifications[{index}].exit_code must be an integer or null")
            for field in ("kind", "started_at", "details", "network"):
                if field in outcome and not isinstance(outcome[field], str):
                    errors.append(
                        f"verifications[{index}].{field} must be a string")

    links = envelope.get("continuity_links")
    if isinstance(links, dict):
        unknown_links = sorted(set(links) - _CONTINUITY_FIELDS)
        if unknown_links:
            errors.append(
                f"continuity_links has unknown field(s): {unknown_links}")
        for field, value in links.items():
            if field == "proof_node_id":
                if not is_public_identifier(value):
                    errors.append(
                        "continuity_links.proof_node_id must be a public identifier")
            elif not isinstance(value, list) or not all(
                    is_public_identifier(node_id) for node_id in value):
                errors.append(
                    f"continuity_links.{field} must be an array of public identifiers")

    context = envelope.get("evidence_context")
    if isinstance(context, dict):
        unknown_context = sorted(set(context) - _EVIDENCE_CONTEXT_FIELDS)
        if unknown_context:
            errors.append(
                f"evidence_context has unknown field(s): {unknown_context}")
        for field in ("unpinned_required", "policy_pinned"):
            if field in context and (
                    not isinstance(context[field], list)
                    or not all(isinstance(value, str) for value in context[field])):
                errors.append(
                    f"evidence_context.{field} must be an array of strings")
        if "mutation" in context and context["mutation"] is not None and \
                not isinstance(context["mutation"], dict):
            errors.append("evidence_context.mutation must be an object or null")
        if "determinism" in context and not isinstance(context["determinism"], dict):
            errors.append("evidence_context.determinism must be an object")

    digest = envelope.get("proof_digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        errors.append("proof_digest must be a sha256 content address")

    signature = envelope.get("signature")
    if isinstance(signature, dict):
        missing_signature = sorted({"key_id", "algorithm", "value"} - set(signature))
        unknown_signature = sorted(set(signature) - _SIGNATURE_FIELDS)
        if missing_signature:
            errors.append(f"signature missing field(s): {missing_signature}")
        if unknown_signature:
            errors.append(f"signature has unknown field(s): {unknown_signature}")
        algorithm = signature.get("algorithm")
        if not isinstance(algorithm, str) or not algorithm.strip():
            errors.append("signature.algorithm must be a non-empty string")
        value = signature.get("value")
        if not (
                isinstance(value, str) and value
                or isinstance(value, list) and value):
            errors.append("signature.value must be a non-empty string or array")
        if (not isinstance(signature.get("key_id"), str)
                or not signature.get("key_id", "").strip()):
            errors.append("signature.key_id must be a non-empty string")
        fingerprint = signature.get("fingerprint")
        if "fingerprint" in signature and (
                not isinstance(fingerprint, str)
                or not _DIGEST.fullmatch(fingerprint)):
            errors.append("signature.fingerprint must be a sha256 digest")
        if "public_key" in signature and not isinstance(
                signature["public_key"], list):
            errors.append("signature.public_key must be an array")

    summary = envelope.get("verification_summary")
    if isinstance(summary, dict):
        missing_summary = sorted(_SUMMARY_FIELDS - set(summary))
        unknown_summary = sorted(set(summary) - _SUMMARY_FIELDS)
        if missing_summary:
            errors.append(
                f"verification_summary missing field(s): {missing_summary}")
        if unknown_summary:
            errors.append(
                f"verification_summary has unknown field(s): {unknown_summary}")
        for field in sorted(_SUMMARY_FIELDS):
            value = summary.get(field)
            if not isinstance(value, list) or not all(
                    isinstance(name, str) for name in value):
                errors.append(
                    f"verification_summary.{field} must be an array of strings")
    return errors


def verify_envelope(envelope: dict, signer) -> dict:
    """Tamper check (PA-002/PA-003): digest + signature + authenticity.

    A signature scheme that carries its own public key proves INTEGRITY but
    not AUTHENTICITY: anyone can mint a keypair, re-sign a rewritten proof,
    and produce something internally consistent. For those schemes the key's
    fingerprint must appear in a registry the signer holds independently of
    the artifact, or the envelope is reported unauthenticated (ADR-031).
    """
    shape_errors = validate_envelope_shape(envelope)
    if shape_errors:
        return {
            "valid": False, "shape_ok": False, "shape_errors": shape_errors,
            "digest_ok": False, "signature_ok": False, "authentic": False,
            "reason": "; ".join(shape_errors), "status": "invalid",
        }

    body = {
        k: v for k, v in envelope.items()
        if k not in ("signature", "proof_digest")
    }
    try:
        digest_ok = digest_obj(body) == envelope.get("proof_digest")
        sig_ok = signer.verify(envelope) if signer else False
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return {
            "valid": False, "shape_ok": True, "shape_errors": [],
            "digest_ok": False, "signature_ok": False,
            "authentic": False,
            "reason": f"envelope is not canonical I-JSON: {exc}",
            "status": "invalid",
        }

    authentic = True
    reason = None
    # Defaults to False: a signer that does not declare the property is
    # assumed NOT to prove authenticity on its own. Defaulting True let any
    # third-party Signer omit one attribute and skip the check (ADR-044).
    if sig_ok and not getattr(signer, "self_authenticating", False):
        # The identity must be DERIVED from the attached key material, never
        # read from a field beside it. Trusting the declared fingerprint lets
        # an attacker sign with their own key and simply write a registered
        # fingerprint next to it (ADR-044).
        derive = getattr(signer, "derive_fingerprint", None)
        if derive is None:
            authentic, reason = False, (
                "signer cannot derive a key identity from the signature, so "
                "authenticity cannot be established")
        else:
            registry = getattr(signer, "registered_fingerprints", set())
            actual = derive(envelope.get("signature") or {})
            claimed = (envelope.get("signature") or {}).get("fingerprint")
            if actual is None:
                authentic, reason = False, "signature carries no usable key"
            elif claimed is not None and claimed != actual:
                authentic, reason = False, (
                    "the declared fingerprint does not match the attached "
                    "public key")
            elif not registry:
                authentic, reason = False, (
                    "signature scheme carries its own public key and no key "
                    "registry was supplied: authenticity cannot be established")
            elif actual not in registry:
                authentic, reason = False, (
                    f"key {actual} is not registered: a valid signature under "
                    f"an unknown key only means someone signed this")

    expected_status, expected_summary = evaluate_status(
        envelope.get("verifications", []),
        (envelope.get("verification_summary") or {}).get("required", []))
    summary_ok = expected_summary == envelope.get("verification_summary")
    sufficiency_ok = expected_status == envelope.get("status") and summary_ok
    if not sufficiency_ok:
        reason = (
            f"recorded status/summary contradict verification contents, "
            f"which evaluate to status {expected_status!r} and summary "
            f"{expected_summary!r}")

    valid = digest_ok and sig_ok and authentic and sufficiency_ok
    return {
        "valid": valid,
        "shape_ok": True,
        "shape_errors": [],
        "digest_ok": digest_ok,
        "signature_ok": sig_ok,
        "authentic": authentic,
        "sufficiency_ok": sufficiency_ok,
        "expected_status": expected_status,
        "summary_ok": summary_ok,
        "expected_summary": expected_summary,
        "reason": reason,
        "status": envelope.get("status") if valid else "invalid",
    }


def detect_stale(envelope: dict, current_inputs: dict[str, str]) -> dict:
    """EV-005: compare envelope inputs against current digests; changed
    inputs make the proof stale (valid -> stale, with explanation)."""
    changed, untracked = [], []
    for inp in envelope.get("inputs", []):
        current = current_inputs.get(inp["name"])
        if current is None:
            # An ARTIFACT the caller can no longer account for is not evidence
            # that nothing moved; it is the opposite (ADR-047). An input the
            # caller merely DECLARED is different: the project never undertook
            # to collect it, so its absence from the comparison says nothing
            # about the world. Treating the two alike made one declared input
            # — a commit sha, a ticket id — permanently stale the proof, under
            # a reason that read "deliverables changed" when none had
            # (ADR-065).
            if inp.get("kind") == "artifact":
                changed.append({"name": inp["name"], "recorded": inp["digest"],
                                "current": None,
                                "why": "no longer reported by the project"})
            else:
                untracked.append({
                    "name": inp["name"], "kind": inp.get("kind"),
                    "recorded": inp["digest"],
                    "why": "declared by the caller; the project does not "
                           "collect it, so its freshness is not checked"})
            continue
        if current != inp["digest"]:
            changed.append({"name": inp["name"], "recorded": inp["digest"],
                            "current": current})
    return {
        "stale": bool(changed),
        "changed_inputs": changed,
        "untracked_inputs": untracked,
        "explanation": (
            "Proof inputs changed since attestation; verifiers must re-run."
            if changed else "All recorded inputs still match."),
    }


# ------------------------------------------------------------------- in-toto

def to_intoto(envelope: dict) -> dict:
    """PA-006: lossless mapping into an in-toto-compatible statement."""
    return {
        "_type": INTOTO_TYPE,
        "subject": [
            {"name": s["name"], "digest": {"sha256": s["digest"].removeprefix("sha256:")}}
            for s in envelope.get("subject", [])
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            k: v for k, v in envelope.items()
            if k not in ("subject", "schema_version")
        },
    }


def from_intoto(statement: dict) -> dict:
    """Round-trip an in-toto statement back to a CCE envelope (PA-006)."""
    if statement.get("_type") != INTOTO_TYPE or \
            statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError("not a CCE proof-carrying-action statement")
    envelope = dict(statement["predicate"])
    envelope["schema_version"] = PROOF_SCHEMA
    envelope["subject"] = [
        {"name": s["name"], "digest": "sha256:" + s["digest"]["sha256"]}
        for s in statement.get("subject", [])
    ]
    return envelope
