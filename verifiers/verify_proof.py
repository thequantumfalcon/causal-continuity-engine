#!/usr/bin/env python3
"""Independent verifier for cce.proof.v1 envelopes.

Written against SPEC.md. Standard library only. Imports NOTHING from `causal_continuity_engine`
by design — if it did, it would share whatever the reference implementation
gets wrong, and agreement between the two would prove nothing.

    python verifiers/verify_proof.py proof.json
    python verifiers/verify_proof.py 'vectors/*.json' --json
    python verifiers/verify_proof.py proof.json --hmac-key-hex <hex>
    python verifiers/verify_proof.py proof.json --fingerprint sha256:...
    python verifiers/verify_proof.py proof.json --expect-project prj_x \\
                                                --expect-task tsk_y

Exit codes (SPEC §10.1) — INVALID dominates:
    0  every envelope VALID
    1  any INVALID
    2  any UNVERIFIED (no INVALID)
    3  any INCOMPLETE (no INVALID, no UNVERIFIED)
    64 usage error
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
from datetime import datetime

SCHEMA = "cce.proof.v1"
MAX_PATH_PATTERNS = 128
MAX_PATTERN_BYTES = 4096
MAX_GLOB_MATCHES = 4096
MAX_GLOB_SCAN_ENTRIES = 100_000
MAX_BATCH_FILES = 1024
MAX_PROOF_BYTES = 1024 * 1024
PROOF_READ_CHUNK_BYTES = 64 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

RESULTS = {"passed", "failed", "skipped", "missing", "inconclusive", "stale"}
STATUSES = {"draft", "verified", "failed", "incomplete", "inconclusive",
            "stale", "invalid"}
AUTHORITATIVE = {"executed", "verifier_authoritative"}

# SPEC §7.1 — worst wins. Lower is worse.
SEVERITY = {"failed": 0, "inconclusive": 1, "stale": 1,
            "missing": 2, "skipped": 3, "passed": 4}

REQUIRED_TOP_LEVEL = (
    "schema_version", "proof_id", "created_at", "tenant_id", "project_id",
    "action_id", "subject", "action_intent", "actor", "inputs", "environment",
    "execution", "verifications", "policy_decision", "continuity_links",
    "evidence_context", "status", "verification_summary", "proof_digest",
    "signature",
)

SELF_AUTHENTICATING = {"hmac-sha256"}

PROOF_ID = re.compile(r"prf_[0-9a-f]{24}\Z")
PUBLIC_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}\Z", re.ASCII)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CANONICAL_CREATED_AT = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{6}Z\Z")
ACTION_INTENT_FIELDS = {"type", "statement", "requirement_ids"}
SUBJECT_FIELDS = {"name", "digest"}
INPUT_FIELDS = {"name", "digest", "kind"}
SUMMARY_FIELDS = {
    "unbacked_self_assertions", "required", "missing", "failed",
    "inconclusive", "skipped", "passed",
}
EXECUTION_FIELDS = {
    "tool", "command_digest", "exit_code", "started_at", "output_digest",
}
VERIFICATION_FIELDS = {
    "source", "pinned", "command_digest", "definition_digest", "verifier",
    "kind", "result", "started_at", "duration_seconds", "exit_code",
    "output_digest", "evidence_digest", "coverage", "control", "observed",
    "details", "network",
}
CONTROL_FIELDS = {"command_present", "status", "exit_code", "details"}
POLICY_DECISION_FIELDS = {
    "decision", "reason", "action_type", "required_level", "effective_level",
    "action_scope", "applicable_grant_ids", "reasons", "policy_config",
    "decided_at", "action_scopes", "scope_decisions",
}
CONTINUITY_FIELDS = {
    "task_ids", "requirement_ids", "decision_ids", "assumption_ids",
    "artifact_ids", "evidence_ids", "action_ids", "proof_node_id",
}
EVIDENCE_CONTEXT_FIELDS = {
    "unpinned_required", "policy_pinned", "mutation", "determinism",
}
SOURCES = {"executed", "verifier_authoritative", "self_asserted"}
CONTROL_STATUSES = {"held", "unmet", "absent", "inconclusive"}
SIGNATURE_FIELDS = {
    "key_id", "algorithm", "value", "fingerprint", "public_key",
}


class SpecError(Exception):
    """A structural violation, carrying its SPEC error code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class UsageLimitError(ValueError):
    """A bounded CLI-expansion contract was exceeded before verification."""


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SpecError("E_CJSON", f"duplicate object key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str):
    raise SpecError("E_CJSON", f"non-finite number {value!r}")


# ── SPEC §2: canonical form ────────────────────────────────────────────────

def _validate_i_json_string(value: str, *, path: str) -> None:
    for char in value:
        codepoint = ord(char)
        if (0xD800 <= codepoint <= 0xDFFF
                or 0xFDD0 <= codepoint <= 0xFDEF
                or codepoint & 0xFFFF in (0xFFFE, 0xFFFF)):
            raise SpecError(
                "E_CJSON", f"non-I-JSON Unicode U+{codepoint:04X} at {path}")


_JCS_SHORT_ESCAPES = {
    "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r",
    '"': '\\"', "\\": "\\\\",
}


def _jcs_string(value: str, *, path: str) -> str:
    _validate_i_json_string(value, path=path)
    encoded = []
    for char in value:
        if char in _JCS_SHORT_ESCAPES:
            encoded.append(_JCS_SHORT_ESCAPES[char])
        elif ord(char) <= 0x1F:
            encoded.append(f"\\u{ord(char):04x}")
        else:
            encoded.append(char)
    return '"' + "".join(encoded) + '"'


def _jcs_number(value: int | float, *, path: str) -> str:
    try:
        number = float(value)
    except OverflowError:
        raise SpecError("E_CJSON", f"number outside binary64 at {path}") from None
    if not math.isfinite(number):
        raise SpecError("E_CJSON", f"non-finite number at {path}")
    if isinstance(value, int) and int(number) != value:
        raise SpecError(
            "E_CJSON", f"integer is not exactly representable as binary64 at {path}")
    if number == 0:
        return "0"

    sign = "-" if number < 0 else ""
    shortest = repr(abs(number)).lower()
    if "e" in shortest:
        mantissa, exponent_text = shortest.split("e", 1)
        exponent = int(exponent_text)
    else:
        mantissa, exponent = shortest, 0
    if "." in mantissa:
        whole, fraction = mantissa.split(".", 1)
    else:
        whole, fraction = mantissa, ""
    digits = whole + fraction
    decimal_position = len(whole) + exponent
    leading_zeroes = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0")
    decimal_position -= leading_zeroes
    digits = digits.rstrip("0")

    if 0 < decimal_position <= 21:
        if decimal_position >= len(digits):
            body = digits + "0" * (decimal_position - len(digits))
        else:
            body = digits[:decimal_position] + "." + digits[decimal_position:]
    elif -6 < decimal_position <= 0:
        body = "0." + "0" * (-decimal_position) + digits
    else:
        body = digits[0]
        if len(digits) > 1:
            body += "." + digits[1:]
        scientific_exponent = decimal_position - 1
        body += "e" + ("+" if scientific_exponent >= 0 else "") \
            + str(scientific_exponent)
    return sign + body


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _render_jcs(value, *, markers: set[int], path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value, path=path)
    if isinstance(value, (int, float)):
        return _jcs_number(value, path=path)
    if isinstance(value, (list, tuple)):
        marker = id(value)
        if marker in markers:
            raise SpecError("E_CJSON", f"circular JSON value at {path}")
        markers.add(marker)
        try:
            return "[" + ",".join(
                _render_jcs(item, markers=markers, path=f"{path}[{index}]")
                for index, item in enumerate(value)) + "]"
        finally:
            markers.remove(marker)
    if isinstance(value, dict):
        marker = id(value)
        if marker in markers:
            raise SpecError("E_CJSON", f"circular JSON value at {path}")
        keys = list(value)
        for key in keys:
            if not isinstance(key, str):
                raise SpecError("E_CJSON", f"object key at {path} is not a string")
            _validate_i_json_string(key, path=f"{path} object key")
        markers.add(marker)
        try:
            members = []
            for key in sorted(keys, key=_utf16_sort_key):
                encoded_key = _jcs_string(key, path=f"{path} object key")
                encoded_value = _render_jcs(
                    value[key], markers=markers, path=f"{path}.{key}")
                members.append(encoded_key + ":" + encoded_value)
            return "{" + ",".join(members) + "}"
        finally:
            markers.remove(marker)
    raise SpecError("E_CJSON", f"value at {path} is not a JSON type")


def canonical(value) -> str:
    """RFC 8785 JCS text over the RFC 7493 I-JSON data model."""
    return _render_jcs(value, markers=set(), path="$")


def _validate_i_json(value, *, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _validate_i_json_string(value, path=path)
        return
    if isinstance(value, (int, float)):
        _jcs_number(value, path=path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_i_json(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_i_json_string(key, path=f"{path} object key")
            _validate_i_json(item, path=f"{path}.{key}")
        return
    raise SpecError("E_CJSON", f"value at {path} is not a JSON type")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _body(envelope: dict, *, drop: tuple) -> dict:
    return {k: v for k, v in envelope.items() if k not in drop}


def _is_canonical_created_at(value: str) -> bool:
    """Whether value is CCE's one canonical RFC-3339 UTC representation."""
    if not CANONICAL_CREATED_AT.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


# ── SPEC §3: shape ─────────────────────────────────────────────────────────

def check_shape(envelope) -> None:
    if not isinstance(envelope, dict):
        raise SpecError("E_SHAPE", f"envelope is {type(envelope).__name__}")
    if envelope.get("schema_version") != SCHEMA:
        raise SpecError("E_SHAPE",
                        f"schema_version {envelope.get('schema_version')!r}")
    missing = [k for k in REQUIRED_TOP_LEVEL if k not in envelope]
    if missing:
        raise SpecError("E_SHAPE", f"absent fields {missing}")
    unknown = sorted(set(envelope) - set(REQUIRED_TOP_LEVEL))
    if unknown:
        raise SpecError("E_SHAPE", f"unknown top-level fields {unknown}")

    for name in ("proof_id", "created_at", "tenant_id", "project_id",
                 "action_id"):
        if not isinstance(envelope[name], str) or not envelope[name].strip():
            raise SpecError("E_SHAPE", f"{name} is not a non-empty string")
    for name in ("tenant_id", "project_id", "action_id"):
        if not PUBLIC_ID.fullmatch(envelope[name]):
            raise SpecError("E_SHAPE", f"{name} is not a public identifier")
    if not PROOF_ID.fullmatch(envelope["proof_id"]):
        raise SpecError("E_SHAPE", "proof_id syntax")
    if not _is_canonical_created_at(envelope["created_at"]):
        raise SpecError("E_SHAPE", "created_at is not canonical UTC")
    if (not isinstance(envelope["status"], str)
            or envelope["status"] not in STATUSES):
        raise SpecError("E_SHAPE", f"status {envelope['status']!r}")

    for name in ("subject", "inputs", "execution", "verifications"):
        if not isinstance(envelope[name], list):
            raise SpecError("E_SHAPE", f"{name} is not an array")
    for name in ("actor", "environment", "policy_decision",
                 "continuity_links", "evidence_context",
                 "verification_summary", "signature"):
        if not isinstance(envelope[name], dict):
            raise SpecError("E_SHAPE", f"{name} is not an object")

    intent = envelope.get("action_intent")
    if not isinstance(intent, dict):
        raise SpecError("E_SHAPE", "action_intent is not an object")
    if set(intent) != ACTION_INTENT_FIELDS:
        raise SpecError("E_SHAPE", "action_intent fields")
    if not isinstance(intent["type"], str) or not intent["type"].strip():
        raise SpecError("E_SHAPE", "action_intent.type")
    if not isinstance(intent["statement"], str):
        raise SpecError("E_SHAPE", "action_intent.statement")
    if not isinstance(intent["requirement_ids"], list) or not all(
            isinstance(value, str) for value in intent["requirement_ids"]):
        raise SpecError("E_SHAPE", "action_intent.requirement_ids")
    if not all(PUBLIC_ID.fullmatch(value)
               for value in intent["requirement_ids"]):
        raise SpecError("E_SHAPE", "action_intent.requirement_ids identifiers")

    for i, subject in enumerate(envelope["subject"]):
        if not isinstance(subject, dict) or set(subject) != SUBJECT_FIELDS:
            raise SpecError("E_SHAPE", f"subject[{i}] fields")
        if not isinstance(subject["name"], str) or not subject["name"].strip():
            raise SpecError("E_SHAPE", f"subject[{i}].name")
        if not isinstance(subject["digest"], str) or not DIGEST.fullmatch(
                subject["digest"]):
            raise SpecError("E_SHAPE", f"subject[{i}].digest")

    for i, item in enumerate(envelope["inputs"]):
        if not isinstance(item, dict) or set(item) != INPUT_FIELDS:
            raise SpecError("E_SHAPE", f"inputs[{i}] fields")
        if any(not isinstance(item[field], str) or not item[field].strip()
               for field in ("name", "kind")):
            raise SpecError("E_SHAPE", f"inputs[{i}] name/kind")
        if not isinstance(item["digest"], str) or not DIGEST.fullmatch(
                item["digest"]):
            raise SpecError("E_SHAPE", f"inputs[{i}].digest")

    for i, item in enumerate(envelope["execution"]):
        if not isinstance(item, dict):
            raise SpecError("E_SHAPE", f"execution[{i}] is not an object")
        if set(item) != EXECUTION_FIELDS:
            raise SpecError("E_SHAPE", f"execution[{i}] fields")
        if not isinstance(item.get("tool"), str) or not item["tool"].strip():
            raise SpecError("E_SHAPE", f"execution[{i}].tool")
        if not isinstance(item.get("started_at"), str) or not item[
                "started_at"].strip():
            raise SpecError("E_SHAPE", f"execution[{i}].started_at")
        for field in ("command_digest", "output_digest"):
            value = item.get(field)
            if value is not None and (
                    not isinstance(value, str) or not DIGEST.fullmatch(value)):
                raise SpecError("E_SHAPE", f"execution[{i}].{field}")
        if item.get("exit_code") is not None and (
                isinstance(item.get("exit_code"), bool)
                or not isinstance(item.get("exit_code"), int)):
            raise SpecError("E_SHAPE", f"execution[{i}].exit_code")

    for i, v in enumerate(envelope["verifications"]):
        if not isinstance(v, dict):
            raise SpecError("E_SHAPE", f"verifications[{i}] is not an object")
        if set(v) - VERIFICATION_FIELDS:
            raise SpecError("E_SHAPE", f"verifications[{i}] unknown fields")
        if not isinstance(v.get("verifier"), str) or not v["verifier"].strip():
            raise SpecError("E_SHAPE", f"verifications[{i}].verifier")
        result = v.get("result")
        if not isinstance(result, str) or result not in RESULTS:
            raise SpecError("E_SHAPE",
                            f"verifications[{i}].result {v.get('result')!r}")
        source = v.get("source", "self_asserted")
        if not isinstance(source, str) or source not in SOURCES:
            raise SpecError("E_SHAPE", f"verifications[{i}].source")
        if "pinned" in v and not isinstance(v["pinned"], bool):
            raise SpecError("E_SHAPE", f"verifications[{i}].pinned")
        for field in ("command_digest", "definition_digest",
                      "output_digest", "evidence_digest"):
            value = v.get(field)
            if field in v and value is not None and (
                    not isinstance(value, str) or not DIGEST.fullmatch(value)):
                raise SpecError("E_SHAPE", f"verifications[{i}].{field}")
        control = v.get("control")
        if "control" in v and control is not None and (
                not isinstance(control, dict)
                or not isinstance(control.get("status"), str)
                or control.get("status") not in CONTROL_STATUSES):
            raise SpecError("E_SHAPE", f"verifications[{i}].control")
        if isinstance(control, dict):
            if set(control) != CONTROL_FIELDS:
                raise SpecError("E_SHAPE", f"verifications[{i}].control fields")
            if not isinstance(control["command_present"], bool):
                raise SpecError(
                    "E_SHAPE", f"verifications[{i}].control.command_present")
            if control["exit_code"] is not None and (
                    isinstance(control["exit_code"], bool)
                    or not isinstance(control["exit_code"], int)):
                raise SpecError(
                    "E_SHAPE", f"verifications[{i}].control.exit_code")
            if not isinstance(control["details"], str):
                raise SpecError(
                    "E_SHAPE", f"verifications[{i}].control.details")
        for field in ("coverage", "observed"):
            if field in v and v[field] is not None and not isinstance(v[field], dict):
                raise SpecError("E_SHAPE", f"verifications[{i}].{field}")
        if "duration_seconds" in v:
            duration = v["duration_seconds"]
            if (isinstance(duration, bool)
                    or not isinstance(duration, (int, float))
                    or not math.isfinite(duration) or duration < 0):
                raise SpecError("E_SHAPE", f"verifications[{i}].duration_seconds")
        if "exit_code" in v and v["exit_code"] is not None and (
                isinstance(v["exit_code"], bool)
                or not isinstance(v["exit_code"], int)):
            raise SpecError("E_SHAPE", f"verifications[{i}].exit_code")
        for field in ("kind", "started_at", "details", "network"):
            if field in v and not isinstance(v[field], str):
                raise SpecError("E_SHAPE", f"verifications[{i}].{field}")

    policy = envelope["policy_decision"]
    if set(policy) - POLICY_DECISION_FIELDS:
        raise SpecError("E_SHAPE", "policy_decision unknown fields")
    decision = policy.get("decision")
    if not isinstance(decision, str) or decision not in {"allow", "deny"}:
        raise SpecError("E_SHAPE", "policy_decision.decision")
    for field in ("action_type", "reason", "decided_at"):
        if field in policy and not isinstance(policy[field], str):
            raise SpecError("E_SHAPE", f"policy_decision.{field}")
    for field in ("required_level", "effective_level"):
        if field in policy and (
                isinstance(policy[field], bool)
                or not isinstance(policy[field], int)):
            raise SpecError("E_SHAPE", f"policy_decision.{field}")
    if "action_scope" in policy and policy["action_scope"] is not None and \
            not isinstance(policy["action_scope"], str):
        raise SpecError("E_SHAPE", "policy_decision.action_scope")
    for field in ("applicable_grant_ids", "reasons", "action_scopes"):
        if field in policy and (
                not isinstance(policy[field], list)
                or not all(isinstance(value, str) for value in policy[field])):
            raise SpecError("E_SHAPE", f"policy_decision.{field}")
    if "policy_config" in policy and not isinstance(policy["policy_config"], dict):
        raise SpecError("E_SHAPE", "policy_decision.policy_config")
    if "scope_decisions" in policy and (
            not isinstance(policy["scope_decisions"], list)
            or not all(isinstance(value, dict)
                       for value in policy["scope_decisions"])):
        raise SpecError("E_SHAPE", "policy_decision.scope_decisions")

    links = envelope["continuity_links"]
    if set(links) - CONTINUITY_FIELDS:
        raise SpecError("E_SHAPE", "continuity_links unknown fields")
    for field, value in links.items():
        if field == "proof_node_id":
            if not isinstance(value, str) or not PUBLIC_ID.fullmatch(value):
                raise SpecError("E_SHAPE", "continuity_links.proof_node_id")
        elif not isinstance(value, list) or not all(
                isinstance(node_id, str) and PUBLIC_ID.fullmatch(node_id)
                for node_id in value):
            raise SpecError("E_SHAPE", f"continuity_links.{field}")

    context = envelope["evidence_context"]
    if set(context) - EVIDENCE_CONTEXT_FIELDS:
        raise SpecError("E_SHAPE", "evidence_context unknown fields")
    for field in ("unpinned_required", "policy_pinned"):
        if field in context and (
                not isinstance(context[field], list)
                or not all(isinstance(value, str) for value in context[field])):
            raise SpecError("E_SHAPE", f"evidence_context.{field}")
    if "mutation" in context and context["mutation"] is not None and \
            not isinstance(context["mutation"], dict):
        raise SpecError("E_SHAPE", "evidence_context.mutation")
    if "determinism" in context and not isinstance(context["determinism"], dict):
        raise SpecError("E_SHAPE", "evidence_context.determinism")

    summary = envelope["verification_summary"]
    if set(summary) != SUMMARY_FIELDS:
        raise SpecError("E_SHAPE", "verification_summary fields")
    for field in SUMMARY_FIELDS:
        if not isinstance(summary[field], list) or not all(
                isinstance(value, str) for value in summary[field]):
            raise SpecError("E_SHAPE", f"verification_summary.{field}")

    proof_digest = envelope["proof_digest"]
    if not isinstance(proof_digest, str) or not DIGEST.fullmatch(proof_digest):
        raise SpecError("E_SHAPE", "proof_digest")

    sig = envelope["signature"]
    if not {"key_id", "algorithm", "value"} <= set(sig):
        raise SpecError("E_SHAPE", "signature required fields")
    if set(sig) - SIGNATURE_FIELDS:
        raise SpecError("E_SHAPE", "signature unknown fields")
    if not isinstance(sig["key_id"], str) or not sig["key_id"].strip():
        raise SpecError("E_SHAPE", "signature.key_id")
    if not isinstance(sig["algorithm"], str) or not sig["algorithm"].strip():
        raise SpecError("E_SHAPE", "signature.algorithm")
    if not ((isinstance(sig["value"], str) and sig["value"])
            or (isinstance(sig["value"], list) and sig["value"])):
        raise SpecError("E_SHAPE", "signature.value")
    if "fingerprint" in sig and (
            not isinstance(sig["fingerprint"], str)
            or not DIGEST.fullmatch(sig["fingerprint"])):
        raise SpecError("E_SHAPE", "signature.fingerprint")
    if "public_key" in sig and not isinstance(sig["public_key"], list):
        raise SpecError("E_SHAPE", "signature.public_key")


# ── SPEC §4 / §5: digest and signature ─────────────────────────────────────

def check_digest(envelope: dict) -> None:
    expected = digest(_body(envelope, drop=("signature", "proof_digest")))
    if envelope["proof_digest"] != expected:
        raise SpecError("E_DIGEST", "proof_digest does not cover the body")


def _lamport_message(envelope: dict) -> bytes:
    body = _body(envelope, drop=("signature",))
    return hashlib.sha256(canonical(body).encode("utf-8")).digest()


def _bits(message: bytes):
    for byte in message:
        for i in range(8):
            yield (byte >> (7 - i)) & 1


def _public_pairs(sig: dict) -> list[tuple[bytes, bytes]]:
    raw = sig.get("public_key")
    if not isinstance(raw, list) or len(raw) != 256:
        raise SpecError("E_SIGNATURE", "public_key is not 256 pairs")
    pairs = []
    for pair in raw:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise SpecError("E_SIGNATURE", "malformed public_key pair")
        try:
            a, b = bytes.fromhex(pair[0]), bytes.fromhex(pair[1])
        except (ValueError, TypeError) as exc:
            raise SpecError("E_SIGNATURE", f"public_key hex: {exc}") from None
        if len(a) != 32 or len(b) != 32:
            raise SpecError("E_SIGNATURE", "public_key block is not 32 bytes")
        pairs.append((a, b))
    return pairs


def check_signature(envelope: dict, *, hmac_key: bytes | None) -> str:
    """Returns 'PASS' or 'SKIPPED'; raises on failure."""
    sig = envelope["signature"]
    algorithm = sig["algorithm"]

    if algorithm == "hmac-sha256":
        if hmac_key is None:
            return "SKIPPED"        # unverifiable without the secret, honestly
        supplied = sig.get("value")
        if (not isinstance(supplied, str)
                or re.fullmatch(r"[0-9a-f]{64}", supplied, re.ASCII) is None):
            raise SpecError("E_SIGNATURE", "hmac value is not 64 lowercase hex digits")
        body = _body(envelope, drop=("signature",))
        expected = hmac.new(hmac_key, canonical(body).encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, supplied):
            raise SpecError("E_SIGNATURE", "hmac does not match")
        return "PASS"

    if algorithm == "lamport-sha256/1":
        pairs = _public_pairs(sig)
        blocks = sig.get("value")
        if not isinstance(blocks, list) or len(blocks) != 256:
            raise SpecError("E_SIGNATURE", "value is not 256 blocks")
        message = _lamport_message(envelope)
        ok = True
        for i, bit in enumerate(_bits(message)):
            try:
                revealed = bytes.fromhex(blocks[i])
            except (ValueError, TypeError):
                raise SpecError("E_SIGNATURE", "signature block hex") from None
            # Constant time over the whole loop: no early exit on mismatch.
            ok &= hmac.compare_digest(hashlib.sha256(revealed).digest(),
                                      pairs[i][bit])
        if not ok:
            raise SpecError("E_SIGNATURE", "lamport signature does not match")
        return "PASS"

    raise SpecError("E_SCHEME", f"unknown algorithm {algorithm!r}")


# ── SPEC §6: authenticity ──────────────────────────────────────────────────

def derive_fingerprint(sig: dict) -> str:
    """Identity recomputed from the ATTACHED key, never read beside it."""
    pairs = _public_pairs(sig)
    flat = b"".join(a + b for a, b in pairs)
    return "sha256:" + hashlib.sha256(flat).hexdigest()


def check_authenticity(envelope: dict, *, registry: set[str],
                       signature_checked: bool) -> str:
    """SPEC §6. Undecidable without C2: authenticity is a claim about who
    produced a signature, and there is nothing to attribute if the signature
    itself was never verified."""
    if not signature_checked:
        return "SKIPPED"
    sig = envelope["signature"]
    algorithm = sig["algorithm"]
    if algorithm in SELF_AUTHENTICATING:
        return "PASS"
    actual = derive_fingerprint(sig)
    declared = sig.get("fingerprint")
    if declared is not None and declared != actual:
        raise SpecError("E_FINGERPRINT",
                        "declared fingerprint is not the attached key's")
    if not registry:
        raise SpecError("E_UNREGISTERED",
                        "no out-of-band registry: authenticity undecidable")
    if actual not in registry:
        raise SpecError("E_UNREGISTERED", f"key {actual} is not registered")
    return "PASS"


# ── SPEC §7: sufficiency ───────────────────────────────────────────────────

def recompute_sufficiency(envelope: dict) -> tuple[str, dict]:
    required = set(envelope["verification_summary"].get("required", []))
    worst: dict[str, str] = {}
    self_asserted: set[str] = set()
    for v in envelope["verifications"]:
        name, result = v.get("verifier"), v.get("result")
        if v.get("source", "self_asserted") in AUTHORITATIVE:
            if name not in worst or SEVERITY[result] < SEVERITY[worst[name]]:
                worst[name] = result
        else:
            self_asserted.add(name)

    unbacked = sorted(
        name for name in required if name in self_asserted and name not in worst)
    missing = sorted(
        {name for name in required if name not in worst}
        | {name for name, result in worst.items()
           if result == "missing" and name in required})
    failed = sorted(
        name for name, result in worst.items() if result == "failed"
        and (not required or name in required))
    inconclusive = sorted(
        name for name, result in worst.items()
        if result in ("inconclusive", "stale")
        and (not required or name in required))
    skipped = sorted(
        name for name, result in worst.items()
        if result == "skipped" and name in required)
    passed = sorted(
        name for name, result in worst.items() if result == "passed")

    if failed:
        status = "failed"
    elif missing or skipped:
        status = "incomplete"
    elif inconclusive:
        status = "inconclusive"
    elif required and all(worst.get(name) == "passed" for name in required):
        status = "verified"
    elif not required and passed and all(
            result == "passed" for result in worst.values()):
        status = "verified"
    else:
        status = "incomplete"
    return status, {
        "unbacked_self_assertions": unbacked,
        "required": sorted(required),
        "missing": missing,
        "failed": failed,
        "inconclusive": inconclusive,
        "skipped": skipped,
        "passed": passed,
    }


def recompute_status(envelope: dict) -> str:
    return recompute_sufficiency(envelope)[0]


def check_sufficiency(envelope: dict) -> None:
    status, summary = recompute_sufficiency(envelope)
    if status != envelope["status"] or summary != envelope["verification_summary"]:
        raise SpecError(
            "E_STATUS",
            f"recorded status/summary contradict contents, which imply "
            f"{status!r} and {summary!r}")


# ── SPEC §8: scope ─────────────────────────────────────────────────────────

def check_scope(envelope: dict, *, project=None, tenant=None, task=None) -> str:
    if project is None and tenant is None and task is None:
        return "SKIPPED"
    if project is not None and envelope["project_id"] != project:
        raise SpecError("E_PROJECT",
                        f"issued for {envelope['project_id']}, not {project}")
    if tenant is not None and envelope["tenant_id"] != tenant:
        raise SpecError("E_TENANT",
                        f"issued for {envelope['tenant_id']}, not {tenant}")
    if task is not None:
        links = envelope.get("continuity_links") or {}
        task_ids = links.get("task_ids") if isinstance(links, dict) else None
        bound = (
            isinstance(task_ids, list)
            and all(isinstance(item, str) for item in task_ids)
            and task in task_ids
        )
        if not bound:
            raise SpecError(
                "E_UNBOUND",
                f"continuity_links.task_ids does not contain {task}")
    return "PASS"


# ── SPEC §9: verdict ───────────────────────────────────────────────────────

def verify(envelope, *, hmac_key=None, registry=None, project=None,
           tenant=None, task=None) -> dict:
    checks = {"C1_digest": "FAIL", "C2_signature": "FAIL",
              "C3_authenticity": "FAIL", "C4_sufficiency": "FAIL",
              "C5_scope": "FAIL"}
    errors: list[str] = []
    registry = set(registry or ())

    def run(name, fn):
        try:
            checks[name] = fn() or "PASS"
        except SpecError as exc:
            checks[name] = "FAIL"
            errors.append(exc.code)
        except (TypeError, ValueError, OverflowError, RecursionError):
            checks[name] = "FAIL"
            errors.append("E_CJSON")

    try:
        check_shape(envelope)
    except SpecError as exc:
        return {"verdict": "INVALID", "checks": checks, "errors": [exc.code],
                "status": None, "detail": str(exc)}

    run("C1_digest", lambda: check_digest(envelope))
    run("C2_signature", lambda: check_signature(envelope, hmac_key=hmac_key))
    run("C3_authenticity",
        lambda: check_authenticity(envelope, registry=registry,
                                   signature_checked=checks["C2_signature"] == "PASS"))
    run("C4_sufficiency", lambda: check_sufficiency(envelope))
    run("C5_scope", lambda: check_scope(envelope, project=project,
                                        tenant=tenant, task=task))

    # SPEC §9. C5 may be SKIPPED without preventing VALID — scope is a
    # question about the caller's intent. C2 and C3 may not: skipping those
    # removes the only grounds for believing the envelope at all, and
    # reporting VALID there tells a third party a forgery is genuine.
    undecidable = [c for c in ("C2_signature", "C3_authenticity")
                   if checks[c] == "SKIPPED"]
    if any(v == "FAIL" for v in checks.values()):
        verdict = "INVALID"
    elif undecidable:
        verdict = "UNVERIFIED"
    elif envelope["status"] != "verified":
        verdict = "INCOMPLETE"
    else:
        verdict = "VALID"
    established = not undecidable and verdict != "INVALID"
    return {"verdict": verdict, "checks": checks, "errors": errors,
            "undecidable": undecidable,
            "status": envelope["status"] if established else None}


def _input_indirect(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _input_identity_key(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        getattr(info, "st_file_attributes", 0),
        getattr(info, "st_reparse_tag", 0),
    )


def _input_path_content_key(info: os.stat_result) -> tuple:
    return (
        *_input_identity_key(info),
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
    )


def _input_descriptor_key(info: os.stat_result) -> tuple:
    return (
        *_input_path_content_key(info),
        info.st_nlink,
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _read_proof_bytes(path: str) -> bytes:
    """Read one stable physical regular file without exceeding the proof cap."""
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise SpecError("E_CJSON", "proof input is unreadable or missing") from exc
    if _input_indirect(before) or not stat.S_ISREG(before.st_mode):
        raise SpecError(
            "E_CJSON",
            "proof input must be a physical regular file, not a link, "
            "reparse point, directory, or special file",
        )
    if before.st_size > MAX_PROOF_BYTES:
        raise SpecError(
            "E_CJSON",
            f"proof input exceeds the {MAX_PROOF_BYTES}-byte limit",
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SpecError(
            "E_CJSON", "proof input is unreadable or changed") from exc

    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (
            _input_indirect(opened)
            or not stat.S_ISREG(opened.st_mode)
            or _input_path_content_key(opened) != _input_path_content_key(before)
        ):
            raise SpecError(
                "E_CJSON", "proof input changed before it could be read")
        if opened.st_size > MAX_PROOF_BYTES:
            raise SpecError(
                "E_CJSON",
                f"proof input exceeds the {MAX_PROOF_BYTES}-byte limit",
            )

        while True:
            remaining = MAX_PROOF_BYTES - total
            chunk = os.read(
                descriptor,
                min(PROOF_READ_CHUNK_BYTES, remaining + 1),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PROOF_BYTES:
                raise SpecError(
                    "E_CJSON",
                    f"proof input exceeds the {MAX_PROOF_BYTES}-byte limit",
                )
            chunks.append(chunk)

        after_open = os.fstat(descriptor)
        after_path = os.lstat(path)
        if (
            _input_indirect(after_path)
            or not stat.S_ISREG(after_path.st_mode)
            or _input_descriptor_key(after_open) != _input_descriptor_key(opened)
            or _input_path_content_key(after_path)
            != _input_path_content_key(opened)
            or total != opened.st_size
        ):
            raise SpecError(
                "E_CJSON", "proof input changed while it was being read")
    except SpecError:
        raise
    except OSError as exc:
        raise SpecError(
            "E_CJSON", "proof input is unreadable or changed") from exc
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _load_proof_document(path: str):
    raw = _read_proof_bytes(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecError("E_CJSON", "proof input is not strict UTF-8") from exc
    try:
        envelope = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_i_json(envelope)
    except SpecError:
        raise
    except (json.JSONDecodeError, ValueError, OverflowError, RecursionError) as exc:
        raise SpecError("E_CJSON", "proof input is not strict JSON") from exc
    return envelope


def _validate_pattern(pattern: str) -> None:
    try:
        encoded = os.fsencode(pattern)
    except (TypeError, UnicodeError) as exc:
        raise UsageLimitError("proof path pattern is not filesystem text") from exc
    if len(pattern) > MAX_PATTERN_BYTES or len(encoded) > MAX_PATTERN_BYTES:
        raise UsageLimitError(
            f"proof path pattern exceeds the {MAX_PATTERN_BYTES}-byte limit")
    directory, _name = os.path.split(pattern)
    if glob.has_magic(directory):
        raise UsageLimitError(
            "glob magic is supported only in the final path component")


def _expand_final_component_glob(
        pattern: str,
        counters: dict[str, int],
        match_identities: set[str],
) -> list[str]:
    directory, name_pattern = os.path.split(pattern)
    if not glob.has_magic(name_pattern):
        return []
    scan_root = directory or os.curdir
    matches: list[str] = []
    try:
        with os.scandir(scan_root) as entries:
            for entry in entries:
                counters["scanned"] += 1
                if counters["scanned"] > MAX_GLOB_SCAN_ENTRIES:
                    raise UsageLimitError(
                        "glob expansion exceeds the "
                        f"{MAX_GLOB_SCAN_ENTRIES}-entry scan limit")
                if entry.name.startswith(".") and not name_pattern.startswith("."):
                    continue
                if not fnmatch.fnmatch(entry.name, name_pattern):
                    continue
                candidate = (
                    os.path.join(directory, entry.name)
                    if directory else entry.name
                )
                identity = os.path.normcase(
                    os.path.abspath(os.path.normpath(candidate)))
                if identity not in match_identities:
                    if len(match_identities) >= MAX_GLOB_MATCHES:
                        raise UsageLimitError(
                            "glob expansion exceeds the "
                            f"{MAX_GLOB_MATCHES}-match limit")
                    match_identities.add(identity)
                matches.append(candidate)
    except UsageLimitError:
        raise
    except OSError:
        return []
    return sorted(matches, key=lambda item: (os.path.normcase(item), item))


def _expand_paths(patterns: list[str]) -> list[str]:
    if len(patterns) > MAX_PATH_PATTERNS:
        raise UsageLimitError(
            f"at most {MAX_PATH_PATTERNS} proof path patterns are allowed")
    counters = {"scanned": 0}
    match_identities: set[str] = set()
    files: dict[str, str] = {}
    for pattern in dict.fromkeys(patterns):
        _validate_pattern(pattern)
        hits = _expand_final_component_glob(
            pattern, counters, match_identities)
        for path in hits if hits else [pattern]:
            identity = os.path.normcase(os.path.abspath(os.path.normpath(path)))
            if identity in files:
                continue
            if len(files) >= MAX_BATCH_FILES:
                raise UsageLimitError(
                    f"proof batch exceeds the {MAX_BATCH_FILES}-file limit")
            files[identity] = path
    return list(files.values())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Verify cce.proof.v1 envelopes.")
    p.add_argument(
        "paths",
        nargs="+",
        help="proof JSON files or globs in the final path component",
    )
    p.add_argument("--hmac-key-hex")
    p.add_argument("--fingerprint", action="append", default=[],
                   help="a key fingerprint obtained OUT OF BAND (repeatable)")
    p.add_argument("--expect-project")
    p.add_argument("--expect-tenant")
    p.add_argument("--expect-task")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        key = bytes.fromhex(args.hmac_key_hex) if args.hmac_key_hex else None
    except ValueError:
        print("--hmac-key-hex is not hex", file=sys.stderr)
        return 64

    try:
        files = _expand_paths(args.paths)
    except UsageLimitError as exc:
        print(f"proof input usage error: {exc}", file=sys.stderr)
        return 64
    if not files:
        print("proof input usage error: no files matched", file=sys.stderr)
        return 64

    results, worst = [], 0
    for path in files:
        try:
            envelope = _load_proof_document(path)
        except SpecError as exc:
            out = {"verdict": "INVALID", "errors": [exc.code],
                   "detail": str(exc), "checks": {}, "status": None}
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError,
                OverflowError, RecursionError):
            out = {"verdict": "INVALID", "errors": ["E_CJSON"],
                   "detail": "E_CJSON: proof input could not be verified safely",
                   "checks": {}, "status": None}
        else:
            out = verify(envelope, hmac_key=key,
                         registry=set(args.fingerprint),
                         project=args.expect_project,
                         tenant=args.expect_tenant, task=args.expect_task)
        out["file"] = path
        results.append(out)
        # INVALID dominates (SPEC §10.1): a batch with both an INVALID and an
        # INCOMPLETE must exit 1, or a CI gate keyed on that code misses the
        # forgery.
        rank = {"VALID": 0, "INCOMPLETE": 1, "UNVERIFIED": 2, "INVALID": 3}
        worst = max(worst, rank[out["verdict"]])

    exit_for = {0: 0, 1: 3, 2: 2, 3: 1}          # rank -> SPEC §10.1 code
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
    else:
        for r in results:
            marks = " ".join(
                f"{c.split('_')[0]}:{v[0]}" for c, v in sorted(r["checks"].items()))
            line = f"{r['verdict']:10s} {marks}  {r['file']}"
            if r["errors"]:
                line += f"  [{', '.join(sorted(set(r['errors'])))}]"
            print(line)
        counts: dict[str, int] = {}
        for r in results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print("\n" + ", ".join(f"{n} {v}" for v, n in sorted(counts.items())))
        if any(r["verdict"] == "UNVERIFIED" for r in results):
            print("\nUNVERIFIED means nothing was established, not that nothing "
                  "is wrong.\nAn hmac-sha256 envelope needs --hmac-key-hex; a "
                  "lamport envelope needs --fingerprint\nfrom a source other "
                  "than the envelope itself.", file=sys.stderr)
    return exit_for[worst]


if __name__ == "__main__":
    raise SystemExit(main())
