"""Capture modes and secret redaction (SEC-003, SEC-004, TM-006).

Applied BEFORE durable persistence: the store receives already-redacted
payloads in 'redacted' mode and digest/metadata-only envelopes in
'metadata_only' mode. Redaction is recorded (count, kinds), never the
secrets themselves.
"""

from __future__ import annotations

import re

CAPTURE_MODES = {"metadata_only", "redacted", "full"}

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(
        r"(?i)\baws[_-]?secret[_-]?(?:access[_-]?)?key\b[\"'\s:=]+[A-Za-z0-9/+=]{30,}")),
    ("private_key_block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("generic_assignment", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
        r"\s*[:=]\s*[\"']?[^\s\"']{8,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
]

_CONTENT_FIELDS = {"body", "text", "content", "message", "description", "output",
                   "title", "diff", "patch", "stdout", "stderr",
                   # GitHub wraps the previous value of an edited field here
                   "changes", "commit_message", "summary", "note"}


def scan_secrets(text: str) -> list[dict]:
    findings = []
    for kind, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            findings.append({"kind": kind, "start": m.start(), "end": m.end()})
    return findings


def redact_text(text: str) -> tuple[str, list[str]]:
    """Replace secrets with typed placeholders. Returns (clean, kinds_found)."""
    kinds: list[str] = []
    for kind, pattern in _SECRET_PATTERNS:
        def _sub(m, kind=kind):
            kinds.append(kind)
            return f"[REDACTED:{kind}]"
        text = pattern.sub(_sub, text)
    return text, kinds


def apply_capture_mode(payload, mode: str):
    """Transform a payload for persistence under the given capture mode.

    metadata_only — content-bearing string fields dropped (digests and ids in
                    the envelope survive); structure retained.
    redacted      — content retained with secrets replaced.
    full          — secrets still redacted (SEC-004 applies in every mode for
                    persistence unless the field is explicitly exempted).
    Returns (payload', report).
    """
    if not isinstance(mode, str) or mode not in CAPTURE_MODES:
        raise ValueError(f"unknown capture mode {mode!r}")
    report = {"mode": mode, "redactions": [], "dropped_fields": 0}

    def walk(obj, key: str | None = None, under_content: bool = False):
        # Once we are inside a content-bearing field, EVERYTHING below it is
        # content — GitHub nests prior values (e.g. changes.body.from on an
        # edit), and checking only the immediate key would leave those in
        # plaintext under metadata_only.
        content_here = under_content or key in _CONTENT_FIELDS
        if isinstance(obj, dict):
            return {k: walk(v, k, content_here) for k, v in obj.items()}
        # ``canonical_json`` accepts tuples as the Python representation of a
        # JSON array. Walk them too, and normalize to the array type returned
        # by strict JSON parsing; otherwise a secret nested in a tuple crosses
        # this boundary untouched and is persisted as an array afterwards.
        if isinstance(obj, (list, tuple)):
            return [walk(v, key, content_here) for v in obj]
        if isinstance(obj, str):
            if mode == "metadata_only" and content_here:
                report["dropped_fields"] += 1
                return f"[DROPPED:{key}:{len(obj)}chars]"
            clean, kinds = redact_text(obj)
            report["redactions"].extend(kinds)
            return clean
        return obj

    return walk(payload), report
