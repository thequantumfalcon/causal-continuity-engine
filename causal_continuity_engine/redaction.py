"""Capture modes and secret redaction (SEC-003, SEC-004, TM-006).

Applied BEFORE durable persistence: the store receives already-redacted
payloads in 'redacted' mode and digest/metadata-only envelopes in
'metadata_only' mode. Redaction is recorded (count, kinds), never the
secrets themselves. A secret-bearing mapping key is refused because replacing
it could collide with another key, while preserving it would persist the
secret in every capture mode. Ordinary capture never trusts sentinel-shaped
source text. A separate stored-output validator recognizes exact metadata-only
placeholders structurally so a producer output can be processed again.
"""

from __future__ import annotations

import re

CAPTURE_MODES = {"metadata_only", "redacted", "full"}

_PRIVATE_KEY_KIND = "private_key_block"
_PRIVATE_KEY_MARKER = re.compile(
    r"-----(?P<action>BEGIN|END) (?P<label>[A-Z ]*PRIVATE KEY)-----")
_PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PRIVATE_KEY_BODY_LINE = re.compile(
    r"(?:[A-Za-z0-9+/=]+|[A-Za-z0-9-]+:[ \t]*[A-Za-z0-9,./+=-]+)")
_PRIVATE_KEY_LINE_BREAK = re.compile(r"\r\n?|\n")
_PRIVATE_KEY_INLINE_WHITESPACE = str.maketrans("", "", " \t\v\f")

# No word-boundary anchors. `_` and `-` are word or identifier characters and
# diff markers, so `\b` next to one suppressed the match and the secret was
# persisted in clear text. Redaction must fail safe: matching a secret embedded
# in a longer identifier over-redacts, which is the harmless direction, while a
# trailing anchor only forces the backtracking that left a token's tail behind.
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret", re.compile(
        r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key[\"'\s:=]+[A-Za-z0-9/+=]{30,}")),
    (_PRIVATE_KEY_KIND, _PRIVATE_KEY_BEGIN),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9_-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("generic_assignment", re.compile(
        r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
        r"\s*[:=]\s*[\"']?[^\s\"']{8,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai_key", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("gitlab_token", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"AIza[A-Za-z0-9_-]{35}")),
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("pypi_token", re.compile(r"pypi-[A-Za-z0-9_-]{30,}")),
    ("stripe_key", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("stripe_key", re.compile(r"rk_(?:live|test)_[A-Za-z0-9]{16,}")),
]

_CONTENT_FIELDS = {"body", "text", "content", "message", "description", "output",
                   "title", "diff", "patch", "stdout", "stderr",
                   # GitHub wraps the previous value of an edited field here
                   "changes", "commit_message", "summary", "note"}


def _canonical_placeholder_count(count: str) -> bool:
    return count == "0" or (
        bool(count) and count[0] in "123456789"
        and all(character in "0123456789" for character in count[1:]))


def _is_metadata_placeholder(value: str, key: str | None) -> bool:
    """Whether ``value`` has exactly the placeholder syntax emitted for key."""
    if key is None:
        return False
    prefix = f"[DROPPED:{key}:"
    suffix = "chars]"
    if not value.startswith(prefix) or not value.endswith(suffix):
        return False
    return _canonical_placeholder_count(value[len(prefix):-len(suffix)])


def _private_key_spans(text: str) -> list[tuple[int, int]]:
    """Locate complete or visibly truncated PEM blocks in one linear pass.

    An END marker closes a complete block regardless of its contents;
    malformed key material is still sensitive. Only a block with no END uses
    the narrower PEM-line boundary below.

    A truncated block ends after its last PEM-shaped line. Candidate lines
    ignore SP, HT, VT and FF, while CR, LF and CRLF delimit lines. This
    syntax-only fail-closed policy can over-redact whitespace-separated
    control text made only from the base64 alphabet through EOF; trailing
    blank-only lines are scanned across but do not advance the span.
    """
    complete: list[tuple[int, int]] = []
    truncated: list[tuple[int, int, int]] = []
    active: tuple[int, int] | None = None

    for marker in _PRIVATE_KEY_MARKER.finditer(text):
        action = marker.group("action")
        if action == "BEGIN":
            if active is not None:
                truncated.append((active[0], active[1], marker.start()))
            active = (marker.start(), marker.end())
        elif active is not None:
            complete.append((active[0], marker.end()))
            active = None

    if active is not None:
        truncated.append((active[0], active[1], len(text)))

    def bounded_end(marker_end: int, limit: int) -> int:
        end = marker_end
        cursor = marker_end
        while cursor < limit:
            line_break = _PRIVATE_KEY_LINE_BREAK.search(text, cursor, limit)
            content_end = limit if line_break is None else line_break.start()
            content = text[cursor:content_end].translate(
                _PRIVATE_KEY_INLINE_WHITESPACE)
            if content and _PRIVATE_KEY_BODY_LINE.fullmatch(content) is None:
                break
            if content:
                end = content_end
            if line_break is None:
                break
            cursor = line_break.end()
        return end

    spans = complete + [
        (start, bounded_end(marker_end, limit))
        for start, marker_end, limit in truncated
    ]
    return sorted(spans)


def scan_secrets(text: str) -> list[dict]:
    findings = []
    for kind, pattern in _SECRET_PATTERNS:
        if kind == _PRIVATE_KEY_KIND:
            findings.extend(
                {"kind": kind, "start": start, "end": end}
                for start, end in _private_key_spans(text)
            )
            continue
        for m in pattern.finditer(text):
            findings.append({"kind": kind, "start": m.start(), "end": m.end()})
    return findings


def redact_text(text: str) -> tuple[str, list[str]]:
    """Replace secrets with typed placeholders. Returns (clean, kinds_found)."""
    kinds: list[str] = []
    private_key_spans = _private_key_spans(text)
    if private_key_spans:
        replacement = f"[REDACTED:{_PRIVATE_KEY_KIND}]"
        parts = []
        cursor = 0
        for start, end in private_key_spans:
            parts.extend((text[cursor:start], replacement))
            cursor = end
        parts.append(text[cursor:])
        text = "".join(parts)
    kinds.extend(_PRIVATE_KEY_KIND for _ in private_key_spans)
    for kind, pattern in _SECRET_PATTERNS:
        if kind == _PRIVATE_KEY_KIND:
            continue
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
            if any(isinstance(k, str) and scan_secrets(k) for k in obj):
                raise ValueError(
                    "capture payload contains a secret-bearing object key")
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


def _capture_payload_is_current(payload, mode: str) -> bool:
    """Validate stored output without treating source sentinels as provenance.

    Every mapping key and retained string must satisfy current secret handling.
    Metadata-only output additionally requires every string below a content
    field to have the exact placeholder syntax for its current key.
    """
    if not isinstance(mode, str) or mode not in CAPTURE_MODES:
        raise ValueError(f"unknown capture mode {mode!r}")

    def valid(obj, key: str | None = None, under_content: bool = False):
        content_here = under_content or key in _CONTENT_FIELDS
        if isinstance(obj, dict):
            if any(not isinstance(item_key, str) or scan_secrets(item_key)
                   for item_key in obj):
                return False
            return all(
                valid(item, item_key, content_here)
                for item_key, item in obj.items())
        if isinstance(obj, (list, tuple)):
            return all(valid(item, key, content_here) for item in obj)
        if isinstance(obj, str):
            if mode == "metadata_only" and content_here:
                return _is_metadata_placeholder(obj, key)
            return redact_text(obj)[0] == obj
        return True

    return valid(payload)
