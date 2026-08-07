"""Core primitives: ids, canonical JSON, digests, time, signing.

Every material artifact is digest-addressed (ADR-004). Signing defaults to
HMAC-SHA256 with tenant-scoped keys (ADR-013); asymmetric schemes plug in via
the same interface.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
from datetime import datetime, timedelta, timezone
from threading import Lock

ID_PREFIXES = {
    "tenant": "ten",
    "project": "prj",
    "event": "evt",
    "artifact": "art",
    "claim": "clm",
    "assumption": "asm",
    "requirement": "req",
    "constraint": "cst",
    "decision": "dec",
    "plan": "pln",
    "task": "tsk",
    "action": "act",
    "evidence": "evd",
    "verification": "ver",
    "session": "ses",
    "outcome": "out",
    "skill": "skl",
    "evaluation": "evl",
    "invalidation": "inv",
    "packet": "rsp",
    "capsule": "cap",
    "proof": "prf",
    "checkpoint": "ckp",
    "grant": "grt",
    "replay": "rpl",
    "failure": "flr",
    "node": "nod",
    "edge": "edg",
}

# Public resource identifiers are embedded as one HTTP path segment. Keep the
# contract to RFC 3986 unreserved ASCII so a stored identity has exactly one
# transport spelling: no slash, percent escape, Unicode normalization, control
# byte, whitespace, or dot-segment ambiguity (ADR-102).
PUBLIC_IDENTIFIER_MAX_LENGTH = 128
PUBLIC_IDENTIFIER_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
)
_PUBLIC_IDENTIFIER = re.compile(PUBLIC_IDENTIFIER_PATTERN, re.ASCII)

PROJECT_NAME_MAX_LENGTH = 256
REPOSITORY_COMPONENT_MAX_LENGTH = 100
REPOSITORY_NAME_MAX_LENGTH = REPOSITORY_COMPONENT_MAX_LENGTH * 2 + 1
_REPOSITORY_NAME = re.compile(
    rf"[A-Za-z0-9_.-]{{1,{REPOSITORY_COMPONENT_MAX_LENGTH}}}/"
    rf"[A-Za-z0-9_.-]{{1,{REPOSITORY_COMPONENT_MAX_LENGTH}}}\Z",
    re.ASCII,
)
_UNSAFE_HUMAN_CONTROLS = {
    0x061C, 0x200E, 0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
}


# Transaction-time intervals are half open.  On platforms whose wall clock has
# coarser than microsecond resolution, two adjacent writes used to receive the
# same timestamp and there was no representable instant between their versions.
# This process-local floor gives callers strict ordering without pretending to
# coordinate clocks between processes or machines.
_utcnow_lock = Lock()
_last_utcnow: datetime | None = None
_CANONICAL_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_RFC3339_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-][0-9]{2}:[0-9]{2})\Z",
    re.ASCII,
)


def new_id(kind: str) -> str:
    prefix = ID_PREFIXES.get(kind, kind[:3])
    return validate_public_identifier(
        f"{prefix}_{secrets.token_hex(12)}", field="generated identifier")


def is_public_identifier(value: object) -> bool:
    """Whether *value* has one bounded URI-path-segment representation."""
    return (
        isinstance(value, str)
        and _PUBLIC_IDENTIFIER.fullmatch(value) is not None
    )


def validate_public_identifier(value: object, *, field: str = "identifier") -> str:
    """Return a valid public identifier or raise a deterministic ValueError."""
    if not is_public_identifier(value):
        raise ValueError(
            f"{field} must be 1-{PUBLIC_IDENTIFIER_MAX_LENGTH} ASCII URI-"
            "unreserved characters, beginning with a letter or digit")
    return value


def validate_human_text(
    value: object,
    *,
    field: str,
    max_length: int = PROJECT_NAME_MAX_LENGTH,
) -> str:
    """Validate bounded display text before it reaches JSON, logs, or a TTY."""
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(
            f"{field} must be a non-empty string of at most {max_length} "
            "Unicode characters")
    _validate_i_json_string(value, path=field)
    for char in value:
        codepoint = ord(char)
        if (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F
                or codepoint in _UNSAFE_HUMAN_CONTROLS):
            raise ValueError(
                f"{field} must not contain control character U+{codepoint:04X}")
    return value


def validate_repository_name(
    value: object,
    *,
    field: str = "repository",
    optional: bool = False,
) -> str | None:
    """Validate one bounded, transport-stable GitHub ``owner/name`` value."""
    if value is None and optional:
        return None
    if (not isinstance(value, str)
            or len(value) > REPOSITORY_NAME_MAX_LENGTH
            or _REPOSITORY_NAME.fullmatch(value) is None):
        suffix = " or null" if optional else ""
        raise ValueError(
            f"{field} must be a non-empty ASCII owner/name{suffix}; each "
            f"component is limited to {REPOSITORY_COMPONENT_MAX_LENGTH} "
            "letters, digits, dots, underscores, or hyphens")
    owner, repository = value.split("/", 1)
    if owner in {".", ".."} or repository in {".", ".."}:
        raise ValueError(f"{field} components must not be dot segments")
    return value


def utcnow() -> str:
    global _last_utcnow
    sampled = datetime.now(timezone.utc)
    with _utcnow_lock:
        if _last_utcnow is not None and sampled <= _last_utcnow:
            sampled = _last_utcnow + timedelta(microseconds=1)
        _last_utcnow = sampled
    return sampled.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp; 'Z' suffix and offsets both accepted."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_canonical_utc_timestamp(value: object) -> bool:
    """Whether value is CCE's emitted, real-calendar UTC timestamp form."""
    if (not isinstance(value, str)
            or _CANONICAL_UTC_TIMESTAMP.fullmatch(value) is None):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError, OverflowError):
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") == value


def is_rfc3339_datetime(value: object) -> bool:
    """Whether *value* is a timezone-qualified, real-calendar RFC3339 time."""
    if (not isinstance(value, str)
            or _RFC3339_TIMESTAMP.fullmatch(value) is None):
        return False
    normalized = value[:10] + "T" + value[11:]
    if normalized.endswith("z"):
        normalized = normalized[:-1] + "Z"
    try:
        parse_ts(normalized)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False
    return True


def _validate_i_json_string(value: str, *, path: str) -> None:
    """Reject Unicode values excluded by RFC 7493's I-JSON profile."""
    for char in value:
        codepoint = ord(char)
        if (0xD800 <= codepoint <= 0xDFFF
                or 0xFDD0 <= codepoint <= 0xFDEF
                or codepoint & 0xFFFF in (0xFFFE, 0xFFFF)):
            raise ValueError(
                f"non-I-JSON Unicode U+{codepoint:04X} at {path}")


_JCS_SHORT_ESCAPES = {
    "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r",
    '"': '\\"', "\\": "\\\\",
}


def _jcs_string(value: str, *, path: str) -> str:
    """Apply the exact ECMAScript JSON string escaping used by RFC 8785."""
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
    """Serialize one binary64 value as ECMAScript requires for RFC 8785."""
    try:
        number = float(value)
    except OverflowError:
        raise ValueError(f"number outside binary64 at {path}") from None
    if not math.isfinite(number):
        raise ValueError(f"non-finite JSON number at {path}")
    if isinstance(value, int) and int(number) != value:
        # Python integers are unbounded.  Silently rounding one into the JCS
        # binary64 data model would sign a different value from the caller's.
        raise ValueError(f"integer is not exactly representable as binary64 at {path}")
    if number == 0:
        return "0"  # ECMAScript serializes positive and negative zero alike.

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

    # RFC 8785 §3.2.2.3 delegates number spelling to ECMAScript.  Python's
    # repr supplies the same shortest round-tripping significand; these are
    # ECMAScript's fixed/exponential presentation thresholds and exponent form.
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
    """RFC 8785 object order is raw UTF-16 code units, not code points."""
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
    if isinstance(value, int):
        return _jcs_number(value, path=path)
    if isinstance(value, float):
        return _jcs_number(value, path=path)

    if isinstance(value, (list, tuple)):
        marker = id(value)
        if marker in markers:
            raise ValueError(f"circular JSON value at {path}")
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
            raise ValueError(f"circular JSON value at {path}")
        keys = list(value)
        for key in keys:
            if not isinstance(key, str):
                raise TypeError(f"JSON object key at {path} is not a string")
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

    raise TypeError(f"value at {path} is not a JSON type")


def canonical_json(obj) -> str:
    """RFC 8785 JCS text over the RFC 7493 I-JSON data model."""
    return _render_jcs(obj, markers=set(), path="$")


def _validate_i_json(value, *, path: str = "$") -> None:
    """Validate parsed JSON without allocating a second serialized copy."""
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
    raise TypeError(f"value at {path} is not a JSON type")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON value {value!r}")


def strict_json_loads(value: str | bytes | bytearray):
    """Parse the RFC 7493 I-JSON domain consumed by RFC 8785 JCS.

    Duplicate member names have parser-dependent meaning and therefore cannot
    be safely signed, hashed, or used as control state.  The remaining checks
    reject non-finite or non-binary64 numbers and invalid I-JSON Unicode before
    those values can become CCE control state.
    """
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError(
                "JSON bytes must be valid UTF-8 without a BOM") from None
    if isinstance(value, str) and value.startswith("\ufeff"):
        raise ValueError("JSON text must not begin with a BOM")
    try:
        parsed = json.loads(
            value, object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant)
        _validate_i_json(parsed)
    except RecursionError:
        raise ValueError("JSON nesting exceeds supported depth") from None
    return parsed


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_obj(obj) -> str:
    """Digest of the canonical JSON form of a structure."""
    return sha256_hex(canonical_json(obj))


class Signer:
    """HMAC-SHA256 signer over canonical JSON. Tenant-scoped key material.

    sign()/verify() operate on the object WITHOUT its 'signature' field; the
    envelope carries {key_id, algorithm, value}.
    """

    algorithm = "hmac-sha256"

    #: A correct HMAC proves authenticity on its own: producing one requires
    #: the shared secret, which the claimant does not hold. Schemes that
    #: carry their own public key (see causal_continuity_engine.lamport) do NOT
    #: have this property
    #: — anyone can mint a keypair — so they must declare False and force the
    #: caller to check a fingerprint obtained out of band.
    self_authenticating = True

    def __init__(self, key_id: str, key: bytes):
        self.key_id = key_id
        self._key = key

    @classmethod
    def generate(cls, key_id: str = "local") -> "Signer":
        return cls(key_id, secrets.token_bytes(32))

    def sign(self, obj: dict) -> dict:
        body = {k: v for k, v in obj.items() if k != "signature"}
        mac = hmac.new(
            self._key, canonical_json(body).encode("utf-8"), hashlib.sha256)
        return {"key_id": self.key_id, "algorithm": self.algorithm, "value": mac.hexdigest()}

    def verify(self, obj: dict) -> bool:
        if not isinstance(obj, dict):
            return False
        sig = obj.get("signature")
        if (not isinstance(sig, dict)
                or sig.get("algorithm") != self.algorithm
                or sig.get("key_id") != self.key_id):
            return False
        supplied = sig.get("value")
        if (not isinstance(supplied, str)
                or re.fullmatch(r"[0-9a-f]{64}", supplied, re.ASCII) is None):
            return False
        expected = self.sign(obj)
        return hmac.compare_digest(expected["value"], supplied)
