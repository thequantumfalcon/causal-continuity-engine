"""Lamport one-time signatures — stranger-verifiable proofs, stdlib only.

CCE's default signer is HMAC (ADR-013). `verify()` there re-signs with the
same secret, so checking a proof requires holding the key that made it —
which means a CCE proof envelope is not verifiable by a stranger, only by
its issuer. That is a real limit on "proof a third party can check", and
this closes it without leaving the standard library.

A Lamport signature needs nothing but a hash function: the private key is
256 pairs of random blocks, the public key is their digests, and signing
reveals one block per message bit. Verification is 256 hash comparisons.

THE PRECONDITION IS THE WHOLE VALUE. A verifier that reads the public key
off the artifact it is checking learns integrity and nothing about
authenticity — an attacker who rewrites the proof simply attaches their own
key. The fingerprint must arrive out of band. `verify_envelope_with()`
therefore REQUIRES an expected fingerprint and refuses to guess (ADR-031).

One-time means one-time: each signature burns its keypair. Reusing a key
for a second message leaks enough preimages to forge a third. `LamportSigner`
generates a fresh keypair per signature and publishes the public key in the
signature block, which is why registration is by fingerprint rather than by
key.

Cost: ~16 KB of public key and ~8 KB of signature per attestation. Use it
for proof envelopes and session capsules, never per event.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from .core import canonical_json, validate_human_text

ALGORITHM = "lamport-sha256/1"
_BITS = 256
_BLOCK = 32
_HEX_BLOCK = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_SIGNATURE_FIELDS = frozenset({
    "key_id", "algorithm", "fingerprint", "public_key", "value",
})


def _validate_key_id(value) -> str:
    return validate_human_text(value, field="Lamport key_id", max_length=256)


def _normalize_fingerprints(values, *, allow_none: bool = False) -> set[str]:
    if values is None and allow_none:
        return set()
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise ValueError("fingerprints must be a list, tuple, set, or frozenset")
    normalized = set(values)
    if any(not isinstance(value, str)
           or _FINGERPRINT.fullmatch(value) is None for value in normalized):
        raise ValueError("fingerprints must be canonical sha256 digest URIs")
    return normalized


def _signature_shape(signature) -> bool:
    return (
        isinstance(signature, dict)
        and set(signature) == _SIGNATURE_FIELDS
        and isinstance(signature.get("key_id"), str)
        and bool(signature["key_id"])
        and signature.get("algorithm") == ALGORITHM
        and isinstance(signature.get("fingerprint"), str)
        and _FINGERPRINT.fullmatch(signature["fingerprint"]) is not None
    )


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_keypair() -> tuple[list[tuple[bytes, bytes]], list[tuple[bytes, bytes]]]:
    """(private, public). Private is 256 pairs of random blocks."""
    private = [(secrets.token_bytes(_BLOCK), secrets.token_bytes(_BLOCK))
               for _ in range(_BITS)]
    public = [(_h(a), _h(b)) for a, b in private]
    return private, public


def fingerprint(public: list[tuple[bytes, bytes]]) -> str:
    """Stable identity of a public key: what gets registered out of band."""
    if (not isinstance(public, list) or len(public) != _BITS
            or any(not isinstance(pair, tuple) or len(pair) != 2
                   or any(not isinstance(block, bytes) or len(block) != _BLOCK
                          for block in pair)
                   for pair in public)):
        raise ValueError("Lamport public key must contain 256 pairs of 32-byte blocks")
    flat = b"".join(a + b for a, b in public)
    return "sha256:" + hashlib.sha256(flat).hexdigest()


def _message_bits(digest: bytes):
    for byte in digest:
        for i in range(8):
            yield (byte >> (7 - i)) & 1


def sign(private: list[tuple[bytes, bytes]], message: bytes) -> list[bytes]:
    """Reveal one preimage per message bit. Burns the keypair."""
    if (not isinstance(message, bytes)
            or not isinstance(private, list) or len(private) != _BITS
            or any(not isinstance(pair, tuple) or len(pair) != 2
                   or any(not isinstance(block, bytes) or len(block) != _BLOCK
                          for block in pair)
                   for pair in private)):
        raise ValueError(
            "Lamport private key and message have malformed runtime types")
    digest = _h(message)
    return [private[i][bit] for i, bit in enumerate(_message_bits(digest))]


def verify(public: list[tuple[bytes, bytes]], message: bytes,
           signature: list[bytes]) -> bool:
    """Hash each revealed block and compare against the public key."""
    if (not isinstance(message, bytes)
            or not isinstance(signature, list) or len(signature) != _BITS
            or any(not isinstance(block, bytes) or len(block) != _BLOCK
                   for block in signature)
            or not isinstance(public, list) or len(public) != _BITS
            or any(not isinstance(pair, tuple) or len(pair) != 2
                   or any(not isinstance(block, bytes) or len(block) != _BLOCK
                          for block in pair)
                   for pair in public)):
        return False
    digest = _h(message)
    ok = True
    for i, bit in enumerate(_message_bits(digest)):
        # Constant-time over the whole loop: no early return on mismatch.
        ok &= hmac.compare_digest(_h(signature[i]), public[i][bit])
    return bool(ok)


def _encode(blocks) -> list[str]:
    return [b.hex() for b in blocks]


def _decode_pairs(pairs) -> list[tuple[bytes, bytes]]:
    if not isinstance(pairs, list) or len(pairs) != _BITS:
        raise ValueError("public_key must contain exactly 256 pairs")
    decoded = []
    for pair in pairs:
        if (not isinstance(pair, list) or len(pair) != 2
                or any(not isinstance(value, str)
                       or _HEX_BLOCK.fullmatch(value) is None for value in pair)):
            raise ValueError("public_key pairs must contain canonical 32-byte hex blocks")
        decoded.append((bytes.fromhex(pair[0]), bytes.fromhex(pair[1])))
    return decoded


def _decode_blocks(values) -> list[bytes]:
    if (not isinstance(values, list) or len(values) != _BITS
            or any(not isinstance(value, str)
                   or _HEX_BLOCK.fullmatch(value) is None for value in values)):
        raise ValueError("signature value must contain 256 canonical 32-byte hex blocks")
    return [bytes.fromhex(value) for value in values]


class LamportSigner:
    """A Signer that a stranger can check, given the fingerprint out of band.

    Implements the same interface as `core.Signer`: `sign(obj) -> dict` and
    `verify(obj) -> bool`. Each `sign()` mints a fresh keypair and records
    its fingerprint, so an issuer publishes the fingerprint list (or a
    per-project registry) rather than one long-lived key.
    """

    algorithm = ALGORITHM

    #: The public key travels WITH the artifact, so a valid signature proves
    #: only that the content is unchanged since someone signed it. Anyone can
    #: mint a keypair. Callers that need to know WHO signed must check the
    #: fingerprint against a registry obtained elsewhere, which is why the
    #: engine refuses to accept these proofs without one.
    self_authenticating = False

    def __init__(self, key_id: str = "local",
                 registered_fingerprints: "set[str] | None" = None):
        self.key_id = _validate_key_id(key_id)
        self.issued_fingerprints: list[str] = []
        #: Fingerprints this signer will vouch for when asked to authenticate.
        #: Populated out of band by the operator, or by an issuer that signs
        #: and registers in one process.
        self.registered_fingerprints = _normalize_fingerprints(
            registered_fingerprints, allow_none=True)

    def register(self, fingerprint_value: str) -> None:
        self.registered_fingerprints.update(
            _normalize_fingerprints([fingerprint_value]))

    @staticmethod
    def derive_fingerprint(signature: dict) -> str | None:
        """The identity of the key ACTUALLY attached, recomputed from it.

        Never returns the `fingerprint` field: that is the signer's claim
        about itself, and an attacker writes whatever they like there
        (ADR-044). Only the key material decides.
        """
        if not _signature_shape(signature):
            return None
        try:
            public = _decode_pairs(signature["public_key"])
        except (KeyError, TypeError, ValueError):
            return None
        return fingerprint(public)

    def sign(self, obj: dict) -> dict:
        if not isinstance(obj, dict):
            raise ValueError("Lamport signed object must be an object")
        body = {k: v for k, v in obj.items() if k != "signature"}
        try:
            message = canonical_json(body).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError(f"Lamport signed object must be canonical JSON: {exc}") from None
        private, public = generate_keypair()
        fp = fingerprint(public)
        self.issued_fingerprints.append(fp)
        # An issuer trusts the keys it minted itself; a verifier on another
        # machine must be given these fingerprints out of band.
        self.registered_fingerprints.add(fp)
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "fingerprint": fp,
            "public_key": [[a.hex(), b.hex()] for a, b in public],
            "value": _encode(sign(private, message)),
        }

    def verify(self, obj: dict) -> bool:
        """Integrity only.

        Deliberately does NOT establish authenticity: the public key comes
        from the artifact being checked. Use `verify_envelope_with()` with a
        fingerprint you obtained elsewhere to learn who signed it.
        """
        if not isinstance(obj, dict):
            return False
        sig = obj.get("signature")
        if not _signature_shape(sig):
            return False
        try:
            public = _decode_pairs(sig["public_key"])
            blocks = _decode_blocks(sig["value"])
        except (KeyError, TypeError, ValueError):
            return False
        body = {k: v for k, v in obj.items() if k != "signature"}
        try:
            message = canonical_json(body).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False
        return verify(public, message, blocks)


class UnregisteredKeyError(Exception):
    """The signature is intact but nobody vouched for the key that made it."""


def verify_envelope_with(obj: dict, *, expected_fingerprints) -> dict:
    """Stranger verification: integrity AND authenticity.

    `expected_fingerprints` must come from somewhere other than the artifact
    — a registry, a pinned config, a published list. Without it a valid
    signature says only "this object has not changed since someone signed
    it", which is not the question a third party is asking.
    """
    expected = _normalize_fingerprints(expected_fingerprints)
    if not expected:
        raise UnregisteredKeyError(
            "no expected fingerprints supplied: reading the key off the "
            "artifact would verify it against itself")
    if not isinstance(obj, dict):
        return {"valid": False, "reason": "envelope must be an object"}
    sig = obj.get("signature")
    if not _signature_shape(sig):
        return {"valid": False, "reason": "malformed Lamport signature shape"}
    try:
        public = _decode_pairs(sig["public_key"])
        blocks = _decode_blocks(sig["value"])
    except (KeyError, TypeError, ValueError) as exc:
        return {"valid": False, "reason": f"malformed signature: {exc}"}

    actual = fingerprint(public)
    claimed = sig.get("fingerprint")
    if claimed != actual:
        return {"valid": False, "reason": "declared fingerprint does not match "
                                          "the attached public key"}
    body = {k: v for k, v in obj.items() if k != "signature"}
    try:
        message = canonical_json(body).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return {"valid": False, "reason": f"malformed envelope body: {exc}"}
    if not verify(public, message, blocks):
        return {"valid": False, "reason": "signature does not cover this content",
                "fingerprint": actual}
    if actual not in expected:
        return {"valid": False, "authentic": False, "fingerprint": actual,
                "reason": "signature is intact but the key is not registered: "
                          "anyone can mint a keypair and sign a rewritten proof"}
    return {"valid": True, "authentic": True, "fingerprint": actual}
