#!/usr/bin/env python3
"""Generate the conformance corpus for SPEC.md.

Every vector is produced BY the reference implementation and its expected
verdict is derived from the reference's own behaviour, so the corpus cannot
be written to agree with a verifier that is wrong. Regenerating and diffing
is the drift guard: if the reference changes what it emits, the corpus
changes, and the independent verifier must be updated to match or CI fails.

    python vectors/generate.py            # regenerate vectors/
    python vectors/generate.py --check    # reference must still agree

`--check` does NOT compare bytes. Ids, timestamps and Lamport keypairs are
fresh on every run, so a byte comparison would fail always and prove
nothing. It asks the question that matters instead: does the REFERENCE
implementation, applied to each committed vector, still reach the verdict
the corpus records? Together with tests/test_conformance.py — which asks
the same of the independent verifier — that pins both implementations to
one committed set of expectations, and either one drifting fails the build.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from causal_continuity_engine.core import digest_obj  # noqa: E402
from causal_continuity_engine.engine import Engine  # noqa: E402
from causal_continuity_engine.lamport import LamportSigner  # noqa: E402
from causal_continuity_engine.proof import evaluate_status  # noqa: E402

OUT = ROOT / "vectors"

#: Frozen so the corpus is byte-stable across runs.
FIXED_HMAC_KEY = bytes.fromhex(
    "5cce0000000000000000000000000000000000000000000000000000000000ff")


def _python_command(script: str) -> str:
    """Render an argv string that the verifier's POSIX shlex parser preserves."""
    return f"{json.dumps(sys.executable)} -c {json.dumps(script)}"


def _reads_deliverable() -> str:
    return _python_command(
        "import pathlib,sys; "
        "sys.exit(0 if pathlib.Path('deliverable.py').read_text() else 1)")


def _fails() -> str:
    return _python_command("raise SystemExit(1)")


def _mint(workdir: Path, *, signer, command=None, bind_task=True):
    """One honest attestation from the reference implementation."""
    (workdir / "deliverable.py").write_text("def f(): return 1\n")
    cfg = {
        "max_autonomy_level": 2, "require_proof_for": ["task_complete"],
        "min_evidence_grade": "C",
        "required_verifiers": [{
            "name": "unit-tests", "command": command or _reads_deliverable(),
            "expect_fail_command": _fails(),
            "artifacts": ["deliverable.py"]}],
    }
    engine = Engine(workdir=workdir, signer=signer)
    engine.create_project("vectors", project_id="prj_vectors", config=cfg)
    engine.policy.grant(project_id="prj_vectors", level=2, granted_by="lead")
    engine.policy.set_project_config("prj_vectors", cfg)
    task = engine.graph.put_node(
        entity_type="task", tenant_id=engine.tenant_id,
        project_id="prj_vectors", data={"title": "ship it"}, status="open")
    proof = engine.attest_action(
        "prj_vectors", intent_type="task_complete",
        intent_statement="the exporter is done", actor={"agent": "generator"},
        action_type="run_verifier",
        continuity={"task_ids": [task.id]} if bind_task else None)
    engine.close()
    return proof, task.id


def _reseal(proof: dict) -> dict:
    """Recompute the digest so a tamper is internally consistent."""
    proof["proof_digest"] = digest_obj(
        {k: v for k, v in proof.items()
         if k not in ("signature", "proof_digest")})
    return proof


def build() -> list[dict]:
    """Each vector: name, envelope, expected verdict, expected error codes."""
    vectors: list[dict] = []
    from causal_continuity_engine.core import Signer

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        hmac_signer = Signer("vectors", FIXED_HMAC_KEY)
        good_hmac, task_id = _mint(work, signer=hmac_signer)

        lam = LamportSigner("vectors-lamport")
        good_lam, lam_task = _mint(work, signer=lam)
        lam_fp = good_lam["signature"]["fingerprint"]

        failed_hmac, _ = _mint(work, signer=hmac_signer, command=_fails())
        unbound, _ = _mint(work, signer=hmac_signer, bind_task=False)

    def add(name, envelope, verdict, errors=(), **ctx):
        vectors.append({
            "name": name, "expected_verdict": verdict,
            "expected_errors": sorted(errors), "context": ctx,
            "envelope": envelope,
        })

    key_hex = FIXED_HMAC_KEY.hex()

    def empty_required(verifications):
        """Reseal a boundary envelope with no declared verifier set."""
        envelope = json.loads(json.dumps(good_hmac))
        envelope["execution"] = []
        envelope["verifications"] = verifications
        envelope["evidence_context"] = {
            "unpinned_required": [],
            "policy_pinned": [],
            "mutation": None,
            "determinism": {},
        }
        policy_config = envelope["policy_decision"].get("policy_config")
        if isinstance(policy_config, dict):
            policy_config["require_proof_for"] = []
            policy_config["required_verifiers"] = []
        (
            envelope["status"],
            envelope["verification_summary"],
        ) = evaluate_status(verifications, [])
        _reseal(envelope)
        envelope["signature"] = hmac_signer.sign(envelope)
        return envelope

    # ---- valid -----------------------------------------------------------
    add("valid_hmac", good_hmac, "VALID", hmac_key_hex=key_hex,
        expect_project="prj_vectors", expect_task=task_id)
    unicode_hmac = json.loads(json.dumps(good_hmac))
    unicode_hmac["action_intent"]["statement"] = (
        "Ship café parser — 東京 / مرحبا / 🚀")
    _reseal(unicode_hmac)
    unicode_hmac["signature"] = hmac_signer.sign(unicode_hmac)
    add("valid_hmac_unicode", unicode_hmac, "VALID", hmac_key_hex=key_hex,
        expect_project="prj_vectors", expect_task=task_id)
    jcs_edges = json.loads(json.dumps(good_hmac))
    jcs_edges["environment"]["jcs_edges"] = {
        "numbers": [-0.0, 1.0, 1e-6, 1e-7, 1e20, 1e21],
        "escape_sample": "\u20ac$\x0f\nA'B\"\\\\\"/",
        "\ue000": "bmp",
        "\U0001f600": "astral",
    }
    _reseal(jcs_edges)
    jcs_edges["signature"] = hmac_signer.sign(jcs_edges)
    add("valid_hmac_jcs_edges", jcs_edges, "VALID", hmac_key_hex=key_hex,
        expect_project="prj_vectors", expect_task=task_id)
    add(
        "empty_required_authoritative_pass",
        empty_required([{
            "verifier": "optional-check",
            "result": "passed",
            "source": "executed",
        }]),
        "VALID",
        hmac_key_hex=key_hex,
    )
    # ---- undecidable: honest, unforged, and still not established ---------
    # A stranger holds no HMAC secret, so C2 and C3 are SKIPPED and the
    # verdict is UNVERIFIED (SPEC §5, §9) — NOT VALID. The pair below is the
    # point of the vector: an untouched envelope and a forged one are
    # indistinguishable without the key, so reporting VALID for the first
    # would necessarily report VALID for the second.
    add("unverified_hmac_no_key", good_hmac, "UNVERIFIED",
        expect_project="prj_vectors")

    t = _reseal(json.loads(json.dumps(good_hmac)))
    t["action_intent"]["statement"] = "I did work I did not do"
    add("unverified_forged_body_no_key", _reseal(t), "UNVERIFIED",
        expect_project="prj_vectors")
    add("valid_lamport", good_lam, "VALID", fingerprints=[lam_fp],
        expect_project="prj_vectors", expect_task=lam_task)

    # ---- honest negatives: authentic records of work not done -------------
    add("incomplete_failed_check", failed_hmac, "INCOMPLETE",
        hmac_key_hex=key_hex)
    add(
        "empty_required_no_results",
        empty_required([]),
        "INCOMPLETE",
        hmac_key_hex=key_hex,
    )
    add(
        "empty_required_self_asserted_pass",
        empty_required([{
            "verifier": "optional-check",
            "result": "passed",
            "source": "self_asserted",
        }]),
        "INCOMPLETE",
        hmac_key_hex=key_hex,
    )
    add(
        "empty_required_authoritative_failure",
        empty_required([
            {
                "verifier": "optional-check",
                "result": "passed",
                "source": "executed",
            },
            {
                "verifier": "second-check",
                "result": "failed",
                "source": "verifier_authoritative",
            },
        ]),
        "INCOMPLETE",
        hmac_key_hex=key_hex,
    )

    # ---- adversarial -----------------------------------------------------
    t = json.loads(json.dumps(good_hmac))
    t["action_intent"]["statement"] = "something else entirely"
    add("tamper_statement", t, "INVALID", ["E_DIGEST"], hmac_key_hex=key_hex)

    t = _reseal(json.loads(json.dumps(good_hmac)))
    t["action_intent"]["statement"] = "something else entirely"
    add("tamper_statement_resealed", _reseal(t), "INVALID", ["E_SIGNATURE"],
        hmac_key_hex=key_hex)

    t = json.loads(json.dumps(good_hmac))
    t["status"] = "verified"
    t["verifications"][0]["result"] = "failed"
    add("status_contradicts_contents", _reseal(t), "INVALID",
        ["E_SIGNATURE", "E_STATUS"], hmac_key_hex=key_hex)

    t = json.loads(json.dumps(good_hmac))
    for v in t["verifications"]:
        v["source"] = "self_asserted"
    add("self_asserted_cannot_satisfy", _reseal(t), "INVALID",
        ["E_SIGNATURE", "E_STATUS"], hmac_key_hex=key_hex)

    # An unauthoritative claimant cannot deny service to genuine evidence by
    # appending a worse report under the same verifier display name.
    t = json.loads(json.dumps(good_hmac))
    t["verifications"].append({
        **t["verifications"][0],
        "source": "self_asserted",
        "result": "failed",
    })
    _reseal(t)
    t["signature"] = hmac_signer.sign(t)
    add("self_assertion_cannot_poison_authoritative_pass", t, "VALID", [],
        hmac_key_hex=key_hex)

    t = json.loads(json.dumps(good_lam))
    t["signature"]["fingerprint"] = "sha256:" + "0" * 64
    add("lamport_fingerprint_spoof", t, "INVALID", ["E_FINGERPRINT"],
        fingerprints=[lam_fp])

    add("lamport_no_registry", good_lam, "INVALID", ["E_UNREGISTERED"])

    t = json.loads(json.dumps(good_lam))
    t["signature"]["public_key"] = t["signature"]["public_key"][:255]
    add("lamport_truncated_key", t, "INVALID", ["E_SIGNATURE"],
        fingerprints=[lam_fp])

    add("unbound_task", unbound, "INVALID", ["E_UNBOUND"],
        hmac_key_hex=key_hex, expect_task="tsk_not_named_here")

    # Merely carrying the target under an unrelated field must not satisfy a
    # typed task relation.  This vector is otherwise genuine and correctly
    # re-signed, so E_UNBOUND cannot be hidden behind a signature failure.
    t = json.loads(json.dumps(good_hmac))
    t["continuity_links"] = {"unrelated_ids": [task_id]}
    _reseal(t)
    t["signature"] = hmac_signer.sign(t)
    add("task_id_under_unrelated_field", t, "INVALID", ["E_SHAPE"],
        hmac_key_hex=key_hex, expect_task=task_id)

    add("wrong_project", good_hmac, "INVALID", ["E_PROJECT"],
        hmac_key_hex=key_hex, expect_project="prj_somewhere_else")

    t = json.loads(json.dumps(good_hmac))
    del t["verification_summary"]
    add("missing_required_field", t, "INVALID", ["E_SHAPE"])

    # Every shape here is one a real producer emits by accident: a naive
    # datetime, a space separator from a database column, lowercase
    # designators from a hand-built string, and a leap second that no
    # calendar library will parse.  Each must be refused on shape, before
    # any digest or signature work, so a malformed instant can never be
    # signed into the record and read back as a real moment.
    for name, created_at in (
        ("created_at_noncanonical_offset", "2026-08-04T04:05:06+00:00"),
        ("created_at_invalid_calendar_date",
         "2026-02-30T04:05:06.123456Z"),
        ("created_at_missing_timezone", "2026-08-04T04:05:06.123456"),
        ("created_at_space_separator", "2026-08-04 04:05:06.123456Z"),
        ("created_at_lowercase_designators", "2026-08-04t04:05:06.123456z"),
        ("created_at_leap_second", "2026-06-30T23:59:60.000000Z"),
    ):
        t = json.loads(json.dumps(good_hmac))
        t["created_at"] = created_at
        _reseal(t)
        t["signature"] = hmac_signer.sign(t)
        add(name, t, "INVALID", ["E_SHAPE"], hmac_key_hex=key_hex)

    t = json.loads(json.dumps(good_hmac))
    t["schema_version"] = "cce.proof.v2"
    add("unknown_schema_version", t, "INVALID", ["E_SHAPE"])

    t = json.loads(json.dumps(good_hmac))
    t["signature"]["algorithm"] = "rot13"
    add("unknown_algorithm", t, "INVALID", ["E_SCHEME"], hmac_key_hex=key_hex)

    t = json.loads(json.dumps(good_hmac))
    t["verifications"][0]["result"] = "definitely-fine"
    add("invalid_result_value", _reseal(t), "INVALID", ["E_SHAPE"])

    t = json.loads(json.dumps(good_hmac))
    t["verification_summary"]["passed"] = []
    _reseal(t)
    t["signature"] = hmac_signer.sign(t)
    add("summary_contradicts_contents", t, "INVALID", ["E_STATUS"],
        hmac_key_hex=key_hex)

    # A valid signature cannot manufacture semantics for malformed nested
    # values.  These cases specifically guard parity between the reference
    # runtime and the independent verifier rather than relying on a digest or
    # signature failure to hide structural disagreement.
    for name, field, value in (
        ("actor_wrong_type", "actor", "worker"),
        ("action_intent_wrong_type", "action_intent", ["task_complete"]),
        ("policy_decision_wrong_type", "policy_decision", ["allow"]),
        ("input_item_wrong_type", "inputs", [42]),
    ):
        t = json.loads(json.dumps(good_hmac))
        t[field] = value
        _reseal(t)
        t["signature"] = hmac_signer.sign(t)
        add(name, t, "INVALID", ["E_SHAPE"], hmac_key_hex=key_hex)

    # cce.proof.v1 is a closed contract.  Unknown fields cannot acquire
    # meaning merely by being covered by a signature.
    t = json.loads(json.dumps(good_hmac))
    t["future_semantics"] = {"completed": True}
    _reseal(t)
    t["signature"] = hmac_signer.sign(t)
    add("unknown_top_level_field", t, "INVALID", ["E_SHAPE"],
        hmac_key_hex=key_hex)

    t = json.loads(json.dumps(good_hmac))
    t["action_intent"]["future_semantics"] = "complete"
    _reseal(t)
    t["signature"] = hmac_signer.sign(t)
    add("unknown_action_intent_field", t, "INVALID", ["E_SHAPE"],
        hmac_key_hex=key_hex)

    # An unknown field is refused wherever it appears, not only at the top
    # level and in action_intent.  A reader that tolerated one inside a
    # verification, an execution record, or the evidence context would accept an
    # envelope carrying meaning it cannot see, which is how a future
    # producer silently changes what a proof asserts.
    for name, mutate in (
        ("unknown_verification_field",
         lambda e: e["verifications"][0].__setitem__("future_field", "x")),
        ("unknown_execution_field",
         lambda e: e["execution"][0].__setitem__("future_field", "x")),
        ("unknown_evidence_context_field",
         lambda e: e["evidence_context"].__setitem__("future_field", "x")),
    ):
        t = json.loads(json.dumps(good_hmac))
        mutate(t)
        _reseal(t)
        t["signature"] = hmac_signer.sign(t)
        add(name, t, "INVALID", ["E_SHAPE"], hmac_key_hex=key_hex)

    # Python preserves arbitrary-precision integers while JCS consumes the
    # binary64 I-JSON domain.  Rounding this value would sign a different
    # integer, so rejection must precede shape, digest, and signature checks.
    t = json.loads(json.dumps(good_hmac))
    t["environment"]["non_binary64_integer"] = 9_007_199_254_740_993
    add("non_binary64_integer", t, "INVALID", ["E_CJSON"],
        hmac_key_hex=key_hex)

    # A duplicate report where the WORST must win (SPEC §7.1).
    t = json.loads(json.dumps(good_hmac))
    t["verifications"].append(dict(t["verifications"][0], result="failed"))
    t["status"] = "verified"
    add("retry_cannot_launder_a_failure", _reseal(t), "INVALID",
        ["E_SIGNATURE", "E_STATUS"], hmac_key_hex=key_hex)

    return vectors


def write(vectors) -> None:
    if OUT.exists():
        for stale in OUT.glob("*.json"):
            stale.unlink()
    OUT.mkdir(exist_ok=True)
    index = []
    for v in vectors:
        path = OUT / f"{v['name']}.json"
        path.write_text(json.dumps(v, indent=2, sort_keys=True) + "\n")
        index.append({k: v[k] for k in
                      ("name", "expected_verdict", "expected_errors")})
    (OUT / "index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n")


def reference_verdict(vector) -> str:
    """The verdict the REFERENCE implementation reaches for this vector.

    Uses cce's own verification path, so a change in reference semantics
    shows up as disagreement with the committed corpus.
    """
    from causal_continuity_engine.core import Signer, canonical_json, digest_obj
    from causal_continuity_engine.engine import _proof_covers
    from causal_continuity_engine.lamport import LamportSigner
    from causal_continuity_engine.proof import evaluate_status, verify_envelope

    envelope = vector["envelope"]
    ctx = vector["context"]

    try:
        canonical_json(envelope)
    except (TypeError, ValueError):
        return "INVALID"

    # SPEC §9: INVALID dominates UNVERIFIED, so every check that does NOT
    # need key material has to run before the undecidable case below. A
    # forgery a keyless party CAN detect must still read INVALID.
    if not isinstance(envelope, dict) or \
            envelope.get("schema_version") != "cce.proof.v1" or \
            "verification_summary" not in envelope or \
            "signature" not in envelope:
        return "INVALID"

    algorithm = (envelope.get("signature") or {}).get("algorithm")
    if algorithm not in ("hmac-sha256", "lamport-sha256/1"):
        return "INVALID"

    for v in envelope.get("verifications", []):
        if v.get("result") not in ("passed", "failed", "skipped", "missing",
                                   "inconclusive", "stale"):
            return "INVALID"

    body = {k: v for k, v in envelope.items()
            if k not in ("signature", "proof_digest")}
    if digest_obj(body) != envelope.get("proof_digest"):          # C1
        return "INVALID"

    recomputed, _ = evaluate_status(                              # C4
        envelope["verifications"],
        (envelope.get("verification_summary") or {}).get("required") or [])
    if recomputed != envelope.get("status"):
        return "INVALID"

    for name, expected in (("expect_project", "project_id"),      # C5
                           ("expect_tenant", "tenant_id")):
        if ctx.get(name) and envelope.get(expected) != ctx[name]:
            return "INVALID"
    if ctx.get("expect_task") and not _proof_covers(envelope, ctx["expect_task"]):
        return "INVALID"

    if algorithm == "hmac-sha256":
        signer = Signer("vectors", bytes.fromhex(ctx["hmac_key_hex"])) \
            if ctx.get("hmac_key_hex") else None
    else:
        signer = LamportSigner("check",
                               registered_fingerprints=set(
                                   ctx.get("fingerprints") or ()))

    # SPEC §5/§6: without the key material C2 and C3 are undecidable, and an
    # undecidable signature is not a passing one.
    if signer is None:
        return "UNVERIFIED"
    try:
        if not verify_envelope(envelope, signer)["valid"]:        # C2, C3
            return "INVALID"
    except Exception:
        return "INVALID"

    return "VALID" if envelope.get("status") == "verified" else "INCOMPLETE"


def check_committed() -> int:
    committed = sorted(p for p in OUT.glob("*.json") if p.name != "index.json")
    if not committed:
        print("no committed vectors; run without --check first")
        return 1
    bad = []
    for path in committed:
        vector = json.loads(path.read_text())
        got = reference_verdict(vector)
        if got != vector["expected_verdict"]:
            bad.append(f"{vector['name']}: corpus says "
                       f"{vector['expected_verdict']}, reference says {got}")
    if bad:
        print("the reference no longer agrees with the committed corpus:")
        for line in bad:
            print(f"  {line}")
        print("either the reference regressed, or the corpus needs "
              "regenerating: python vectors/generate.py")
        return 1
    print(f"reference agrees with all {len(committed)} committed vectors")
    return 0


def main() -> int:
    if "--check" in sys.argv:
        return check_committed()
    vectors = build()
    write(vectors)
    print(f"wrote {len(vectors)} vectors to {OUT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
