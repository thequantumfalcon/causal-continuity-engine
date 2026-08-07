# CCE Proof Envelope — verification specification v1

Normative. This document defines what a `cce.proof.v1` envelope is and how a
party who holds only the envelope decides whether to believe it. It is
written so a second implementation can be produced from this text alone,
without reading `causal_continuity_engine/`.

`verifiers/verify_proof.py` is such an implementation: standard library
only, imports nothing from `causal_continuity_engine`. `vectors/` is a
conformance corpus
generated from the reference implementation, so the two cannot silently
drift apart.

> **What a second implementation buys, and what it does not.** Two
> implementations agreeing proves the *specification* is unambiguous enough
> to reimplement, and that neither has a bug the other shares by
> construction. It does not constitute implementation independence, because
> both were written by the same author. A verifier written by a different
> party against this document is the thing that would. Stated here so it is
> not discovered later and reported as a finding.

---

## 1. Scope

A verifier implementing this document answers exactly one question:

> Given this envelope, and nothing else except optionally a key registry,
> may a completion claim rest on it?

It answers **nothing** about whether the work was any good, whether the
checks were the right checks, or whether the project is in a healthy state.
Those are engine concerns and require state the envelope does not carry.

A verifier MUST NOT import the reference implementation, and MUST NOT
require network access.

---

## 2. Canonical form and digests

**C-JSON.** The canonical encoding of a value is the UTF-8 output of the
[JSON Canonicalization Scheme (JCS), RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).
Its input MUST satisfy the
[I-JSON profile, RFC 7493](https://www.rfc-editor.org/rfc/rfc7493), including:

- duplicate object member names are a **parse error**; a parser MUST NOT
  choose a first or last occurrence
- strings contain Unicode scalar values but no Unicode noncharacters; lone
  surrogates and noncharacters are `E_CJSON`, and Unicode normalization MUST
  NOT be applied
- every number is finite and exactly expressible as IEEE-754 binary64; a
  producer with a wider integer type MUST reject an integer that is not exact
  in binary64 rather than silently sign a rounded value; extended-precision
  values belong in strings

JCS emits no whitespace, applies ECMAScript string escaping, serializes each
binary64 number using ECMAScript's shortest round-tripping form (including
`-0` as `0`), and recursively sorts raw object names by unsigned UTF-16 code
units. UTF-16 ordering is not Unicode-code-point or UTF-8 byte ordering.
Non-ASCII scalar values are emitted directly and the resulting text is encoded
as UTF-8.

**Digest.** `digest(v) = "sha256:" + hex(SHA-256(utf8(C-JSON(v))))`, lower
case hex.

RFC 8785 and RFC 7493 are normative. The corpus pins their number, escaping,
Unicode-ordering, and rejection boundaries so either implementation drifting
from the standards fails conformance rather than redefining C-JSON by accident.

---

## 3. Envelope shape

```
{
  "schema_version":       "cce.proof.v1",      // exact string
  "proof_id":             "prf_<24 hex>",
  "created_at":           <canonical RFC-3339 UTC; defined below>,
  "tenant_id":            <string>,
  "project_id":           <string>,
  "action_id":            <string>,
  "subject":              [ {"name": <string>, "digest": <digest>} ],
  "action_intent":        {"type": <string>, "statement": <string>,
                           "requirement_ids": [<string>]},
  "actor":                <object>,
  "inputs":               [ {"name": <string>, "digest": <digest>,
                             "kind": <string>} ],
  "environment":          <object>,
  "execution":            [ <execution> ],
  "verifications":        [ <verification> ],
  "policy_decision":      {"decision": "allow"|"deny", ...},
  "continuity_links":     <object>,
  "evidence_context":     <object>,
  "status":               <status>,
  "verification_summary": <summary>,
  "proof_digest":         <digest>,
  "signature":            <signature>
}
```

`created_at` has exactly one v1 representation:
`YYYY-MM-DDTHH:MM:SS.ffffffZ`. The date and time MUST be a real Gregorian
UTC instant with year 0001–9999, seconds 00–59, exactly six fractional digits,
upper-case `T`, and a terminal upper-case `Z`. Leap seconds, numeric offsets,
lower-case separators, omitted fractions, and any other otherwise-valid
RFC-3339 spelling are non-canonical and are `E_SHAPE`. Engine-produced proofs
use this exact form.

`tenant_id`, `project_id`, `action_id`, every `requirement_ids` member, and
every identifier in `continuity_links` use the public CCE identifier grammar:
1–128 ASCII URI-unreserved characters, with an ASCII letter or digit first and
only letters, digits, `.`, `_`, `~`, or `-` thereafter. Slash, percent, control
characters, whitespace, Unicode, dot segments, and longer values are
`E_SHAPE`. This gives each resource exactly one HTTP path-segment spelling;
percent-encoding never legitimizes a rejected identifier (ADR-102).

The JSON Schema pattern commits the spelling above and its `date-time` format
declares the calendar semantics. Generic JSON Schema libraries do not always
execute format assertions, and some make RFC-3339 support an optional package.
The repository conformance harness therefore registers and self-tests a
standard-library format assertion; the reference implementation and the
independent verifier separately parse the Gregorian date before accepting it.

A field absent where this document says it is present is a **structural
failure** (§8, `E_SHAPE`). A verifier MUST NOT infer a default. The top-level
object and every fixed-shape object below are **closed**: an unknown member is
also `E_SHAPE`, even when a valid signature covers it. Unknown signed data has
integrity but no v1 semantics and MUST NOT silently acquire them.

The intentionally open extension containers are `actor`, `environment`,
`coverage`, `observed`, `policy_config`, each object inside
`scope_decisions`, `mutation`, and `determinism`. Their enclosing objects
remain closed. `subject` items contain exactly `name,digest`; `action_intent`
contains exactly `type,statement,requirement_ids`; and `inputs` items contain
exactly `name,digest,kind`. Every digest has the exact lower-case form
`sha256:` followed by 64 hexadecimal digits.

### 3.1 execution and verification

An `execution` object contains exactly:

```
{ "tool": <non-empty string>, "command_digest": <digest|null>,
  "exit_code": <integer|null>, "started_at": <non-empty string>,
  "output_digest": <digest|null> }
```

A `verification` object may contain only the members below. `verifier` and
`result` are required; the others are optional so an untrusted assertion can
be preserved without inventing provenance.

```
{ "verifier": <string>, "result": <result>, "source": <source>,
  "pinned": <bool>, "command_digest": <digest|null>,
  "definition_digest": <digest|null>, "kind": <string>,
  "started_at": <string>, "duration_seconds": <finite number >= 0>,
  "exit_code": <integer|null>, "output_digest": <digest|null>,
  "evidence_digest": <digest|null>, "coverage": <object|null>,
  "control": <control|null>, "observed": <object|null>,
  "details": <string>, "network": <string> }
```

`result` ∈ `passed | failed | skipped | missing | inconclusive | stale`.

`source` ∈ `executed | verifier_authoritative | self_asserted`. A missing
`source` MUST be read as `self_asserted` — the weakest reading, never the
strongest.

`control` is null or exactly `{"command_present": <bool>, "status":
"held"|"unmet"|"absent"|"inconclusive", "exit_code": <integer|null>,
"details": <string>}`.

`definition_digest` identifies what a pass means, not merely what executable
started. It is `digest()` of this complete normalized object:

```
{ "schema": "cce.verifier-definition.v1", "name": <string>,
  "kind": <string>, "command": <string|null>,
  "expected_properties": <object>, "timeout_seconds": <integer>,
  "required": <bool>, "network": <string>,
  "expect_fail_command": <string|null>,
  "artifacts": <sorted unique array of strings>, "pinned": <bool>,
  "isolate_sys_path": <bool>, "allow_user_site": <bool> }
```

All defaults MUST be materialized before hashing. For a pinned current-policy
check, absence or mismatch of `definition_digest` means the proof did not run
that definition. A command digest alone is insufficient: kind, expectations,
control, artifact surface, timeout, and isolation all alter the proposition
being tested.

### 3.2 policy, continuity, evidence, and summary

`policy_decision` requires `decision` (`allow|deny`) and permits only:
`decision,reason,action_type,required_level,effective_level,action_scope,
applicable_grant_ids,reasons,policy_config,decided_at,action_scopes,
scope_decisions`. Levels are integers; `action_scope` is string or null;
the id/reason/scope collections are arrays of strings; `policy_config` is an
object; and `scope_decisions` is an array of objects.

`continuity_links` permits only `task_ids,requirement_ids,decision_ids,
assumption_ids,artifact_ids,evidence_ids,action_ids` (arrays of strings) and
`proof_node_id` (a non-empty string). `evidence_context` permits only
`unpinned_required,policy_pinned` (arrays of strings), `mutation` (object or
null), and `determinism` (object).

`verification_summary` contains exactly `unbacked_self_assertions,required,
missing,failed,inconclusive,skipped,passed`; every value is an array of
strings.

### 3.3 status

`status` ∈ `draft | verified | failed | incomplete | inconclusive | stale |
invalid`.

Only `verified` may support a completion claim (§7).

---

## 4. C1 — Digest

`proof_digest` MUST equal `digest(body)` where `body` is the envelope with
the keys `signature` and `proof_digest` removed.

The signature block is excluded from the digest. **A verifier MUST NOT
therefore treat any field inside `signature` as attested** — see C3.

---

## 5. C2 — Signature

`signature` requires `key_id,algorithm,value` and permits only those members
plus `public_key,fingerprint`. `key_id` and `algorithm` are non-empty strings.

**`hmac-sha256`** — `value` is hex `HMAC-SHA256(key, utf8(C-JSON(body)))`,
where `body` is the envelope minus `signature` only (note: `proof_digest`
IS included here, unlike C1). Verifiable only by a holder of the key.

**An undecidable signature is not a passing signature.** A verifier without
the material to check C2 MUST report it `SKIPPED` and MUST NOT return
`VALID` (§9). This mirrors §6's rule for authenticity, and exists because
the failure is otherwise silent and total: without it, a third party — who
by definition does not hold an HMAC secret — sees `VALID` for any envelope
whose `proof_digest` is self-consistent, which a forger simply recomputes
after rewriting the body. `hmac-sha256` is not a third-party-verifiable
scheme, and a verifier must say so rather than skip the check that would
have revealed it.

**`lamport-sha256/1`** — `signature` additionally carries `public_key` (256
pairs of 32-byte hex blocks) and `fingerprint`. Let `m = SHA-256(utf8(C-JSON(
body)))` where `body` excludes `signature` only. For bit *i* of *m*, most
significant bit of the first byte first, `value[i]` MUST hash to
`public_key[i][bit]`. All 256 comparisons MUST use a constant-time
equality.

---

## 6. C3 — Authenticity

**This is the check that separates "unchanged" from "vouched for", and it
is where a naive implementation goes wrong.**

A signature scheme is *self-authenticating* when producing a valid signature
requires a secret the claimant does not hold. `hmac-sha256` is
self-authenticating. `lamport-sha256/1` is **not**: the public key travels
inside the envelope, so anyone may mint a keypair and sign anything.

**C3 depends on C2.** Authenticity is a claim about who produced a
signature; it is undecidable if the signature itself was not checked. A
verifier MUST report C3 `SKIPPED` whenever C2 is `SKIPPED`, for every
scheme including self-authenticating ones. Returning `PASS` there reports
"vouched for" on the strength of a signature nobody verified.

For a scheme that is not self-authenticating, and whose signature verified:

1. Recompute the key identity **from the attached key material**:
   `fp = digest(concat(public_key[i][0] || public_key[i][1] for i in 0..255))`
   over the raw 32-byte blocks, not their hex.
2. If the envelope declares `signature.fingerprint` and it differs from
   `fp`, the envelope is **`E_FINGERPRINT`**. A declared identity that
   disagrees with the attached key is a forgery signal, not a typo.
3. `fp` MUST appear in a registry the verifier obtained **out of band**. A
   verifier with no registry MUST report `E_UNREGISTERED` and MUST NOT
   report success.

A verifier MUST NOT default an unknown scheme to self-authenticating.

> Reading the key off the artifact and checking the artifact against it
> verifies the artifact against itself. That is integrity. Authenticity
> requires a fact from outside the envelope.

---

## 7. C4 — Sufficiency

Given `required` = `verification_summary.required`:

1. Discard non-authoritative reports for sufficiency (but retain them in the
   envelope as claims). For each verifier name, its effective result is the
   **worst authoritative** result it reports in `verifications`, ordered
   `failed < inconclusive = stale < missing < skipped < passed`. A later
   passing entry never retracts an earlier failure.
2. Authoritative sources are `{executed, verifier_authoritative}`. A required
   verifier with only self-asserted reports is `missing`. Self-assertion can
   neither satisfy a verifier nor poison an authoritative result with the same
   name.
3. When `required` is non-empty, status follows, in order: any required
   `failed` → `failed`; any required `missing`/`skipped` → `incomplete`;
   any required `inconclusive`/`stale` → `inconclusive`; all required
   `passed` → `verified`; otherwise `incomplete`.
4. When `required` is empty, “all required passed” is **not** vacuously true.
   Reduce all authoritative observations by rule 1, then apply: any effective
   `failed` → `failed`; otherwise any effective `inconclusive`/`stale` →
   `inconclusive`; otherwise at least one effective result exists and every
   effective result is `passed` → `verified`; otherwise `incomplete`.
   Self-assertions do not count as effective results. In this branch
   `required`, `unbacked_self_assertions`, `missing`, and `skipped` are
   empty because they describe declared requirements; `failed`,
   `inconclusive`, and `passed` classify the authoritative observations.
5. The verifier MUST also derive the complete summary: `required` is the
   sorted unique requirement set; `unbacked_self_assertions`, `missing`,
   `failed`, `inconclusive`, `skipped`, and `passed` are the sorted verifier
   names in the corresponding categories under rules 1–4. The derived object
   MUST exactly equal `verification_summary`.
6. The recomputed status and summary MUST equal the recorded values, else
   **`E_STATUS`**.

A verifier reports `E_STATUS` on divergence rather than substituting its own
result: an envelope whose recorded status disagrees with its own contents is
not a proof of anything, whichever value is "right".

---

## 8. C5 — Scope

These are the questions the envelope alone can answer about whether it is
*this* claim's proof. A verifier given the optional context MUST check them;
without the context it MUST report each as `SKIPPED`, never as passed.

| Context given | Check | Failure |
|---|---|---|
| `expected_project` | `project_id` equals it | `E_PROJECT` |
| `expected_tenant` | `tenant_id` equals it | `E_TENANT` |
| `expected_task` | the id is an exact element of the typed `continuity_links.task_ids` array | `E_UNBOUND` |

An occurrence under any other field, a substring match, or a requirement or
subject with the same text does not bind the proof to the task.  The array MUST
contain only strings; an absent or malformed `task_ids` relation fails closed.

---

## 9. Verdict

```
{ "verdict": "VALID" | "INVALID" | "INCOMPLETE" | "UNVERIFIED",
  "checks":  { "C1_digest": "PASS"|"FAIL",
               "C2_signature": "PASS"|"FAIL"|"SKIPPED",
               "C3_authenticity": "PASS"|"FAIL"|"SKIPPED",
               "C4_sufficiency": "PASS"|"FAIL",
               "C5_scope": "PASS"|"FAIL"|"SKIPPED" },
  "errors":  [ <error code> ],
  "status":  <the envelope's status, or null when C1/C2/C3 failed> }
```

- **INVALID** — any check FAIL. Something is wrong with this envelope.
- **UNVERIFIED** — no check FAIL, but C2 or C3 is SKIPPED. Nothing was found
  wrong and nothing was established either: the verifier lacked the material
  to decide. A caller MUST NOT treat this as success. This is the verdict a
  third party gets for an `hmac-sha256` envelope, which is the honest answer.
- **INCOMPLETE** — C1, C2 and C3 all PASS, no check FAIL, but
  `status != "verified"`. The envelope is authentic and says the work is not
  done: a successful verification of a truthful negative record.
- **VALID** — every check PASS or, for C5 only, SKIPPED, **and**
  `status == "verified"`.

C5 may be SKIPPED without preventing VALID, because scope is a question
about the caller's intent rather than about the envelope's integrity; a
caller that supplies no expectations has asked nothing. C2 and C3 are not
like that: skipping them removes the only grounds for believing the envelope
at all.

A verifier MUST report each check independently. Collapsing them to a
boolean loses the distinction between "this was tampered with" and "this
honestly records a failure", which are opposite situations.

---

## 10. Error codes

`E_SHAPE`, `E_CJSON`, `E_DIGEST`, `E_SIGNATURE`, `E_FINGERPRINT`,
`E_UNREGISTERED`, `E_SCHEME`, `E_STATUS`, `E_PROJECT`, `E_TENANT`,
`E_UNBOUND`.

## 10.1 Exit codes (for a command-line verifier)

`0` every envelope VALID · `1` any INVALID · `2` any UNVERIFIED (no INVALID)
· `3` any INCOMPLETE (no INVALID, no UNVERIFIED) · `64` usage error.

**INVALID dominates.** A batch containing both an INVALID and an INCOMPLETE
MUST exit 1. Anything else lets a CI gate keyed on that code miss a
forgery.

---

## 11. What this specification does not cover

Stated so they are not discovered later and presented as findings.

1. **Freshness.** An envelope is a statement about a moment. Whether the
   deliverables and typed continuity targets it names still have the artifact
   and versioned-semantic digests it records requires the project, not the
   envelope. Engine-issued proofs reserve input kind `continuity` for those
   engine-collected graph-state commitments and check them at consumption
   (ADR-043, ADR-080); a stranger holding only the envelope can verify that
   the commitments were signed, but cannot reconstruct current state.
2. **Adequacy.** C4 establishes that the declared checks passed. Whether
   those checks test anything worth testing is not decidable from the
   envelope, and the engine's own answer (mutation probes, ADR-027) is an
   explicitly mechanical lower bound.
3. **Registry distribution.** §6 requires an out-of-band registry and says
   nothing about how it travels. That is the unsolved part, and no amount of
   verifier code closes it.
4. **Revocation.** There is no mechanism for withdrawing a key. A
   fingerprint in the registry is trusted for every envelope it signed.
5. **Shared authorship.** Both implementations have one author (see the note
   at the top).

---

## 12. Counterfactual continuity receipt v1

`cce.continuity-receipt.v1` is a separate authenticated operator artifact. It
binds one transaction-current causal/policy frontier to the decision CCE would
publish and to a bidirectional Boolean explanation. Its domain separator is
exactly
`https://raw.githubusercontent.com/thequantumfalcon/causal-continuity-engine/v0.1.0/schemas/cce.continuity-receipt.v1.json`;
a verifier
MUST reject another `payload_type` even when its signature is valid. The JSON
shape is declared by `schemas/cce.continuity-receipt.v1.json`.

### 12.1 Decision predicates

Version 1 has exactly these unique predicates:

1. `critical_invalidations_empty`
2. `human_approvals_complete`
3. `authority_conflicts_empty`
4. `active_proof_failures_empty`
5. `required_verifiers_current`
6. `resume_packet_current`
7. `revision_frontier_decidable`
8. `integrity_chains_intact`

For v1, `satisfied` MUST equal `observed == required`. A verifier MUST derive
each observation and its `evidence_digest` from `decision_state`; trusting the
recorded Boolean merely verifies that someone signed a claim, not that the
claim follows from the signed state. Missing, unknown, or duplicate predicate
names are invalid.

The top-level `satisfied` and `blockers` arrays MUST be a disjoint, exhaustive
partition of those derived predicate objects. Order has no meaning. The
recorded decision MUST equal the result of the continuity decision function:
broken trust or log integrity is `cancelled`; critical invalidation, authority
conflict, or required approval is `action_required`; a proof/verifier gap is
`failure`; an otherwise-current packet is `success`; otherwise `neutral`.

### 12.2 Counterfactual frontier

`flip_conditions.semantics` MUST be
`ceteris_paribus_boolean_frontier`. `to_success` uses operator `all` and names
exactly the blocker set. `from_success` uses operator `any` and names exactly
the satisfied set. These are why/why-not conditions at the frozen snapshot.
They are not an executable remediation guarantee: changing one condition may
causally change another.

### 12.3 Authenticity and currentness

The receipt digest covers every field except `receipt_digest` and `signature`.
Issuer algorithm, key id, verification mode, and independent-verification
claim MUST be derived from the configured verifier and MUST agree with the
signature block. A carried public key is not its own authority: for a
non-self-authenticating scheme, the derived fingerprint MUST be present in an
out-of-band registry. An HMAC receipt is locally authenticated only; every
holder of the shared secret can forge one, so it is not public
non-repudiation.

`basis.decision_state_digest` MUST cover the complete decision state.
Project-event frontier, policy, projection, packet commitment, and revision
frontier determine semantic currentness. Global event/audit checkpoints are
valid when their `(count, tip)` is a stored chain prefix; unrelated later
appends do not stale a project receipt. A broken current chain is nevertheless
a decision blocker. Tail truncation cannot be detected without an externally
published anchor.

Verification returns:

- `INVALID` when shape, canonical JSON, digest, authenticity, scope, predicate
  semantics, partition, flip sets, decision, or chain checkpoint fails;
- `AUTHENTIC_HISTORICAL` when the receipt is authentic and coherent but its
  project frontier no longer matches live state;
- `CURRENT` when authenticity, semantics, and the live semantic frontier all
  match.

`CURRENT` does not impose an age limit. Relying-party nonce/challenge freshness
or policy TTLs require a later profile.

### 12.4 Privacy and time model

Detailed receipts are operator output. They contain stable tenant, project,
proof, invalidation, verifier, and log identifiers and MUST NOT be described as
public or anonymous. A selective-disclosure publication profile is future
work. Version 1 is an atomic transaction-current snapshot; although the graph
stores bitemporal facts, this receipt does not claim a shared historical
`valid_time`/`transaction_time` evaluation point.
