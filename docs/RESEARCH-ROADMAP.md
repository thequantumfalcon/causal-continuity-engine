# Research and differentiation roadmap

CCE's working differentiation hypothesis is a composition: one atomic, signed
causal-and-policy frontier; missing required evidence as an explicit blocker;
bidirectional why/why-not answers; live authority; and a receipt bound to the
exact revision, projection, policy, artifact inputs, and log prefix that
produced the decision.

Do not make an absolute “never before seen” claim. After a documented
literature, standards, product, and patent search, use only “to our knowledge,
as of [date], within [defined scope],” and retain the search protocol and
negative results. Even that search cannot cover unpublished applications or
prove worldwide absence. Recent preprints are useful signals, not independent
validation. The goal is to turn promising combinations into falsifiable
protocol claims with conformance vectors and hostile evaluation.

## P0: independently witnessed continuity

Define a CCE predicate schema at a stable, project-controlled absolute TypeURI
and embed that predicate in an
[in-toto Statement v1](https://in-toto.io/Statement/v1). Define the canonical
payload serialization and media type separately. Bind artifact digests, the
policy digest, verifier-definition digests, capability/corpus digests, causal
projection, audit/event frontiers, and the complete blocker set. For SCITT
registration, wrap those exact payload bytes in the RFC 9943 COSE_Sign1 Signed
Statement envelope, including the required protected CWT `iss` and `sub`
claims. Register it with independently operated transparency services and ship
their receipts beside the artifact.

Do not publish a provisional or unowned TypeURI in an artifact. Namespace
control and the immutable schema location are protocol prerequisites, not
values to fill in after an identifier has shipped.

[SCITT (RFC 9943)](https://www.rfc-editor.org/rfc/rfc9943.html) supplies the
content-agnostic registration architecture; [COSE Receipts
(RFC 9942)](https://www.rfc-editor.org/rfc/rfc9942.html) supplies portable
verifiable-data-structure proofs; and [Certificate Transparency
(RFC 9162)](https://www.rfc-editor.org/rfc/rfc9162.html) supplies the established
inclusion/consistency/monitor pattern. A receipt proves that the signed
statement was registered in a particular transparency-service VDS state, not
that CCE's statement is true. RFC 9943 does not require a receipt to identify
or digest the registration policy; if consumers rely on that policy, the CCE
profile must bind its URI and digest explicitly. Consumer policy must verify
the CCE predicate, issuer, artifact digest, inclusion, consistency, and
acceptable witnesses separately.

**Exit test:** an offline auditor verifies the issuer signature, both inclusion
receipts, service identities, and consistency from pinned prior checkpoints.
When the harness supplies conflicting signed checkpoints through the declared
gossip, witness, or quorum channel, the auditor emits non-repudiable fork
evidence. An authentic statement with a non-empty blocker set is rejected. Two
isolated inclusion receipts alone are not claimed to detect a split view.

## P1: minimal repair families, not one-step hints

The current receipt reports ceteris-paribus single-predicate flips. Extend this
into families of subset-minimal interventions: the smallest incomparable sets
of assumptions, missing checks, grants, inputs, or decisions whose change makes
the target outcome reachable. Re-evaluate every proposed set on an isolated
snapshot; never infer sufficiency from graph reachability alone.

This combines the multiple-context support and nogood machinery of de Kleer's
[assumption-based TMS](https://doi.org/10.1016/0004-3702(86)90080-9), the
explanation discipline of Doyle's
[truth-maintenance system](https://doi.org/10.1016/0004-3702(79)90008-0),
[PUG why/why-not provenance](https://arxiv.org/abs/1808.05752), and minimal
correction/hitting-set model reconciliation
([Vasileiou, Previti, and Yeoh](https://arxiv.org/abs/2012.09274)).

**Candidate differentiator:** a signed counterfactual repair certificate whose
minimality is independently replayable against the exact historic frontier.
For a finite committed intervention universe, a checker must replay every
repair, show that removing any member makes it fail, and compare the emitted
family with an exhaustive oracle on the bounded corpus. Do not call it globally
minimal until the search domain, cost ordering, and completeness bound are
explicit; if the bound is exhausted without a completeness result, report
`UNDECIDABLE`.

## P1: lineage-separated, non-expansive authority

Issue a short-lived capability for each approved effect, bound to the exact
action, resource, revision, expiry, and causal predecessor. At every hop,
authority is intersection-only. Two independent lineages may travel together
but must never be unioned into a stronger permission set.

This direction is consistent with the 2026 preprints
[Proof-of-Continuity](https://arxiv.org/abs/2607.08906),
[Verifiable Agentic Infrastructure](https://arxiv.org/abs/2605.15228), and
[FAVA](https://arxiv.org/abs/2607.27267). CCE should differentiate through
effect-level lineage, explicit missing-evidence blockers, and receipts that
show the exact authority contraction—not through a broad claim to have invented
proof-derived authorization.

As of 2026-08-04, all three are arXiv v1 preprints. Their guarantees and
evaluations are author-reported and are not independent validation of CCE.

**Exit test:** under a published operational semantics and bounded trace
grammar, model checking finds no confused-deputy or mixed-authority trace that
obtains a capability; replay proves every exercised permission existed in the
one lineage that caused that effect. An unbounded “cannot” claim requires a
mechanized proof, not only a test corpus.

## P1: interoperable provenance and delegated verification

Publish a versioned CCE
[PROV-O](https://www.w3.org/TR/prov-o/) application profile and extension
vocabulary with a canonical inverse mapping. Represent blocker completeness,
negative evidence, tenant/project scope, and policy identity explicitly;
PROV-O's open-world absence of an assertion must never be interpreted as CCE
negative evidence. Export verification decisions as
[SLSA 1.2 Verification Summary Attestations](https://slsa.dev/spec/v1.2/verification_summary)
only where their semantics match. Populate the required `verifiedLevels`
(`SLSA_BUILD_LEVEL_UNEVALUATED` until a level is actually assessed), subject
digest, verifier/signer pair, resource URI, exact policy digest, complete
`inputAttestations` set, and truthful PASSED/FAILED result. Put arbitrary CCE
artifact inputs in the CCE extension rather than mislabelling them as input
attestations.

**Exit test:** independent tooling round-trips a CCE receipt through the
declared CCE PROV profile and in-toto with extension retention, without losing
scope, negative evidence, blocker completeness, policy identity, or causal
direction.

## P2: selective disclosure without rewriting history

Never redact a signed private receipt and call the result authentic. Evaluate
three distinct constructions: (a) an issuer-signed public projection bound to
a private source commitment; (b) a BBS-derived proof after defining a
conforming VC/JSON-LD representation; and (c) an SD-CWT profile after defining
a CWT/COSE representation. A separately issuer-signed projection is not a BBS
derived proof, and neither BBS nor SD-CWT is a drop-in transform for arbitrary
JSON. As observed on 2026-08-04, the W3C
[BBS cryptosuite](https://www.w3.org/TR/vc-di-bbs/) is the 07 April 2026
Candidate Recommendation Draft, and the IETF
[SD-CWT work](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/) is
`draft-ietf-spice-sd-cwt-08`. Both remain work in progress, so either path
requires crypto review and algorithm agility.
Avoid stable source digests and unsalted field commitments when unlinkability
is required because they become correlation handles.

**Exit test:** publish an adversary model, corpus distribution, anonymity-set
threshold, and measured linkability advantage. A verifier proves the disclosed
project, decision, artifact, and policy commitments while undisclosed node text
remains hidden. Two example presentations looking different is not evidence of
unlinkability.

## P2: continuity-preserving portable memory

Extend capsules from signed transfer objects into Merkle-addressed, selectively
disclosable memory segments whose rehydration preserves data/instruction
separation and is evaluated for indirect prompt-injection resistance under an
explicit threat model. Retain CCE's stricter rules: imported content cannot
promote its own authority, live target invalidations are unioned into the
challenge, and old source state can never erase newer target control state.
The [Portable Agent Memory](https://arxiv.org/abs/2605.11032) v1 preprint is
relevant related work for transfer structure; its Merkle-DAG, scoped-disclosure,
and injection-resistance claims are author-reported. CCE's research question is
preserving causal retraction and non-expansive authority across runtimes.

## P1: closed-world blocker coverage certificates

Commit the canonical policy-rule universe, quantified evaluation domain, and
leaves of the form `(rule_id, applicability, PASS|BLOCK|UNDECIDABLE,
evidence_digest)` in a Merkle root. Require `blockers` to equal exactly the
`BLOCK` and `UNDECIDABLE` projection. This makes completeness of the declared
decision domain independently testable rather than equating “not recorded”
with “passed.”

**Exit test:** deleting, relabelling, or omitting any applicable rule or domain
member changes the commitment or fails independent recomputation; an unknown
evaluator version produces `UNDECIDABLE`.

## P1: proof-checked repair-family certificates

Encode the bounded repair search as SAT or pseudo-Boolean optimization. Ship
successful replay witnesses plus a machine-checkable proof that no strict
subset or better cost vector succeeds; block emitted solutions and prove that
no nondominated family member was omitted. Candidate proof formats and
checkers include [LRAT/RAT verification](https://arxiv.org/abs/1612.02353),
[VeriPB-style pseudo-Boolean proof logging](https://doi.org/10.4230/LIPIcs.CP.2025.21),
and recent work on
[certifying Pareto optimality](https://arxiv.org/abs/2501.17493).

**Exit test:** a separately implemented or formally verified checker rejects
planted nonminimal, insufficient, and incomplete families; an exhaustive
small-instance oracle agrees exactly.

## P1: authenticated projection-transition witnesses

Alongside the append-only event frontier, commit materialized causal state as a
sparse Merkle map. Each event carries before/after roots, affected-key
multiproofs, and the exact transition-program digest. This verifies projection
correctness rather than merely event inclusion, following the authenticated
map direction exemplified by
[CONIKS](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/melara)
and the checkpoint/consistency discipline of
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html).

**Exit test:** an offline verifier follows a trusted root through a corpus and
derives the final queried state; a direct row edit, omitted invalidation,
cross-tenant substitution, reordered event, or nondeterministic extractor
changes the root and is rejected.

## P1: dual-time proof currency

Give every receipt distinct status-known time, production time, refresh
deadline, and invalidation-effective time while also binding monotonic log
positions. A later invalidation can supersede current acceptability without
rewriting what was known at an earlier frontier. This composes OCSP's time
semantics ([RFC 6960 §2.4](https://www.rfc-editor.org/rfc/rfc6960.html)),
[PROV-O invalidation and revision](https://www.w3.org/TR/prov-o/), and
[SCITT superseding statements](https://www.rfc-editor.org/rfc/rfc9943.html).

**Exit test:** a revocation learned at transaction time T3 but effective at
valid time T2 makes the proof unusable for effects after T2 while preserving
the signed claim about what was known at T1; stale status, clock rollback, and
reordered supersession fail verification.

## Benchmark program

ContinuityBench should add adversarial tracks for:

- split-view transparency logs and consistency-proof failures;
- exact versus non-minimal repair sets under bounded search;
- authority union, delegation expansion, expiry, and confused deputies;
- stale capsules confronted with newer target invalidations;
- selective-disclosure linkage and inference leakage;
- cross-implementation PROV/in-toto/CCE semantic round trips;
- direct database edits, retention, and bitemporal reconstruction.

Every research claim needs a negative control, an independent verifier, a
committed corpus, and an honest undecidable state. A mechanism that only ever
reports success is not evidence of the property it names.
