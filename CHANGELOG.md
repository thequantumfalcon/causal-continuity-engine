# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

No unreleased changes.

## 0.1.5 — not yet released

Closes the trust and release-boundary findings discovered during the post-0.1.4
audit, with each defect pinned against the 0.1.4 source baseline.

### Added

- **A content-ingress firewall for repository and release bytes.** The same
  fail-closed scanner covers exact Git objects, commit and tag metadata,
  distributions, local hooks, and advisory CI. A Git-free isolated-review
  reference implementation and provisioning specification are included. Its
  privileged macOS acceptance test has not run on a provisioned installation,
  and the dedicated external GitHub App is not deployed; neither is an active
  or release-relied-upon control in 0.1.5.

### Changed

- **MCP sessions now implement the initialization lifecycle.** Normal tools are
  unavailable until `initialize` and `notifications/initialized` complete;
  `ping`, notification silence, request identifiers, parameter shapes, and
  tool arguments are validated before project state opens. Resume packets are
  available as exhaustive Markdown or canonical JSON.
- **MCP resume reads are logically read-only.** The database is compared before
  and after packet composition, including the quarantine-collision path. An MCP
  observation does not advance the resume watermark or append an audit row.
- **`prose_may_mandate=false` covers every extracted control kind.**
  Requirements, constraints, decisions, and checklist tasks become claims.
  Packet composition also applies the current policy to older extracted prose,
  so tightening the setting does not leave latent authority behind.

### Fixed

- **Release Git inherited repository programs and API credentials.** The owner
  tag helper now rejects unadmitted local Git configuration and uses an
  explicit SSH-only signing and transport profile. Every Git child uses a
  fixed absolute executable and a purpose-specific environment without the
  GitHub API token.
- **The owner tag helper could push before scanning the raw tag object.** It now
  disables replacement objects, scans the exact annotated-tag bytes, binds them
  back to their Git object identifier, and cleans the local tag on any finding
  before a remote push can occur.
- **A validated release tag could be replaced before push or cleanup.** The
  helper now captures the full tag-object identifier once, validates and
  verifies that object directly, pushes that identifier, and removes a failed
  local tag only through an identifier-matched reference update.
- **Artifact behavior ran before the publication bytes became immutable.** The
  workflow now uploads the built wheel, sdist, and checksum manifest first,
  structurally verifies a fresh download using the independently derived commit
  epoch and cross-runtime portable semantics, and runs installed behavior only
  in a permission-empty disposable job. Both publishers consume the original
  immutable artifact ID, so either verifier can block but cannot replace it;
  the producer's double build retains the same-runtime exact-byte proof.

- **A budgeted packet could instruct work it withheld.** The next safe action
  is reconciled after trimming and quarantine stripping. It either names a
  retained actionable task or truthfully discloses blocked or withheld work.
- **The Markdown packet silently omitted decision-relevant sections.** It now
  renders mission control, assumptions, environment, verifier outcomes,
  evidence, recent context, lineage, and explicit cryptographic-metadata
  treatment. A schema-backed test makes the projection exhaustive.
- **Named-directory backfill wrote an orphan layout.** `--dir` now initializes
  the canonical `.cce` project. GitHub authorization follows only same-origin
  HTTPS redirects and malformed origins fail closed.
- **Benchmark metric failures could exit zero.** The process now fails when any
  scenario fails or any metric verdict is not `PASS`.
- **The development lock disagreed with its direct inputs.** Pip 26.2 and its
  reviewed wheel/source hashes are locked; a regression compares every direct
  declaration with the compiled closure.
- **Unicode format controls bypassed injection screening and corrupted source
  spans.** Matching uses canonical visible text while evidence maps to original
  coordinates. At the fixed statement cap, a continuation guard abstains before
  category-M marks, U+200D, and named variation selectors, including through
  intervening format controls. This is not Unicode grapheme-cluster segmentation.
  Behavior is versioned as extractor 1.1.0 and processor 1.1.0.
- **MCP list projections read the wrong state.** Assumptions now include only
  active/supported nodes; invalidation severity and reason come from canonical
  nested data.
- **Durable statement identity was unnamed.** The v2 normalization contract is
  explicit and pinned by ASCII and non-ASCII vectors; historical v1 nodes are
  retained rather than rewritten.

## 0.1.4 — prepared 2026-08-10, never published

This version was prepared and validated but never tagged or published.
Its changes were carried forward into the 0.1.5 line. The section is retained
because the changes are real even though no 0.1.4 distribution exists.

Adds the surface through which an editor can read a project, and fixes what
using it revealed.

### Added

- **`cce-engine mcp` — a Model Context Protocol server over stdio.** Any MCP
  client (Claude Code, Cursor, VS Code) can read a project's control state
  through four read-only tools: `resume_packet`, `list_assumptions`,
  `list_invalidations`, `continuity_check`.

  It adds no dependencies. The transport is hand-rolled JSON-RPC 2.0 on `json`
  and `sys`, because the official SDK pulls sixteen packages including
  starlette, uvicorn and pyjwt, and that would end this package's
  zero-runtime-dependency property to save a couple of hundred lines. A test
  fails if importing the module ever pulls in anything outside the standard
  library.

  Read-only is a boundary, not an omission. An MCP client is an untrusted
  caller in this project's authority model, so exposing verification,
  completion or policy over this transport would let a caller mint authority
  from outside the trust model — the failure AD-006 exists to prevent. A test
  fails if a future tool name contains `verify`, `complete`, `policy`, `grant`,
  `ingest`, `quarantine`, `promote` or `attest`.

  The handshake negotiates. A client asking for a protocol revision the server
  speaks gets that revision back; anything else is answered with the newest one
  it speaks, rather than echoed — echoing would claim conformance to whatever
  string arrived.

- **`prose_may_mandate`, a project-level policy flag.** Set it `false` and
  requirements and constraints extracted from repository prose are recorded as
  claims rather than authority, through the same demotion path AD-006 already
  applies to untrusted sources. It defaults to `true`, leaving existing
  behaviour unchanged. There is deliberately no way to promote a claim back to
  authority yet; who may confirm, and how that is audited, is open in #33.

### Fixed

- **`token_budget` bounded nothing.** It trimmed each trimmable section to a
  fixed cap and then stopped, however far over budget the packet remained, so
  a project with a few months of history returned a byte-identical packet at
  every budget from 500 to 8000. Sections are now reduced progressively.
  Authority is still never dropped — that invariant is the point of the design
  — so a packet whose authority alone exceeds the budget is emitted over
  budget, and `token_estimate` reports its real size.
- **`continuity_check` shipped its signed receipt.** The answer to "is this
  project continuous?" was 10,602 characters on a one-issue project, of which
  8,244 was cryptographic material for export that no client can act on. Now
  346 characters of the fields a caller decides on; the receipt remains
  available through `cce-engine check --export-receipt`.
- **An unknown project answered as an empty one.** Naming a project that does
  not exist returned "No active assumptions." — a confident negative that
  conflates *none* with *not found*. It is now an error, as it is everywhere
  else in the engine.

## 0.1.3 — 2026-08-09

The deterministic extractor met real prose for the first time and did badly.
Twenty-two defects were found by running it against actual repository history
rather than fixtures, and every one is fixed here with a regression test that
was confirmed to fail against the code it pins. `AD-002` treats this extractor
as the degradation path rather than the primary one; a degradation path that
mangles its input is worse than useless, because nothing downstream can tell
the difference.

### Fixed

- **Statements were fabricated across masked regions.** The gap between a cue
  word and its clause matched newlines, so it walked over a blanked code fence
  and joined the text either side — recording "The exporter must stream rows to
  the client" from a body where those words never appear together. A fabricated
  statement is worse than a lost one: nothing downstream can tell.
- **Sentences were truncated at the line wrap.** Every clause rule excluded
  `\n`, so a sentence wrapped at eighty columns — which is how comment bodies
  are written — was cut at the break. "must stream rows … instead of" survives
  as a grammatical clause with its point removed. Identical text on one line
  extracted in full, so the record depended on the author's editor.
- **Clauses began and ended mid-word.** An unanchored character budget started
  the statement wherever the count landed ("stale capsules" recorded as "le
  capsules"), and the tail bound ended it the same way in 23 of 40 measured
  cases.
- **Dotted identifiers truncated or silently dropped statements.** A `.` was
  always a sentence end, so `generate.py` and `v0.1.2` cut a clause short — and
  because the forward patterns have a minimum length, "We assume numpy 1.26.4
  is installed" extracted nothing at all while "We decided to pin pip 26.1.2"
  recorded the false statement "pin pip 26".
- **Text nobody wrote became authority.** Code fences, blockquotes, HTML
  comments and four-space indented blocks were read as the author's own prose.
  A requirement hidden inside `<!-- ... -->` is invisible in every rendered
  view, so no reviewer could catch it; a blockquote is by definition someone
  else's words, frequently quoted in order to disagree with them.
- **A hidden checklist became actionable open work.** The checklist scan read
  raw text while every other pattern read the mask, so `- [ ]` items inside a
  comment or fence arrived as `open` task nodes in the resume packet, needing
  no injection wording at all.
- **An invisible character inverted a prohibition.** A zero-width space inside
  "not" left the sentence identical to a reader while re-typing the constraint
  as a requirement, so control state mandated what the sentence forbids. Word
  joiners and soft hyphens behaved the same, and word processors insert soft
  hyphens routinely. Matching now ignores them while the statement keeps them,
  so the packet still shows that the text carried them.
- **Non-ASCII statements collided.** The dedup key discarded every character
  outside ASCII, so "must not exceed €500" and "must not exceed £500" shared a
  key and one was dropped. In a script with no ASCII the key was empty, giving
  every statement the same identity.
- Markdown decoration was stored inside statements; `must never X` was filed as
  both a constraint and a requirement; consecutive table rows merged into one
  statement; and longer or CRLF code fences never found their closer, masking
  the remainder of the body and discarding every statement after it.

### Added

- `examples/quickstart.py` — the whole arc end to end in a temporary directory:
  a proof minted by actually running a pinned verifier, accepted for the task
  it names, refused for one it does not, and checked by the independent
  verifier, which reports UNVERIFIED without the key and VALID with it.
- `examples/backfill_github.py` — builds a project from a repository's real
  history through the REST API, with no webhook, App or public endpoint. This
  is the instrument that found everything above.
- A regression test for cross-project rejection in `Memory.promote`.

### Changed

- **Node identity changes for statements containing non-ASCII characters.**
  `stable_node_id` is derived from the dedup key, so such a statement now
  hashes to a different id than it did in 0.1.2. A project that re-ingests one
  records a new node rather than updating the old; the previous node remains,
  with its history intact. Pure-ASCII projects are unaffected.

## 0.1.2 — 2026-08-09

A documentation and hygiene release. No engine, schema, proof, or HTTP
behaviour changed; the only executable changes are the credential-handling and
release-workflow fixes below.

`v0.1.1` was tagged from this same work and never published: the release
workflow's checksum recheck rejected its own verified artifacts, for the reason
recorded under Fixed. The tag is left in place so that failure stays
attributable, and the version was incremented rather than reused.

### Fixed

- **`cce-engine serve` no longer echoes a byte of the API token file.** A
  token file containing non-ASCII bytes surfaced Python's decode error, which
  quotes the offending byte value. The raw bytes are now checked before
  decoding and the command fails with `api token file must be ASCII`, naming
  no content. Found while closing out a CodeQL triage: the alert itself was a
  false positive, this residue was not.
- **The release workflow's checksum recheck compared the manifest in the wrong
  order.** `SHA256SUMS` is filename-ordered, as both `build_distributions.py`
  and `verify_distributions.py` define it, but the two shell rechecks in
  `release.yml` sorted whole lines — which begin with the digest. The
  comparison therefore succeeded only when the artifacts' digests happened to
  sort the same way their filenames do, making every release a coin flip that
  0.1.0 won and the 0.1.1 attempt lost. Both rechecks now sort on the filename
  field, and a regression test pins the contract.
- **Documentation that described the repository as private and unpublished.**
  Those statements were accurate when written and became false when the
  repository went public and 0.1.0 shipped. The security policy was the
  serious one — it stated there was no reporting channel at all and told
  anyone who found a defect to withhold the report until the repository was
  public, while private vulnerability reporting was already enabled.
  `CONTRIBUTING.md` also said sign-off was unenforced and that native secret
  scanning was unavailable, and `docs/RELEASE.md` said the release workflow
  did not upload to PyPI and that installation instructions must not name
  `pip install`. Each now states the live state, re-read from the API rather
  than assumed.
- **The README demo image is referenced by an absolute URL.** PyPI does not
  resolve repository-relative image paths, so the relative form would have
  rendered as a broken image on the project page while rendering correctly on
  GitHub.

### Added

- A terminal quickstart demo on the README's first screen, built from real
  captured command output.
- `.svg` assets under `docs/` are admitted to the reviewed source contract and
  ship in the sdist, alongside the existing `.png` allowance.

## 0.1.0 — 2026-08-08

Everything below is new; this is the first release.

**The public API is not declared stable.** While the version is `0.y.z`,
anything may change in any release, without a deprecation period: module
paths, function and method signatures, the SQLite schema, the CLI surface,
the HTTP endpoints, and the JSON shapes in `schemas/`. Semantic versioning
constrains nothing until an API has been declared, and this project has not
declared one — so read `0.1.0 → 0.2.0` as "assume everything moved" rather
than as a compatibility promise.

The one format with a written, normative definition is the proof envelope
([SPEC.md](SPEC.md)). It carries its version in the artifact itself
(`schema_version: "cce.proof.v1"`), so a consumer can detect a format change
rather than infer one; the conformance corpus in `vectors/` includes a vector
for an envelope declaring a version the verifier does not know.

The Fixed and Security entries record defects found and closed by
adversarial review during development; every one was found and fixed before
this first release shipped. They are listed because the decision records and
regression tests that pin them are part of what ships.

### Added

- **Event-sourced canonical history.** Append-only event log, content-addressed
  evidence, idempotent redelivery with payload-mismatch flagging, and
  projections that rebuild from the log — `Engine.rebuild_projection` compares
  a replayed projection against live state rather than asserting they agree
  (`causal_continuity_engine/store.py`, `causal_continuity_engine/engine.py`;
  ADR-001).
- **Bi-temporal causal graph.** Versioned nodes and edges carrying both valid
  time and transaction time, as-of queries, bounded traversal, and provenance
  trails (`causal_continuity_engine/graph.py`; ADR-003).
- **Memory tiers L0–L4 and Resume Packets.** Token-budgeted packets that state
  their own omissions, separate pinned from retired control state, and carry an
  evidence index and a next-safe-action, so a resuming agent receives control
  state rather than a summary (`causal_continuity_engine/memory.py`,
  `causal_continuity_engine/resume.py`).
- **Causal invalidation.** Eight trigger types, blast radius computed over typed
  edges and bounded by budget, deterministic severity classification, a
  human-confirmation gate for broad invalidation, and resolution that records
  which nodes a transition could not be applied to
  (`causal_continuity_engine/invalidation.py`;
  ADR-008, ADR-023, ADR-060).
- **Proof-carrying completion.** A task cannot be marked complete without a
  signed proof envelope; `complete_task` has independently instrumented
  rejection paths covering target type, unresolved invalidation
  control, completed-state monotonicity, completable-state eligibility,
  authenticity, scope, intent, subject binding, single use, atomic proof
  claiming, currency, quarantine, policy coverage, policy decision, evidence
  grade, and state-race detection
  (`causal_continuity_engine/proof.py`, `causal_continuity_engine/engine.py`).
- **Evidence grading A–F.** Negative controls (`expect_fail_command`: a command
  that must fail, so a green check is shown capable of being red), mutation
  probes (the deliverable is destroyed in a sandbox copy and a required check
  must notice), determinism probes, and a `min_evidence_grade` policy floor
  defaulting to `C` (`causal_continuity_engine/evidence.py`; ADR-026, ADR-027).
  It is a mechanical
  lower bound: it establishes that a check binds to a deliverable's existence
  and content, never that it checks the right property. Lint, not an oracle.
- **Tamper-evident event and audit chains.** SQLite triggers refusing UPDATE and
  DELETE on canonical history, hash chains linking each entry to its
  predecessor over every immutable column, a separate chained commitment to
  the exact persisted payload bytes, and exportable `{count, tip}`
  anchors committing to the log's length and head
  (`causal_continuity_engine/store.py`; ADR-028,
  ADR-037). The anchor is only worth what its publication is worth, and CCE
  ships no publication channel — that step is manual and unbuilt.
- **Lamport one-time signatures** for proofs a stranger can check without
  holding the signing key, with out-of-band fingerprint registration made
  mandatory rather than optional (`causal_continuity_engine/lamport.py`;
  ADR-031).
- **A normative specification, an independent verifier, and a corpus pinning
  both.** [SPEC.md](SPEC.md) defines the `cce.proof.v1` envelope and its
  verification checks normatively; `verifiers/verify_proof.py` implements that
  document using the standard library only and importing nothing from
  `causal_continuity_engine`;
  `vectors/` holds valid, honest-negative and adversarial vectors that both
  implementations must agree with, checked in CI (ADR-057). The verdict has
  four values — VALID, INVALID, INCOMPLETE, UNVERIFIED — and neither collapse
  is safe: folding INCOMPLETE into INVALID confuses "someone tampered with
  this" with "this honestly says the work is not done", and folding UNVERIFIED
  into VALID tells a stranger that an envelope nothing authenticated is sound.
  Both implementations have one author, which enables implementation
  independence without constituting it.
- **Deterministic extraction.** Pattern-based extractor with source typing,
  calibration, abstention, and injection screening, shipped as the default and
  only built-in path so the pipeline stays reproducible and useful when model
  extraction is unavailable (`causal_continuity_engine/extraction.py`;
  ADR-012).
- **Deterministic autonomy policy, levels 0–4, deny by default.** The decision
  is a pure function of stored state; no request input can force an allow, and
  level 4 is unreachable in this release (`causal_continuity_engine/policy.py`;
  ADR-006, ADR-009).
- **Session Capsules** for migration between agents: signed, tamper-detecting,
  with a challenge step and lineage, and hidden-reasoning keys excluded
  structurally rather than filtered (`causal_continuity_engine/capsule.py`;
  ADR-005).
- **GitHub ingestion.** Webhook signature verification, idempotent
  normalization of 12 event types, and check-run conclusions
  (`causal_continuity_engine/github.py`).
- **Generated HTTP contract documentation.** The 14-route registry is the
  shared source for dispatch metadata and `docs/API.md`; a byte-equality test
  rejects stale route, authentication, request, response, status, and limit
  documentation (`causal_continuity_engine/api.py`; ADR-098).
- **Privacy and retention.** Metadata-only, redacted and full capture modes with
  secret scanning before persistence, and retention sweeps that null raw
  payloads without breaking chain integrity. `payload_digest` preserves raw
  delivery/idempotency identity while `stored_payload_digest` authenticates
  the canonical post-capture bytes actually processed
  (`causal_continuity_engine/redaction.py`,
  `causal_continuity_engine/store.py`).
- **Mechanically checked capability claims.**
  `causal_continuity_engine/capabilities.py` declares,
  for each claim, the symbols that must import, the files and tests that must
  exist, and an `honest_limit` recording what the claim does not mean;
  `docs/CAPABILITIES.md` is generated from those declarations, and `just caps`
  — which CI runs — regenerates the table and then requires a clean
  `git diff`, so a stale claim or a hand-edited table fails the build
  (ADR-029). It checks that claimed code exists, never that it is correct.
- **Instrument validation.** `tests/test_instrument_validation.py` builds one
  known-good completion, plants each defect a gate exists to catch, and asserts
  both that the named gate catches it and that harmless activity does not block
  a valid completion. A defect caught by the wrong gate is a mismatch, not a
  pass, and a rejection path added without a planted defect fails the coverage
  test (ADR-056, ADR-067).
- **ContinuityBench.** Ten scenario families with metric gates; all ten pass
  with the six metrics at target (`benchmarks/continuitybench/`). Self-scored
  on curated deterministic fixtures: this demonstrates mechanism correctness,
  not real-world performance.
- **CLI** (`cce-engine`, also runnable as
  `python -m causal_continuity_engine.cli`): `init`, `ingest`,
  `resume`, `assumptions`, `invalidations`, `verify`, `check`, `migrate`,
  `replay`, `rebuild`, `audit`, `evidence`, `policy`, `serve`.
- **Versioned JSON Schemas** for the event, resume, proof, in-toto proof
  predicate, capsule, counterfactual continuity-receipt, recovery, and
  external-anchor formats
  (`schemas/`). Their public identifiers are immutable `v0.1.0`-tagged raw
  GitHub URLs controlled by this repository; the unresolved provisional
  namespace was removed before release.
- **Cross-platform CI** running the complete suite on Python 3.11, 3.12, 3.13
  and 3.14 on Linux and natively on Windows 3.14 and macOS 15 ARM64/Python
  3.14, alongside the benchmark, capability audit, conformance corpus, and
  stdlib-only import gate.
- **Reproducible, source-equivalent release artifacts.** Every direct and
  transitive test/build tool is exact-versioned and SHA-256 locked; automated
  setup refuses source distributions and the build backend cannot resolve a
  second environment. Each pass binds the exact index-backed source bytes,
  stages only those bytes in an empty disposable directory, and builds and
  canonicalizes the closed-manifest, regular-file-only sdist there. It validates
  all members before manually materializing any archive path and builds the
  wheel only from that exact normalized source payload. The build runs twice
  from a source-derived timestamp, rejects
  backend source mutation, and must produce byte-identical wheel and sdist
  files. Both retain the audit surface, every shipped runtime module is
  byte-identical to the source tree, sdist/wheel metadata must agree, and a
  wheel installed outside the checkout must pass import and CLI checks after
  installation-only pip/setuptools are removed, then capability and behavioral
  conformance checks with only the exact locked audit tools added. The wheel exposes only the
  `causal_continuity_engine` import namespace; its audit material installs
  under `share/causal-continuity-engine/audit/`. Strict verification retains
  same-runtime compressed-byte reconstruction, while explicit-epoch portable
  semantic mode lets an extracted archive verify every invariant except
  zlib-specific recompression bytes. Releases carry an exact `SHA256SUMS` file
  (ADR-087).
- **Decision records and requirement traceability.** `docs/adr/ADR-INDEX.md`
  records the foundational design decisions, later corrections and hardening
  findings, and the review-process notes. `docs/REQUIREMENTS.md` defines every
  public requirement ID, and `docs/REQUIREMENTS_COVERAGE.md` tracks explicit
  per-ID implementation and evidence status.

### Changed

- **Collision-free public package identity.** The distribution is
  `causal-continuity-engine`, the import package is
  `causal_continuity_engine`, and the command is `cce-engine`. The shorter
  `cce` distribution/import/command belongs to an unrelated published project,
  so retaining it would make installation and executable resolution ambiguous.
  Package metadata derives its version from the runtime package attribute so a
  release cannot silently report two versions. Generic `tests`, `benchmarks`,
  `vectors`, `verifiers`, `SPEC.md`, and `schemas/` install roots were removed
  as well so another distribution cannot collide with or uninstall CCE's audit
  evidence (ADR-087).
- **Release-tree provenance is explicit.** Three obsolete binary planning
  artifacts were removed from the release tip because their embedded creator
  metadata could not be reconciled with this repository's attribution and
  licensing statements and their status claims contradicted the implemented
  system. `SPEC.md`, `docs/REQUIREMENTS.md`, `docs/CAPABILITIES.md`, and
  `docs/REQUIREMENTS_COVERAGE.md` are the maintained sources of truth. The
  public-visibility checklist records that the historical blobs still require
  an owner decision before the private repository is made public.
- **Repository publication controls tightened.** GitHub now rejects mutable
  Action references at repository level, and immutable releases are enabled
  before the first tag. Both settings were read back through the GitHub API on
  2026-08-04.

Three deliberate deviations from the specification this implements, each
recorded with a rationale and a revisit condition, and each reversible behind
an interface:

- **Storage is SQLite** (WAL, single file) rather than PostgreSQL. The schema is
  the PostgreSQL-first relational design — adjacency tables, bi-temporal
  columns, application-enforced append-only versions, and hash chains — with
  recursive traversal expressed as bounded BFS, which is also what keeps
  traversal inside its budget. A database operator can disable local triggers
  or truncate a tail; detecting that externally requires publishing an anchor.
  Nothing in the API leaks SQLite specifics (ADR-011, ADR-028).
- **Extraction is deterministic-first.** Model-based extraction is an adapter
  interface with the same calibration and abstention contract, not a shipped
  component (ADR-012).
- **Signing defaults to HMAC-SHA256** with tenant-scoped keys behind a `Signer`
  interface, which is what a stdlib-only engine can honestly claim within one
  trust domain. Lamport signing is available where a third party must verify
  (ADR-013, ADR-031).

### Fixed

The ADR review notes record seven initial adversarial rounds and the pre-fix
revisions used for their regressions; current CI runs the committed
`tests/test_regressions*.py` suite rather than replaying every historical
checkout. Three defects were introduced by an earlier
round's own fixes, and nine of round 5's twelve and nine of round 6's fifteen
were in machinery written days earlier to close the previous round. Both were
caught only because later rounds re-reviewed the hardening; a fix is a change
like any other and earns its own pass.

- Public Python, CLI, and HTTP inputs now use `None` as the only absent value,
  require typed finite canonical data and strict BOM-less UTF-8 JSON bytes,
  validate scoped references before any state change, and preserve existing
  fields during partial updates (ADR-105).
- The HTTP boundary now rejects unknown, missing, mistyped, non-finite, and
  out-of-range request/configuration values without Python coercion or
  traceback-shaped responses. Known routes have exact methods and `Allow`,
  every response uses the stable JSON error envelope and security headers,
  domain conflicts retain their 409/422 meaning, and unexpected exceptions
  disclose only a generic 500. Typed invalidation resolution must target or
  affect the resource named by the route instead of ignoring its path id
  (ADR-098).
- Retention-aware replay comparison now checks both directions for the closed
  subset whose rows are entirely event-derived and whose complete source
  history remains retained and replayable. Runtime, hybrid, and
  retention-deleted provenance remains explicitly undecidable (ADR-091).
- Explicit project-id creation now validates before the transaction and
  serializes the identity recheck, graph row, policy row, and audit evidence
  under one SQLite writer boundary, so concurrent creators have one winner and
  no partial loser state (ADR-092).
- Policy initialization now re-inspects `tracked_ref_revision` after acquiring
  `BEGIN IMMEDIATE`; two Store/PolicyEngine initializers cannot race the same
  migration `ALTER` (ADR-093).
- Capsule migration challenge compares a complete semantic control-basis
  commitment captured before packet trimming. Token-budget omissions remain
  disclosed but no longer manufacture control drift; real state changes still
  do (ADR-094).
- Repository JSON Schema conformance now owns a standard-library RFC 3339
  calendar assertion and self-test instead of silently depending on an optional
  ambient `jsonschema` format package. The schemas retain pattern/format while
  both proof implementations separately enforce timestamp validity (ADR-097).
- Canonical JSON now implements RFC 8785 JCS over the RFC 7493 I-JSON domain
  in both the runtime and standalone verifier. Python's encoder had different
  number spellings and Unicode key ordering from ECMAScript, so an independent
  implementation could derive different proof digests and signatures from the
  same value. All RFC 8785 Appendix B finite-number cases and the ordering,
  escaping, and invalid-domain boundaries are pinned in tests and vectors;
  affected pre-release digests, signatures, proofs, capsules, receipts, and
  event/audit chains must be regenerated. Pre-release local stores should be
  reinitialized rather than assumed release-compatible (ADR-088).
- Projection writes and their `processed_events=ok` marker now commit in the
  same transaction. A marker failure rolls the complete projection back and
  records only the quarantined event, never live derived state labelled as a
  failed processing attempt (ADR-079).
- Replay completion and skill approval enforce their legal source states in
  the write transaction. Generated evaluation identity is deterministic over
  tenant, project, split and failure boundary, making two-connection dedup a
  database-serialized operation rather than a read-then-insert race (ADR-080).
- Direct `process_event` calls now own the same nested-safe projection
  transaction as ingestion. `Store.transaction` rolls back a deferred
  commit-time failure instead of leaving a depth-zero connection trapped in an
  unmanaged transaction.
- Legacy event, packet-watermark and proof-spend migrations re-inspect and alter
  under cross-process `BEGIN IMMEDIATE` ownership. Proof-spend backfill scans
  every historical task version and commits inherited spends with their audit
  record, so reopening cannot make an old proof reusable or permanently omit
  migration evidence.

- Adjacent transaction-time writes are strictly ordered even when the host
  wall clock returns equal samples, preventing a later bi-temporal version
  from becoming invisible on coarse Windows clocks.
- Executed verifier tests and ContinuityBench no longer assume POSIX commands,
  paths, symlink privileges, permissions, or a UTF-8 console. Generated
  capability documentation is explicitly UTF-8 with LF line endings.
- Verification aggregation is worst-result-wins. Last-write-wins let a retry
  launder a red run: an envelope recording `unit-tests: failed` finalized as
  `verified` because a later duplicate said `passed` (ADR-015).
- Extraction reads the persisted, redacted payload rather than the incoming
  envelope, so live processing and replay share one code path and a secret
  redacted out of an event no longer reappears in a graph node (ADR-016).
- Blast radius is a set of nodes, not a list of paths. Re-emitting a node once
  per improved path inflated the count that drives the human-confirmation gate
  and the severity rule (ADR-023).
- A pending-confirmation invalidation no longer holds nodes it never touched,
  so rejecting one releases them instead of stranding them (ADR-030).
- Replay is at least as tolerant as ingestion: an event whose processing raises
  is quarantined and replay continues, rather than one transient fault making
  the projection permanently unrebuildable (ADR-036).
- An anchor with `count == 0` commits to GENESIS alone. Previously, following
  the documented quick start — export an anchor right after `init` — produced
  an anchor that reported "history was rewritten" forever after the first
  honest event (ADR-038).
- A `file-digest` check declaring no files returns `inconclusive` rather than
  `passed`, which had made a pinned required check with an empty list a free
  green (ADR-040).
- Idempotency digests the raw payload rather than the redacted one, so under
  `metadata_only` two genuinely different bodies no longer reduce to the same
  stored form and pass as a benign duplicate (ADR-041).
- Chain appends take the write lock before reading the tip. `audit()` began
  with a SELECT, so two engines on one file read the same tip and forked the
  chain (ADR-046).
- Retention-cleared history reports UNDECIDABLE, not DIVERGES. Reporting an
  intended privacy sweep as corruption told operators their history was broken
  and failed the CI gate permanently; a node that replays to a *different*
  value is still DIVERGES (ADR-063).
- A mutation probe counts only a `failed` check as a detection, and runs a
  baseline on an unmutated copy first. `inconclusive` had counted as detection,
  so a check that crashed in the sandbox graded as bound — the engine's own
  rule inverted, since absence of success is never success (ADR-066).
- Generated evaluations deduplicate within a split, never across, so a
  development-split request can no longer receive the withheld case (ADR-055).
- `Memory.demote` refuses a tier the node is not in. A sweep naming the wrong
  tier, or naming none, silently removed an L0 pin — the one thing a resume
  packet may never drop (ADR-062).
- Freshness is claimed only for inputs the engine collects. A caller-declared
  input such as a commit sha is disclosed as untracked rather than reported as
  a changed deliverable, which had made such proofs permanently stale under a
  reason that described something that had not happened (ADR-065).

### Security

- **Verifier subjects are bounded physical snapshots.** Every command,
  negative control, file-digest adapter, and mutation probe operates on a
  disposable stable copy with explicit entry, file, total-byte, and depth
  limits. Local trust/VCS/cache/dependency state is omitted; dynamic Store
  database/WAL/SHM exclusions take precedence over declared artifacts; and a
  command that mutates a declared artifact cannot create proof or evidence
  state. Verifier kinds now have closed adapter-specific contracts, and an
  empty value-oracle cannot pass (ADR-103).
- **Standalone proof verification now has a closed input budget.** Path-pattern
  count and size, directory scanning, distinct glob matches, batch files, and
  per-proof bytes are capped. Only stable physical regular files are read;
  symlinks, reparse points, directories, special files, and observed
  read-time mutation fail closed. The standard-library verifier parses the
  complete bounded byte sequence as strict UTF-8 JSON and reports deterministic
  per-file `INVALID`/`E_CJSON` results rather than truncating or blocking
  (ADR-104).
- **Webhook and bearer authentication fail closed at the HTTP boundary.**
  Ordinary routes require a configured minimum-length bearer credential and JSON media type;
  signed GitHub bodies are authenticated over the original bytes before JSON
  parsing. Ping validates repository and optional installation binding, returns
  a liveness acknowledgement without mutating engine state, and operational
  webhook errors remain explicit non-success responses (ADR-098).
- **An unresolved invalidation cannot be bypassed with a later proof.**
  Completion treats open and pending-confirmation invalidations as current
  control state: affected tasks are blocked and a critical unresolved
  invalidation blocks the project. Resolution or rejection is explicit
  (ADR-089).
- **External passes are bound to the protected-ref policy epoch.** A pass counts
  only for the current tracked-ref head, matching monotonic ref revision, and a
  non-uncertain frontier. Ref change, deletion, unset state, or out-of-order
  delivery fails closed without claiming to reconstruct Git ancestry
  (ADR-090).
- **Audit anchors are closed, typed, internally consistent, and optionally
  scope-bound.** Malformed documents and expected-scope mismatches return a
  clean non-success result rather than raising; external assurance still
  requires independent publication (ADR-095).
- **Declared artifact routes remain physical.** Attestation and proof currency
  reject a symlink, junction, or reparse point in any route component or nested
  descendant instead of following it outside the work tree. These
  standard-library checks do not claim kernel isolation or defeat privileged
  concurrent filesystem mutation (ADR-096).
- **The local state trust root cannot redirect writes.** `.cce` must be a
  physical direct child of the resolved project root; symbolic links, Windows
  junctions/reparse points, and pre-existing uninitialized roots are refused
  before chmod, secret access, or SQLite open. Initialization builds and syncs
  a complete private sibling then atomically renames it, so interruption leaves
  no half-trusted final root and retry is clean (ADR-085).
- **Verifier output is bounded while it is produced.** Stdout and stderr are
  drained concurrently under fixed retention caps, overflow is discarded, and
  the stored deterministic transcript is at most 256 KiB with an explicit
  truncation marker. Timeout and inherited-pipe cases terminate the isolated
  process group/tree on a best-effort platform basis and remain inconclusive,
  never failed or passed by absence (ADR-086).
- **Proofs bind the graph state they verified.** Each typed task, requirement,
  decision, assumption, artifact, evidence and action target contributes an
  engine-collected, signed versioned-semantic digest. Currency reconstructs
  those digests transactionally, so an old green proof cannot complete a
  changed task or outlive a changed dependency. Proof-spend uniqueness is
  scoped to `(tenant, project, proof)` with a fail-closed legacy migration
  (ADR-080).
- **L3 provenance must terminate in a real trust root.** Bounded, cycle-safe
  traversal now requires a canonical event, typed evidence, authoritative
  passed verification or human decision; unsupported agent nodes and cycles
  cannot vouch for one another. A graph node is authenticated only by its
  current event binding—never by a stale historical version or a colliding
  identifier—while a direct edge to a scoped unprojected raw event remains
  valid (ADR-080).
- **Canonical events authenticate both identities.** The raw-source digest
  remains the idempotency identity, while a second chain-bound digest verifies
  the exact persisted post-capture bytes on every read and chain audit.
  Processing requires the complete canonical row, including predecessor and
  entry hashes, rather than accepting substituted chain metadata. Store writes
  enforce the closed public event schema, strict RFC 3339 timestamps, authority
  vocabulary and payload-commitment invariant before persistence (ADR-079).
- **Public reads are tenant/project capabilities.** HTTP assumption/evaluation
  lists, CLI invalidation explanation, replay and failure-composting event
  resolution now use the bound tenant/project directly. A foreign identifier
  is indistinguishable from a missing one and same-project labels cannot mix
  rows from different tenants. The unauthenticated health response exposes no
  project id. Local trace/capsule source sessions must resolve in scope before
  becoming signed lineage, while an unresolved portable source session creates
  no target-local edge and is never globally probed (ADR-083).

- **Fail-closed repository and release policy is committed and auditable.**
  Every Action is pinned to a full commit SHA; the desired branch rules require
  `ci`, `attribution`, full-history `secrets`, verified signatures, and no
  bypass. The 2026-08-04 remote audit found that stricter branch JSON was not
  yet applied: live branch enforcement still requires only `ci` and retains a
  role bypass. No-bypass signed-tag ruleset `20350891` was then created and
  read back exactly; branch drift remains an explicit pre-release blocker
  rather than a shipped claim. Once the branch rule is applied, signed
  annotated release tags are
  version- and commit-bound, restricted to commits reachable from `main`
  with trusted exact-SHA checks, built reproducibly under read-only
  permissions, handed immutably to a separate write/OIDC job,
  provenance-attested when public, serialized per tag, and published through a
  resumable draft whose remote assets are downloaded and byte-checked before
  finalization. A rerun can repair only a draft and treats a published
  immutable release as read-only. The release quorum remains the three reviewed
  push workflows when explicitly classified PR-only checks are later added to
  the branch ruleset, and unclassified additions fail closed. Workflow-run
  binding accepts GitHub's documented nonempty `@ref` path presentation while
  still requiring the exact reviewed base path. Later package tags continue
  verifying the immutable `v0.1.0` schema TypeURIs instead of repointing those
  v1 identities. Release authorization now explicitly queries latest check
  runs, refuses tied latest completions and stale or implausibly future-dated
  check metadata, and lets a newer failure override any older exact-SHA
  success.
- **A required verifier is pinned by policy, not by name.** The policy supplies
  the command and the engine discards a caller spec reusing a pinned name. A
  bare name remains satisfiable by whatever the claimant runs under it, so it
  is recorded in the signed evidence context and caps the grade at D, which the
  default floor of `C` refuses. Before this, `VerifierSpec(name="unit-tests",
  command="/usr/bin/true")` produced a signed `verified` proof and a completed
  task with no test run (ADR-024, ADR-039).
- **Self-asserted verification satisfies nothing.** Outcomes supplied by the
  caller are relabelled `self_asserted` unconditionally and recorded truthfully
  in the envelope, but only results the engine executed or an authoritative
  external verifier produced can satisfy a required verifier (ADR-019).
- **Value oracles ask for values, never verdicts.** A check emits values as JSON
  and the policy's declared expectations judge them; exit code is not the
  verdict and empty output is `inconclusive`. A test suite must import the code
  under test, so the subject runs inside the runner's process and can rewrite
  the runner's report — no sandbox hardening reaches a forgery that happens
  after the sandbox is entered (ADR-025). A failing oracle names the keys that
  were wrong and never the expected values, since the details travel inside the
  envelope the claimant receives (ADR-034).
- **Policy-required verifiers are additive, never substitutable.** A caller may
  raise the bar and never lower it; nominating one trivial verifier no longer
  makes the project's mandated checks disappear from the required set
  (ADR-020).
- **A proof is scoped, subject-bound, and single-use.** It must carry this
  tenant and project, name this task in a signed field, and not have been spent
  already. Without those bindings one genuine "tests passed" envelope completed
  unlimited tasks, including tasks in other projects under the same key
  (ADR-018).
- **A signed envelope is immutable after finalize.** Annotating a proof after
  signing is byte-indistinguishable from tampering; the action node is created
  before signing so its id is bound inside the signed continuity links
  (ADR-014).
- **Identity is derived from the attached key material, never read beside it.**
  A declared fingerprint disagreeing with the key is a rejection, and
  `self_authenticating` defaults to false. Previously an attacker re-signed a
  rewritten proof with a self-minted keypair and copied the issuer's published
  fingerprint into the signature block, which is excluded from the digest
  (ADR-033, ADR-044).
- **Quarantine is enforced at every tier and at the exit.** Quarantined content
  is barred from L0–L3, skipped by retrieval, and stripped from composed
  packets by text as well as by id, with the removal disclosed as an omission.
  When a text block trips the injection screen every item extracted from that
  block is quarantined, not only the matched span — otherwise an attacker need
  only put the instruction in the sentence after the trigger (ADR-021, ADR-035,
  ADR-042, ADR-053, ADR-061, ADR-062).
- **A proof must still describe the world to be spent.** Completion is refused
  when declared deliverables have changed since attestation, when the task is
  blocked or uncertain, or when an invalidation touching it fired after the
  proof was created. An artifact that cannot be read records a sentinel digest
  and counts as changed, because unreadable is not unchanged (ADR-043,
  ADR-047).
- **An action's class is what it does, not what it is called.** If verifiers
  will execute, the action is classified at least `run_verifier` regardless of
  the caller's label, and the reclassification is recorded in the signed policy
  decision. An agent under an autonomy downgrade had been declaring `observe`
  and continuing to run checks (ADR-048).
- **A mutation probe may only ever destroy copies.** The ADR-032 containment
  boundary made `_apply_mutation` refuse an artifact resolving outside its
  sandbox and treat a symlink already present in a synthetic sandbox as the
  link itself, never its referent. Current probes first apply ADR-103's bounded
  physical materialization, so a symlink or reparse point in the subject yields
  an inconclusive result before any check or mutation runs; the helper rule is
  defence in depth. The previous version could truncate files outside its
  sandbox through a symlink named as a deliverable, reachable from the public
  probe API, while the module documented that the real tree is never touched.
- **Partial chain coverage was closed.** The immutability trigger and the hash
  chain had listed the same twelve columns and omitted the same six, leaving an
  event's actor, validity window, sensitivity and capture mode rewritable with
  every trigger intact and both the chain and the anchor reporting clean. The
  columns are now enumerated once so the two cannot drift apart. A chain that
  covers most of a row is more dangerous than no chain, because its verdict is
  believed (ADR-037).
- **Endpoints act inside the project they name.** The resolve endpoint had read
  the target's own entity type and never compared its project, so one call
  could rewrite any node of any type anywhere (ADR-052).
- **The policy in force at completion is the one that applies.** A proof minted
  under a laxer policy is no longer spendable after the project tightens: it
  did not fail the new requirement, it never tested it (ADR-054).
- **Requiring proof means declaring what would count as proof.** A project that
  requires proof and declares no required verifiers is refused at completion,
  with a message naming the fix. The grade gate had only run when verifiers
  were declared, so the default configuration had no gate at all (ADR-045).
- **A gap is not a pass.** The continuity check reports verifier gaps and will
  not conclude success while a required verifier has never produced a pass;
  previously it derived success from the absence of failure. Proof-required
  policy with no verifier definitions now contributes the stable signed gap
  `policy:proof-required-without-required-verifiers`; only explicitly disabling
  proof requirements permits an empty verification basis (ADR-051, ADR-084).
- **Spent proofs survive the mechanism that replaced them.** When the
  duplicate-completion guard moved to a primary key, an existing store produced
  an empty table and every proof the project had ever spent became spendable
  again; the table is now seeded from completion evidence and the carry-over is
  audited (ADR-064).
- **A specification defect in the envelope verification rules was fixed in the
  specification.** SPEC §9 told a stranger holding an `hmac-sha256` envelope and
  no key that the envelope was VALID, for a body a forger had rewritten and
  resealed. The verdict `UNVERIFIED` was added and an adversarial no-key vector
  now pins both implementations so they cannot drift back (ADR-057).
