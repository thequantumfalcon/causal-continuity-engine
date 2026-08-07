# Requirement Coverage — CCE reference implementation

> **Public vocabulary.** Every identifier in this matrix is defined in
> [REQUIREMENTS.md](REQUIREMENTS.md). The mechanically checked subset lives in
> [CAPABILITIES.md](CAPABILITIES.md), which is generated from
> `causal_continuity_engine/capabilities.py` and fails the build when a claim
> stops resolving.
> Where this narrative status matrix and CAPABILITIES.md cover the same
> implementation claim and disagree, CAPABILITIES.md is authoritative because
> it is the one a machine checks. REQUIREMENTS.md remains authoritative for what
> an identifier means.

Status legend:
* **implemented** — behavior present and covered by automated tests
* **partial** — core behavior present; named residual is deployment/scale work
* **contract-only** — interface/schema exists; behavior needs external infra
* **out-of-scope** — hosted-service concern, not engine code

## Core — Causal graph (CCG)

| ID | Status | Evidence |
|---|---|---|
| CCG-001 | implemented | `test_store_graph.py::TestEventStore` (idempotency, mismatch flag) |
| CCG-002 | implemented | `causal_continuity_engine/ontology.py` entity set; graph writes validated |
| CCG-003 | implemented | typed edges + validation; `TestGraph::test_edge_versioning_dedupe` |
| CCG-004 | implemented | bi-temporal rows; `TestGraph::test_as_of_transaction_time` |
| CCG-005 | implemented | conflict ranking uses authority/freshness/confidence with explanation |
| CCG-006 | implemented | `Engine.rebuild_projection` + fingerprint equality; live ingest and replay share one processing path (ADR-016). The retention-aware comparator checks both directions only for fully retained, replayable, entirely event-derived nodes/edges; runtime, hybrid, and retention-deleted provenance remains undecidable (ADR-091; `test_retention_comparator_flags_live_only_replayable_nodes_and_edges`). |
| CCG-007 | implemented | `Graph.provenance`; `TestGraph::test_provenance_trail` |
| CCG-008 | implemented | depth/node budgets over DISTINCT nodes (ADR-023); `TestGraph::test_traversal_node_budget`, `TestM3TraversalReturnsDistinctNodes` |

## Core — Temporal memory (TM)

| ID | Status | Evidence |
|---|---|---|
| TM-001 | implemented | append-only tier assignments; promote/demote audited |
| TM-002 | implemented | L0 in every packet; `test_l0_never_dropped_under_budget` |
| TM-003 | implemented | `Memory.checkpoint`, `last_safe_checkpoint` |
| TM-004 | implemented | causal+temporal+lexical scoring; `test_retrieval_signals` (no vector index — see AD note) |
| TM-005 | implemented | L3 requires provenance that resolves (no self-loops or dangling ids, ADR-022); quarantine blocked at every tier (ADR-021) |
| TM-006 | implemented | capture modes + `sweep_retention` keeps metadata |
| TM-007 | implemented | decay in retrieval scoring; pinned items exempt |
| TM-008 | implemented | `Memory.export/correct`; deletion via store + retention |

## Core — Assumption detection (AD)

| ID | Status | Evidence |
|---|---|---|
| AD-001 | implemented | pattern extraction from issues/PRs/comments/decisions |
| AD-002 | partial | implicit assumptions only via dependency/scope heuristics; LLM adapter is the plug point (ADR-012) |
| AD-003 | implemented | scope/criticality/confidence/authority/valid-time on every node |
| AD-004 | implemented | normalized-statement stable ids; occurrences become versions |
| AD-005 | implemented | resolve API (accept/reject/narrow/supersede) versioned |
| AD-006 | implemented | source typing by author association (outsiders = untrusted, cannot mandate) + injection quarantine; bench `prompt_injection`, `TestF6OutsiderCannotMandate` |
| AD-007 | implemented | calibration by source authority + abstention gate |
| AD-008 | partial | assumes/depends_on edges supported; automatic linking only where extraction sees both ends |

## Core — Causal invalidation (CI)

| ID | Status | Evidence |
|---|---|---|
| CI-001 | implemented | 8 trigger types incl. changed_requirement, failed_check, dependency_drift; a requirement stated by several sources is retired only when the last source retracts it (ADR-017) |
| CI-002 | implemented | typed-edge propagation with strength decay + budgets |
| CI-003 | implemented | deterministic matrix `classify()` |
| CI-004 | implemented | minimal causal path + evidence + recommended action |
| CI-005 | implemented | `pending_confirmation` applies no silent L0 rewrite. Completion also refuses any task touched by an unresolved open/pending invalidation and refuses every task under a critical unresolved invalidation, even for later proofs; the affected set still depends on the typed graph and classification policy (ADR-089). |
| CI-006 | implemented | persisted packet watermark (survives process restarts; `TestF5PacketWatermarkPersists`); on-demand recompute |
| CI-007 | implemented | 3 resolution modes with lineage |
| CI-008 | implemented | `metrics()` counters + ContinuityBench precision/recall |

## Core — Resume & migration (MIG)

| ID | Status | Evidence |
|---|---|---|
| MIG-001 | implemented | `ResumeComposer.compose` emits target, mission, authority, accepted-decision, verified-progress, invalidation, assumption, open-work, environment, trust, lineage, evidence, recent-context, and omission sections; closed schema `cce.resume.v1` |
| MIG-002 | implemented | budget trim with explicit omissions; L0 never dropped. Capsules commit the full semantic control basis before trimming, so presentation omissions do not manufacture migration drift and real state changes remain detectable; this does not establish model-semantic equivalence (ADR-094). |
| MIG-003 | implemented | signed capsules, digest tamper detection |
| MIG-004 | implemented | migrated_from lineage edges + source identities |
| MIG-005 | implemented | challenge step ENFORCES a policy-engine ceiling on failure (`test_failed_migration_challenge_enforces_ceiling`) |
| MIG-006 | contract-only | comparison harness exists (bench scenario); multi-adapter CSR delta needs real model adapters |
| MIG-007 | implemented | resume by issue/branch/task target |
| MIG-008 | implemented | hidden-reasoning keys stripped; schema forbids them |

## Trust (PA, EV, AUT, GPP)

| ID | Status | Evidence |
|---|---|---|
| PA-001 | implemented | `ProofEnvelope` builds the closed action, subject, input, execution, policy, verification, and continuity record; conformance shape tests |
| PA-002 | implemented | canonical content and artifact digests in `proof.py`; tamper and reseal vectors |
| PA-003 | implemented | tenant HMAC and one-time Lamport signers; authenticity requires an out-of-band key binding (ADR-013, ADR-031, ADR-057) |
| PA-004 | implemented | signed continuity links plus tenant/project/subject checks and project-scoped single-use proof spends (ADR-018, `TestR5ProofBinding`) |
| PA-005 | implemented | immutable finalized envelopes and worst-result-wins authoritative aggregation; missing, failed, skipped, and inconclusive work stay non-success (ADR-014, ADR-015) |
| PA-006 | implemented | in-toto statement round-trip test |
| EV-001 | implemented | typed `VerifierSpec` and `VerificationOutcome` records in `verifiers.py` |
| EV-002 | implemented | command, unit-test, integration-test, lint, type-check, build, file-digest, and value-oracle adapters exercised in verifier tests |
| EV-003 | implemented | `check_run`/`workflow_run` -> verification nodes. An external pass is current only for the current head under the same monotonic tracked-ref revision and a non-uncertain frontier; missing, changed, deleted, or out-of-order ref observations fail closed without claiming complete Git ancestry (ADR-090). |
| EV-004 | implemented | Non-substitutable **only when pinned** with a command (ADR-024): a bare-name entry is satisfiable by a command the claimant chooses, caps the evidence grade at D, and is refused by the default `min_evidence_grade: C`. Self-asserted results never satisfy a required verifier (ADR-019). |
| EV-005 | implemented | Wired into the completion gate (ADR-043): attestation records declared artifact digests as signed inputs, and `complete_task` refuses changed deliverables or changed linked continuity state. Every declared artifact route and nested descendant must remain a physical path under the work tree; symlinks, junctions, and reparse points fail closed. This is not a kernel sandbox and cannot eliminate privileged concurrent filesystem mutation (ADR-096). Unresolved invalidations are current control state under CI-005, not merely a proof-age test (ADR-089). |
| EV-006 | partial | Timeouts, output caps, a scrubbed env with a named threat per entry, and an indirection guard. NOT kernel isolation, and NOT a defence against in-process forgery — a test must import the code under test, so the subject can rewrite the runner's report (ADR-025). |
| EV-007 | implemented | Mutation probes establish that a check binds to a declared deliverable (ADR-027). A mechanical LOWER BOUND: never evidence that the check tests the right property. Per-file line coverage is still not computed. |
| AUT-001 | implemented | levels 0–4 are explicit; new projects default to observation-only |
| AUT-002 | implemented | `PolicyEngine.decide` derives the effective level deterministically from stored policy and state |
| AUT-003 | implemented | `PolicyEngine.grant` creates an audited authorization record |
| AUT-004 | implemented | grant scope, expiry, and revocation are enforced at decision time |
| AUT-005 | implemented | downgrades fire automatically on failed proof, failed migration challenge, and critical invalidation (`TestF4AutonomyGatesBite`) |
| GPP-001 | implemented | `Memory.checkpoint` and partial-run checkpoints preserve a safe recovery boundary |
| GPP-002 | implemented | `RUN_OUTCOMES` distinguishes completed, partially completed, blocked, failed, cancelled, and inconclusive states |
| GPP-003 | implemented | recovery packets name completed work, incomplete work, and the next safe action |
| GPP-004 | implemented | compromised partial output is quarantined and excluded from live control state |
| GPP-005 | implemented | rollback records retain the restored state and its lineage |

## Learning (TR, FC, SD, AE)

| ID | Status | Evidence |
|---|---|---|
| TR-001 | implemented | replay descriptors bind source inputs, environment, and expected outputs |
| TR-002 | implemented | replay forks retain source lineage without overwriting the source run |
| TR-003 | implemented | explicit fidelity classes never accept a self-claimed exact replay |
| FC-001 | implemented | deterministic, correctable failure taxonomy in `FailureComposter.classify` |
| FC-002 | implemented | failure records retain the minimal failing boundary and its evidence |
| FC-003 | implemented | failure clusters are scoped by project |
| SD-001 | implemented | distillation creates a proposal only; no proposal auto-activates |
| SD-002 | implemented | approval requires a recorded sandbox evaluation and human decision |
| SD-003 | contract-only | canary/rollback fields exist; deployment layer executes them |
| AE-001 | implemented | incident-to-evaluation conversion preserves versioned hidden ground truth |
| AE-002 | implemented | deterministic deduplication and withheld-split assignment |
| AE-003 | contract-only | comparison contract exists; cross-version execution needs a fleet runner |
| AE-004 | contract-only | mutation-test contract exists; execution needs a fleet runner |

## Platform (GHI, PLT, SEC, NFR)

| ID | Status | Evidence |
|---|---|---|
| GHI-001 | out-of-scope | App registration, event subscriptions, and permissions are GitHub-side deployment configuration; the transport-neutral normalizer is implemented |
| GHI-002 | implemented | constant-time signature check, delivery-id idempotency |
| GHI-003 | implemented | 12 event types normalized with fixtures |
| GHI-004 | implemented | `continuity_check` computes success, failure, neutral, cancelled, and action-required conclusions; publishing them needs the App |
| GHI-005 | implemented | command parsing + author-association authorization + audit |
| GHI-006 | implemented | text authority typing (human_intent vs untrusted_content) |
| GHI-007 | implemented | nodes/proofs reference commit SHAs from events |
| GHI-008 | partial | forced-push/delete/rename flags recorded + audited; deep lineage repair across rebases not implemented |
| PLT-001 | partial | all 14 versioned local REST routes, authentication modes, typed requests, responses, errors, methods, and limits are generated from `API_ROUTES` into `API.md` and byte-checked in tests; artifact JSON Schemas ship separately; SDK codegen is not included |
| PLT-002 | implemented | OTel-shaped trace ingestion with CCE fields |
| PLT-003 | partial | durable=SQLite + quarantine/replayable events. Explicit project identity creation and checked-in schema migrations serialize their recheck and dependent writes under `BEGIN IMMEDIATE` (ADR-092, ADR-093); this is one-database SQLite writer safety, not distributed identity reservation or Temporal-class retry orchestration. |
| PLT-004 | implemented | full CLI, JSON + human output |
| PLT-005 | out-of-scope | web dashboard |
| SEC-001 | out-of-scope | TLS/at-rest encryption = deployment |
| SEC-002 | partial | tenant scoping on every row + project-scoped queries; RLS needs Postgres |
| SEC-003 | implemented | capture modes and secret screening run before persistence; raw-source and stored-byte commitments stay distinct (ADR-016, ADR-079) |
| SEC-004 | implemented | extraction reads only the persisted redacted payload, and quarantine is enforced at every memory and packet exit (`TestR3RedactionBeforeExtraction`) |
| SEC-005 | partial | approvals and sensitive transitions are audited; service-layer RBAC roles remain deployment work |
| SEC-006 | partial | deletion and retention sweeps preserve audit metadata and integrity commitments; service retention policy remains deployment work |
| SEC-007 | implemented | Triggers refuse mutation; event and audit entry hashes bind every immutable canonical field, including the raw-source and persisted-byte commitments, and retained payload bytes are checked against the latter. Anchor input is a closed, typed, internally consistent v1 document with optional tenant/project binding and clean malformed-input failure (ADR-095). The chain detects rewrites even with triggers dropped; an anchor detects tail truncation **only if published somewhere the operator does not control**, and CCE ships no publication channel (ADR-028, ADR-079). |
| SEC-008 | partial | see EV-006 |
| NFR-001 | out-of-scope | webhook latency objectives need deployed infrastructure; local timings do not evidence an SLO |
| NFR-002 | out-of-scope | API latency objectives need deployed infrastructure; local timings do not evidence an SLO |
| NFR-003 | out-of-scope | ingestion-throughput objectives need deployed infrastructure and representative traffic |
| NFR-004 | out-of-scope | production-scale capacity and failure testing need deployed infrastructure |
| NFR-005 | partial | audit events and operational counters exist; deployment dashboards and alerting do not |
| NFR-006 | partial | OTel-shaped trace ingestion exists; an exporter to an observability backend is not wired |
| NFR-007 | implemented | `schema_version` on every envelope; schemas versioned in `/schemas`. JSON Schema `format` is not self-executing: the repository harness owns and self-tests a standard-library RFC 3339 calendar assertion without optional ambient packages, while the runtime and standalone proof verifier separately enforce proof timestamps. Generic consumers must explicitly enable or implement format assertion (ADR-097). |
| NFR-008 | out-of-scope | dashboard accessibility |
