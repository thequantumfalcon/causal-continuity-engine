# CCE requirements catalog

This catalog defines the public meaning of every requirement identifier used
by the reference implementation. It is the maintained vocabulary for design
discussion, tests, capability claims, and the narrative coverage matrix.

This document defines what each identifier means. It does not claim that every
requirement is implemented. Implementation status and evidence live in
[REQUIREMENTS_COVERAGE.md](REQUIREMENTS_COVERAGE.md); the mechanically checked
subset lives in [CAPABILITIES.md](CAPABILITIES.md). The proof-envelope wire
format is a separate contract defined by [SPEC.md](../SPEC.md).

## Core — causal graph (CCG)

| ID | Requirement |
|---|---|
| CCG-001 | Ingest the same source delivery idempotently, while detecting reuse of an idempotency key with different source content. |
| CCG-002 | Represent project state with a closed set of typed causal entities whose writes are validated. |
| CCG-003 | Represent causal relationships as typed, versioned edges and deduplicate an identical edge version. |
| CCG-004 | Preserve both valid time and transaction time so callers can query the graph as it was known at a selected time. |
| CCG-005 | Resolve competing facts deterministically from authority, freshness, and confidence, while exposing unresolved conflicts and the reason for a ranking. |
| CCG-006 | Rebuild event-derived projections from canonical history and report whether the rebuilt fingerprint matches, diverges, or is undecidable. |
| CCG-007 | Return the provenance trail supporting a graph fact. |
| CCG-008 | Bound traversal by depth and distinct-node budgets so cycles and duplicate paths cannot defeat limits. |

## Core — temporal memory (TM)

| ID | Requirement |
|---|---|
| TM-001 | Record memory-tier assignments and every promotion or demotion as append-only, auditable state transitions. |
| TM-002 | Include the live mission and hard constraints in every resume packet, even when a token budget forces other omissions. |
| TM-003 | Create checkpoints and identify the latest checkpoint that is safe to resume from. |
| TM-004 | Rank retrieval candidates using causal, temporal, and lexical signals, with an explicit extension point for richer retrieval. |
| TM-005 | Admit distilled memory only when its provenance terminates in trusted evidence, and exclude quarantined content from every tier and retrieval path. |
| TM-006 | Apply capture and retention modes while retaining the metadata needed for audit and lifecycle accounting. |
| TM-007 | Decay unpinned memory in retrieval scoring while keeping pinned items exempt. |
| TM-008 | Export, correct, and delete memory through auditable lifecycle operations. |

## Core — assumption detection (AD)

| ID | Requirement |
|---|---|
| AD-001 | Extract explicit assumptions, claims, requirements, and decisions from supported project text. |
| AD-002 | Detect implicit assumptions where possible and expose a calibrated adapter boundary when deterministic extraction cannot establish them. |
| AD-003 | Attach scope, criticality, confidence, authority, and valid-time metadata to every extracted statement. |
| AD-004 | Give a normalized statement a stable identity while recording later occurrences as versions rather than unrelated duplicates. |
| AD-005 | Resolve an assumption by accepting, rejecting, narrowing, or superseding it without erasing prior state. |
| AD-006 | Type text authority, prevent untrusted authors from creating mandates, and quarantine suspected instruction injection before it reaches control state. |
| AD-007 | Calibrate confidence by source authority and abstain when the extractor cannot support a claim. |
| AD-008 | Link assumptions to the facts they assume or depend on when the available evidence supports that relationship. |

## Core — causal invalidation (CI)

| ID | Requirement |
|---|---|
| CI-001 | Recognize the supported invalidation triggers and preserve a multi-source requirement until its last live source retracts it. |
| CI-002 | Propagate invalidation only across eligible typed edges, with strength decay and traversal budgets. |
| CI-003 | Classify an invalidation deterministically from its trigger, scope, and impact. |
| CI-004 | Explain an invalidation with a minimal causal path, supporting evidence, and a recommended action. |
| CI-005 | Require confirmation before a broad invalidation mutates protected live state. |
| CI-006 | Persist packet freshness watermarks across process restarts and support an on-demand currentness check. |
| CI-007 | Resolve invalidations through explicit resolution modes while retaining lineage to the invalidated state. |
| CI-008 | Expose invalidation counters and benchmarkable precision and recall measures. |

## Core — resume and migration (MIG)

| ID | Requirement |
|---|---|
| MIG-001 | Compose a versioned resume packet containing target, mission, authority, accepted decisions, verified progress, invalidations, assumptions, open work, environment, trust, continuity lineage, evidence coverage, recent context, and explicit omissions. |
| MIG-002 | Fit a packet to a budget with explicit omissions while never dropping the live mission or hard constraints. |
| MIG-003 | Export and import signed continuity capsules whose digest and signature detect tampering. |
| MIG-004 | Preserve source identity and migrated-from lineage across a session migration. |
| MIG-005 | Challenge a migrated context against current target state and cap autonomy when the challenge fails. |
| MIG-006 | Compare resume quality across model or runtime adapters with a consistent continuity-success measure. |
| MIG-007 | Locate resumable work by issue, branch, or task target. |
| MIG-008 | Exclude hidden reasoning and provider-private state from portable packets and capsules. |

## Trust — proof-carrying actions (PA)

| ID | Requirement |
|---|---|
| PA-001 | Build a versioned proof envelope that records the action, subjects, inputs, execution, verification, policy, and continuity context. |
| PA-002 | Bind proof content and named artifacts to deterministic digests. |
| PA-003 | Sign proof envelopes and distinguish integrity from authenticity when a verifier lacks an independently trusted key binding. |
| PA-004 | Bind a proof to its tenant, project, action subject, and continuity lineage, and prevent one proof from completing more than one task. |
| PA-005 | Derive status from authoritative verification results so failure, missing evidence, skipped work, and inconclusive work never become success. |
| PA-006 | Project a proof envelope into an in-toto Statement without losing its subject or predicate identity. |

## Trust — execution verification (EV)

| ID | Requirement |
|---|---|
| EV-001 | Represent verifier definitions and outcomes as typed, serializable records. |
| EV-002 | Execute the supported command, unit-test, integration-test, lint, type-check, build, file-digest, and value-oracle verification adapters. |
| EV-003 | Normalize trusted GitHub check and workflow outcomes into verification evidence. |
| EV-004 | Prevent a self-asserted or command-substituted result from satisfying a policy-pinned required verifier. |
| EV-005 | Reject completion evidence whose declared artifacts or relevant continuity inputs changed after attestation. |
| EV-006 | Bound verifier time, retained output, environment, and process cleanup while stating that this is not kernel isolation or a defence against in-process forgery. |
| EV-007 | Use mutation and negative-control probes to establish a mechanical lower bound that a verifier is bound to its declared deliverable. |

## Trust — autonomy (AUT)

| ID | Requirement |
|---|---|
| AUT-001 | Represent the supported autonomy levels and default a new project to observation-only authority. |
| AUT-002 | Decide the permitted autonomy level deterministically from stored policy and current state. |
| AUT-003 | Grant autonomy only through an auditable authorization record. |
| AUT-004 | Enforce grant scope, expiry, and revocation at the decision boundary. |
| AUT-005 | Downgrade autonomy automatically after failed proof, failed migration challenge, or critical invalidation. |

## Trust — graceful partial progress (GPP)

| ID | Requirement |
|---|---|
| GPP-001 | Record a safe checkpoint before work that may only partially succeed. |
| GPP-002 | Distinguish completed, partially completed, blocked, failed, cancelled, and inconclusive outcomes rather than collapsing them into a Boolean. |
| GPP-003 | Emit a recovery packet that identifies completed work, incomplete work, and the next safe action. |
| GPP-004 | Quarantine compromised or untrusted partial results so they cannot become live control state. |
| GPP-005 | Record rollback actions and the state lineage they restore. |

## Learning — replay, failures, skill proposals, and evaluations

| ID | Requirement |
|---|---|
| TR-001 | Describe a replay with explicit source inputs, environment, and expected outputs. |
| TR-002 | Fork a replay without overwriting the source run or its lineage. |
| TR-003 | Report replay fidelity honestly and never label a self-claimed replay exact. |
| FC-001 | Classify failures with a deterministic, correctable taxonomy. |
| FC-002 | Record the minimal failing boundary and evidence that isolates a failure. |
| FC-003 | Cluster related failures within project scope without merging unrelated tenants or projects. |
| SD-001 | Produce learned behavior only as a reviewable proposal, never as an automatically active skill. |
| SD-002 | Require sandbox evaluation and explicit approval before a proposal may become active. |
| SD-003 | Carry canary, rollback, and deployment fields needed by an external deployment layer. |
| AE-001 | Convert a diagnosed incident into a versioned evaluation with hidden ground truth. |
| AE-002 | Deduplicate evaluations and preserve a withheld split for honest assessment. |
| AE-003 | Compare evaluation results across model or system versions through an external fleet runner. |
| AE-004 | Exercise evaluations with controlled mutations through an external fleet runner. |

## Platform — GitHub integration (GHI)

| ID | Requirement |
|---|---|
| GHI-001 | Define the GitHub App registration, event subscriptions, and least-privilege permissions needed by a hosted integration. |
| GHI-002 | Authenticate webhook bytes in constant time and deduplicate deliveries by delivery id. |
| GHI-003 | Normalize every supported GitHub event type into the canonical event envelope. |
| GHI-004 | Compute and expose continuity conclusions suitable for a GitHub check without treating cancellation, timeout, or missing trust as success. |
| GHI-005 | Parse repository commands, authorize them from immutable association data, and audit the decision. |
| GHI-006 | Distinguish human intent from untrusted repository content before extraction or policy use. |
| GHI-007 | Bind nodes and proofs to immutable commit SHAs supplied by authenticated events. |
| GHI-008 | Record force-push, deletion, and rename signals and repair lineage where supported. |

## Platform — API and operations (PLT)

| ID | Requirement |
|---|---|
| PLT-001 | Expose versioned REST and JSON Schema contracts and leave SDK generation to a separate distribution step. |
| PLT-002 | Ingest OpenTelemetry-shaped traces while retaining CCE scope and continuity fields. |
| PLT-003 | Persist state durably, quarantine failed work, and keep events replayable; distributed retry orchestration belongs to deployment. |
| PLT-004 | Provide a complete command-line interface with machine-readable JSON output and useful human-readable output. |
| PLT-005 | Provide a web dashboard in a hosted deployment. |

## Platform — security and privacy (SEC)

| ID | Requirement |
|---|---|
| SEC-001 | Protect deployed transport and stored data with deployment-appropriate encryption. |
| SEC-002 | Scope every read and write by tenant and project, with database row-level security in a multi-tenant service deployment. |
| SEC-003 | Apply capture modes and secret detection before sensitive source bytes can be persisted or projected. |
| SEC-004 | Ensure redacted, dropped, or quarantined content cannot reappear in graph nodes, memory, or resume packets. |
| SEC-005 | Audit approvals and security-sensitive state transitions with actor and reason. |
| SEC-006 | Delete retained content through an auditable operation that preserves the evidence needed to prove what was removed. |
| SEC-007 | Detect event and audit rewrites and tail truncation, while requiring an operator-independent anchor publication channel for external assurance. |
| SEC-008 | Constrain verifier execution at the application boundary and delegate kernel isolation to hardened deployment infrastructure. |

## Platform — non-functional requirements (NFR)

| ID | Requirement |
|---|---|
| NFR-001 | Define and measure deployed webhook-processing latency objectives. |
| NFR-002 | Define and measure deployed API latency objectives. |
| NFR-003 | Define and measure deployed ingestion-throughput objectives. |
| NFR-004 | Validate capacity and failure behavior under production-scale load. |
| NFR-005 | Emit auditable operational events and counters for security- and continuity-relevant decisions. |
| NFR-006 | Export operational metrics and traces to the deployment's observability backend. |
| NFR-007 | Version every public envelope and publish immutable versioned schemas. |
| NFR-008 | Meet accessibility requirements for any hosted dashboard. |
