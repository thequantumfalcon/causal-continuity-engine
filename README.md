<!-- mcp-name: io.github.thequantumfalcon/causal-continuity-engine -->

# Causal Continuity Engine

Continuity, causal invalidation, and proof for long-running coding agents.

![ci](https://github.com/thequantumfalcon/causal-continuity-engine/actions/workflows/ci.yml/badge.svg?branch=main)
![license](https://img.shields.io/badge/license-Apache_2.0-blue.svg)
![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

<p align="center"><img src="https://raw.githubusercontent.com/thequantumfalcon/causal-continuity-engine/main/docs/assets/demo.svg" alt="cce-engine quickstart: install, init, audit verify, assumptions" width="760"></p>

## The problem

An agent working a codebase over weeks does not fail by forgetting text. It
fails by losing the causal thread, in three specific ways:

**It forgets why.** A decision was made in session 4 for a reason that lived
in session 4's context. By session 40 the decision survives and the reason
does not, so the agent either re-litigates it or violates it. A summary of
the conversation does not carry the reason; it carries a paraphrase of the
conclusion.

**It keeps working from an assumption that has since been contradicted.** The
agent assumed the upstream feed was ordered by timestamp. Three days later an
issue comment says it is not. Nothing connects that comment to the twelve
things built on the assumption, so the agent keeps building on it, and the
contradiction surfaces as a bug much later and much further away.

**It reports success it cannot evidence.** "Done, tests pass" is a claim about
a claim. The test run may have been self-reported, may have run a command the
agent chose, may have passed with the deliverable deleted, or may have passed
against a state that no longer exists. Absence of success is never success,
and neither is an unexamined green check.

CCE addresses each with a mechanism rather than a better prompt. Decisions,
assumptions, requirements and evidence become nodes in a bi-temporal causal
graph over an application-enforced append-only, hash-chained event log, so
*why* is a queryable edge and not a memory. When a requirement changes or evidence contradicts an assumption, the
blast radius is computed over typed edges, bounded, and classified
deterministically. And a task cannot be marked complete without a signed proof
envelope whose required verifiers actually ran — the rejection gates are
mechanically enumerated and mutation-tested below.

Event integrity separates two facts that are easy to conflate:
`payload_digest` identifies the raw source delivery for idempotency, while
`stored_payload_digest` authenticates the exact redacted or metadata-only
canonical bytes that processing consumed. Both commitments survive retention;
the removable payload bytes do not have to remain present forever.

The engine is Python 3.11+ and imports nothing outside the standard library.
`just deps` AST-scans `causal_continuity_engine/` and fails on any import that is not stdlib —
parsing rather than importing, so a lazy or guarded import is caught too. CI
invokes the same `.github/scripts/check_stdlib.py` scanner through
`run_gates.py` on every pull request and every push to `main`.

The PyPI distribution name is `causal-continuity-engine`, the import package is
`causal_continuity_engine`, and the executable is `cce-engine`. Those longer
names are intentional: the shorter `cce` distribution, import namespace, and
command are already used by an unrelated published project.

## Use it from an editor

`cce-engine mcp` speaks the Model Context Protocol over stdio, so an MCP client
can read a project's control state directly. Four read-only tools:
`resume_packet`, `list_assumptions`, `list_invalidations`, `continuity_check`.

**Not in a published release yet.** The subcommand exists on `main` and is not
in any version on PyPI, so install from source to use it. It has been driven
end to end from a built wheel with the reference MCP SDK; other clients are
expected to work over the same transport but have not been exercised here.

```json
{
  "mcpServers": {
    "cce": {"command": "cce-engine", "args": ["--dir", ".", "mcp"]}
  }
}
```

The server is read-only by design. An MCP client is an untrusted caller in this
project's authority model, so nothing exposed here mutates state, mints a proof,
or grants autonomy — a test fails if a future tool name suggests otherwise. It
adds no dependencies: the transport is hand-rolled on `json` and `sys` rather
than the official SDK, which would pull in sixteen packages.

## Quickstart

Under five minutes, no dependencies beyond the package itself.

```bash
python -m venv .venv
# Activate with: source .venv/bin/activate          (macOS/Linux)
#            or: .venv\Scripts\Activate.ps1         (Windows PowerShell)
python -m pip install causal-continuity-engine
```

To work on the engine instead of using it, install the checkout editable — see
[.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) for the full toolchain:

```bash
git clone https://github.com/thequantumfalcon/causal-continuity-engine
cd causal-continuity-engine
python -m venv .venv
python -m pip install -e .
```

Global flags come **before** the subcommand: `cce-engine --dir <path> <subcommand>`.

```bash
mkdir cce-demo
cd cce-demo
cce-engine --dir . init --repo octo/demo --repo-id 123456789
```

Use the positive numeric `repository.id` from GitHub's webhook payload (or
API), not a hash of `owner/name`. The name is mutable; webhook ingestion is
fail-closed until this immutable id is registered. A GitHub App deployment
may additionally pin `--github-installation-id`. Existing unbound projects
can be migrated through `Engine.bind_github_repository(...)`.

`init` provisions three independent local credentials under `.cce/secrets/`:
`signing.key`, `api.token`, and `github-webhook.secret`. The directory is
private on platforms that expose POSIX modes and is ignored by Git. `.cce`
must be a physical direct child of the project root; symlinks, Windows
junctions/reparse points, and pre-existing uninitialized roots are refused.
Initialization builds a complete private sibling and atomically renames it, so
an interruption leaves no partial trust root to adopt. Do not copy any secret
into configuration or commit it.

Feed it something to reason over. `ingest` takes a GitHub webhook payload;
here is a minimal `issues` one:

Save this as `issue.json`:

```json
{
  "action": "opened",
  "repository": {"id": 123456789, "full_name": "octo/demo"},
  "issue": {
    "number": 42, "state": "open", "author_association": "OWNER",
    "created_at": "2026-07-31T10:00:00Z", "updated_at": "2026-07-31T10:00:00Z",
    "title": "Exporter must stream rows instead of buffering",
    "body": "We assume the upstream feed is ordered by timestamp. The exporter must not hold the whole result set in memory."
  }
}
```

```bash
cce-engine --dir . ingest --event issues --delivery-id d1 --file issue.json
# ingested issues: 3 node(s), 0 invalidation(s), 0 conflict(s)
```

A repository-bound project also needs an observed protected-ref frontier:
an issue event cannot establish which commit the evidence describes. Save this
minimal tracked-ref event as `push.json`:

```json
{
  "ref": "refs/heads/main",
  "before": "0000000000000000000000000000000000000000",
  "after": "1111111111111111111111111111111111111111",
  "created": true,
  "deleted": false,
  "forced": false,
  "commits": [],
  "repository": {"id": 123456789, "full_name": "octo/demo"}
}
```

```bash
cce-engine --dir . ingest --event push --delivery-id d2 --file push.json
# ingested push: 0 node(s), 0 invalidation(s), 0 conflict(s)
```

The extractor typed that prose by authority and pulled out what is now
control state:

```bash
cce-engine --dir . assumptions --status active
# [active/medium] the upstream feed is ordered by timestamp  (asm_...)
```

A Resume Packet is what an agent picking up the work receives instead of a
summary — token-budgeted, with omissions stated rather than silent:

```bash
cce-engine --dir . resume --token-budget 1500
```

```markdown
# CCE Resume Packet
Packet `rsp_...` | generated ... | state at event:evt_...

## Mission
**Project:** octo/demo
**Objective:** No explicit mission pinned; see open work.

## Authority
- [constraint] The exporter must not hold the whole result set in memory (high)
- [requirement] Exporter must stream rows instead of buffering

## Accepted decisions

## Invalidated state
- none open

## Verified progress

## Open work

**Next safe action:** No open tasks; verify project state and await instruction.

## Trust
- autonomy level: 0
- required verifiers: none
- verification gaps: policy:proof-required-without-required-verifiers

Evidence coverage: 100% | ~716 tokens
```

That is the whole packet, not an excerpt: every section heading renders
whether or not it has content, so the empty ones above are literal.

The named verification gap is expected on a fresh project: proof is required
by default, but CCE cannot safely invent a project-specific verifier
definition. Configure one below to close the gap. Independently, autonomy is 0
by default and running a verifier requires level 2, so policy denies it until a
human grants otherwise:

```bash
cce-engine --dir . policy grant --level 2 --by operator --reason "quickstart"
# granted level 2 (grt_...)
```

Find the absolute interpreter path:

```bash
python -c "import sys; print(sys.executable)"
```

Save the following as `policy.json`, replace
`ABSOLUTE_PATH_TO_PYTHON` with that path, and use forward slashes if the
Windows path contains backslashes:

```json
{
  "max_autonomy_level": 2,
  "require_proof_for": ["task_complete", "pr_ready"],
  "required_verifiers": [
    {
      "name": "json-check",
      "command": "\"ABSOLUTE_PATH_TO_PYTHON\" -c \"import json;json.load(open('issue.json',encoding='utf-8'))\"",
      "expect_fail_command": "\"ABSOLUTE_PATH_TO_PYTHON\" -c \"import json;json.loads('{')\"",
      "artifacts": ["issue.json"]
    }
  ],
  "min_evidence_grade": "C"
}
```

```bash
# Use the project_id printed by init.
cce-engine --dir . policy configure --project prj_... --file policy.json --by operator
cce-engine --dir . verify
# proof prf_...: verified
#   json-check: passed
```

Policy configuration, grants, and verification results are packet control
state, so they intentionally stale the earlier packet. Refresh it before
gating:

```bash
cce-engine --dir . resume --token-budget 1500
```

Among the full packet output, its Trust section now reads:

```markdown
## Trust
- autonomy level: 2
- required verifiers: json-check
- verification gaps: none
```

```bash
cce-engine --dir . check
# CCE Continuity: success (open invalidations: 0)
```

`verify` always runs the complete verifier set in configured project policy.
It accepts neither a per-verifier selector nor a command: `--verifier` and an
argument such as `unit-tests=...` are rejected. The operator pins commands,
negative controls, and artifact paths in project policy; the party asking for
verification cannot omit a required check or substitute an easier command.

`check` exits 0 only on `success`; `failure`, `action_required`,
`cancelled`, and `neutral` all exit 1, so absence of success cannot appear
green in CI. For headless use, `--json` is a global flag like `--dir` and therefore
goes **before** the subcommand — `cce-engine --json check`, not `cce-engine check --json`,
which argparse rejects. The one exception is `resume`, which renders markdown
regardless; ask for its structured form with `resume --format json`.
`cce-engine --help` lists all fourteen subcommands.

`check` can also export a signed operator receipt and classify it later:

```bash
cce-engine --dir . --json check --export-receipt continuity-receipt.json
cce-engine --dir . --json check --verify-receipt continuity-receipt.json
```

Receipt verification returns `CURRENT` with exit 0 when authenticity,
semantics, stored chain prefixes, and the live continuity frontier match;
`AUTHENTIC_HISTORICAL` with exit 3 when an authentic receipt describes an
older frontier; and `INVALID` with exit 4 for malformed, forged, contradictory,
or unrooted input. The receipt is explicitly operator-audience and uses the
local tenant signer. It is not a public transparency receipt or a substitute
for the independent proof-envelope verifier.

### Local HTTP endpoint

`cce-engine --dir . serve` binds only `127.0.0.1`. Every route except the
unauthenticated `GET /v1/health` check requires authentication. Ordinary routes
use `Authorization: Bearer <contents of .cce/secrets/api.token>`. The
`POST /v1/events:ingest` route is intentionally different: configure GitHub
with the contents of `.cce/secrets/github-webhook.secret`, then send the raw
GitHub JSON body itself with `X-Hub-Signature-256`, `X-GitHub-Event`, and
`X-GitHub-Delivery`. Do not wrap it in `event_name`, `delivery_id`, or
`payload`; the signature is verified over the exact request bytes before JSON
is interpreted. After HMAC verification, routing is authorized against the
project's registered numeric `repository_id` and, when configured, numeric
GitHub App installation id. A matching or renamed `full_name` is not a trust
anchor.

Authenticated clients can verify an operator receipt with
`POST /v1/projects/<project_id>/continuity-receipts:verify` and body
`{"receipt": {...}}`. The response uses the same three verdicts as the CLI.

Public resource identifiers have one transport spelling: 1–128 ASCII
URI-unreserved characters, beginning with a letter or digit. The remaining
characters may be letters, digits, `.`, `_`, `~`, or `-`. Slash, percent
escapes, whitespace, controls, Unicode, and dot segments are rejected before
creation or route lookup; percent-encoding cannot make an invalid identity
valid (ADR-102).

The built-in server is a local integration endpoint, not a public security
boundary: it provides no TLS, OS-user isolation, or distributed rate limiting.
The complete route, request, response, error, method, authentication, and limit
contract is generated from the live route registry in [docs/API.md](docs/API.md).

## How it decides a task is done

`complete_task` is the false-completion gate. When policy requires proof for
`task_complete`, a completion attempt passes through twenty independently
instrumented rejection paths:

1. **The target is a task in this project.** Another entity type, tenant, or
   project cannot be completed through a borrowed identifier.
2. **No unresolved invalidation controls the target.** An open or
   pending-confirmation invalidation touching the task blocks completion even
   when the proof was attested later. A critical unresolved invalidation
   blocks completion project-wide; a resolved or rejected one does not.
3. **A verified completion is monotonic.** An exact retry is an idempotent
   no-op, while a different proof cannot overwrite the recorded evidence or
   authority without an explicit reopen or invalidation.
4. **Not quarantined.** A task flagged for injected or untrusted content
   cannot be completed out of quarantine; that is a human decision, never a
   success claim laid on top.
5. **The current state is completable.** Only a new, open, or in-progress task
   can transition to verified; proof-optional policy cannot overwrite blocked,
   uncertain, invalidated, rejected, or superseded work.
6. **A proof exists.** Policy demands one and none was supplied.
7. **The required proof shape exists.** Missing identifiers or decision
   fields are malformed input, not a signature question.
8. **The envelope verifies.** Signature and digest, checked against the
   signer — not against fields inside the signature block.
9. **Status is `verified`.** Not `incomplete`, not `stale`, not `draft`.
10. **Scope matches.** Same tenant, same project. A genuine proof from
   elsewhere is still a genuine proof of something else.
11. **Intent matches.** A proof of `pr_ready` is not a proof of
   `task_complete`.
12. **Subject matches.** The proof names *this* task. A signature says the
   record is authentic, not what it is evidence for.
13. **Single use.** A proof already spent completing another task cannot be
    replayed.
14. **The proof claim is atomic.** A concurrent completion that wins after the
    precheck cannot be overwritten; the database claim names the winning task
    and the losing attempt fails closed.
15. **The proof is current.** If a named deliverable or any linked task,
    requirement, decision, assumption, artifact, evidence or action changed
    its signed semantic/version digest since attestation, the proof describes
    a world that no longer exists.
16. **The policy declares required verifiers.** Demanding proof without saying
    what must be proven lets the claimant set its own pass mark. This is a
    configuration error and refusing it names the fix.
17. **Current policy checks passed, by pinned definition.** Names and command
    lines are insufficient: the proof records a canonical digest of the full
    normalized verifier definition. Changing its kind, expectations, timeout,
    negative control, artifacts, isolation, or command makes re-attestation
    mandatory.
    Results must come from an authoritative source; self-assertion satisfies
    nothing, and the worst result reported anywhere wins.
18. **The signed policy decision is `allow`.** An authentic record of a
    denied action cannot be promoted into completion.
19. **Evidence grade meets the floor.** Default `C`.
20. **The task state did not race validation.** Its version is re-read before
    the proof is claimed and completion is written; a concurrent change forces
    a retry against the new state.

The instrument-validation suite plants exactly one defect for each path and
asserts that the intended gate, rather than a neighboring one, rejects it.

### Evidence grades

Grading asks one question: could this check have been red? Three mechanical
probes answer it without asking the subject to grade itself — a **negative
control** (show the check failing against known-bad state), a **mutation
probe** (destroy the deliverable in a sandbox copy; some required check must
notice), and a **determinism probe** (run twice; a check that disagrees with
itself evidences nothing).

| Grade | Meaning |
|---|---|
| **A** | Every required check executed by CCE under a pinned command, each with a negative control shown holding, deliverables mutation-bound, no flaky check. |
| **B** | As A, but artifact binding or run-to-run stability was never probed. |
| **C** | Executed and pinned, but no negative control held — the check has not been shown capable of failing. |
| **D** | A required check ran under a command the claimant supplied, or a declared deliverable survived destruction unnoticed. |
| **F** | A required result was self-asserted, missing, or failing. |

There is no E. The default floor of `C` refuses D, which means an unpinned
required verifier does not complete a task unless a project lowers the floor
deliberately.

Declared artifacts are also part of the evidence boundary. Every route
component and nested descendant must remain a physical path under the work
directory; symbolic links, Windows junctions, and other reparse points are
refused at policy write, attestation, and currency checking. Files and complete
directory inventories are streamed through stable pre/post snapshots;
attestation re-snapshots after verifier execution and after evidence probes,
and signs every artifact used by policy or an effective verifier.

Every command and negative control runs in a separate bounded physical copy of
the work tree, even when the project has no local `.cce` directory. That copy
omits CCE trust state, VCS internals, caches, virtual environments, dependency
trees, and bytecode. If policy declares a parent directory as an artifact,
otherwise ignored descendants below it are retained so the command and signed
commitment address the same bytes; directly declaring an omitted component is
invalid. A configured Store database and its WAL/SHM companions are always
excluded, and an artifact that equals, contains, or is contained by that state
is rejected before execution or persistence. The copy is capped at 100,000
entries, 64 MiB per file, 512 MiB total, and 64 levels; indirect, special, or
changing inputs yield an inconclusive result. A command that changes a declared
artifact inside its copy cannot mint a proof or evidence node (ADR-103).

These are path-integrity and bounded-copy controls, not an atomic filesystem
snapshot or kernel sandbox. A hostile same-user process may still use known
absolute paths, access the network where the OS permits it, or attempt a
swap-and-restore between observations, especially on the Windows
standard-library fallback. Run hostile verifier code under OS-enforced
isolation (ADR-099, ADR-103).

Pinning is the difference between a name and a check. The policy supplies the
command, not the claimant:

```json
{
  "require_proof_for": ["task_complete", "pr_ready"],
  "required_verifiers": [
    {
      "name": "unit-tests",
      "command": "\"ABSOLUTE_PATH_TO_PYTHON\" -m pytest -q",
      "expect_fail_command": "\"ABSOLUTE_PATH_TO_PYTHON\" -m pytest tests/known_bad.py",
      "artifacts": ["src/exporter.py"]
    }
  ],
  "min_evidence_grade": "C"
}
```

Apply that file only to the initialized local project:

```bash
cce-engine --dir . policy configure --project prj_... --file policy.json --by operator
```

Configuration persists and audits policy; it never runs a command. The
verifier executes only when an authorized verification action is requested.

GitHub check authority is configured by immutable numeric App identity, not a
sender login or mutable slug. For GitHub Actions the policy entry is:

```json
{
  "trusted_verifier_apps": [
    {"app_id": 15368, "slug": "github-actions"}
  ]
}
```

`app_id` is the authorization key; `slug` is an optional second check.
Webhook `installation_id` is retained as provenance but never grants trust.
Individual workflows can be narrowed separately with a numeric
`trusted_workflows[].workflow_id` and optional path.

An external pass is current only for the present tracked-ref head and the same
tracked-ref policy revision. Clearing or changing the ref, deleting it,
receiving an out-of-order frontier, or retaining an uncertain frontier fails
closed. This protects the evidence decision; it does not reconstruct Git
ancestry or prove that every webhook was delivered.

Run the probes directly with `cce-engine evidence probe` and `cce-engine evidence
determinism`; both exit non-zero on failure.

## Verifying a proof without trusting the engine

[SPEC.md](SPEC.md) is normative: it defines the `cce.proof.v1` envelope and
the five checks (digest, signature, authenticity, sufficiency, scope) well
enough to reimplement from that text alone.
[verifiers/verify_proof.py](verifiers/verify_proof.py) is such a
reimplementation — standard library only, and it imports nothing from
`causal_continuity_engine`,
so agreement between the two is evidence rather than the same code run twice.
[vectors/](vectors/) is a committed conformance corpus, including honest
negatives and adversarial forgeries, that pins both implementations in CI.

```bash
# The complete configured verifier set must already be pinned in project policy.
cce-engine --dir . --json verify > proof.json
python verifiers/verify_proof.py proof.json
```

```text
UNVERIFIED means nothing was established, not that nothing is wrong.
An hmac-sha256 envelope needs --hmac-key-hex; a lamport envelope needs --fingerprint
from a source other than the envelope itself.
UNVERIFIED C1:P C2:S C3:S C4:P C5:S  proof.json
```

**That verdict is the honest one, and it is the point.** `hmac-sha256` is not
a third-party-verifiable scheme at all. Without the secret, an untouched
envelope and a resealed forgery are indistinguishable, so the verifier reports
`UNVERIFIED` — not `VALID` — and exits 2. A verifier that returned `VALID`
there would be telling a stranger that a body a forger rewrote and resealed is
sound. Supply the key and the same envelope verifies:

```bash
python verifiers/verify_proof.py proof.json --hmac-key-hex <hex>
# VALID      C1:P C2:P C3:P C4:P C5:S  proof.json
```

`lamport-sha256/1` is checkable without the signing key, but the public key
travels inside the envelope, so anyone may mint a keypair and sign anything.
Reaching `VALID` as a stranger requires the fingerprint from somewhere other
than the artifact:

```bash
python verifiers/verify_proof.py proof.json --fingerprint sha256:...
```

The verifier's input boundary is deliberately finite. One invocation accepts
at most 128 path patterns, each at most 4,096 characters and filesystem-encoded
bytes; glob magic is supported only in the final path component. Expansion
scans at most 100,000 directory entries and admits at most 4,096 distinct
normalized matches, then the verifier reads at most 1,024 distinct normalized
paths. Each proof must be a stable physical regular file — not a symlink,
reparse point, directory, or special file — of at most 1 MiB. Its complete
bytes are read through one binary descriptor and parsed as strict UTF-8 JSON,
without prefix truncation. A path-expansion limit is a usage error on stderr
with exit 64. An unreadable, unstable, oversized, non-regular, or malformed
file produces a per-file `INVALID`/`E_CJSON` result and makes the batch exit 1.

The verdict has four values because collapsing them loses the distinction
between opposite situations. `INVALID` means something is wrong.
`UNVERIFIED` means nothing was established. `INCOMPLETE` means the envelope is
authentic and honestly records that the work is not done. Exit codes follow,
and `INVALID` dominates — a batch containing both an `INVALID` and an
`INCOMPLETE` exits 1, so a CI gate keyed on the code cannot miss a forgery.

Check that the reference implementation still agrees with the corpus:

```bash
python vectors/generate.py --check
# reference agrees with every committed vector
```

## What this does not do

These are stated here so they are not discovered later and reported as
findings. Several are load-bearing: the design depends on being honest about
them.

**Key registry distribution is unsolved.** Authenticity requires a fact from
outside the envelope — a fingerprint obtained out of band. SPEC §6 requires
such a registry and says nothing about how it travels, because nothing here
solves that. No amount of verifier code closes it.

**There is no revocation.** A fingerprint in the registry is trusted for every
envelope it ever signed. Withdrawing a key is not a mechanism this has.

**A stranger cannot tell whether an envelope is still fresh.** An envelope is a
statement about a moment. Whether the deliverables it names still carry the
digests it records requires the project, not the envelope. The engine checks it
— that is rejection 15 above — but someone holding only the envelope cannot, so
`VALID` from the standalone verifier says the record is sound, not that the
world it describes still exists. SPEC §11, item 1.

**Rebuildability is bounded by the retention window.** Projections rebuild
from the event log until retention clears a payload; after that the log no
longer contains what it would take to check. `cce-engine rebuild` reports
`UNDECIDABLE` (exit 3) rather than pretending the projection either matches or
diverges, because "the log disagrees" and "the log can no longer say" are
opposite diagnoses.

**Evidence grading is a mechanical lower bound, not an oracle.** The probes
prove a check is bound to a deliverable's existence and content. They can
never prove it checks the right property. An A-grade check can be bound,
stable, falsifiable, and still test the wrong thing. It is lint, not an
oracle.

**Injection screening is pattern-based and will miss novel phrasing.** The
structural defences do not depend on the patterns catching anything:
quarantined content is barred from every memory tier, vacates any tier it
already held, and is stripped from composed packets. That is deliberate
layering — the screen is the weak layer and is treated as such.

**Both the engine and its "independent" verifier have one author.** Two
implementations agreeing proves the specification is unambiguous enough to
reimplement, and that neither carries a defect the other lacks by
construction. That enables implementation independence; it does not
constitute it. A verifier written by a different party against SPEC.md is the
thing that would.

**An anchor published nowhere proves nothing.** Tamper evidence has three
layers, and the outermost is only as good as where the anchor is put: one
produced at verification time from the same store agrees with whatever that
store now says. CCE ships no publication channel.

**Verifier sandboxing is not kernel isolation, and not a defence against
in-process forgery.** There are timeouts, concurrent bounded pipe drains, a
deterministic stored transcript capped at 256 KiB, best-effort process-tree
termination, a scrubbed environment with a named threat behind each entry, and
a guard on commands that delegate to a program named in their arguments. But a
test must import the code under test, so the subject can rewrite the runner's
report. That is what value-oracle checks and mutation probes exist for.

**ContinuityBench is self-scored on curated deterministic fixtures.** All eleven
scenarios pass and all six metrics are at target, which demonstrates mechanism
correctness. It is not evidence about real repositories, and it is not a
comparison against anything.

**Transaction timestamps are ordered within one process, not across writers.**
Equal wall-clock samples are advanced by one microsecond under a process-local
lock, which keeps adjacent SQLite versions visible on coarse clocks and across
threads. Separate processes or machines need a database sequence or hybrid
logical clock; CCE does not claim that coordination.

**Append-only is locally enforced, not immutable storage.** SQLite triggers
reject mutation and the event/audit hash chains expose rewrites, but a database
operator can disable those controls or truncate a tail. Tail-truncation
detection becomes externally meaningful only after an exported anchor is
published somewhere the operator cannot rewrite; CCE ships no such channel.

Also absent by design: no hosted GitHub App, no web dashboard, no Postgres
deployment. Storage is SQLite behind one `Store` class implementing a
PostgreSQL-first relational design, so tenant isolation is enforced at the
application level rather than by row-level security.

## Status

Pre-1.0. The public API is **not yet declared** — anything may change, and
there is no deprecation policy yet. The released version is whatever
[PyPI](https://pypi.org/project/causal-continuity-engine/) serves; this file is
that package's description, so it does not restate a version number it cannot
keep in step.

- Hosted CI requires the full suite on Python 3.11, 3.12, 3.13 and 3.14 on
  Linux and natively on Windows 3.14 and macOS 15 ARM64/Python 3.14; 11/11
  ContinuityBench scenarios pass with all 6 metrics at target
- Repository-policy JSON was applied and read back against the live rulesets.
  Remote settings are mutable, so the apply/read-back procedure that re-checks
  them is in [.github/ruleset.README.md](.github/ruleset.README.md).
- The accepted ADRs in [docs/adr/ADR-INDEX.md](docs/adr/ADR-INDEX.md),
  including the per-round review notes
- Capability claims that must mechanically resolve, generated into
  [docs/CAPABILITIES.md](docs/CAPABILITIES.md) — each with an honest-limit
  column; `just caps` regenerates that table in CI and fails on any diff, so a
  stale or hand-edited copy breaks the build
- The public requirement vocabulary in
  [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md), with implementation status and
  evidence in
  [docs/REQUIREMENTS_COVERAGE.md](docs/REQUIREMENTS_COVERAGE.md)

The trust core is **change-controlled, not frozen**. Successive adversarial
rounds, including the current operator-surface and race hardening, found
defects both in feature code and in the machinery built to check it. The
contribution contract requires a pre-fix reproduction and regression for each
accepted defect fix. That is why
hardening changes get their own adversarial pass: treat a clean integrated
round, not a historical round number or defect count, as the stopping
condition.

## Contributing, security, license

- [CONTRIBUTING.md](.github/CONTRIBUTING.md) — how to propose a change and what a
  patch has to carry.
- [SECURITY.md](.github/SECURITY.md) — how to report a vulnerability. Please do not
  open a public issue for one.
- [LICENSE.txt](LICENSE.txt) — Apache-2.0. Copyright 2026 Thomas Albrecht (The Quantum Falcon).
- [CITATION.cff](CITATION.cff) — citation metadata for the exact release or
  commit evaluated.
- [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) — the plain-language definition
  of every requirement identifier used by code, tests, ADRs, and coverage.
- [docs/REQUIREMENTS_COVERAGE.md](docs/REQUIREMENTS_COVERAGE.md) — the
  per-requirement implementation status and supporting evidence.
- [docs/PUBLIC-FLIP.md](docs/PUBLIC-FLIP.md) — the register of every control
  that could not be enabled while this repository was private, with the exact
  command that turned each one on at the flip.
- [docs/RELEASE.md](docs/RELEASE.md) — the reproducible, signed, immutable-ready
  release procedure and its continuity-bound attestation roadmap.
- [docs/RESEARCH-ROADMAP.md](docs/RESEARCH-ROADMAP.md) — standards-backed
  research priorities, candidate differentiators, falsifiable exit tests, and
  the line between a novel composition and an unsupported novelty claim.
