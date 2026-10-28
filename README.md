<!-- mcp-name: io.github.thequantumfalcon/causal-continuity-engine -->

# Causal Continuity Engine

Continuity, causal invalidation, and proof for long-running coding agents.

![ci](https://github.com/thequantumfalcon/causal-continuity-engine/actions/workflows/ci.yml/badge.svg?branch=main)
![license](https://img.shields.io/badge/license-Apache_2.0-blue.svg)
![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

<p align="center"><img src="https://raw.githubusercontent.com/thequantumfalcon/causal-continuity-engine/main/docs/assets/demo.svg" alt="cce-engine quickstart: install, init, audit verify, assumptions" width="760"></p>

Start with the [Quickstart](#quickstart), [MCP guide](docs/MCP.md), or
[operations guide](docs/OPERATIONS.md).

## The problem

Long-running coding work needs durable decision provenance, current assumptions,
and evidence for completion. CCE provides:

- An application-enforced append-only, hash-chained event log and a bi-temporal
  graph of decisions, assumptions, requirements, and evidence.
- Bounded invalidation over recorded typed edges when requirements change,
  source statements are withdrawn, or an integration calls
  `engine.invalidation.fire(...)` with contradicting evidence.
- Signed completion proofs checked against configured verifiers, current
  authority, policy, and declared artifacts.

Extraction uses deterministic patterns. A trusted comment that explicitly
negates an active assumption's wording raises a notice for owner confirmation;
differently worded disputes may be missed. Ingest does not create `assumes` or
`depends_on` edges. An integration must record those dependencies before
invalidation can traverse them. See [limits](#what-this-does-not-do).

Two commitments serve different integrity checks:
`payload_digest` identifies the raw source delivery for idempotency, while
`stored_payload_digest` authenticates the exact redacted or metadata-only
canonical bytes that processing consumed. Both commitments survive retention;
payload bytes may be removed.

The engine is Python 3.11+ and imports nothing outside the standard library.
`just deps` and CI AST-scan `causal_continuity_engine/` with
`.github/scripts/check_stdlib.py`, including lazy and guarded imports.

The PyPI distribution name is `causal-continuity-engine`, the import package is
`causal_continuity_engine`, and the executable is `cce-engine`. The shorter
`cce` names belong to an unrelated project.

## Use it from an editor

`cce-engine mcp` exposes four read-only tools over Model Context Protocol stdio:
`resume_packet`, `list_assumptions`, `list_invalidations`, `continuity_check`.
[docs/MCP.md](docs/MCP.md) covers installation, connection, and a continuity
check on a runner that holds the store.

MCP first shipped in 0.1.6; the earlier published packages lack it. Version
0.1.4 was prepared but unpublished, and 0.1.5 was tagged but unpublished.
The 0.1.6 lifecycle was exercised with the reference MCP SDK. Other client
compatibility has not been established here; the guide records later reruns.

Initialize a fresh project with the quickstart below before connecting a client.
Use the absolute path to the installed `cce-engine` executable and the initialized
project directory in the client configuration; an editor may not inherit your
terminal's virtual environment or working directory. For example, on macOS/Linux:

```json
{
  "mcpServers": {
    "cce": {
      "command": "/absolute/path/to/.venv/bin/cce-engine",
      "args": ["--dir", "/absolute/path/to/cce-demo", "mcp"]
    }
  }
}
```

On Windows, use the virtual environment's `Scripts/cce-engine.exe`; forward
slashes avoid JSON backslash escaping. Replace both example paths with real paths.
MCP observes a closed store: stop writers cleanly before connecting. Any SQLite
WAL, SHM, or rollback-journal sidecar causes refusal. If another process changes
the store, calls refuse the stale snapshot; restart the MCP session after
writers have stopped. Never delete a sidecar to force admission; it may contain
recovery data.

The transport uses only the standard library. MCP callers cannot ingest,
confirm authority, mint proofs, grant autonomy, or complete tasks.

## Quickstart

Install either the published package (the next blocks) or this checkout (the
editable installation further down), not both: one virtual environment is
enough. The published package runs this quickstart when this checkout is the
release PyPI serves; for `main` between releases, or your own changes, use the
editable installation.

Python 3.11 or newer is required; the engine has no third-party runtime
dependencies. Choose the block for your platform and run it in a new working
directory.

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install causal-continuity-engine
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install causal-continuity-engine
```

If PowerShell blocks activation, do not weaken its execution policy: install
with `.\.venv\Scripts\python.exe -m pip install causal-continuity-engine`
and invoke the environment's `cce-engine.exe` by its absolute path in the
commands below. After activation, `cce-engine --help` checks the installation.

**Upgrading an existing project:** this release uses processor 1.12.0 and
extractor 1.5.0; projections written by 0.4.1's processor 1.11.0 or earlier
processors are refused. There is no in-place projection or authority upgrade. Stop writers,
preserve the complete old project state (including its database and any SQLite
sidecars), and re-ingest retained sources into a separate new project/store.
Review and explicitly confirm the new proposals there; old prose is not approval.
Do not remove markers or sidecars to bypass refusal. Payloads already removed
by retention cannot be reconstructed from their digests. New users can simply
start a fresh project. See [the upgrade notes for this release](CHANGELOG.md#050--2026-10-17);
the [0.1.6 notes](CHANGELOG.md#016--2026-09-20) remain historical.

To run this exact checkout instead of the published package, or to work on the
engine, replace the path below with the checkout's path and install it
editable — see [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) for the
development toolchain:

```bash
cd /absolute/path/to/this/local/checkout
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows, use the PowerShell environment-creation and activation commands
above, then `python -m pip install -e .` from the checkout. Keep that
environment active and `cd` back to your new working directory before the steps
below, so `cce-demo` and its secrets are not created inside the checkout.

The editable install is enough for the engine but not for the test suite,
which fails at collection without the hash-locked development tools. Install
them with `python -m pip install -r requirements-dev.lock` (or `just setup`),
then run `python -m pytest tests` from the checkout. The project configuration
already adds `-q`; adding another hides the closing pass/skip summary. The full
suite can take around fifteen minutes. A few tests skip when the environment
lacks what they exercise; `-rs` lists each skip with its reason. To see the
completion gates described below exercised, run
`python -m pytest tests/test_instrument_validation.py`: it plants each defect a
gate exists to catch and checks that the named gate catches it.

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

The extractor proposed three claims: a requirement, a constraint and an
assumption. Even an `OWNER` source does not approve them. At this point:

```bash
cce-engine --dir . assumptions --status active
# no assumptions
```

Only for this **fresh, initialized demo directory that you control**, save the
following as `prepare_reviews.py`. It prepares review operands for the three
exact statements above; it does not approve them or read signing keys. This is
an owner-local Python example, not a general secure filesystem opener or a
read-only guarantee: `Engine` normally opens writable, schema-capable storage.

<!-- quickstart-review-requests -->

```python
import json
from pathlib import Path

from causal_continuity_engine.engine import Engine

root = Path.cwd()
meta = json.loads((root / ".cce" / "meta.json").read_text(encoding="utf-8"))
engine = Engine(root / ".cce" / "cce.db", tenant_id=meta["tenant_id"], workdir=root)
try:
    def prepare(kind, text):
        matches = [node for node in engine.graph.current(
            meta["project_id"], "claim", tenant_id=meta["tenant_id"])
            if node["data"].get("proposed_kind") == kind
            and node["data"].get("statement") == text]
        if len(matches) != 1:
            raise ValueError("expected exactly one matching retained proposal")
        proposal = engine.authority_proposal(meta["project_id"], matches[0]["node_id"])
        request = {
            "operation": "confirm", "request_id": "quickstart-" + kind,
            "tenant_id": meta["tenant_id"], "project_id": meta["project_id"],
            **proposal, "authority_scope": {"kind": "global"},
        }
        (root / ("review-" + kind + ".json")).write_text(
            json.dumps(request, indent=2) + "\n", encoding="utf-8")

    prepare("requirement", "Exporter must stream rows instead of buffering")
    prepare("constraint", "The exporter must not hold the whole result set in memory")
    prepare("assumption", "the upstream feed is ordered by timestamp")
finally:
    engine.close()
```

```bash
python prepare_reviews.py
```

Inspect the complete source in `issue.json`, the exact retained proposal text,
and **each complete request file**, including its tenant/project and global
scope. Stop if they do not match what you intend to authorize. Preparing these
files is not approval. Submit each only if you approve that individual statement:

```bash
# Only after approving the requirement:
cce-engine --dir . --json authority --request review-requirement.json
# Only after approving the constraint:
cce-engine --dir . --json authority --request review-constraint.json
# Only after approving the assumption:
cce-engine --dir . --json authority --request review-assumption.json
```

Each command returns a receipt naming the confirmation and canonical event.
Now `cce-engine --dir . assumptions --status active` lists the confirmed
assumption. Owner-local authority means possession of the local OS/store
capability, not independent authentication of a human. Neither HTTP nor MCP
exposes this confirmation operation. Revocation and scope replacement also use
explicit structured decisions; editing a source does not silently approve new text.

A Resume Packet is what an agent picking up the work receives instead of a
summary. A project packet includes all applicable mandatory control, work,
policy and trust state. `resume --task-id <confirmed-task-id>` explicitly selects
a live confirmed task and its applicable controls; descriptive `--issue` or
target metadata does not select authority. Task and project freshness records
are separate, while broad project safety changes can stale both. Capsules and
continuity receipts remain project-only, not task-specific verdicts.

The token budget is an advisory trimming target, not a hard ceiling; mandatory
state is not dropped to meet it. `token_estimate` is not a model-specific
tokenizer count. Separately, `--max-response-bytes` is a hard bound on the final
UTF-8 response (default `131072`, allowed `1`–`1048576`). For CLI output that
includes JSON formatting or terminal sanitization and the final newline. HTTP
measures its JSON body; MCP measures the complete result frame including its
request ID and newline. Re-encoding elsewhere is not covered by this bound.

Only optional context may be trimmed, with omissions disclosed. If complete
mandatory state cannot fit, CCE refuses before packet signing or a new success
watermark. The CLI returns exit 2 with the fixed `packet_budget_exceeded` error
on stderr, not a partial packet; the small error frame has its own bound.
Use an adequate limit or legitimate narrower task scope, never truncate authority.

```bash
cce-engine --dir . resume --token-budget 1500
```

Selected lines from that real Markdown output follow. `...` marks excerpted
content here, not a packet omission; the actual output includes the complete
mandatory members, configured policy and other sections.

<!-- quickstart-packet-excerpt -->

```markdown
Scope: {"kind": "project"} | complete: True
Response: cli-markdown | max bytes: 131072

## Mandatory control
...
## Authority
...
### Active requirements
- Exporter must stream rows instead of buffering
...
## Trust
- autonomy level: 0
- required verifiers: none
- verification gaps: policy:proof-required-without-required-verifiers
...
## Transport and cryptographic metadata
...
- schema: cce.resume.v2
- packet digest present: True
- signature present: True
```

The full human view renders each schema field or declares it as metadata kept
in canonical JSON. Use `resume --format json` for those complete canonical
field values, including signatures, digests and the state-basis object.
Recent context lists retrieved nodes by their text; an event node has none, so
it appears by its id alone (`-  (evt_...)`).

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
`cce-engine --help` lists every subcommand.

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

`complete_task` is the false-completion gate, with twenty-three independently
instrumented rejection paths. Authority and state guards apply even when proof
is optional. Explicit revision-frontier uncertainty blocks completion, including
an exact retry; a project without a tracked revision may still complete.
For a new completion, any supplied proof is validated; missing
proof is rejected when policy requires it:

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
6. **A required proof exists.** A missing proof blocks completion when policy
   requires one.
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
    a world that no longer exists. It also binds the complete applicable
    requirement, constraint, decision and assumption set and verifier policy:
    newly applicable controls, withdrawals and scope changes cannot hide behind
    an unchanged caller-selected list of links.
16. **The policy declares required verifiers.** Demanding proof without saying
    what must be proven lets the claimant set its own pass mark. This is a
    configuration error and refusing it names the fix.
17. **Current policy checks passed, by pinned definition.** Names and command
    lines are insufficient: the proof records a canonical digest of the full
    normalized verifier definition. Changing its kind, expectations, timeout,
    negative control, artifacts, isolation, or command makes re-attestation
    mandatory.
    Results must come from an authoritative source; self-assertion satisfies
    nothing, and the worst authoritative result for a required check wins.
18. **The signed policy decision is `allow`.** An authentic record of a
    denied action cannot be promoted into completion.
19. **Evidence grade meets the floor.** Default `C`.
20. **The task state did not race validation.** Its version is re-read before
    the proof is claimed and completion is written; a concurrent change forces
    a retry against the new state.
21. **The task has current authority.** Its owner-local confirmation must still
    have the required canonical decision and retained source witnesses; mutable
    graph labels or an old approval receipt cannot substitute for them.
22. **Applicable authority is not conflicted.** An applicable blocked, uncertain,
    review-required or explicitly conflicted control prevents completion, even
    under proof-optional policy.
23. **The tracked revision is not explicitly uncertain.** An out-of-order
    tracked push blocks completion, including an exact retry, until an admitted
    push reconciles the frontier. A project that has never tracked a revision
    remains completable.

The instrument-validation suite plants exactly one defect for each path and
asserts that the intended gate, rather than a neighboring one, rejects it.

### Evidence grades

Evidence grading uses three probes: a **negative control** must fail against
known-bad state; a **mutation probe** checks whether destroying a copied
deliverable makes a required check fail; a **determinism probe** repeats the
check twice and compares results. These probes assess the checks, without
establishing that they test the intended property.

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

Pin each verifier's command, negative control, and artifacts in project policy:

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

[SPEC.md](SPEC.md) is normative: it defines the `cce.proof.v2` envelope and
five checks: digest, signature, authenticity, sufficiency, and scope.
[verifiers/verify_proof.py](verifiers/verify_proof.py) implements them using
only the standard library, without importing `causal_continuity_engine`.
The committed [conformance corpus](vectors/) includes valid records, negative
cases, and forgeries checked against both implementations in CI.
Published v1 schemas remain historical contracts; v1 proofs are not current
completion evidence. The v2 schema URLs are bound to the `v0.2.0` release tag,
and the release workflow verifies that each serves the checked-out bytes.

`verify_proof.py` is a single file. Installing the published package places a
copy under the environment's `share/causal-continuity-engine/audit/verifiers/`;
with an editable install, use the checkout's `verifiers/verify_proof.py`. From
the project directory:

```bash
# The complete configured verifier set must already be pinned in project policy.
cce-engine --dir . --json verify > proof.json
VERIFY_PROOF="$VIRTUAL_ENV/share/causal-continuity-engine/audit/verifiers/verify_proof.py"
# editable install: VERIFY_PROOF=/absolute/path/to/this/local/checkout/verifiers/verify_proof.py
python "$VERIFY_PROOF" proof.json
```

```text
UNVERIFIED means nothing was established, not that nothing is wrong.
An hmac-sha256 envelope needs --hmac-key-hex; a lamport envelope needs --fingerprint
from a source other than the envelope itself.
UNVERIFIED C1:P C2:S C3:S C4:P C5:S  proof.json

1 UNVERIFIED
```

HMAC verification requires the project's local signing key,
`.cce/secrets/signing.key`, supplied as hex. Without it the verifier reports
`UNVERIFIED` and exits 2. Anyone holding that key can also sign a forged
record, so HMAC provides an operator check within the shared trust domain.
The command below puts the key on the command line; run it only on a machine
you control:

```bash
python "$VERIFY_PROOF" proof.json \
  --hmac-key-hex "$(python -c "import pathlib; print(pathlib.Path('.cce/secrets/signing.key').read_bytes().hex())")"
# VALID      C1:P C2:P C3:P C4:P C5:S  proof.json
```

For `lamport-sha256/1`, the envelope carries the public key. Independent
verification requires its fingerprint from a trusted source outside the artifact:

```bash
python "$VERIFY_PROOF" proof.json --fingerprint sha256:...
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

The four verdicts preserve distinct outcomes: `VALID` passes the applicable
envelope checks; `INVALID` fails a check; `UNVERIFIED` lacks required trust;
`INCOMPLETE` is authentic but records unfinished work. `INVALID` dominates
batch results: a batch containing both `INVALID` and `INCOMPLETE` exits 1.

Check that the reference implementation still agrees with the corpus:

```bash
# from the checkout
python vectors/generate.py --check
# reference agrees with all 50 committed vectors
```

## What this does not do

**Key registry distribution and revocation are absent.** SPEC §6 requires a
trusted fingerprint obtained outside the envelope. CCE supplies no distribution
channel or mechanism for withdrawing trust in a signing key.

**Envelope validation does not establish live freshness.** The engine checks
current project state before completion. A standalone verifier with only the
envelope cannot check whether its deliverables or controls have since changed
(SPEC §11, item 1).

**Retention bounds rebuildability.** Once retention removes source payloads,
the event-derived projection cannot be fully rebuilt from the log.
`cce-engine rebuild` reports `UNDECIDABLE` (exit 3). Runtime records such as
proofs, imported sessions, and checkpoints rely on signatures and audit history,
not event replay; preserve the complete store for recovery.

**Evidence grade does not establish test adequacy.** Even grade A can describe
stable, falsifiable checks that test the wrong property. Probes assess binding
to declared deliverables; the operator must choose the required properties.

**Injection screening is pattern-based.** Novel phrasing can evade detection.
Recognized quarantined content is barred from every memory tier, removed from
previous tiers, and stripped from packets. Secret redaction also uses a pattern
denylist and can miss unfamiliar formats.

**The proof implementations share an author.** Agreement on the conformance
corpus does not establish independent assurance or exclude shared defects.

**External anchors need separate publication.** Tail-truncation detection
requires an anchor held somewhere the store operator cannot rewrite. CCE
supplies no publication channel.

**Verifier execution needs OS isolation for hostile code.** The runner supplies
timeouts, bounded pipe capture, a transcript capped at 256 KiB, best-effort
process-tree termination, environment scrubbing, and a command-wrapper guard.
It cannot prevent same-user absolute-path access, enforce network isolation,
or stop imported code from forging an in-process report. Use OS isolation,
property checks, and mutation probes appropriate to the threat model.

**Dependency drift identifies names, not actual manifest changes.** Since 0.5.0,
automatic `dependency_drift` invalidation needs a matching assumption scope path
or a named package bump in the subject of a commit changing a manifest. Common words and
message bodies cannot supply package names. Dependency vocabulary or distinctive shared
words instead raise a human-gated notice: the assumption stays active pending review, but
the notice blocks completion of touched tasks and can lower autonomy for critical assumptions.
Rejection acknowledges only that push's revision; later matching pushes raise fresh control state.
Grouped bot subjects without package names need vocabulary/shared-word cues to raise review,
even when their bodies list packages; without those cues they can be missed.
CCE does not inspect manifest contents, infer aliases or expand monorepo membership; the
closed English bump grammar can miss real changes or match coincidental names. A confirmed
notice keeps the existing human-gated impact classification, which can be weaker than an
automatic invalidation. See [ADR-135](docs/adr/ADR-INDEX.md#adr-135--dependency-drift-binds-names-and-push-revisions).

**Nothing creates `assumes` or `depends_on` edges yet.** The ontology declares them and
invalidation traverses them, but no ingest path, CLI command or MCP tool produces them, so in
practice invalidation does not propagate along them.

**Impact receipts are bounded.** Initial propagation uses six hops and 500
distinct nodes by default. Node-budget exhaustion retries two hops with a
5,000-node cap. The `truncated` flag reports that fallback, not depth
completeness. Completion separately follows current dependencies and holds on
traversal exhaustion while a notice remains open. See the
[operations guide](docs/OPERATIONS.md#dependency-coverage-and-traversal).

**ContinuityBench uses curated deterministic fixtures and its own scoring.**
Passing its eleven scenarios and six metric targets exercises those cases;
it does not establish real-repository accuracy or comparative performance.

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

Pre-1.0. The public API is **not yet declared** and has no deprecation policy.
Check [PyPI](https://pypi.org/project/causal-continuity-engine/) for the released
version; `main` can contain unreleased changes.

An [offline KRY replay](docs/evidence/real_repo_kry/FINDINGS.md) recorded 418
GitHub envelopes, 1 automatic invalidation, 9 human-gated notices, and grade D
with 8 of 10 snapshot mutations detected.

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

Trust-core changes require a reproduction, a regression demonstrated against
the pre-fix revision, and adversarial review of the fix. Historical review
counts do not substitute for validating the current change.

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
- [docs/MCP.md](docs/MCP.md) — connecting an agent over MCP, walked end to end on
  this repository: install, init, ingest real events, confirm, verify, packet, check,
  client configuration, and the freshness rule.
- [docs/RELEASE.md](docs/RELEASE.md) — the reproducible, signed, immutable-ready
  release procedure and its continuity-bound attestation roadmap.
- [docs/RESEARCH-ROADMAP.md](docs/RESEARCH-ROADMAP.md) — standards-backed
  research priorities, candidate differentiators, falsifiable exit tests, and
  the line between a novel composition and an unsupported novelty claim.
