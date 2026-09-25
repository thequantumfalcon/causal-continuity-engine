# Using CCE from an MCP client

This guide walks through connecting a coding agent to a CCE project over the
Model Context Protocol, end to end, on a real repository. Every command and
every output below was run against this repository's own `main` on
2026-09-24 with the published 0.2.0 wheel; nothing here is hypothetical.

The short version: install the package, initialize a project inside your
repository, feed it real events, confirm the proposals you actually mean,
pin a verifier in policy, verify, compose a packet, and only then point the
agent at `cce-engine mcp`. The agent reads control state; it cannot write it.

## What MCP exposes, and what it does not

`cce-engine --dir <project> mcp` speaks MCP over stdio and offers four
read-only tools:

| Tool | Returns | Notes |
|---|---|---|
| `resume_packet` | the Resume Packet as Markdown (`mcp-markdown`), complete or refused | optional `task_id` selects a live confirmed task; `max_response_bytes` bounds the complete result frame |
| `continuity_check` | JSON with `conclusion` and the frontier predicates | anything other than `success` is reported as such, never as a pass |
| `list_assumptions` | active assumptions with current authority, as text | repository prose that was never confirmed does not appear |
| `list_invalidations` | open invalidations with blast radius, as text | |

Nothing over MCP ingests, confirms, grants, attests or completes. The
confirmation step that turns extracted prose into authority is deliberately
owner-local: it runs only through the CLI on the machine that holds the store.
An MCP client is an untrusted caller in the authority model, and a test in this
repository fails if a tool name ever suggests otherwise.

MCP observes a closed store. Stop the CLI or the HTTP server before connecting;
any SQLite `-wal`, `-shm` or rollback-journal sidecar next to `cce.db` causes a
refusal rather than a partial view. Never delete a sidecar to force admission.

## 1. Install into a virtual environment

```bash
python3 -m venv ~/cce-env
~/cce-env/bin/pip install "causal-continuity-engine==0.2.0"
~/cce-env/bin/cce-engine --help
```

Verify the wheel you received against the release: the 0.2.0 wheel is
`sha256:8e3d3dee3d62af1ec246f74113bc1387d8becb9bef59940b3cbefda4a0c86421`
(`pip download --no-deps --only-binary=:all: causal-continuity-engine==0.2.0`,
then `shasum -a 256`). The same digest is on the GitHub release and on PyPI.

Use the environment's absolute `cce-engine` path in every client configuration
below; an editor does not inherit your shell's activation or working directory.

## 2. Initialize a project inside the repository

Bind the project to the repository's immutable numeric id, not its name:

```bash
cd /path/to/your/repo
REPO_ID=$(gh api repos/OWNER/NAME --jq .id)
~/cce-env/bin/cce-engine --dir . init --repo OWNER/NAME --repo-id "$REPO_ID"
# initialized CCE project prj_... (capture: redacted); local API credentials are in .cce/secrets
```

`.cce/` holds the store and three local secrets. It is in this repository's
`.gitignore`; add it to yours. Never commit it.

## 3. Feed it real events

`ingest` takes GitHub webhook payloads. With the HTTP server (`cce-engine serve`)
GitHub delivers them; without it, build them from the API. The dogfood run used
the real issue, pull request, push and check-run objects of this repository:

```bash
cce-engine --dir . ingest --event issues       --delivery-id d-01 --file issue-33-opened.json
cce-engine --dir . ingest --event issues       --delivery-id d-02 --file issue-35-opened.json
cce-engine --dir . ingest --event pull_request --delivery-id d-03 --file pr-140-closed.json
cce-engine --dir . ingest --event push         --delivery-id d-04 --file push-main.json
cce-engine --dir . ingest --event check_run    --delivery-id d-05 --file check-run-ci-main.json
```

The push establishes the tracked-ref frontier (`refs/heads/main` by default);
the check run from GitHub Actions (App id 15368) is retained as verifier
evidence, trusted only if policy lists that App id.

Expect noise. From two issues and one pull request of real prose, the
extractor proposed six claims: two genuine invariants and four sentences that
merely contain "must" or "never". That is why 0.2.0 makes every extracted
claim a proposal.

## 4. Confirm only what you mean

List the proposals and prepare a confirmation request for each one you
approve. The request carries the exact operands the engine returns, so a later
edit to the source cannot be confirmed by accident:

```python
# prepare_review.py — run from the repository root
import json, sys
from pathlib import Path
from causal_continuity_engine.engine import Engine

root = Path.cwd()
meta = json.loads((root / ".cce" / "meta.json").read_text(encoding="utf-8"))
engine = Engine(root / ".cce" / "cce.db", tenant_id=meta["tenant_id"], workdir=root)
try:
    for node in engine.graph.current(meta["project_id"], "claim", tenant_id=meta["tenant_id"]):
        print(node["node_id"], node["data"].get("proposed_kind"), node["data"].get("statement")[:100])
    if len(sys.argv) == 2:
        proposal = engine.authority_proposal(meta["project_id"], sys.argv[1])
        request = {"operation": "confirm", "request_id": "review-" + sys.argv[1][-8:],
                   "tenant_id": meta["tenant_id"], "project_id": meta["project_id"],
                   **proposal, "authority_scope": {"kind": "global"}}
        Path("review.json").write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
finally:
    engine.close()
```

```bash
~/cce-env/bin/python prepare_review.py                    # list proposals
~/cce-env/bin/python prepare_review.py clm_024fbba35f993c1c7e8ccebc   # prepare one
cat review.json                                           # read every field before you submit it
cce-engine --dir . --json authority --request review.json
```

The dogfood run confirmed exactly one constraint, "authority is never silently
dropped", and left the other five as proposals. The receipt names the
canonical event and the confirmation id:

```json
{"operation": "confirm", "event_id": "evt_3c286e67…", "confirmation_id": "cst_ef0ac802…", "recorded_at": "2026-09-24T04:07:03Z", "request_digest": "sha256:b0773beb…"}
```

Revocation and scope changes are structured decisions too (`operation`
`revoke` or `replace_scope` with the operands from `authority_confirmation`).

## 5. Pin a verifier and verify

Proof is required by default, and the engine refuses to invent a verifier for
you, so a fresh project reports the gap
`policy:proof-required-without-required-verifiers`. Grant autonomy, then
configure a policy whose command, negative control and artifacts you chose:

```bash
cce-engine --dir . policy grant --level 2 --by operator --reason "setup"
```

```json
{
  "max_autonomy_level": 2,
  "require_proof_for": ["task_complete", "pr_ready"],
  "required_verifiers": [
    {
      "name": "release-controls",
      "command": "\"/ABS/cce-env/bin/python\" -m pytest -q tests/test_release_controls.py",
      "expect_fail_command": "\"/ABS/cce-env/bin/python\" -m pytest -q tests/known_bad_does_not_exist.py",
      "artifacts": ["tests/test_release_controls.py", ".github/scripts/check_release_metadata.py"]
    }
  ],
  "min_evidence_grade": "C"
}
```

```bash
cce-engine --dir . policy configure --project prj_... --file policy.json --by operator
cce-engine --dir . verify
# proof prf_...: verified
#   release-controls: passed
```

`verify` runs the complete pinned set in a bounded copy of the work tree,
runs the negative control and expects it to fail, and grades the evidence. The
claimant cannot pick the command.

## 6. Compose a packet, then check

```bash
cce-engine --dir . resume --token-budget 1500        # Markdown
cce-engine --dir . resume --format json > packet.json # canonical JSON, cce.resume.v2
cce-engine --dir . --json check                      # exit 0 only on success
```

On the dogfood store the packet was `cce.resume.v2`, `complete: true`,
project scope, with the confirmed constraint under Authority and the pinned
verifier under Trust, and `check` reported `success` with exit 0.

**Freshness rule.** Any new event stales the current packet. After ingesting
the real closure of issue #35, `check` reported `neutral` with exit 1 until a
new packet was composed, after which it was `success` again. The confirmed
constraint stayed active because its source text was unchanged; withdrawal
tracks the text, not the issue state. Compose before you check, and treat
`neutral` as what it is: not a pass.

## 7. Connect the agent

Claude Code, project scope (creates `.mcp.json` in the repository; do not
commit it if it holds machine-specific paths):

```bash
claude mcp add --scope project cce -- /ABS/cce-env/bin/cce-engine --dir /ABS/path/to/repo mcp
```

Any MCP client, generic form:

```json
{
  "mcpServers": {
    "cce": {
      "command": "/ABS/cce-env/bin/cce-engine",
      "args": ["--dir", "/ABS/path/to/repo", "mcp"]
    }
  }
}
```

On Windows use `Scripts/cce-engine.exe` and forward slashes.

What the reference SDK client (`mcp` 1.29.0) saw against the dogfood store:

```text
protocol 2025-11-25 | server causal-continuity-engine 0.2.0
tools ['continuity_check', 'list_assumptions', 'list_invalidations', 'resume_packet']
continuity_check  isError False  {"conclusion": "success", "open_invalidations": [], ...}
list_assumptions  isError False  "No active assumptions."
list_invalidations isError False
resume_packet     isError False  "# CCE Resume Packet ... Scope: {"kind": "project"} | complete: True ..."
```

Tell the agent, in its instructions, to call `resume_packet` at the start of a
session and `continuity_check` before claiming anything is done. The packet's
`omissions` field lists what was trimmed; an empty list means nothing was.

## 8. Keep it honest in CI

GitHub Actions cannot see your store: `.cce/` is local trust state and never
lives in a hosted checkout. The continuity check therefore runs where the
store lives, on your machine or on a self-hosted runner that holds it, and an
absent store is a failure, not a pass. A minimal job on such a runner:

```yaml
jobs:
  continuity:
    runs-on: [self-hosted, cce-store]
    steps:
      - run: |
          python3 -m venv "$RUNNER_TEMP/cce"
          "$RUNNER_TEMP/cce/bin/pip" install --only-binary=:all: "causal-continuity-engine==0.2.0"
          cd /srv/projects/my-repo                       # the directory that contains .cce/
          "$RUNNER_TEMP/cce/bin/cce-engine" --dir . resume --format json > /dev/null   # compose, then check
          "$RUNNER_TEMP/cce/bin/cce-engine" --dir . --json check
```

`check` exits 0 only on `success`; composing first matters because new events
stale the previous packet and the check then reports `neutral`. Pin the wheel
digest in your own workflow if you want the install to refuse a substitute.
A separate composite action, `thequantumfalcon/cce-continuity-action`, wraps
exactly these steps with a digest-checked install and a step summary; it is
kept outside this repository because this repository ships only its published
source surface.

Hosted workflows contribute the other way round: their check runs reach the
store as `check_run` events and count as verifier evidence when policy trusts
App id 15368 (`trusted_verifier_apps`).

## Troubleshooting

- `refusing a store with sidecars`: a writer is open or crashed. Stop it; do not delete `-wal`/`-shm`.
- The client cannot start the server: use absolute paths for both the executable and `--dir`.
- `check` says `neutral`: compose a packet first; new events stale the last one.
- `verification gaps: policy:proof-required-without-required-verifiers`: configure a policy with at least one pinned verifier.
- `packet_budget_exceeded` (CLI exit 2): the complete mandatory state does not fit `--max-response-bytes`; raise the bound or narrow to a confirmed task with `--task-id`. Authority is never trimmed to fit.
