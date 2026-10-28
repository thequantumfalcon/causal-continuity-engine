# Operating a local CCE project

CCE stores project state in SQLite and exposes CLI, local HTTP, and read-only
MCP interfaces. This guide covers their operating boundaries. Use the
[quickstart](../README.md#quickstart) for commands and [API.md](API.md) for the
HTTP contract.

## Store lifecycle

1. Initialize a project and bind its immutable numeric repository ID.
2. Ingest source events. Review exact proposal operands before confirming
   authority through the owner-local CLI or Python API
   (`record_authority_decision`). HTTP and MCP cannot confirm authority.
3. Configure the verifier policy, run verification, compose a fresh packet,
   and run the continuity check.
4. Close writers before connecting MCP. A live HTTP server or a SQLite WAL,
   SHM, or rollback-journal sidecar prevents MCP admission.
5. To update the project, disconnect MCP, ingest and review the new state,
   compose and check again, close writers, and reconnect MCP.

MCP holds one immutable snapshot. A change to the database or its sidecars
makes subsequent calls refuse the stale view; it does not trigger a refresh.
Never delete a sidecar to force admission: it may contain committed data or
recovery information. Preserve interrupted state before attempting recovery.

## Authority and verifier isolation

Owner-local confirmation trusts possession of the OS/store capability. It
does not authenticate a named human or distinguish processes using the same
account. Keep agent and verifier execution outside the account and filesystem
permissions that own approvals, the store, and `.cce/secrets/` when those actors
must be separated.

The verifier runner copies the work tree, scrubs its environment, and limits
time and output. The requested `network` value is recorded, not enforced.
Use OS-enforced filesystem and network isolation for hostile code. The HTTP
server binds loopback and supplies no TLS, user isolation, or distributed rate
limiting; non-loopback access needs a separately authenticated gateway.

## Read verification outcomes separately

| Result | What it establishes |
|---|---|
| Test command exits 0 | That command reported success. Inspect skipped or unexercised checks. |
| Proof status `verified` | The envelope records successful required verifications; inspect its evidence grade and currency. |
| Evidence grade | Binding, negative-control, and determinism evidence for declared checks; it does not establish that they test the intended property. |
| Continuity `success` | Current continuity predicates passed. Other conclusions exit non-zero. |
| Task completion accepted | The completion gate accepted current authority, state, policy, and any required proof for that task. |

Pin executable paths, negative controls, and all relevant artifacts in policy.
Check tool availability inside the scrubbed verifier environment: its PATH uses
absolute `os.defpath` locations, not the caller's shell PATH. Required Node or
other language tests can otherwise skip. The [KRY replay](evidence/real_repo_kry/FINDINGS.md)
records this case: passing pytest, grade-D evidence, unresolved confirmations,
and no task-completion attempt.

Use a negative control that fails on a relevant known-bad property. Failure to
find a deliberately missing test file only establishes missing-file handling.

## Dependency coverage and traversal

Ingest, CLI, and MCP do not create `assumes` or `depends_on` edges. The graph API
accepts them from a trusted integration. Verify that the intended edges exist
before relying on downstream invalidation.

Initial propagation defaults to six hops and 500 distinct nodes. If the node
budget is exceeded, it retries two hops with a 5,000-node cap and marks the
receipt `truncated`. Exceeding that fallback cap raises an error. A receipt
with `truncated: false` can still exclude dependencies beyond the depth bound.

Completion uses a separate bounded walk through current dependencies. While
an invalidation is open or pending, exhaustion conservatively blocks completion
even when a task was outside the original impact receipt. Resolved or rejected
notices release that hold. Missing typed edges remain outside this coverage.

## Upgrades, retention, and recovery

Before upgrading, record the package and processor versions, stop writers, and
preserve the complete `.cce/` state, including any sidecars, plus the associated
work tree and retained source inputs. Protect secret files with the same access
controls as the live store. Rehearse restoration on a separate copy.

Processor 1.12.0 refuses older projections. There is no in-place projection or
authority upgrade: keep the old store, re-ingest retained sources into a new
project/store, and review and confirm its proposals again. Do not remove
compatibility markers to force an old store open.

Retention can remove the inputs needed for a complete event-derived rebuild;
digests cannot reconstruct them. Runtime proofs, checkpoints, imported sessions,
and grants are not all replay-derived. A log export alone is therefore not a
complete backup. Validate recovery with `audit verify`, `rebuild`, and a newly
composed packet and continuity check. `UNDECIDABLE` rebuild output records
missing replay evidence and is not a successful rebuild.

## Ownership

The project supplies no support SLA, hosted service, key-revocation mechanism,
or external anchor-publication channel. Assign an operator for upgrades,
retention, recovery, and incident response. If independent parties will rely on
proofs, define key-fingerprint distribution and protected anchor storage outside
CCE before using them as audit evidence.
