# Content Ingress Firewall — Development and Verification Sheet

Status: known-carrier scanning is implemented. The isolated-review launcher is
a reference implementation with focused tests, but its privileged macOS
acceptance test has not run against a provisioned root-controlled installation.
The launcher is therefore not an active or release-relied-upon control for
v0.1.5. Hosted enforcement and `cce-integrity-v1` are specified but not
implemented.

## Decision

Externally generated material is not trusted merely because a byte scanner
finds no known mark. Undisclosed model-level text markings may be statistical
properties of token selection and therefore have no removable character or
metadata representation. The preventive boundary is non-ingress: an external
reviewer sees a Git-free export under operating-system isolation, cannot read
or write any protected worktree or the common Git directory, and leaves all
output in quarantine. A trusted root supervisor launches the review under an
explicitly named, dedicated, non-login, non-admin account. That account must
have no sudo authority, credentials, existing processes, or write access to
protected state. A disposable VM with the repository absent is the strongest
deployment. This launcher becomes an active local boundary only after the exact
installed bytes pass the privileged acceptance test on the deployed
operating-system version; inclusion in the source tree does not establish
deployment.

Known-carrier scanning is a second, independent tripwire. It rejects exact
standard carriers, malformed dedicated carriers, and repository-disallowed
hidden Unicode. It never strips, rewrites, or claims to identify an author.

## Threat model

Protected state consists of the repository's common Git directory and every
worktree returned by Git, not only the directory from which a review starts.
The boundary covers direct file tools, shell commands, subprocesses, symlink
paths, staging, refs, and index changes made by the isolated process tree.

The following are treated as failures:

- operating-system isolation is absent or cannot initialize;
- a registered worktree or Git object cannot be inspected;
- the repository changes while its review snapshot is exported;
- any protected byte, path, type, mode, or symlink target changes during the
  review;
- a selected Git blob cannot be scanned completely;
- a dedicated content-provenance carrier is present or malformed;
- a repository-disallowed non-rendering Unicode control is present.

## Deciding paths

1. Before review, inventory the common Git directory and all registered
   worktrees, then hash a bounded physical snapshot.
2. Export tracked and non-ignored untracked source into new plain inodes. The
   copy contains no Git metadata, hardlinks, source extended attributes,
   symlinks, gitlinks, or special files. Oversize inputs and snapshot races
   fail closed. Current macOS may attach its own `com.apple.provenance`
   attribute to every newly created inode; that local outbound attribute is
   allowed, but no source attribute is copied.
3. From a root-owned launcher and isolated Python 3.9+ runtime, start the
   reviewer through `sudo -n -H -u`. The review executable must be absolute,
   root-owned, non-group/other-writable, outside every protected/home/
   quarantine root, and bound to the operator-supplied SHA-256. Safe ancestor
   ownership and the digest are checked again immediately before launch and
   after cleanup.
4. Run the entire reviewer process tree under a Seatbelt policy that denies
   protected reads and writes, all filesystem writes except three quarantine
   runtime directories, Mach and POSIX IPC, notifications, Apple Events,
   signals to other users, and network access. If remote review is required,
   the sole exception is a root-owned proxy on a privileged loopback port;
   that external proxy must enforce the exact provider endpoint.
5. Before the reviewer command executes, a sandboxed wrapper writes an
   unpredictable startup marker. Missing or invalid marker means boundary
   failure, not reviewer failure. A planted direct-child and grandchild probe
   must also prove the deciding denies on the installed macOS version.
6. Stop and reap the launched process group, kill every process under the
   reviewer UID, and require that UID to be process-free. Re-discover the full
   worktree inventory, then re-hash both protected state and the immutable
   snapshot. Inherited process, descriptor, CPU, output-file, quarantine-entry,
   and quarantine-byte limits fail closed. Any mismatch is a boundary failure.
7. Scan the exact proposed Git index locally and exact commit tree in CI and
   release jobs. Findings reject; an incomplete scan is not clean.
8. Accept stdout only when it is bounded UTF-8 JSON using the exact
   `cce.external-review-findings.v1` schema. Each finding contains only an
   integer file id, integer start and end lines, and closed category and
   severity values. Paths, prose, code, patches, comments, extra keys,
   duplicate keys, duplicate findings, unknown ids, and invalid ranges are
   rejected. Raw stdout and stderr stay in quarantine and are never rendered.
9. Never copy a quarantined patch, prose passage, generated file, or report
   into the repository. Findings are coordinates to reproduce. Accepted
   changes are implemented independently against protected source.

## Result semantics

The carrier gate has three process outcomes:

- `0 CLEAN`: every selected object was scanned and no policy finding exists;
- `1 REJECTED`: a known carrier, malformed dedicated carrier, or prohibited
  hidden control was found;
- `2 INCOMPLETE`: any selected object, container, or snapshot could not be
  inspected completely.

The isolated-review launcher returns `0` only after strict scalar-schema and
all postflight checks pass. A started reviewer command that exits nonzero maps
to `124`; setup, missing startup marker, sandbox probe, cleanup, snapshot,
schema, or postflight failure maps to `125`. Raw child status is never allowed
to collide with the boundary result.

The review command receives `CCE_REVIEW_SNAPSHOT`, `CCE_REVIEW_INPUT`, and
`CCE_REVIEW_QUARANTINE`. `INPUT.json` assigns stable integer ids and line
bounds to snapshot files. No parent environment setting crosses. Provider
authentication belongs in the trusted proxy, never the reviewer environment.

## Root-controlled installation

Never run the repository copy with `sudo`, and never resolve Python from the
calling user's `PATH`. Audit and install this launcher under
`/Library/PrivilegedHelperTools` or `/usr/local/libexec`, owned by root and not
group/other-writable, with the same property on every ancestor. Use an audited
root-controlled Python 3.9+ interpreter and standard library, invoked by an
absolute path with `-I -E -s`; the root-owned macOS `/usr/bin/python3` is the
preferred baseline when all runtime checks pass. The launcher mechanically checks isolated-mode
flags, its installed path, the interpreter, and import-path ownership, but
those post-start checks cannot redeem an interpreter or standard library that
was already attacker-controlled before the script began.

Install the review executable and its transitive runtime under the same
root-controlled discipline. Setuid/setgid executables and privileged
transitive helpers or runtime components are not permitted. Invoke the installed launcher with
`--reviewer-user`, `--command-sha256`, and an absolute command path. The
optional `--provider-proxy-port` accepts only ports 1 through 1023 and requires
a root-owned listener before export, immediately before launch, and after
cleanup.

## Frozen acceptance tests

- Before any reviewer process starts, every protected regular file has exactly
  one link. A pre-existing external alias is refused, while a protected tree
  whose regular files each have one link proceeds to the next launch control.
- A child and its grandchild can write inside quarantine but cannot read or
  modify the main worktree, any linked worktree, or the common Git directory.
- A non-root supervisor, the repository owner as reviewer, a reviewer that
  owns or can write protected content, a privileged/login reviewer, a reviewer
  with credentials or existing processes, and a replaceable quarantine parent
  are all refused before export.
- An unavailable sandbox, unreadable worktree, special file, unsafe symlink,
  oversize source, or concurrent mutation stops before review.
- The export contains current tracked and non-ignored untracked bytes but no
  `.git` directory or file, source extended attribute, or shared inode.
- Review stdout containing a path, explanation, comment, code, patch, unknown
  file id, invalid line range, extra key, duplicate key, non-finite number,
  invalid UTF-8, or more than the fixed limits is rejected.
- A marked staged blob plus a clean working file is rejected; a clean staged
  blob plus a marked working file is clean in index mode.
- PNG, JPEG, SVG, structured text, and variation-selector carrier fixtures are
  detected by structure rather than filename or substring.
- Clean near-misses remain clean: exactly one initial UTF-8 BOM in prose,
  ordinary prose emoji selectors/joiners, bytes resembling a PNG chunk inside payload data,
  unrelated JPEG APP11 data, and an unused XML namespace declaration.
- Truncation, malformed lengths, parser limits, missing Git objects, gitlinks,
  large-file pointers, and scanner crashes cannot produce `CLEAN`.
- Local hooks, the alternative pre-commit configuration, base CI, artifact
  verification, and release verification all call the same scanner.

## Hosted enforcement

Workflows stored in this repository are advisory controls: candidate content
can change them. A status produced by the shared GitHub Actions App (integration
15368) proves only that some Actions workflow produced that context; it does
not uniquely bind the trusted scanner.

A hard remote gate requires a private, single-purpose external GitHub App and
the versioned required context `cce-integrity-v1`. Its credential, webhook
verifier, and pinned scanner must remain outside this repository. The service
must scan and report on the exact current pull-request head SHA and exact push
SHA, with missing, stale, crashed, or incomplete work remaining non-success.
This external service and ruleset binding are not implemented here. Bootstrap
and live ruleset activation remain external, manual operations after positive
and spoofed-context negative tests; this document does not add the context to
the committed ruleset.

## Limits

This mechanism does not establish authorship, ownership, first creation,
trusted time, or that a provider never processed the underlying ideas. A
standard provenance carrier reports processing history, not ownership. A
clean known-carrier scan cannot establish absence of an unpublished or
statistical text mark.

The launcher protects only sessions started by the audited root supervisor
through the installed entry point. At each protected-manifest scan it refuses
every protected regular file whose link count is not exactly one. This proves
only that no additional hardlink exists at those scan points. It does not prove
that an alias never existed, or prevent a cooperating unsandboxed process from
creating one after a scan. The dedicated reviewer account supplies DAC
separation but does not substitute for the hardlink preflight. A disposable VM
with a Git-free copy and no host mounts or credentials is stronger than either.

Seatbelt is deprecated platform machinery and can change across operating
system releases. The launcher therefore refuses to run when it is absent, and
its behavior must be re-tested after an operating-system upgrade. An
administrator, kernel compromise, cooperating unsandboxed service, escaped
host mount, or a person manually copying quarantined bytes remains outside the
boundary. No automatic removal or transformation is an accepted remedy.

The local guarantee also depends on the audited interpreter, standard library,
review executable and its transitive runtime, root proxy and upstream
allowlist, `sudo` policy, and macOS kernel. The launcher checks the surfaces it
can inspect but cannot prove a remote proxy's forwarding policy. Provisioning
those trust roots incorrectly makes the launcher fail or voids the claim.
Resource limits reduce accidental and adversarial host exhaustion but are not
a quota boundary: a VM with enforced disk, memory, process, and CPU quotas is
required when host resource denial of service must be contained completely.

The external provider still receives the exported source needed for review.
This boundary does not alter that provider's retention, training, disclosure,
or ownership policy and cannot prove what happens remotely. The return channel
is bounded, not nonexistent: validated file ids, line ranges, categories, and
severities cross back. Those coordinates may direct later local work, but no
provider-supplied wording or bytes are accepted through that channel.

## Primary technical references

- C2PA Content Credentials 2.4:
  <https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html>
- European Commission Article 50 guidance:
  <https://digital-strategy.ec.europa.eu/en/library/guidelines-transparency-obligations-providers-and-deployers-ai-systems>
- European Commission transparency code:
  <https://digital-strategy.ec.europa.eu/en/policies/code-practice-ai-generated-content>
