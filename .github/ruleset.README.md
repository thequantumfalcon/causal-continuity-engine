# Repository rulesets

.github/ruleset.json is the reviewable desired state for the default branch;
.github/tag-ruleset.json is the desired state for release tags. These files
are not synchronized by GitHub. Committing them changes no remote protection;
the API update and a read-back are separate operational steps.

## Verified live state and drift

A remote read-back on 2026-08-04 found:

- branch ruleset 20196699, protect-default, is active;
- it requires only the ci status context;
- RepositoryRole id 5 has bypass_mode always;
- required_signatures is absent;
- tag ruleset 20350891, protect-releases, is active with no bypass actors and
  deletion, non-fast-forward, and required-signature rules.

The attribution and secrets workflows run, but they are not merge-blocking in
that live state. The observed main tip had a valid GitHub-Verified signature,
but one signed commit is not enforcement for the next commit.

Inspect the live objects, not just this document:

    gh api repos/thequantumfalcon/causal-continuity-engine/rulesets --jq '.[] | [.id, .name, .target, .enforcement]'
    gh api repos/thequantumfalcon/causal-continuity-engine/rulesets/20196699 --jq '{id,name,enforcement,bypass_actors,rules}'
    gh api repos/thequantumfalcon/causal-continuity-engine/rulesets/20350891 --jq '{id,name,enforcement,bypass_actors,rules}'

## Apply and verify the desired state

Update the existing branch object by ID. Do not POST a duplicate:

    gh api -X PUT repos/thequantumfalcon/causal-continuity-engine/rulesets/20196699 --input .github/ruleset.json

The release-tag ruleset is already live. Update it by ID if its committed
desired state changes; do not POST a duplicate:

    gh api -X PUT repos/thequantumfalcon/causal-continuity-engine/rulesets/20350891 --input .github/tag-ruleset.json

Run all three inspection commands again after mutation. The branch read-back
must show an empty bypass_actors array, required_signatures, and required
status contexts ci, attribution, and secrets, each with integration_id 15368
(the GitHub Actions app). The tag query must show active
protect-releases with an empty bypass list plus deletion, non_fast_forward,
and required_signatures rules. Save the returned tag ruleset ID for later
updates.

## Desired default-branch contract

Once the JSON has been applied and read back, the branch contract is:

- a pull request, linear history, and squash merge;
- every review thread resolved;
- verified commit signatures;
- no force-push and no deletion;
- current-head success from ci, attribution, and secrets, accepted only from
  the GitHub Actions app (integration_id 15368);
- no permanent bypass actor, including repository administrators.

The project has one maintainer, so GitHub cannot supply an independent
approval. required_approving_review_count, code-owner review, and last-push
approval therefore remain disabled. That exception does not weaken the three
machine gates or conversation resolution.

The empty desired bypass list is deliberate. If a required check is broken,
fix the check through the same pull-request path. Until the remote read-back
matches, however, that is policy intent rather than a fact about enforcement.

## Why the check names are stable

ci fans in the Linux Python 3.11-3.14 matrix, native Windows execution, and
the double-build/installed-wheel audit. Requiring individual matrix names
would silently lose coverage whenever the matrix changes. The fan-in uses
if: always() and explicitly requires every dependency result to be success,
so a skipped or cancelled leg cannot appear green.

attribution and secrets live in separate workflows because they are
independent policy controls. Listing them in the desired JSON is what makes
them merge-blocking after application; merely running a workflow does not.
The source binding matters because a repository writer or another integration
can otherwise report a status under the same context name. GitHub requires the
selected app to be installed and to have recently emitted the pre-existing
check, so confirm those conditions before applying the ruleset.

The release verifier treats `ci`, `attribution`, and `secrets` as a fixed core
quorum and reads their App IDs from this file. `dependency-review` and `DCO`
are explicitly classified as PR-only requirements; they do not pretend to
have emitted a push-event check for the eventual squash commit. Any other new
branch context makes release verification fail closed until its event and
exact workflow-path semantics are reviewed in `check_release_tag.py`. GitHub
may present a run path with a nonempty `@ref` suffix; the verifier accepts that
documented form only after the reviewed base path matches exactly.

`commit-signature-audit.yml` separately asks GitHub's commit API whether the
exact pushed `main` SHA is Verified. It is deliberately a post-push detective
control: it can expose a missing signature but cannot stop that commit from
landing. The desired `required_signatures` branch rule is the preventive
control; do not describe the audit workflow as a substitute.

## Desired release-tag contract

Live tag ruleset `20350891` was created and read back on 2026-08-04. It matches
refs/tags/v*, blocks update and deletion, requires the target commit to have a
verified signature, and has no bypass actor.

After that rule is created, the release workflow adds checks a tag ruleset
cannot express: the tag must be an annotated PGP- or SSH-signed object,
GitHub must verify the tag signature, its name must equal v plus the package
version, it must point at the checked-out commit, the commit must be reachable
from `origin/main`, and that exact SHA must have successful push-event
`ci`, `attribution`, and `secrets` runs from GitHub Actions App ID 15368
and their expected workflow paths.

Enable release immutability in repository settings before the first release.
The read-only job builds and verifies; only its immutable artifact handoff
reaches the write/OIDC job. That job has no checkout, executes no repository
code, downloads by artifact ID with fail-closed digest validation, recomputes
the exact checksum manifest with fixed runner tools, creates or resumes a
draft, attaches every asset, downloads and byte-checks the remote copies, and
publishes once. Per-tag concurrency prevents races; reruns can repair a draft
but only verify an already-published immutable release.

GitHub's `verified: true` response validates a tag signature under GitHub's
key/account rules; it is not a project-maintained signer allowlist. No approved
fingerprint, SSH principal, or certificate is configured here. Until one is
supplied and enforced, tag authorization comes from repository permissions
and the no-bypass tag ruleset, not a cryptographic claim that a particular
maintainer signed.

## Controls outside these JSON files

Repository settings require every Action reference to use a full-length commit
SHA; the 2026-08-04 API read-back reports `sha_pinning_required: true`. The
workflows comply, and Dependabot tracks those SHAs. Public visibility
additionally unlocks native secret scanning,
push protection, dependency review, and public artifact attestations; the
transition checklist is docs/PUBLIC-FLIP.md.
