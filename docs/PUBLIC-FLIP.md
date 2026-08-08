# Going public — the deferred register

This repository is **private**, owned by a personal account on the **Pro** plan. A large part
of the GitHub security surface is public-repo-only or needs a paid organisation add-on, so it
could not be enabled at setup time. Rather than leave those gaps implicit, every one of them is
recorded here with what it is, why it is off, and the exact action that turns it on.

This is an evidence-and-action register, not a claim that every desired
setting is live. Completed items name the observation that supports them;
pending items are commands to run or decisions to make. Items marked
**BLOCKER** must be resolved *before* the repository is made public.

---

## Completed before the visibility change

### 1. Commit signing — complete

The signing key is registered with GitHub as a signing key. The main tip
observed on 2026-08-04 reports a valid **Verified** signature on GitHub. This
evidence is about one observed tip; it does not mean the live ruleset requires
future commits to be signed. Nor is GitHub-Verified a project signer allowlist: the
release workflow has no configured maintainer fingerprint, SSH principal, or
certificate to compare. Until that material is supplied, tag authorization
comes from repository/tag-push permissions and the no-bypass ruleset, not a
claim that the workflow identified a particular maintainer.

### Repository Action SHA enforcement — complete

Every committed Action reference already uses a full 40-character SHA. On
2026-08-04 the repository-level `sha_pinning_required` setting was enabled and
read back as true, so a later workflow cannot silently introduce a mutable tag
or branch reference even if review misses it.

### Release immutability — complete

Release immutability was enabled through the repository settings UI on
2026-08-08, while the repository still had no tags or releases. The current
repository API does not expose the flag for read-back, so this is an
owner-attested setting; verify it in the settings UI before the first
publication. It applies to future releases and must remain enabled through
the first publication.

### Signed release-tag protection — complete

Tag ruleset `20590968` (`protect-releases`) was created and read back on
2026-08-08. It is active for `refs/tags/v*`, has no bypass actors, blocks
deletion and non-fast-forward updates, requires signatures, and reports that
the current user can never bypass it.

---

## BLOCKER — resolve before flipping visibility

### Resolve the provenance of the removed planning binaries — RESOLVED 2026-08-06

The release tree no longer contains the original DOCX, PDF, and XLSX planning
artifacts. Their embedded creator metadata could not be reconciled with the
repository's attribution and licensing statements, and their roadmap/status
claims had been superseded by `SPEC.md`, `docs/CAPABILITIES.md`, and
`docs/REQUIREMENTS_COVERAGE.md`.

Resolution: the owner authorized the new-clean-repository route. This public
repository was created from the exact verified release-candidate tree, with no
inherited history; the superseded planning artifacts were never part of it.
The full development history, including those inputs, remains in the owner's
private archive repository. No published history was rewritten and no
force-push occurred.

### Verify release-tagged protocol URIs

Published schemas and signed wire artifacts use immutable
`raw.githubusercontent.com/thequantumfalcon/causal-continuity-engine/v0.1.0/`
identifiers. This replaces the unresolved `cce.dev` namespace before anything
shipped. The paths are controlled by this repository and become dereferenceable
when the repository is public and the protected `v0.1.0` tag exists. Before
publishing the release, fetch every schema URI, require byte equality with the
tagged file, and retain the no-update/no-delete tag ruleset. The release
workflow now performs that complete runtime-registry exact-byte check before building or
creating a draft; this item remains open until the first public tag makes the
URLs dereferenceable and the job passes. A future schema revision gets a new
schema id and release-tagged URI rather than mutating these resources.

### Claim and publish the Python distribution atomically

The PyPI JSON API returned 404 for `causal-continuity-engine` on 2026-08-04.
That avoids the existing `cce` collision but means the intended name is still
unclaimed. [PyPI explicitly states](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
that a pending Trusted Publisher neither creates a project nor reserves its
name until the first successful publish.

Before exposing the name in a public repository, configure PyPI's pending
Trusted Publisher for owner `thequantumfalcon`, repository
`causal-continuity-engine`, workflow `release.yml`, and the protected `pypi`
environment. Resolve the provenance, patent, and contact blockers first, then
coordinate the public flip and signed `v0.1.0` release without an announcement
gap. The release workflow must publish the exact verified wheel and sdist by
OIDC; afterwards, require PyPI's filenames and SHA-256 digests to match the
GitHub release before announcing availability. Do not describe a pending
publisher as a reservation.

**Progress 2026-08-08:** the pending Trusted Publisher was configured by the
owner (project `causal-continuity-engine`, owner `thequantumfalcon`,
repository `causal-continuity-engine`, workflow `release.yml`, environment
`pypi`); the `pypi` GitHub environment exists; and `release.yml` now carries
the OIDC publish job gated on that environment. Environment protection rules
(required owner review, tag-only deployments) are unavailable on a private
personal repository and are a mandatory post-flip step below — add them
before approving the first `pypi` deployment.

### Apply and read back the committed branch ruleset — complete

Branch ruleset `20590966` (`protect-default`) was applied from the committed
`.github/ruleset.json` and read back exactly on 2026-08-08: no bypass actors,
required signatures, linear history, PR-only squash merges, and required
status contexts `ci`, `attribution`, and `secrets` (integration_id 15368)
plus `DCO` (integration_id 1861, added after the DCO app's check was observed
on a real pull request). The tag ruleset is live alongside it; inspection
commands are in `.github/ruleset.README.md`. Merely committing JSON does not
change GitHub — re-verify the live objects after any change.

### 2. Re-run the full-history secret scan

Native push protection does not exist on this plan. The `secrets` workflow
scans pull requests, pushes to `main`, and the full history every week. It
becomes merge-blocking only after the ruleset blocker above is resolved. The
workflow starts only after content has reached GitHub. The pre-commit scan is
the sole local pre-remote scan only when gitleaks is installed and the hook is
not bypassed; a missing binary emits a warning and does not block the commit.
The local scan must still be re-run against the exact history that will become public:

```bash
gitleaks git . --config .gitleaks.toml --redact --no-banner
```

Expect `no leaks found`. On any hit: **rotate the credential first**, then rewrite history.
Rotation matters more than rewriting — clones may already exist.

`.gitleaks.toml` allowlists exactly one synthetic value (the GitHub-PAT-shaped literal that
`TestR3RedactionBeforeExtraction` uses to prove redaction works). It is allowlisted **by value,
not by path**, so a real secret in that same file is still caught. Verified by planting one.

### 3. Establish a monitored security contact

`.github/SECURITY.md` currently states plainly that the repository has **no external security
reporting channel** while it is private, because none of the usual ones exist here:

- GitHub private vulnerability reporting is a public-repository feature.
- Repository security advisories return 404 on private repos for this account (checked against
  three other private repos; the same call returns 200 on a public one).
- `thequantumfalcon@users.noreply.github.com` does not accept inbound mail, and GitHub has no
  user-to-user direct messaging.

Before going public, add a real monitored address and update SECURITY.md to
match. Private vulnerability reporting cannot be enabled until after the
visibility change, so it is not a substitute for this pre-publication contact.
Do not publish a reporting policy that names a channel nobody reads.

### 4. Decide the patent question

Publishing can be a patent-relevant disclosure event. [WIPO warns](https://www.wipo.int/en/web/patents/faq_patents)
that pre-filing public disclosure can become prior art and destroy novelty unless the applicable
law provides an exception or grace period; the rules vary by jurisdiction. The
[USPTO describes](https://www.uspto.gov/patents/basics/apply/provisional-application)
a one-year exception for qualifying inventor-originated disclosures, while warning that the same
disclosure may preclude protection elsewhere. Apache-2.0 also gives recipients an express patent
license, limited to claims necessarily infringed by each contributor's contribution.

If any part of this work might be patentable, that decision belongs **before** the first public
push, not after. This is a flag, not legal advice — take it to a lawyer if it matters.

**RESOLVED 2026-08-08 (owner decision):** defensive publication. The public
release itself is the disclosure; no patent filing will precede it. This
followed a prior-art search recorded on 2026-08-06 that recommended defensive
publication with an optional provisional; the owner declined the provisional.

### 5. Decide on a CLA

As sole copyright holder, the owner controls licensing of the current code. Once someone else's
copyrighted contribution lands, relicensing that contribution requires whatever permission its
license or contributor grant supplies; changing course later can require contacting contributors
or replacing their code. If future relicensing matters, decide whether to use a CLA **before**
accepting the first external pull request.

The DCO (`git commit -s`) is a weaker, different thing: it asserts the contributor had the right
to submit, and it does not give you relicensing rights. See item 9.

**DECIDED 2026-08-08 (owner decision):** no CLA for now — DCO only, enforced
by the DCO app as a required merge context. Revisit before accepting any
contribution whose relicensing might matter; adding a CLA later binds only
subsequent contributions.

---

## Free the moment the repository is public

### Restrict Actions to the reviewed repositories

The repository Actions-permissions read-back on 2026-08-04 reported
`allowed_actions: all` and `sha_pinning_required: true`. GitHub's
[`patterns_allowed` contract](https://docs.github.com/en/rest/actions/permissions?apiVersion=2022-11-28)
applies only to public repositories, so this private, non-enterprise repository
cannot treat a selected repository pattern list as effective before the
visibility change.

Immediately after the public flip, keep Actions enabled, change
`allowed_actions` to `selected`, retain full-SHA enforcement, and permit only
the eight Action repositories reviewed in the committed workflows:

```bash
REPO=thequantumfalcon/causal-continuity-engine

gh api --method PUT "/repos/$REPO/actions/permissions" --input - <<'JSON'
{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}
JSON

gh api --method PUT "/repos/$REPO/actions/permissions/selected-actions" --input - <<'JSON'
{
  "github_owned_allowed": false,
  "verified_allowed": false,
  "patterns_allowed": [
    "actions/checkout@*",
    "actions/setup-python@*",
    "actions/upload-artifact@*",
    "actions/download-artifact@*",
    "actions/attest-build-provenance@*",
    "actions/dependency-review-action@*",
    "gitleaks/gitleaks-action@*",
    "pypa/gh-action-pypi-publish@*"
  ]
}
JSON
```

Here `@*` allows any reference only from the named Action repository; the
independent `sha_pinning_required: true` policy still requires each workflow
reference to use a full-length commit SHA. `github_owned_allowed: false` and
`verified_allowed: false` are intentional: ownership or Marketplace
verification alone does not expand the reviewed set.

Read back both endpoints and compare the policy and allowlist as exact values,
not as a successful-write assumption:

```bash
policy="$(gh api "/repos/$REPO/actions/permissions" \
  --jq '[.enabled,.allowed_actions,.sha_pinning_required] | @json')"
test "$policy" = '[true,"selected",true]'

expected_selected='{"github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["actions/attest-build-provenance@*","actions/checkout@*","actions/dependency-review-action@*","actions/download-artifact@*","actions/setup-python@*","actions/upload-artifact@*","gitleaks/gitleaks-action@*","pypa/gh-action-pypi-publish@*"]}'
selected="$(gh api "/repos/$REPO/actions/permissions/selected-actions" \
  --jq '{github_owned_allowed,verified_allowed,patterns_allowed:(.patterns_allowed|sort)} | @json')"
test "$selected" = "$expected_selected"
```

Then exercise every pull-request workflow and run the complete pre-tag release
verification on the exact candidate commit. Do not describe this allowlist as
enforced until both GET read-backs and those workflow runs pass; a missing
repository pattern is an outage, while an extra pattern silently widens the
execution boundary.

### Protect the pypi environment and gate fork PR workflows

Both controls are plan-restricted on a private personal repository and free
once public; run them immediately after the flip, before any release tag:

```bash
REPO=thequantumfalcon/causal-continuity-engine
OWNER_ID="$(gh api user --jq .id)"

# Required owner review plus tag-only deployments for the pypi environment.
gh api --method PUT "repos/$REPO/environments/pypi" --input - <<JSON
{"prevent_self_review":false,
 "reviewers":[{"type":"User","id":$OWNER_ID}],
 "deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
gh api --method POST "repos/$REPO/environments/pypi/deployment-branch-policies" \
  -f name='v*' -f type=tag

# Require approval for ALL outside collaborators' fork PR workflows.
gh api --method PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" \
  -f approval_policy=all_external_contributors
```

Read all three back and compare as exact values: the environment must show
the reviewer and the `v*` tag policy, and the approval policy must be
`all_external_contributors`. The pypi environment's required review is what
turns every index publication into an explicit owner decision.

### 6. Secret scanning, push protection, and private vulnerability reporting

All three are free on public repositories and unavailable here.

```bash
REPO=thequantumfalcon/causal-continuity-engine
gh repo edit "$REPO" --enable-secret-scanning
gh repo edit "$REPO" --enable-secret-scanning-push-protection    # scanning must be on first
gh api -X PUT "/repos/$REPO/private-vulnerability-reporting"
```

Once push protection is live, it adds a server-side pre-acceptance gate. Keep
the `gitleaks` hook in `.githooks/pre-commit` as local defence in depth.

### 7. CodeQL — default setup, not a workflow

Use GitHub's default setup rather than a hand-written `codeql.yml`; the supported language list
now includes `actions`, so it audits the workflows for injection too.

```bash
gh api -X PATCH "/repos/$REPO/code-scanning/default-setup" -f state=configured
```

Note it auto-pauses after six months with no pushes or PRs.

### 8. Dependency review

`.github/workflows/dependency-review.yml` already exists and is deliberately inert on private or
internal repositories. Its classifier accepts only the exact visibility values `public`,
`private`, or `internal`; only `public` enables checkout and dependency review, and an unknown
value fails instead of silently skipping the control. Review starts on its own at the flip, but
is advisory until its first real `dependency-review` context exists. Verify that first run, then
add `dependency-review` with GitHub Actions App integration ID 15368 to the branch ruleset's
required contexts, apply the update, and read it back. Do not call the control merge-blocking
before that read-back.

### 9. DCO enforcement

`.github/CONTRIBUTING.md` asks for `git commit -s` but **nothing enforces it today**. Historical
commits audited before the release-hardening work did not carry the trailer; a later signed-off
commit does not retroactively enforce DCO on contributors. Install the app and add its check to
the required set:

- Install <https://github.com/apps/dco> for the repository.
- Let it report once, record the real check run's GitHub App ID, then add `DCO`
  with that exact `integration_id` to the branch ruleset and read the remote
  rule back. Do not leave a same-named status unbound to its issuing app.

### 10. OpenSSF Scorecard

Public-only. Add `.github/workflows/scorecard.yml` modelled on `ossf/scorecard`'s own live
workflow (weekly cron + push to main, `publish_results: true`, SARIF upload), then add the badge:

```markdown
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/thequantumfalcon/causal-continuity-engine/badge)](https://scorecard.dev/viewer/?uri=github.com/thequantumfalcon/causal-continuity-engine)
```

Do not add the badge before the workflow exists and has published once — a broken badge on a
launch-day README is worse than no badge.

### 11. Artifact attestations

Private personal-account repositories cannot create GitHub artifact
attestations; public repositories use the public Sigstore service for free.
`.github/workflows/release.yml` already contains a full-SHA-pinned provenance
step gated on public visibility, so no source edit is needed at the flip.
Verify the first public release with:

```bash
gh attestation verify <artifact> -R thequantumfalcon/causal-continuity-engine
```

---

## Not blocked by visibility — do when it earns it

### 12. Release automation

Release automation is present but deliberately operator-triggered. The local
gate installs the hash-locked tool closure, builds and validates a canonical
sdist first in each of two passes, builds each wheel only from that exact
source payload without backend dependency resolution, rejects source mutation,
compares artifact bytes, verifies the checksum manifest and
source-to-sdist-to-wheel parity, then installs the wheel outside the checkout
for import, CLI, capability, and behavioral checks.
A signed annotated tag matching the package version triggers the same checks
in `.github/workflows/release.yml`:

```bash
just release
GH_TOKEN="$(gh auth token)" just prepare-release-tag v0.1.0 --push
```

Release immutability is already enabled and was read back on 2026-08-04. Verify
that it remains enabled immediately before the first tag; it applies only to
future releases.
The workflow follows GitHub's required order: create or resume a draft, attach
all artifacts, download and byte-check them, then publish once. A per-tag
concurrency group prevents racing publishers, and a rerun repairs only a draft;
an already-published immutable release is verified without mutation. Its build
job is read-only and requires the
tagged commit on `main` with trusted exact-SHA checks, and hands only the
verified artifact ID and digest to the separate write/OIDC publish job. That
job performs no checkout or repository-code execution; the official download
action validates the immutable transfer digest and runner tools recompute the
exact checksum set before publish. The complete mutable hosted runner/tool
image remains trusted, especially credentialed `gh`, which can mutate release
state and report its own read-back. This is GitHub publication
only; the separate PyPI blocker above remains unresolved. The pre-tag command
also requires exact `origin/main`, commit verification, and the three reviewed
push checks before its explicit network write. See `docs/RELEASE.md`.

### 13. Vigilant mode

Settings → SSH and GPG keys → "Flag unsigned commits as unverified". Turn this on **only after**
item 1 is done and everything you push is signed, or your own history goes yellow.

### 14. Social preview and discovery

- Social preview image: upload `docs/assets/social-preview.png`. It is already
  1280×640 and under 1 MB; GitHub renders it on link shares only after it is
  selected in repository settings.
- Topics are already set (9 of them) and the description is already set.
- Insights → Community Standards currently reports 85%. Do not add a Code of
  Conduct merely to turn the meter green: first establish a private, monitored
  conduct-reporting contact and then publish a policy that names it.
- Seed 3–10 `good first issue` items with real context and file pointers. The label exists.
- Discussions and the Announcements and Q&A categories already exist. Create a
  welcome post once the repository is public; `.github/SUPPORT.md` and the
  issue chooser already link there.

### 15. Things deliberately NOT done

Recorded so they read as decisions rather than oversights.

| Not done | Why |
|---|---|
| `step-security/harden-runner` in CI | Egress policy has not been specified or exercised against the build and verifier subprocesses. Add it only with a full-SHA pin and an observed allowlist; an untested network policy is outage theatre, not a control. |
| `ruff format` as a gate | A broad mechanical rewrite would detach regression tests and review notes from the lines they were written against, for zero behaviour change. Available as advisory `just fmt-check`. |
| Merge queue | Needs Enterprise Cloud, and is meaningless on a repository with one maintainer and no PR volume. |
| Codecov | Not configured. No coverage badge is claimed anywhere. |
| `src/` layout | The flat package layout is deliberate; restructuring thousands of reviewed lines to satisfy a layout convention is churn with real regression risk. Packaging and clean-wheel tests now verify the actual distribution boundary. |
| MADR-format ADRs in `docs/decisions/` | The ADRs already exist in `docs/adr/ADR-INDEX.md` in a working format. Converting them would gain a directory name and lose nothing else. |
| Stale bot, labeler, lock-threads, first-interaction | Maintenance automation for a repository with contributors. There are none yet. Adding them now would be ceremony the project has not earned. |
