# Release procedure

CCE releases are operator-triggered and mechanically reproduced. A green test
run is necessary but not sufficient: the published files must be derivable
twice from the tagged tree, retain the project's independent audit surface,
and remain bound to the reviewed tag.

## One-time repository settings

1. Ensure both committed rulesets described in `.github/ruleset.README.md` are
   applied to their existing remote IDs and read back exactly; do not create
   duplicate rulesets.
2. Preserve the repository-level requirement for full-length commit SHAs on
   every GitHub Action reference. The 2026-08-04 API read-back reports
   `sha_pinning_required: true`.
3. Preserve release immutability. It was enabled before any tag or release
   existed. The setting is not retroactive, so verify it again before each tag.
4. Confirm the maintainer's signing key renders both commits and signed tags
   as **Verified** on GitHub, and record the expected key fingerprint or SSH
   principal in the operator's release record.

The branch ruleset and signer are still real prerequisites, not documentation
of completed settings. A 2026-08-08 read-back found branch ruleset `20590966`
and tag ruleset `20590968` both active and matching the committed desired
state: no bypass actors, required signatures, and signed, non-mutable `v*`
tags. Remote settings are mutable: re-read both immediately
before release, and do not create a tag until both
read-backs in `.github/ruleset.README.md` show the committed desired state.

**GitHub-Verified is not a project signer allowlist.** It says GitHub accepted
the signature under its account/key association rules. No maintainer
fingerprint, SSH principal, or signing certificate has been supplied to this
repository, so the workflow cannot cryptographically compare the tag signer
with a project-owned allowlist. Release authorization currently rests on
repository/tag-push permissions and the no-bypass tag ruleset. Before granting
tag-push authority to another person or automation, configure and test an
explicit signer allowlist; until then, do not claim that the workflow proves
which maintainer signed.

## Prepare the tree

1. Set `__version__` in `causal_continuity_engine/__init__.py`. Change the
   matching `CHANGELOG.md` heading from `not yet released` to the real ISO
   `YYYY-MM-DD` release date, reset `Unreleased` exactly to `No unreleased
   changes.`, remove stale no-tag/not-yet-released language, and give
   `CITATION.cff` the same version and `date-released`. `pyproject.toml`
   derives distribution metadata from the package attribute; do not
   reintroduce another package-version source.
2. Regenerate `docs/CAPABILITIES.md` only with
   `python -m causal_continuity_engine.capabilities --write`.
3. Run `python .github/scripts/check_release_metadata.py --release v0.1.5`,
   then `just setup` and `just release` from a clean checkout.
4. Drive the MCP server by hand from the built wheel with a real client, and
   read the responses. Install the wheel into an empty virtual environment,
   `cce-engine --dir <project> init`, then connect with the reference MCP SDK
   (`mcp.client.stdio`) and confirm `initialize` returns a revision the client
   accepts, `tools/list` returns all four tools, and one `tools/call` returns
   real content. No gate can do this: the packaged tests drive `serve()`
   in-process, and `tests/test_mcp_server.py` skips its protocol-revision check
   unless the reference SDK happens to be installed. The prepared — never
   published — 0.1.4 tree advertised `2026-07-28`, a revision that does not
   exist, and every automated check passed while no client could complete a
   handshake.
5. Land the release commit on `main`. Require GitHub's exact commit API to
   report `commit.verification.verified == true`, and wait for the `ci`,
   `attribution`, and `secrets` push checks on that exact SHA to succeed. Each
   authorizing check must be the sole latest completed run for its context and
   remain inside GitHub's documented seven-day required-check eligibility
   window.

`just release` runs the behavioral gates, refuses uncommitted state, installs
the complete reviewed tool closure from `requirements-dev.lock` with exact
versions, SHA-256 hashes, and binary-only resolution, and derives
`SOURCE_DATE_EPOCH` from the source commit. Both builds reuse that locked
backend with isolation disabled, must leave every tracked or unignored source
byte unchanged, and must produce byte-identical wheel and sdist outputs. Before
either backend runs, the index must equal `HEAD`, no untracked release input is
permitted, and `git hash-object --no-filters` must bind every physical source
byte to its exact index blob. This detects CRLF, clean/smudge, or other worktree
normalization that ordinary clean-status checks can hide. A
second clean-tree check follows backend execution. The captured, index-bound
source bytes are first materialized into an empty disposable directory, so the
sdist backend never runs against the checkout or its ignored residue. Each pass
then builds and canonicalizes the sdist, validates its complete manifest and
archive envelope before creating any extracted path, and manually materializes
only the validated regular-file payload. The wheel backend runs against that
exact normalized sdist payload—not the checkout—and sdist/wheel metadata must
agree.
The structural verifier then checks `dist/SHA256SUMS`, exact source-to-sdist-to-wheel
membership and bytes, canonical archive ordering/ownership/modes/timestamps,
the specification, schemas, tests, corpus, benchmark, type marker, and
independent verifier without installing or executing either distribution. The
local `just release` command then invokes the separate behavior mode, which
installs the wheel into a new environment outside the checkout and exercises
module imports, CLI, capabilities, and a behavioral conformance subset.
That local sequence is a rehearsal on one mutable machine; it does not establish
the hosted workflow's immutable handoff and never publishes.

The source distribution and wheel deliberately carry more than runtime code.
CCE's claim is auditable continuity, so an artifact that strips the proof
specification or the tests that support its capability claims is incomplete.
GitHub-generated source archives likewise retain `.github/` and `tests/`.

## Sign and publish

On the owner's Mac, use a dedicated clean checkout whose exact origin is
`ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git`. Verify the
GitHub host key in `known_hosts` and select the explicit public keys that the
SSH agent holds for signing and GitHub transport. Then authenticate GitHub CLI
and run the fail-closed tag command. It creates a signed annotated tag whose
name is exactly `v` plus the package version and pushes it only because
`--push` is explicit:

On macOS the launchd agent socket normally enters the shell through the
root-owned `/var` alias and may itself be mode `0666`; the command resolves
that alias and accepts the socket only when the resolved socket is owned by
the operator inside an operator-owned mode-`0700` launchd directory. A socket
without that containing-directory boundary is rejected.

Create the dedicated checkout before placing an API token in the environment.
The following clone uses only the selected agent identity and host-key file,
ignores ambient Git and SSH configuration, and disables repository hooks:

```bash
(
  set -eu
  if [ -e "$HOME/cce-release" ]; then
    printf '%s\n' 'Refusing to reuse an existing release checkout.' >&2
    exit 1
  fi
  release_ssh_command="/usr/bin/ssh -F /dev/null -oBatchMode=yes \
  -oPasswordAuthentication=no -oKbdInteractiveAuthentication=no \
  -oStrictHostKeyChecking=yes -oUpdateHostKeys=no -oClearAllForwardings=yes \
  -oPermitLocalCommand=no -oProxyCommand=none \
  -oUserKnownHostsFile=$HOME/.ssh/known_hosts -oGlobalKnownHostsFile=/dev/null \
  -oIdentitiesOnly=yes -oIdentityAgent=$SSH_AUTH_SOCK \
  -oIdentityFile=$HOME/.ssh/id_ed25519.pub"
  /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin SSH_AUTH_SOCK="$SSH_AUTH_SOCK" \
    GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null \
    GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
    GIT_SSH_COMMAND="$release_ssh_command" \
    /usr/bin/git --no-pager --no-replace-objects \
    -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    -c credential.helper= -c credential.interactive=never \
    -c protocol.allow=never -c protocol.ssh.allow=always \
    clone --branch main \
    ssh://git@github.com/thequantumfalcon/causal-continuity-engine.git \
    "$HOME/cce-release"
)
```

Run the setup, complete release gate, and the manual built-wheel MCP exercise
described above in that checkout before creating any tag:

```bash
cd "$HOME/cce-release"
just setup
just release
# Complete the real-client MCP exercise from step 4 before continuing.
```

Only after those checks pass, obtain one fresh owner token without allowing an
ambient token or `PATH` entry to choose the credential source:

```bash
(
  set -eu
  release_token="$(/usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin \
    /opt/homebrew/bin/gh auth token)"
  /usr/bin/env -i GH_TOKEN="$release_token" LANG=C LC_ALL=C \
    /opt/homebrew/bin/python3 -I \
    .github/scripts/prepare_release_tag.py v0.1.5 --push \
    --git-executable /usr/bin/git \
    --tagger-name "Thomas Albrecht" \
    --tagger-email "thequantumfalcon@users.noreply.github.com" \
    --signing-key "$HOME/.ssh/thequantumfalcon_signing.pub" \
    --ssh-keygen-executable /usr/bin/ssh-keygen \
    --allowed-signers-file "$HOME/.ssh/allowed_signers" \
    --ssh-executable /usr/bin/ssh \
    --known-hosts-file "$HOME/.ssh/known_hosts" \
    --transport-key "$HOME/.ssh/id_ed25519.pub" \
    --ssh-auth-sock "$SSH_AUTH_SOCK"
)
```

The fresh clone records only the structural core, origin, and `main` tracking
keys that the profile admits. The existing development checkout is
expected to fail admission because it contains historical branch and local
signing configuration; do not delete those settings or broaden the allowlist
to make it pass.

The command refuses a dirty tree, a non-`main` checkout, a wrong origin, any
divergence from freshly fetched and remotely observed `origin/main`, an
existing local or remote tag, non-release metadata, stale pre-release wording,
an unverified exact commit, or missing trusted exact-SHA checks. The fixed
release quorum (`ci`, `attribution`, and `secrets`) and its GitHub App IDs are
read from the committed branch ruleset. `dependency-review` and `DCO` are
explicitly classified as PR-only branch requirements, not push-event release
attestations. Any other future branch context fails closed until its event and
workflow-path semantics are reviewed in `check_release_tag.py`. The command
creates the tag only after those checks, verifies the tag object's exact name,
object, type, signature, and peeled SHA with both `git cat-file` and
`git verify-tag` against one full object identifier captured immediately after
creation. It rechecks the named ref against that identifier before the final
remote observations, then pushes the identifier rather than the mutable ref
name. Omitting `--push` deliberately leaves a validated local tag and performs
no network write. If post-creation validation fails, the command compare-deletes
only the captured object; a different-object replacement ref is preserved and
stops cleanup. If the initial object cannot be captured exactly, no cleanup is
attempted. After
any push-attempt failure, remote state is unknown: stop, do not retry, recreate,
or delete the tag, and reconcile both the exact remote and local references
through read-only owner observations before taking any further action. No local
cleanup is attempted after a push starts.

The remote-main and remote-tag-absence checks are separate SSH observations,
not atomic conditions on the push. Another actor can change remote state between
them, and Git may report a concurrently created identical tag as already up to
date. Compare-delete likewise cannot distinguish replacement with the same
object identifier. These outcomes still require the stop-and-reconcile path.

The release profile does not inherit `PATH`, global/system/environment Git
configuration, credential helpers, SSH configuration, askpass programs, or
signing settings. It admits only a narrow structural `.git/config`, disables
hooks and filesystem monitors, and gives the Git child either the signing agent
capability or the SSH transport capability required for that operation.
It also refuses shallow history, a redirected common Git directory, grafts,
alternate object stores, replacement refs, and active `.git/info/exclude` or
`.git/info/attributes` rules.
`GH_TOKEN` remains available only to the Python GitHub API verifier, which
disables proxies and uses the interpreter's compiled system trust locations.
A prohibited-config diagnostic is a stop signal, not permission to broaden the
allowlist; prepare a fresh dedicated checkout.
This boundary assumes no concurrent process running as the owner is modifying
the repository or explicit profile inputs. It does not defend against a
compromised owner account, SSH agent, trusted executable, or operating system.
It also assumes the checked-out release helpers and imported Python modules
were owner-reviewed before process start; code already modified in the
checkout can act before a clean-tree check could establish anything.

`.github/workflows/release.yml` verifies all of the following before it
publishes anything:

- package, changelog, citation version, ISO release date, and tag name agree,
  `Unreleased` is reset, and no pre-release marker remains;
- the reference is an annotated PGP- or SSH-signed tag object;
- GitHub returns well-formed verification records with `verified == true`
  separately for the exact tag object and exact peeled release commit (not
  that either signer is on a project-maintained allowlist);
- the tag object's recorded name and object, its peeled commit, and the
  checked-out commit are exactly equal;
- the tagged commit is reachable from `origin/main`;
- the exact commit has successful `ci`, `attribution`, and `secrets`
  push-event check runs from the App IDs declared in the committed ruleset and
  from their reviewed workflow paths, so a same-named status cannot
  substitute; GitHub's optional nonempty `@ref` presentation suffix is
  accepted only after the base path matches exactly. The API request makes
  [`filter=latest`](https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference)
  explicit, a newer non-success overrides an older success, and tied latest
  completions fail as ambiguous. The latest `completed_at` must be canonical
  UTC, no more than five minutes ahead of the verifier clock, and within
  GitHub's documented
  [seven-day eligibility window](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks);
- every runtime-declared immutable public schema `$id`/TypeURI URL returns strict JSON whose
  bytes are exactly equal to the files in the checked-out release tree; those
  v1 URLs remain bound to `v0.1.0` on later package releases rather than being
  derived from the later package tag;
- every release gate passes again from the tag and the second build is
  byte-identical;
- the three-file candidate is uploaded before any artifact-carried code runs;
- a separate job derives the tagged commit epoch from its checkout and applies
  portable-semantic structural verification to a fresh download of that
  immutable service object, then the behavior job installs another download
  and runs its import, CLI, capability, and conformance probes after
  installation-only pip/setuptools are removed and the exact locked audit tools
  are added.

The build job has read-only repository, check, and Actions permissions and
uploads the wheel, sdist, and checksum manifest under one immutable artifact
ID. Structural verification happens only after that upload: a fresh runner
downloads the ID, requires the artifact service's digest comparison, and runs
the non-executing portable-semantic structural verifier against that copy using
the tagged commit epoch independently derived from its checkout. This ordering
means a successful descendant left by the build cannot change what the later
job sees. The producer's two builds retain the same-runtime exact-byte
reproducibility proof; the separately scheduled runner does not assume that its
Python patch and zlib implementation are byte-identical to the producer's.

The behavior job has `permissions: {}`, no checkout, no repository token, no
publisher credential, and no OIDC permission. It downloads the same immutable
ID, rechecks its manifest, safely extracts the already structurally verified
sdist to obtain the hash-locked bootstrap and verifier, then executes the wheel
checks under a new allowlisted process environment as its terminal step. It
emits no artifact or output. Its success and
the structural job's success are publication prerequisites, but both
credentialed publishers independently download only the build job's original
artifact ID and digest; neither verifier can replace or select those bytes.
GitHub's action runtime and artifact service remain trusted and may provide
internal service capabilities to pinned actions; the claim is absence of
repository, publishing, and OIDC authority, not absence of all runner tokens.

The GitHub-release publish job performs no checkout and executes no package or
repository script. It recomputes the exact two-entry `SHA256SUMS` for the wheel
and sdist. The credentialed job trusts the complete
mutable `ubuntu-latest` hosted runner and tool image—not just
`sha256sum`/`find`/`cmp`, but the shell, `gh`, `grep`, `cut`, `sort`, `test`,
`mktemp`, `basename`, and other invoked runner programs. In particular, a
compromised `gh` could mutate release state and counterfeit its own read-back;
pinning Actions does not remove that runner-image trust assumption. It then records
signed build provenance on public repositories, creates or resumes a draft,
uploads the three-file asset set (wheel, sdist, and `SHA256SUMS`), downloads
all three back for byte comparison, and publishes the draft once. A per-tag
concurrency group prevents racing publishers. A rerun may replace assets only
while the release is still a draft; after publication it performs read-only
byte verification. This keeps write and OIDC authority away from repository
tests and build commands. Draft, attach, verify, then publish is required for
immutable releases, whose assets and associated tag cannot be changed after
publication.

The Python interpreter, `venv`, and the interpreter-bundled initial
`ensurepip`/pip are bootstrap trust. That initial pip is used once to install
the hash-locked closure, including `pip==26.2` itself; the bootstrap then
requires every installed distribution and pip's import origin to resolve from
the new environment at the exact locked version. A compromised initial pip
could bypass those checks, so releases must start from the reviewed hosted
Python image (or an equivalently authenticated interpreter distribution).

## Python package index publication

The GitHub release workflow uploads to PyPI. The name
`causal-continuity-engine` was claimed by the first successful publish
(0.1.0, 2026-08-08); a
[pending Trusted Publisher does not reserve a name](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/),
only publishing does.

The `pypi` job runs after candidate creation, structural verification, artifact
behavior, and GitHub publication, and is gated on the protected
`pypi` environment. It authenticates by OIDC Trusted Publishing bound to this
owner, repository, and `release.yml` — no long-lived token. It receives only
the already verified wheel and sdist, re-checks them against the checksum
manifest before upload, and emits PEP 740 attestations. Require PyPI's exposed
SHA-256 digests to match the GitHub release assets before announcing.

Do not reuse a failed version or replace an asset. Correct the cause, increment
the version, and create a new signed tag so the failure remains attributable.

### Incident-only bad-tag recovery

Do not run this during a normal release, and do not use it to replace a
published immutable release. If an erroneous protected tag was pushed but no
release was published, record the incident and exact object IDs first. An
administrator may then disable only tag ruleset `20590968`, confirm that exact
ruleset is disabled, delete only the named bad tag, restore the committed tag
ruleset immediately even if deletion fails, and read it back:

```bash
REPO=thequantumfalcon/causal-continuity-engine
RULESET=20590968
TAG=v0.1.5
ENDPOINT="repos/$REPO/rulesets/$RULESET"

gh api "$ENDPOINT" --jq '{id,name,target,enforcement,bypass_actors,rules}'
gh api -X PUT "$ENDPOINT" -f enforcement=disabled
gh api "$ENDPOINT" --jq '{id,name,target,enforcement,bypass_actors,rules}'

# Incident-only destructive step. Delete no other ref.
git push origin --delete "$TAG"

# Run this restore even if the deletion command failed.
gh api -X PUT "$ENDPOINT" --input .github/tag-ruleset.json
gh api "$ENDPOINT" --jq '{id,name,target,enforcement,bypass_actors,rules}'
git ls-remote --tags origin "refs/tags/$TAG"
```

The final ruleset read-back must show the exact ID/name/target, `active`
enforcement, an empty bypass list, and deletion, non-fast-forward, and
required-signature rules. The final tag query must be empty. Preserve the
incident record and release a corrected, incremented version; never silently
retag the failed version. These commands are a documented recovery path only
and were not executed while preparing this repository.

## Verify as a consumer

Treat the release files as inert input first. Establish the expected
`thequantumfalcon/causal-continuity-engine` repository, signed tag, and peeled
commit through a trusted channel; download all three assets without extracting
or executing them. Before running repository or artifact code, verify each
wheel/sdist attestation and the immutable-release asset binding:

```bash
gh attestation verify <wheel-or-sdist> -R thequantumfalcon/causal-continuity-engine
gh release verify-asset <tag> <asset> -R thequantumfalcon/causal-continuity-engine
```

Require the attestation's repository and source revision to equal that expected
peeled commit, and run `gh release verify-asset` for the wheel, sdist, and
`SHA256SUMS`. These provenance checks precede behavioral execution; they do not
replace the checksum and payload-equivalence checks below.

Distribution verification is not a
standard-library-only operation: it runs the installed conformance subset with
the exact pytest/jsonschema closure and creates a temporary wheel venv with
`pip`. First use Python 3.11 or newer with `venv` and `pip` available, then
create a dedicated environment from the shipped hash-locked, binary-only tool
closure (an index connection or a pre-populated wheelhouse is needed for this
one installation):

```bash
python -m venv .cce-distribution-verify
. .cce-distribution-verify/bin/activate
python -m pip install --force-reinstall --require-hashes \
  --only-binary=:all: -r requirements-dev.lock
python -m pip check
```

On Windows PowerShell, activate with
`.cce-distribution-verify\Scripts\Activate.ps1`; the two `python -m pip`
commands are unchanged. Do not substitute ambient pytest, jsonschema, build,
setuptools, or pip versions. The interpreter's initial pip is still a bootstrap
trust boundary until that command replaces it with the hash-locked pip and the
closure check passes. After the locked tools are present, disconnect network
access and run the verifier in a disposable account, container, or VM that has
no credentials or sensitive files. The verifier scrubs child environment and
configuration paths, caps captured stdout/stderr, imposes a finite deadline on
every child, and attempts process-tree termination on overflow or timeout before
it installs and executes artifact-carried code. Those are bounded process
controls, not a kernel sandbox: same-user file access, network access, fork or
memory exhaustion, and platform limits on descendant cleanup still require the
disposable account/container/VM and network policy above. From a matching Git
checkout in that environment, the strict producer-equivalence verifier
derives the source epoch from the commit and reconstructs the complete
compressed bytes:

```bash
python .github/scripts/verify_distributions.py \
  --structural-only <directory-containing-assets>
```

An extracted source or sdist tree has no `.git`. Give portable semantic mode
the Unix committer timestamp obtained independently from the verified signed
tag's peeled commit—not a timestamp copied from the artifact being checked:

```bash
python .github/scripts/verify_distributions.py \
  --structural-only --portable-semantic --source-epoch <commit-unix-time> \
  <directory-containing-assets>
```

Both structural forms enforce the checksum manifest, bounded/path-safe archives, exact
timestamps, modes and ordering, ZIP local/central framing, raw USTAR bytes,
source-to-sdist-to-wheel membership and payload equivalence, metadata, and
RECORD without executing artifact code. Portable
semantic mode skips only reconstruction of complete ZIP and gzip byte streams,
because raw DEFLATE bytes can vary across Python/zlib releases even when their
decoded payload is identical. Strict mode retains that same-pinned-runtime
whole-byte contract. After a successful structural check, use a disposable
credential-free environment for the separate behavior mode:

```bash
python .github/scripts/verify_distributions.py \
  --behavior-only <directory-containing-assets>
```

Behavior mode rechecks the exact filenames and checksum manifest before it
installs the wheel and runs imports, the CLI, capability claims, and the
wheel-isolated conformance subset. Neither mode is an independent-builder proof; that
roadmap still requires a separately administered, declared toolchain.

This distribution verifier is distinct from `verifiers/verify_proof.py`.
That standalone, standard-library-only program checks one CCE proof envelope;
it does not inspect a wheel, sdist, checksum manifest, build metadata, or an
installed package. Its lack of tool dependencies does not apply to either
distribution-verification mode above.

These checks answer different questions. Reproducibility checks whether the
same source and declared process produce the same bytes. An attestation binds
bytes to the hosted build identity and workflow. Release immutability prevents
post-publication substitution. None alone replaces the others.

## Standards basis

- [PEP 561](https://peps.python.org/pep-0561/) requires a `py.typed` marker to
  opt a package's inline annotations into type-checker discovery; the marker
  must be present in the installed distribution, not merely the source tree.
- [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/specs/source-date-epoch/)
  defines the deterministic source-derived build timestamp used here.
- [pip's secure-install guidance](https://pip.pypa.io/en/stable/topics/secure-installs/)
  requires exact pins and hashes for the complete dependency closure; it also
  recommends binary-only installs when source execution is not intended.
- [PyPA build's CLI contract](https://build.pypa.io/en/stable/reference/cli.html)
  states that `--no-isolation` performs no dependency installation, which lets
  the reviewed active environment be the only backend environment.
- [PyPA's source-distribution specification](https://packaging.python.org/en/latest/specifications/source-distribution-format/)
  defines the `.tar.gz` interchange shape and single top-level directory; CCE
  adds a closed manifest, bounded regular-file-only USTAR profile, canonical
  headers, and validate-before-materialize rules for its stronger release
  contract.
- [Setuptools' reproducibility guidance](https://setuptools.pypa.io/en/latest/deprecated/sdist-reproducibility.html)
  explains why source distributions and drifting build dependencies require
  explicit control.
- [GitHub's immutable release model](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
  prescribes draft, attach, then publish and binds the tag, commit, and assets.
- [GitHub's artifact actions](https://github.com/actions/download-artifact#usage)
  document immutable artifact-ID downloads and fail-closed SHA-256 digest
  comparison; the publish job pins that action and opts into `error`
  explicitly.
- [SLSA 1.2](https://slsa.dev/spec/v1.2/) separates reproducibility from signed
  hosted-build provenance and hardened builder guarantees.
- [in-toto](https://in-toto.io/docs/getting-started/) models authorized steps,
  materials, products, and signed link evidence as a continuous chain.
- [Sigstore](https://docs.sigstore.dev/) binds short-lived signing identities
  to artifacts and records the result in an auditable transparency log.
- [SCITT (RFC 9943)](https://www.rfc-editor.org/rfc/rfc9943.html) standardizes
  signed supply-chain statements, transparency-service registration, and
  portable inclusion receipts. Its content-agnostic model can publish a CCE
  receipt without making a particular log part of the engine.
- [COSE Receipts for Verifiable Data Structures (RFC 9942)](https://www.rfc-editor.org/rfc/rfc9942.html)
  defines receipt envelopes for inclusion and consistency proofs. The proof
  type and auditor policy—not the word “receipt”—determine which append-only
  property a relying party has actually checked.

## Proposed differentiator: continuity-bound release receipts

The engine now emits signed `cce.continuity-receipt.v1` operator receipts
that distinguish a current frontier from an authentic historical one. They
are useful source material, but they are tenant-key, local-state receipts—not
public release attestations. The next trust increment should therefore define
a custom predicate at a stable, project-controlled absolute TypeURI and carry
it in an in-toto Statement, not invent another application signature scheme.
The exact payload serialization, media type, and signing envelope are separate
protocol choices. That release-continuity predicate would bind artifact
digests to:

- the CCE audit anchor at the release decision;
- the digest of generated capability claims and the conformance corpus;
- the exact policy-owned gates and their authoritative outcomes;
- the projection fingerprint and source event tip used to authorize release;
- an explicit gap vector for controls that were unavailable, skipped, or
  undecidable.

That last field is the CCE-specific contribution: ordinary provenance records
what ran, while continuity also treats a required absence as evidence against
success. A consumer could reject an artifact whose provenance is authentic
but whose release decision depended on missing evidence.

Implement this as a release-layer feature in three phases. First, derive the
predicate from the operator receipt plus audit and capability exports, then
attest it with the same short-lived workflow identity as the artifacts. Do not
publish the tenant HMAC or mistake possession of the local database for an
independent witness. Second, have a reusable workflow on an independently
administered builder reproduce the tag and emit a separate rebuild witness.
Third, wrap the exact in-toto Statement bytes in the RFC 9943 COSE_Sign1 Signed
Statement envelope, including the protected CWT `iss` and `sub` claims, and
ship receipts from independently administered transparency services beside
the release.

That third step closes a limit the engine already states honestly: an audit
anchor retained only by the operator cannot expose tail truncation or
equivocation to outsiders. A SCITT receipt proves registration/inclusion in a
particular transparency-service VDS state; by itself it proves neither that the
statement is true nor which registration policy was applied. If policy
identity matters, the CCE profile must bind its URI and digest explicitly.
Two isolated inclusion receipts also cannot reveal a split view.
Non-equivocation needs consistency proofs from pinned checkpoints plus a
declared gossip, witness, auditor, or quorum channel that exchanges signed
checkpoints. Consumer policy must separately validate the CCE predicate,
issuer, artifact digests, and acceptable transparency services.

Do not claim a SLSA level or implementation independence until the relevant
platform and functionary requirements are actually met. This is a
project-specific composition of new and established standards, not a claim
that the underlying mechanisms are inventions of CCE.
