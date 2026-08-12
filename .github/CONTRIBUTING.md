# Contributing to the Causal Continuity Engine

This project makes a narrow, checkable claim: that a coding agent's work can be
resumed, invalidated, and completed under proof, and that the checks doing the
deciding actually run in the path that decides. Contributions are welcome to
the extent they hold that claim up. The bar is not politeness or volume, it is
evidence.

Read [`docs/adr/ADR-INDEX.md`](../docs/adr/ADR-INDEX.md) before proposing a
change. Most design questions a newcomer has are answered there, usually
because the naive answer was tried, shipped, and broken by a later review
round.

## The trust core is change-controlled

The 0.1.0 trust core has a high change bar. It is not literally frozen:
post-round-7 review added operator receipts, policy configuration, and
transactional race hardening. New subsystems require a proposal issue and the
same reproduce-first, adversarial evidence expected of a defect fix.

**In scope**

- Defect fixes, with a reproduction (see below).
- Corrections to `SPEC.md` where it is ambiguous, or where
  `verifiers/verify_proof.py` is faithful to the text and the text is wrong.
  Round 7's worst finding was of exactly this kind: the implementation was
  correct and the specification was not.
- New conformance vectors in `vectors/` that pin a case both implementations
  should already agree on, or that catch a drift they could fall into.
- Portability fixes to `verifiers/verify_proof.py`, which must stay standard
  library only and must never import from `causal_continuity_engine`.
- Documentation that is wrong, stale, or overstated. Claims that outrun the
  code are treated as defects, not as marketing.

**Not in scope**

- New subsystems, new memory tiers, new trigger types, new verifier kinds.
- Restructuring. `causal_continuity_engine/` is a flat layout, not `src/`,
  deliberately. `tests/`
  lives at the repository root, outside the package, deliberately.
- Converting `docs/adr/ADR-INDEX.md` to MADR or any other ADR format.
- Any third-party runtime dependency. `causal_continuity_engine/` is standard
  library only, and
  `just deps` fails if that stops being true.

If you think something belongs in the engine anyway, open a proposal issue
first and argue it there. Do not smuggle feature scope into an unrelated fix.

## Setup

Python 3.11 or newer. The engine has no runtime dependencies, but the checks
do. `just setup` installs every direct and transitive tool from
`requirements-dev.lock` in pip's all-or-nothing hash-checking mode, refuses
source distributions, then installs `causal-continuity-engine` editable without dependency
resolution or an isolated build environment. The reviewed direct inputs are
`pytest` 9.1.1, `ruff` 0.16.1, `build` 1.5.0, `jsonschema` 4.26.0,
`setuptools` 83.0.0, and `pip` 26.2. None is imported by the engine; jsonschema validates
emitted receipt instances only in the test/release gate.

The pins were revalidated on 2026-08-11. Setuptools 83.0.0 is the first patched
release for
[GHSA-h35f-9h28-mq5c](https://github.com/advisories/GHSA-h35f-9h28-mq5c)
and pip 26.2 is later than the first patched release for
[GHSA-wf93-45jw-7689](https://github.com/advisories/GHSA-wf93-45jw-7689);
pytest 9.1.1 is newer than the 9.0.3 fix for
[GHSA-6w46-j5rx-g56g](https://github.com/advisories/GHSA-6w46-j5rx-g56g),
and the lock carries Pygments 2.20.0, the fix for
[GHSA-5239-wwwm-4pmq](https://github.com/advisories/GHSA-5239-wwwm-4pmq).
Build remains at 1.5.0 because PyPI marks 1.5.1 yanked; jsonschema 4.26.0 and
ruff 0.16.1 were the current stable releases on that date. This is a dated
review record, not a claim that pins stay current without future review.

When a direct pin changes, edit `pyproject.toml` and `requirements-dev.in`,
regenerate the lock with the command recorded in its header, and review the
complete dependency and hash diff. A regression requires those direct inputs
to remain identical and every locked requirement to carry a SHA-256 hash.

Your Python interpreter, `venv`, and its initial `ensurepip`/pip are bootstrap
trust: the initial pip installs the hashed closure once. That closure includes
the reviewed pip pin, and the bootstrap verifies every distribution version
and origin inside the new environment before it runs repository gates.

```bash
git clone https://github.com/thequantumfalcon/causal-continuity-engine.git
cd causal-continuity-engine
just setup                            # editable engine + pinned dev/release checks
git config core.hooksPath .githooks   # attribution scan AND gitleaks, both blocking
brew install gitleaks                 # or a release binary from gitleaks/gitleaks
just test                             # should be green before you change anything
```

Install gitleaks. It is load-bearing here, not decoration: GitHub's native
secret scanning and push protection are enabled on this repository, but both
act only once content reaches GitHub. The local hook catches a credential
before it leaves the machine; the `secrets` workflow scans pull requests,
pushes to `main`, and the full history weekly. The hook warns rather than
refuses when gitleaks is missing, so that server-side scan remains visible
after a local `--no-verify`. The live ruleset requires `ci`, `attribution`,
`secrets`, and `DCO`, so a failing scan blocks the merge; see
`.github/ruleset.README.md`. If a
synthetic test value trips the scan,
allowlist it in `.gitleaks.toml` by value, never by path, so a real secret in
the same file is still caught.

`.pre-commit-config.yaml` remains supported for contributors who prefer the
framework, with one constraint: git honours exactly one hook path, and
pre-commit refuses to install while `core.hooksPath` is set. Unset it first
(`git config --unset core.hooksPath`). That path covers gitleaks, `ruff check` (the same
lint gate as `just lint` and CI) and file hygiene, but not the attribution
scan. It deliberately carries no `ruff-format` hook — see the `fmt-check` note
in the `justfile`. CI enforces the attribution rule independently either way
(`.github/workflows/no-ai-attribution.yml`), so nothing that reaches a pull
request depends on which hook path you chose.

Focused recipes live in the `justfile`. Hosted Linux, Windows, macOS, and release
jobs all invoke the checked-in standard-library
`.github/scripts/run_gates.py`, avoiding a downloaded command runner in the
trusted path. `just check` calls the same aggregate locally; every focused
equivalent below is cross-platform.

## Gates

All six focused behavioral recipes — lint, dependency-boundary scan, tests,
corpus, capability audit, and benchmark — must pass locally before you open a
pull request. `just build` is additionally required when packaging, generated
assets, or release machinery changes. Hosted CI runs the six-recipe aggregate
across Python 3.11, 3.12, 3.13, and 3.14, repeats it natively on Windows 3.14
and macOS 15 ARM64/Python 3.14, and always builds twice and audits an installed
wheel. The `ci` job fans all those paths into one context.

| Recipe | Direct equivalent | What it establishes |
|---|---|---|
| `just setup` | `python -m pip install --force-reinstall --require-hashes --only-binary=:all: -r requirements-dev.lock`, then `python -m pip check`, then `python -m pip install --no-deps --no-build-isolation -e .` | Nothing on its own. It installs the reviewed, hash-locked tool closure, checks dependency consistency, and installs the local package without undeclared resolution. |
| `just lint` | `python -m ruff check .` | Ruff passes under the rule set pinned in `pyproject.toml` `[tool.ruff.lint]` — `E`, `F`, `W`, `I`, line length 100. That set, and nothing wider: it is not passed on the command line, so widening the gate means editing `pyproject.toml`. |
| `just deps` | `python .github/scripts/check_stdlib.py` | `causal_continuity_engine/` imports nothing outside the standard library. It parses the AST instead of importing, so a lazy, guarded, or function-local import is caught too. This is the gate behind the zero-runtime-dependency claim. |
| `just test` | `python -m pytest tests/ -q` | The complete regression suite and planted instrument-validation cases pass. |
| `just corpus` | `python vectors/generate.py --check` | The reference implementation still reaches every committed verdict. Cross-implementation agreement is established by `just test`, not here. |
| `just caps` | `python -m causal_continuity_engine.capabilities --write` then `git diff --exit-code -- docs/CAPABILITIES.md` | Every capability claim resolves to real symbols, files, and tests, and the committed `docs/CAPABILITIES.md` is identical to what the audit generates. |
| `just bench` | `python -m benchmarks.continuitybench.run` | All eleven ContinuityBench scenarios still pass and all six metrics are still at their gates. |
| `just build` | the scripts under `.github/scripts/` | Each pass first binds physical source bytes without Git filters to the exact `HEAD`/index blobs, stages only those bytes in an empty disposable source directory, validates a canonical closed-manifest sdist before materializing it, and builds the wheel only from that exact normalized payload; two passes are byte-identical under the locked backend, backend execution leaves source unchanged, the checksum manifest is exact, shipped bytes equal the source tree, the audit surface is present, and an isolated installed wheel passes dependency-free import/CLI probes before exact locked tools run capability and behavioral checks. |

Attribution is not one of these, and it is not a lint rule. It is enforced by
`.githooks/pre-commit` locally and by the `attribution` job in
`.github/workflows/no-ai-attribution.yml`. The live ruleset requires both
`attribution` and `secrets` to pass before a merge; the apply and read-back
procedure is in `.github/ruleset.README.md`.

`docs/CAPABILITIES.md` is generated, never hand-edited. If your change moves a
symbol a claim points at, run
`python -m causal_continuity_engine.capabilities --write` and commit
the result: `just caps` regenerates the table and then requires a clean
`git diff` for it, so a stale or hand-edited copy fails the gate.

Two limits worth stating, because they set expectations for review. The
capability audit proves a symbol resolves and that the table on disk is current
— it cannot see a control that exists but does not run in the path that
decides, which is the shape of three
of this project's worst defects (ADR-014, ADR-043, ADR-044). Instrument
validation only proves each gate distinguishes its own case; it says nothing
about whether the set of gates is complete (ADR-056, ADR-067). Green gates are
a floor, not a verdict.

## Reproduction first

A bug fix is not reviewable without a reproduction. The order is not
negotiable:

1. **Reproduce it against the released code, by hand.** Drive the CLI or the
   engine API the way a user would. Put the exact commands and the exact
   output in the issue or the pull request body.
2. **Write the regression test and watch it fail against the pre-fix code.**
   State in the pull request that you did this, and what the failure looked
   like. A test that has only ever been run against the fixed code proves
   nothing about the bug.
3. **Then fix it,** and show the same test passing.

The reason is on the record. In round 4 the first version of the ADR-024 fix
left the default configuration exploitable while every new test passed,
because the tests all used the pinned form the fix had introduced. Running the
original attack verbatim against the built artifact is what caught it. Tests
written alongside a fix inherit the fix's assumptions; the attack does not.

A fix is a change like any other and earns its own adversarial pass. Two
defects in this repository were introduced by an earlier round's fixes and
found only because the fixes themselves were re-reviewed.

If your change touches a rejection path in `complete_task`, it also needs a
planted-defect case in `tests/test_instrument_validation.py` naming which gate
should catch it. A defect caught by the wrong gate is a mismatch, not a pass.

## Commits and pull requests

**The pull request title must be a Conventional Commit.** Everything is merged
by squash, so the title becomes the permanent commit subject on `main` — it is
what `git log` shows a year from now, and it is what GitHub's generated release
notes list, sorted into sections by label per `.github/release.yml`. Your
Individual branch commits do not drive release notes, but the attribution
gate scans every commit message, author name, and author email. Keep them
descriptive and compliant even though the squash title is the permanent
subject on `main`.

```
fix(proof): reject an envelope whose recorded status contradicts its checks
docs(spec): state that §4 and §5 hash different bodies
test(regressions): pin the round-7 retention/rebuild boundary
```

Use `feat`, `fix`, `docs`, `test`, `refactor`, or `chore` — the same set
`.github/pull_request_template.md` lists. Given the trust core's change bar,
`feat` usually needs an accepted proposal issue before implementation. Mark a
breaking change to the
`cce.proof.v1` envelope, the schemas, or the CLI with `!` before the colon,
explain it in the body, and label the pull request `breaking` so the release
notes file it under Breaking Changes.

Nothing derives a changelog or version bump from commit subjects. Releases are
operator-triggered: `just release` runs the complete clean-tree and
reproducibility gate locally, then a signed annotated tag matching the package
version triggers `.github/workflows/release.yml`. The workflow verifies the
tag on GitHub, requires the commit on `main` with trusted exact-SHA checks,
repeats every gate under read-only permissions, and hands the exact wheel,
sdist, and checksum manifest to a separate draft-to-final publish job. See
`docs/RELEASE.md`.

**Sign off your commits.** Contributions are accepted under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/), and
every commit in a pull request must carry a
`Signed-off-by` trailer:

```bash
git commit -s -m "fix(graph): bound traversal at the configured budget"
```

This is enforced. The DCO app checks every commit in a pull request and its
`DCO` check is a required status, so a pull request missing the trailer is
blocked from merging. Existing history predates enforcement and is not being
rewritten merely to add trailers. `git rebase --signoff` will add the trailer
if you forget it on an unpublished branch. By signing off you certify the
DCO's terms and license your contribution under the repository's Apache-2.0
license.

Keep the branch focused. One defect, one pull request. Do not reformat
adjacent code, rename things you did not introduce, or clean up unrelated dead
code in passing — mention it instead. Diff noise is treated as a defect,
because a review that has to separate intent from noise is a worse review.

## Two standing rules

**Absence of success is never success.** A check that did not run detected
nothing, a probe that crashed found nothing, and an empty required-verifier
list verifies nothing. If your change can produce a "nothing went wrong"
outcome, say what distinguishes it from "nothing happened".

**No authorship attribution to tooling.** The `.githooks/` hooks and the CI
attribution guard both reject it, in commit messages and in committed files.
Do not work around them.

## Security

Do not open a public issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md).
