Real GitHub objects from thequantumfalcon/kry replayed offline through CCE 0.5.0; not a live webhook deployment.

# KRY repository replay: run 2

This records run 2 of the local `EVIDENCE-CCE-REAL-REPO.md` evidence packet,
using the PyPI `causal-continuity-engine==0.5.0` package and an unchanged KRY
v0.1.9 checkout at `8e277a5b9e2768c994be39771495bce4c043bb23`.
The project was initialized at the checkout root. Raw inputs, commands,
outputs, hashes, and the independent classification audit are retained in
the local `cce-real-repo-run2/` packet; they are not bundled in this repository.

## Inputs and authority

| Observed item | Count |
|---|---:|
| Real GitHub envelopes | 418 |
| Reconstructed main pushes | 111, including 11 Dependabot pushes |
| PR opened/closed envelopes, #93–#102 | 18 |
| Issue envelopes | 1: #95 opened; it remained open |
| Completed check-run envelopes | 288 |
| Proposed claims | 63 |
| Proposed kinds | 26 constraints, 6 assumptions, 15 requirements, 4 decisions, 12 tasks |
| Confirmations | 3 constraints and 1 assumption |
| Out-of-order push rejections | 0 |

The 111 pushes follow the contiguous first-parent main chain, including
intervening commits. One offline push was reconstructed per real commit;
original webhook batching and delivery boundaries are unavailable. REST
bodies fetched for the PRs were reused at their historical opened/closed
times, so this does not reconstruct historical body edits. External CI
records were not configured as trusted verifier producers.

The three confirmed constraints came from
[KRY #95](https://github.com/thequantumfalcon/kry/issues/95): report
disagreements without averaging them away; never count absent, crashed, or
verdict-free checks as success; and send fixes through the normal PR process
without editing the frozen protocol. These are protocol process constraints;
pytest success does not prove compliance with them.

## Constructed operator decision, real quoted toolchain

Immediately before the first Ruff-changing push, grouped Dependabot #5
(`b6ffa18f75ea6df64dd595f0186852ca6571736f`), one **constructed operator
decision** was recorded and its resulting assumption confirmed:

> Assumption: the development dependencies remain pinned to the repository declaration dev = ["pytest==9.1.0", "ruff==0.15.17"].

The declaration is quoted verbatim from
[`pyproject.toml:24` at `7934200f867e61aa8145301d994c0b2fe7024801`](https://github.com/thequantumfalcon/kry/blob/7934200f867e61aa8145301d994c0b2fe7024801/pyproject.toml#L24),
the first bump's parent. The quote and pushes are real; the decision is an
operator-constructed event recorded at replay time, not a historical GitHub
decision. The requested `grep -n ruff CONTRIBUTING.md pyproject.toml
requirements-dev.in` printed that line; `requirements-dev.in` did not exist
at that commit, so grep also reported the missing file and exited 2.

## Drift observations for that one assumption

| Outcome across all 111 pushes | Count | Observed behavior |
|---|---:|---|
| Automatic invalidation | 1 | [`96640ca2f3caac5f8d433fe1ed8a894d1b1a3578`](https://github.com/thequantumfalcon/kry/commit/96640ca2f3caac5f8d433fe1ed8a894d1b1a3578), “deps: bump ruff from 0.16.0 to 0.16.1 in the python group (#50)”; reason: “the push bumps ruff” |
| Human-gated notices | 9 | Manifest paths changed without a recognized named-dependency match; the assumption stayed active pending review |
| Untouched | 101 | 27 before the assumption existed, 32 active with no recognized manifest change, 42 already invalidated |

The Dependabot-only subset was 1 automatic invalidation, 1 notice, and 9
untouched pushes. Four of the nine total notices accompanied actual dev-pin
changes, including the first grouped bump; five accompanied metadata-only
`pyproject.toml` changes. The engine matches changed manifest paths and commit
subjects; its reported manifest digest hashes the path list, not manifest
contents. The checkout remained at v0.1.9 during ingestion.

The assumption was never reactivated. Later Ruff bumps and grouped actions
#90 therefore left it invalidated. The 101 untouched rows are not a
true-negative denominator. No notice was accepted or rejected to obtain a
better result. The evidence packet preserves an initial reporting-label
mistake and its correction: nine notices were initially labelled automatic
because the labeler read the wrong key; raw engine states were unchanged.

## Extraction noise on real PR prose

Run 2 reproduced the reviewed PR subset exactly: 18 proposal records, or 9
unique `(source_ref, proposed_kind, statement)` entries. Opened and closed
envelopes repeated the bodies. Manual clear-noise triage found **6/18 =
33.33%**, also **3/9 unique = 33.33%**: historical bug descriptions and a
checked change-category fragment were mistaken for actionable intent.
Four completed pytest/ruff checklist records were accepted as completed
tasks; six meaningful policy records were separately marked as the wrong
proposed kind. The other 45 proposals, including the constructed operator
proposal, were outside this PR-only score. This small retained-proposal
sample measures neither missed claims nor general extraction accuracy.

## Snapshot verification and continuity

The pinned command used an absolute Python interpreter and the relative
deliverable `-m pytest -q tests/test_verifier_hardening.py`. Its matching
negative control targeted `tests/known_bad_does_not_exist.py`, as in
[MCP step 5](../../MCP.md#5-pin-a-verifier-and-verify). CCE marked that
control held, exit 4; it checks missing-file failure, not a planted assertion.

Primary pytest returned **92 passed, 61 skipped in 1.30s**. CCE recorded
proof status `verified`, but evidence **grade D**: **8/10 snapshot mutations
were detected**, and both absent/truncate mutations of
`verifiers/js/verify.mjs` survived. Mutations of the test file, both Python
verifier scripts, and the attestation module were detected. The two
determinism reruns passed; aggregate verification took 27.889 seconds.

Node was installed on the host at `/opt/homebrew/bin/node` but absent from
the verifier sandbox PATH `/bin:/usr/bin`. The Node-dependent tests skipped,
so destroying the declared JS artifact did not fail the required command.
The relative command did hit snapshot files; there was no absolute-checkout
escape, PATH override, test filtering, or artifact removal to improve the
grade. The cap was “deliverables are not bound to the checks: 2 mutation(s)
survived.” Skipped pytest cases are not parsed as a separate score penalty;
here their coverage gap was exposed by surviving mutations.

Markdown and JSON resume calls completed. Final continuity was
**`action_required`**, exit 1, for nine pending confirmations, with
`trust_unavailable: false` and the current v0.1.9 revision frontier. No
task-completion action was submitted. These are separate outcomes: a passing
pytest command, grade-D evidence, and unresolved human review. They do not
establish live-webhook operation, complete JS verification, historical
manifest-content validation, or population-level drift precision/recall.
