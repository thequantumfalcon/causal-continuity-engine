# Causal Continuity Engine - command catalog.
#
# This file is the local command catalog. Hosted CI and release use the
# standard-library `.github/scripts/run_gates.py` aggregate so no downloaded
# command runner participates in a trusted build. The individual recipes here
# remain useful for focused local work and call the same underlying commands.
#
# The engine itself has no runtime dependencies - `causal_continuity_engine/` is stdlib-only, and
# `just deps` enforces it. CI invokes the same scanner through `run_gates.py`. Everything installed by
# `just setup` is for testing and packaging, never for running the engine.
#
# Recipes that shell out to just again use `{{just_executable()}}` rather than
# the bare name, so a nested call cannot pick up a different just, or fail
# because just was run by path and is not itself on PATH.

# Show every recipe in this catalog.
default: help

# List the recipes, in the order they appear in this file.
help:
    @"{{ just_executable() }}" --list --unsorted

# Install the reviewed, hash-locked tool closure, then the local engine without
# dependency resolution or an isolated backend environment.
setup:
    python -m pip install --force-reinstall --require-hashes --only-binary=:all: -r requirements-dev.lock
    python -m pip check
    python -m pip install --no-deps --no-build-isolation -e .

# Run the full test suite.
test:
    python -m pytest tests/ -q

# Scan the exact proposed Git index for known carriers and hidden content.
content-integrity:
    python .github/scripts/check_content_marks.py --index

# The lint scope is pinned in pyproject.toml under [tool.ruff.lint], NOT on the
# command line here. An implicit rule set can change independently of this
# repository's reviewed policy, while an explicit selection changes only when
# this file's companion configuration changes. Passing --select here as well
# would reintroduce the same problem one
# layer up: two spellings of one gate, and the command line silently wins.
# Widen the selection by editing pyproject.toml, and fix the tree in the same
# commit.

# Ruff, with the rule set pinned in pyproject.toml.
lint:
    python -m ruff check .

# Deliberately not part of `lint` and not in the release gate. The engine was
# hand-formatted before ruff. A broad mechanical rewrite would detach
# regression tests and review notes from the lines they were written against,
# for no behaviour change.

# Report where the tree diverges from `ruff format`. Advisory, not a gate.
fmt-check:
    python -m ruff format --check .

# Run ContinuityBench: 11 scenarios, 6 metrics, each against its MVP target.
bench:
    python -W error benchmarks/continuitybench/run.py

# Run the same complete behavioral sequence used by hosted CI.
check:
    python .github/scripts/bootstrap_tools.py

# This does NOT compare bytes - ids, timestamps and Lamport keypairs are fresh
# on every generation. It re-derives a verdict for each committed vector and
# checks it against the verdict the corpus records. A disagreement means either
# the reference regressed or the corpus is stale.
#
# Run `python vectors/generate.py` with no flags only when you intend to
# regenerate: it rewrites every vector in place.

# Drift guard: the reference must still agree with the committed corpus.
corpus:
    python vectors/generate.py --check

# Two different things, and only the first used to be checked. `verify()`
# resolves every declared symbol, file and test - it does NOT compare the
# generated table against the copy on disk, so a hand-edited or stale
# docs/CAPABILITIES.md passed cleanly. README, CONTRIBUTING and AGENTS all
# claimed the table was gated; it was not. Regenerating and then requiring a
# clean diff is what makes that claim true, and it is the same trick the
# corpus drift guard uses: derive the artefact, compare against the committed
# one, fail on disagreement.

# Capability audit: claims resolve, AND docs/CAPABILITIES.md is not stale.
caps:
    python -m causal_continuity_engine.capabilities --write
    git diff --exit-code -- docs/CAPABILITIES.md

# "Zero runtime dependencies" is a supply-chain claim, and this project does
# not make claims it cannot mechanically check. README.md and this file both
# state that causal_continuity_engine/ is stdlib-only; without a gate that sentence decays the first
# time someone reaches for a convenient import, and nothing says so. Parsing
# the AST rather than importing means the check also catches an import that is
# guarded, lazy, or inside a function body.

# Gate: the shipped package must import nothing outside the standard library.
deps:
    python .github/scripts/check_stdlib.py

# verifiers/verify_proof.py is an independent implementation of SPEC.md: stdlib
# only, imports nothing from causal_continuity_engine/. It takes a bare envelope, not a conformance
# vector - vectors/*.json wrap an envelope alongside its expected verdict, so
# passing one here is a shape error, not a signature failure.
#
#   just verify-proof proof.json --hmac-key-hex <hex>
#   just verify-proof proof.json --fingerprint sha256:...
#
# FILE is quoted because the verifier expands globs itself; the shell must not.
# Exits non-zero on any verdict other than VALID, so it composes into a gate.

# Verify a proof envelope with the standalone verifier.
verify-proof FILE *FLAGS:
    python verifiers/verify_proof.py "{{ FILE }}" {{ FLAGS }}

# Build the sdist and wheel into dist/.
build:
    python .github/scripts/bootstrap_tools.py --artifacts-only

# This gate builds. It does not tag, push, or publish; a signed version tag
# triggers the release workflow only after this same gate passes in CI.

# Release gate: refuses to build unless every check above passes.
release:
    python .github/scripts/bootstrap_tools.py --release

# Create a signed, annotated release tag only after exact owner-side metadata,
# commit-verification, required-check, origin/main, and remote-absence checks.
# Nothing is pushed unless the caller includes the explicit --push flag.
prepare-release-tag TAG *FLAGS:
    python .github/scripts/prepare_release_tag.py "{{ TAG }}" {{ FLAGS }}
