# How this repository is tested

Every gate below runs in CI on each pull request and push to `main`. Run them
locally before opening a PR; all of them must pass with zero failures.

## The full suite

```bash
python -W error -m pytest tests
```

Warnings are treated as errors. The suite covers the engine, store, API, CLI,
proof envelopes, verifiers, invalidation, memory, redaction, and the
regression rounds accumulated during release hardening.

## Static and drift gates

```bash
python -m ruff check .
python .github/scripts/check_stdlib.py            # stdlib-only runtime boundary
python .github/scripts/check_release_metadata.py  # version/citation consistency
python .github/scripts/render_api_docs.py --check # docs/API.md drift
python -m causal_continuity_engine.capabilities --write
git diff --exit-code -- docs/CAPABILITIES.md      # capability-claim drift
```

## Conformance and benchmarks

```bash
python vectors/generate.py --check   # deterministic conformance corpus
python -m benchmarks.continuitybench.run
```

The `vectors/` corpus is the arbiter when the library, the standalone
verifier, and `SPEC.md` disagree; a divergence between them is a bug by
definition (see `.github/SECURITY.md`).

## Aggregate gate

```bash
python .github/scripts/run_gates.py
```

Runs the behavioral gate set end to end — the same aggregate CI enforces.

## Platform coverage

Hosted CI runs Linux on Python 3.11–3.14, plus native Windows and
macOS ARM64 on 3.14. A fix that passes only on one platform is not done.
