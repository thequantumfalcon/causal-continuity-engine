## What this changes

<!-- One paragraph: what behaves differently after this merges, and why. -->

## Linked issue

<!-- Closes #NNN. If there is no issue, say what prompted the change. -->

## Checklist

- [ ] The PR title is a Conventional Commit — `feat`, `fix`, `docs`, `test`, `refactor`, or `chore`. Given the trust core's change bar, `feat` usually needs an accepted proposal issue first. Everything is merged by squash, so this title becomes the permanent commit subject on `main`. See [CONTRIBUTING.md](CONTRIBUTING.md#commits-and-pull-requests).
- [ ] `just test` passes.
- [ ] `just lint` passes.
- [ ] `just deps` passes — `causal_continuity_engine/` still imports nothing outside the standard library.
- [ ] `just bench` passes — all eleven ContinuityBench scenarios, every metric at target.
- [ ] `just corpus` passes — the reference still agrees with the committed vectors in `vectors/`.
- [ ] `just caps` passes — every capability claim still resolves to real symbols, files, and tests. If the claims changed, `docs/CAPABILITIES.md` was regenerated with `python -m causal_continuity_engine.capabilities --write` rather than hand-edited.
- [ ] `just build` passes if packaging, generated assets, or release machinery changed — both builds match and the clean-installed wheel audits successfully.
- [ ] Every commit carries a `Signed-off-by` trailer (`git commit -s`). Enforced: the `DCO` check is a required status on `main`, so a pull request with any commit missing the trailer cannot merge.
- [ ] No gate was weakened, skipped, or made conditional in order to get a test to pass. If a gate had to change, that change is the subject of this PR and is argued for above.
- [ ] No AI attribution anywhere in the diff, commit messages, or PR title or body.

## If this is a bug fix

- [ ] A regression test pins the defect, and it was verified to FAIL against the pre-fix code. A test that passes both before and after the fix proves nothing.

Paste the evidence below — the test failing on the pre-fix tree, then passing on this one:

```text
(replace with the real transcript)

$ python -m pytest tests/<file>::<test> -q  # against the recorded pre-fix revision
FAILED tests/<file>::<test>

$ python -m pytest tests/<file>::<test> -q  # against this revision
1 passed
```
