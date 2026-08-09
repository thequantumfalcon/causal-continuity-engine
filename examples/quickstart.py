#!/usr/bin/env python3
"""Runnable end-to-end quickstart: task, evidence, proof, independent check.

Run it from a checkout:

    python examples/quickstart.py

Everything happens in a temporary directory that is removed on exit; no
repository state is touched. Standard library plus this package only, matching
the runtime boundary that `.github/scripts/check_stdlib.py` enforces.

What it demonstrates, in order:

1. A project whose policy pins a required verifier by command, with a negative
   control proving that check can fail.
2. A proof envelope minted by actually running that verifier.
3. The completion gate accepting the proof for the task it names.
4. `verifiers/verify_proof.py` — an independent reimplementation that imports
   nothing from this package — reporting UNVERIFIED without the key and VALID
   with it. UNVERIFIED is the honest answer, not a failure: an `hmac-sha256`
   envelope is not third-party verifiable, so a keyless party is told that
   nothing was established rather than that everything is fine.
5. The gate refusing that same proof for a different task. A signature says
   the record is authentic; it does not say what the record is evidence for.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Run from a bare checkout without installing anything first. An installed
# copy already on sys.path wins, so this only helps and never shadows.
if not (ROOT / "causal_continuity_engine").is_dir():  # pragma: no cover
    raise SystemExit("run this script from a checkout of the repository")
sys.path.append(str(ROOT))

from causal_continuity_engine.core import Signer  # noqa: E402
from causal_continuity_engine.engine import Engine  # noqa: E402

TENANT = "ten_quickstart"
PROJECT = "prj_quickstart"

# A demonstration key, deliberately hard-coded and deliberately not a secret.
# A real deployment keeps this in .cce/secrets/signing.key, which `init`
# provisions with private permissions and .gitignore excludes.
DEMO_KEY = b"cce-quickstart-demo-key-not-a-secret"


def _python(script: str) -> str:
    """A policy-pinnable command line that works on POSIX and Windows."""
    return f'"{Path(sys.executable).as_posix()}" -c "{script}"'


def _say(step: str, detail: str = "") -> None:
    print(f"\n== {step}")
    if detail:
        print(f"   {detail}")


def _run_independent_verifier(proof_path: Path, *, key_hex: str | None) -> str:
    """Run verifiers/verify_proof.py in a separate process and return its line."""
    command = [sys.executable, str(ROOT / "verifiers" / "verify_proof.py"),
               str(proof_path)]
    if key_hex is not None:
        command += ["--hmac-key-hex", key_hex]
    completed = subprocess.run(
        command, capture_output=True, text=True, check=False)
    # The per-file line names the proof and carries the five check results;
    # a trailing line summarises the batch. Report the informative one.
    lines = [line.strip() for line in completed.stdout.splitlines()
             if line.strip()]
    verdict = next(
        (line for line in lines if proof_path.name in line),
        lines[-1] if lines else "")
    print(f"   exit {completed.returncode}: {verdict}")
    return verdict


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)

        deliverable = work / "exporter.py"
        deliverable.write_text(
            "def export(rows):\n    yield from rows\n", encoding="utf-8")

        passing = _python(
            "from pathlib import Path;"
            "p=Path('exporter.py');"
            "raise SystemExit(0 if p.exists() and 'yield from' in"
            " p.read_text(encoding='utf-8') else 19)")
        failing = _python("raise SystemExit(17)")

        _say("1. Initialize a project",
             "policy pins one required verifier, with a negative control")
        engine = Engine(
            work / "cce.db", tenant_id=TENANT,
            signer=Signer("quickstart", DEMO_KEY), workdir=work)
        engine.create_project(
            "quickstart", project_id=PROJECT, config={
                "max_autonomy_level": 2,
                "require_proof_for": ["task_complete"],
                "min_evidence_grade": "C",
                "required_verifiers": [{
                    "name": "streams-rows",
                    "command": passing,
                    "expect_fail_command": failing,
                    "artifacts": ["exporter.py"],
                }],
            })
        # Autonomy is 0 by default and running a verifier needs level 2, so a
        # human grant is required before any of the below can execute.
        engine.policy.grant(project_id=PROJECT, level=2, granted_by="operator")
        print(f"   project {PROJECT}, autonomy granted to level 2")

        try:
            _say("2. Record a task")
            task = engine.graph.put_node(
                entity_type="task", tenant_id=TENANT, project_id=PROJECT,
                status="open", data={"title": "exporter must stream rows"})
            print(f"   task {task.id}: {task['data']['title']}")

            _say("3. Mint a proof by actually running the pinned verifier")
            proof = engine.attest_action(
                PROJECT, intent_type="task_complete",
                intent_statement="exporter streams rows",
                actor={"agent": "quickstart", "model": "n/a"},
                action_type="run_verifier",
                continuity={"task_ids": [task.id]})
            print(f"   proof {proof['proof_id']}: {proof['status']}")
            for verification in proof["verifications"]:
                print(f"     {verification['verifier']}:"
                      f" {verification['result']}"
                      f" (source: {verification['source']})")
            evidence = proof["evidence_context"]
            print(f"   pinned by policy: {evidence['policy_pinned']}")
            print("   mutation-bound to the deliverable:"
                  f" {evidence['mutation']['bound']}")
            print("   stable across repeat runs:"
                  f" {all(d['stable'] for d in evidence['determinism'].values())}")

            _say("4. Complete the task through the gate")
            completed = engine.complete_task(
                PROJECT, task.id, proof=proof, actor="quickstart")
            print(f"   task status: {completed['status']}")

            _say("5. Verify the envelope with the independent verifier",
                 "verifiers/verify_proof.py imports nothing from this package")
            proof_path = work / "proof.json"
            proof_path.write_text(
                json.dumps(proof, indent=2), encoding="utf-8")

            print("   without the key — nothing can be established:")
            keyless = _run_independent_verifier(proof_path, key_hex=None)
            print("   with the key — authenticity is checkable:")
            keyed = _run_independent_verifier(
                proof_path, key_hex=DEMO_KEY.hex())

            _say("6. Try the same proof on a different task",
                 "a signature says the record is authentic, not what it is"
                 " evidence for")
            other = engine.graph.put_node(
                entity_type="task", tenant_id=TENANT, project_id=PROJECT,
                status="open", data={"title": "a different task"})
            try:
                engine.complete_task(
                    PROJECT, other.id, proof=proof, actor="quickstart")
            except PermissionError as exc:
                print(f"   refused, as it must be:\n     {exc}")
            else:
                print("   NOT REFUSED — this is a defect, please report it")
                return 1

            _say("Done")
            print("   The proof was minted by actually running a pinned check,"
                  " accepted for the\n   task it names, refused for one it does"
                  " not, and checked by a verifier\n   that shares no code with"
                  " the engine. SPEC.md defines the envelope; the\n   README"
                  " enumerates every rejection path the completion gate has.")

            if not keyless.startswith("UNVERIFIED"):
                print(f"   unexpected keyless verdict: {keyless}")
                return 1
            if not keyed.startswith("VALID"):
                print(f"   unexpected keyed verdict: {keyed}")
                return 1
        finally:
            engine.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
