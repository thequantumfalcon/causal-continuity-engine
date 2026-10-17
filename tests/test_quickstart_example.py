"""The shipped runnable example still runs.

`examples/quickstart.py` is the first thing a reader is told to run, and
nothing exercised it: when tasks became owner-confirmed authority (#139) it
kept minting its task with a raw `graph.put_node`, and `attest_action` has
refused that task ever since ("confirmation has no canonical origin"). A
crashing example is a false claim about the product, so this runs it exactly
as the docstring says, in a separate process, and checks every step it prints.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "quickstart.py"


def test_quickstart_example_runs_end_to_end():
    completed = subprocess.run(
        [sys.executable, str(EXAMPLE)], cwd=ROOT, capture_output=True,
        text=True, timeout=300, check=False)
    output = completed.stdout
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr
    # Each step the example announces, in order.
    positions = [output.find(marker) for marker in (
        "== 1. Initialize a project", "== 2. Record a task",
        "== 3. Mint a proof", "== 4. Complete the task",
        "== 5. Verify the envelope", "== 6. Try the same proof", "== Done")]
    assert -1 not in positions and positions == sorted(positions), positions
    assert "streams-rows: passed (source: executed)" in output
    assert "task status: verified" in output
    keyless, keyed = output.split("with the key", 1)
    assert "exit 2: UNVERIFIED" in keyless
    assert "exit 0: VALID" in keyed
    assert "refused, as it must be" in output
    assert "NOT REFUSED" not in output
