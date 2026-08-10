"""ContinuityBench runner: executes every scenario and reports CI-008 metrics.

Exit code 1 if any critical check fails.

Usage:  python -W error benchmarks/continuitybench/run.py [--json]
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path


def _is_redirected(path: Path, info: os.stat_result) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return bool(
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        or is_junction is not None and is_junction()
    )


def _direct_scenarios_path() -> Path:
    script_directory = Path(os.path.abspath(__file__)).parent
    scenarios_path = script_directory / "scenarios.py"
    try:
        directory_info = os.lstat(script_directory)
        scenarios_info = os.lstat(scenarios_path)
    except OSError as exc:
        raise ImportError("benchmark scenarios are unreadable") from exc
    if (_is_redirected(script_directory, directory_info)
            or not stat.S_ISDIR(directory_info.st_mode)):
        raise ImportError("benchmark script directory must be a physical directory")
    if (_is_redirected(scenarios_path, scenarios_info)
            or not stat.S_ISREG(scenarios_info.st_mode)):
        raise ImportError("benchmark scenarios must be a physical regular file")
    return scenarios_path


if __package__:
    from . import scenarios as scenarios_module
else:
    scenarios_path = _direct_scenarios_path()
    scenarios_spec = importlib.util.spec_from_file_location(
        "cce_continuitybench_scenarios", scenarios_path)
    if scenarios_spec is None or scenarios_spec.loader is None:
        raise ImportError(f"cannot load benchmark scenarios from {scenarios_path}")
    scenarios_module = importlib.util.module_from_spec(scenarios_spec)
    scenarios_spec.loader.exec_module(scenarios_module)

ALL_SCENARIOS = scenarios_module.ALL_SCENARIOS

MVP_TARGETS = {
    "continuity_success_rate": 0.85,
    "critical_invalidation_recall": 0.90,
    "invalidation_precision": 0.80,
    "evidence_coverage": 0.95,
    "false_completion_rate": 0.0,
    "recovered_work_ratio": 0.70,
}


def _cleanup_workdirs() -> None:
    workdirs = tuple(scenarios_module._WORKDIRS)
    scenarios_module._WORKDIRS.clear()
    for workdir in reversed(workdirs):
        workdir.cleanup()


def run() -> dict:
    try:
        results = []
        t0 = time.monotonic()
        for scenario in ALL_SCENARIOS:
            start = time.monotonic()
            try:
                result = scenario()
            except Exception as exc:  # noqa: BLE001 - reported as a failure
                # A scenario that raises must not take the run with it. An
                # aborted run emits no metrics at all, and no metrics reads
                # the same as never having run — the confusion this project
                # exists to prevent. Record the crash as a failed scenario.
                result = {
                    "name": getattr(scenario, "__name__", "unknown_scenario"),
                    "checks": [(f"scenario raised "
                                f"{type(exc).__name__}: {exc}", False)],
                    "metrics": {},
                    "crashed": True,
                }
            result["seconds"] = round(time.monotonic() - start, 3)
            result["passed"] = all(ok for _, ok in result["checks"])
            results.append(result)
        total_seconds = round(time.monotonic() - t0, 3)

        def collect(metric):
            vals = [r["metrics"][metric] for r in results if metric in r["metrics"]]
            return sum(vals) / len(vals) if vals else None

        csr = sum(1 for r in results if r["passed"]) / len(results)
        metrics = {
            "continuity_success_rate": csr,
            "critical_invalidation_recall": collect("invalidation_recall"),
            "invalidation_precision": collect("invalidation_precision"),
            "evidence_coverage": collect("evidence_coverage"),
            "false_completion_rate": collect("false_completion_rate"),
            "recovered_work_ratio": collect("recovered_work_ratio"),
        }
        # A crashed scenario contributes no metrics, so every average above is
        # taken over an incomplete set — and a scenario that would have scored
        # badly improves the average by crashing. Report those as incomplete
        # rather than as a pass the run cannot support. `continuity_success_
        # rate` is exempt: a crash counts as a failure in its denominator, so
        # it stays meaningful as a lower bound.
        crashed = [r["name"] for r in results if r.get("crashed")]
        gates = {}
        for name, target in MVP_TARGETS.items():
            actual = metrics.get(name)
            if actual is None:
                gates[name] = "no-data"
            elif crashed and name != "continuity_success_rate":
                gates[name] = "incomplete"
            elif name == "false_completion_rate":
                gates[name] = "PASS" if actual <= target else "FAIL"
            else:
                gates[name] = "PASS" if actual >= target else "FAIL"
        return {"scenarios": results, "metrics": metrics, "gates": gates,
                "total_seconds": total_seconds}
    finally:
        _cleanup_workdirs()


def main():
    report = run()
    if "--json" in sys.argv:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print("ContinuityBench — scenario families")
        print("=" * 64)
        for r in report["scenarios"]:
            flag = "PASS" if r["passed"] else "FAIL"
            print(f"[{flag}] {r['name']}  ({r['seconds']}s)")
            for desc, ok in r["checks"]:
                # Keep the human report encodable on Windows consoles whose
                # default code page cannot represent checkmark glyphs.
                print(f"    {'OK' if ok else 'XX'} {desc}")
        print("\nMetrics vs MVP targets")
        print("=" * 64)
        for name, value in report["metrics"].items():
            target = MVP_TARGETS.get(name)
            gate = report["gates"].get(name, "")
            shown = "n/a" if value is None else f"{value:.2%}"
            print(f"{name:32s} {shown:>8s}  target "
                  f"{'<=' if name == 'false_completion_rate' else '>='}"
                  f" {target:.0%}  [{gate}]")
        print(f"\ntotal: {report['total_seconds']}s")
    failed = [r["name"] for r in report["scenarios"] if not r["passed"]]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
