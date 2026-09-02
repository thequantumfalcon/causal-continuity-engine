"""Run the canonical cross-platform CI and release gate sequence."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GATE_TIMEOUT_SECONDS = 300
GATE_TIMEOUT_SECONDS = {
    "content integrity": 120,
    "commit metadata integrity": 60,
    "release metadata": 60,
    "tests": 900,
    "lint": 300,
    "stdlib boundary": 120,
    "benchmark": 300,
    "conformance corpus": 180,
    "capability generation": 120,
    "capability drift": 60,
    "clean source before release": 60,
    "reproducible distributions": 1200,
    "distribution structure": 900,
    "distribution behavior": 900,
    "clean source after release": 60,
}

BASE_GATES = (
    (
        "content integrity",
        (
            sys.executable,
            ".github/scripts/check_content_marks.py",
            "--tree",
            "HEAD",
        ),
    ),
    (
        "commit metadata integrity",
        (
            sys.executable,
            ".github/scripts/check_content_marks.py",
            "--commit",
            "HEAD",
        ),
    ),
    (
        "release metadata",
        (sys.executable, ".github/scripts/check_release_metadata.py"),
    ),
    ("tests", (sys.executable, "-W", "error", "-m", "pytest", "tests/", "-q")),
    ("lint", (sys.executable, "-m", "ruff", "check", ".")),
    ("stdlib boundary", (sys.executable, ".github/scripts/check_stdlib.py")),
    ("benchmark", (
        sys.executable, "-W", "error", "benchmarks/continuitybench/run.py")),
    ("conformance corpus", (sys.executable, "vectors/generate.py", "--check")),
    (
        "capability generation",
        (sys.executable, "-m", "causal_continuity_engine.capabilities", "--write"),
    ),
    ("capability drift", ("git", "diff", "--exit-code", "--", "docs/CAPABILITIES.md")),
)

RELEASE_PREFIX = (
    ("clean source before release", (sys.executable, ".github/scripts/check_clean.py")),
)

RELEASE_SUFFIX = (
    (
        "reproducible distributions",
        (
            sys.executable,
            ".github/scripts/build_distributions.py",
            "--outdir",
            "dist",
            "--check-reproducible",
        ),
    ),
    (
        "distribution structure",
        (
            sys.executable,
            ".github/scripts/verify_distributions.py",
            "--structural-only",
            "dist",
        ),
    ),
    ("clean source after release", (sys.executable, ".github/scripts/check_clean.py")),
)

RELEASE_BEHAVIOR = (
    (
        "distribution behavior",
        (
            sys.executable,
            ".github/scripts/verify_distributions.py",
            "--behavior-only",
            "dist",
        ),
    ),
)

FULL_RELEASE_SUFFIX = RELEASE_SUFFIX[:-1] + RELEASE_BEHAVIOR + RELEASE_SUFFIX[-1:]
RELEASE_BUILD_SUFFIX = (RELEASE_SUFFIX[0], RELEASE_SUFFIX[-1])


def _release_verifier():
    path = ROOT / ".github" / "scripts" / "verify_distributions.py"
    spec = importlib.util.spec_from_file_location("cce_gate_process_runner", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the bounded release process runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(gates) -> int:
    runner = _release_verifier()
    environment = dict(os.environ)
    environment.update({
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    })
    for label, command in gates:
        print(f"==> {label}", flush=True)
        try:
            result = runner._run_checked(
                list(command),
                cwd=ROOT,
                environment=environment,
                label=label,
                timeout_seconds=GATE_TIMEOUT_SECONDS.get(
                    label, DEFAULT_GATE_TIMEOUT_SECONDS),
            )
        except SystemExit as exc:
            print(f"gate failed: {label}", file=sys.stderr)
            if exc.code:
                print(exc, file=sys.stderr)
            return 1
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--release",
        action="store_true",
        help="also require a clean tree and build/verify release artifacts",
    )
    mode.add_argument(
        "--release-build",
        action="store_true",
        help="run release gates and build the candidate before immutable upload",
    )
    mode.add_argument(
        "--artifacts-structural",
        action="store_true",
        help="build twice and structurally verify artifacts without executing them",
    )
    mode.add_argument(
        "--behavior-only",
        action="store_true",
        help="execute only the installed-wheel checks after an immutable handoff",
    )
    mode.add_argument(
        "--structure-only",
        action="store_true",
        help="structurally verify only an immutable downloaded release set",
    )
    parser.add_argument("--portable-semantic", action="store_true")
    parser.add_argument("--source-epoch", type=int)
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args(argv)
    if args.portable_semantic != (args.source_epoch is not None):
        parser.error("--portable-semantic and --source-epoch must be supplied together")
    if args.portable_semantic and not args.structure_only:
        parser.error("portable structural options require --structure-only")
    gates = BASE_GATES
    if args.release:
        if args.dist is not None:
            parser.error("--dist is available only with a single-phase verifier")
        gates = RELEASE_PREFIX + BASE_GATES + FULL_RELEASE_SUFFIX
    elif args.release_build:
        if args.dist is not None:
            parser.error("--dist is available only with a single-phase verifier")
        gates = RELEASE_PREFIX + BASE_GATES + RELEASE_BUILD_SUFFIX
    elif args.artifacts_structural:
        if args.dist is not None:
            parser.error("--dist is available only with a single-phase verifier")
        gates = RELEASE_PREFIX + RELEASE_SUFFIX
    elif args.structure_only:
        dist = args.dist or Path("dist")
        command = [
            sys.executable,
            ".github/scripts/verify_distributions.py",
            "--structural-only",
        ]
        if args.portable_semantic:
            command.extend([
                "--portable-semantic",
                "--source-epoch",
                str(args.source_epoch),
            ])
        command.append(str(dist))
        gates = ((
            "distribution structure",
            tuple(command),
        ),)
    elif args.behavior_only:
        dist = args.dist or Path("dist")
        gates = ((
            "distribution behavior",
            (
                sys.executable,
                ".github/scripts/verify_distributions.py",
                "--behavior-only",
                str(dist),
            ),
        ),)
    elif args.dist is not None:
        parser.error("--dist requires --structure-only or --behavior-only")
    return _run(gates)


if __name__ == "__main__":
    raise SystemExit(main())
