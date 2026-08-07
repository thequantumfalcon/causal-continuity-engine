"""Create a fresh hash-verified tool environment, then run trusted gates."""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "requirements-dev.lock"
ENSUREPIP_TIMEOUT_SECONDS = 300
TOOL_INSTALL_TIMEOUT_SECONDS = 600
TOOL_CHECK_TIMEOUT_SECONDS = 120
LOCAL_INSTALL_TIMEOUT_SECONDS = 300
GATE_RUNNER_TIMEOUT_SECONDS = 1500

_CLOSURE_PROBE = r"""
import importlib.metadata
import json
import pathlib
import re
import sys
import sysconfig
from packaging.markers import Marker, default_environment
from packaging.utils import canonicalize_name

lock = open(sys.argv[1], encoding="utf-8").read().splitlines()
expected = {}
for line in lock:
    if not line or line.startswith((" ", "#")):
        continue
    requirement = line.removesuffix("\\").strip()
    match = re.fullmatch(
        r"([A-Za-z0-9_.-]+)==([^ ;]+)(?:\s*;\s*(.+))?", requirement)
    if match is None:
        raise SystemExit(f"unparseable locked requirement: {line}")
    name, version, marker = match.groups()
    if marker is None or Marker(marker).evaluate(default_environment()):
        expected[canonicalize_name(name)] = version

distributions = list(importlib.metadata.distributions())
installed_names = [
    canonicalize_name(item.metadata["Name"])
    for item in distributions
]
if len(installed_names) != len(set(installed_names)):
    raise SystemExit("duplicate bootstrap distributions: " + json.dumps(
        sorted(name for name in set(installed_names)
               if installed_names.count(name) > 1)))
installed = {
    name: item.version
    for name, item in zip(installed_names, distributions, strict=True)
}
if installed.keys() - expected.keys():
    raise SystemExit("unexpected bootstrap distributions: " + json.dumps(
        sorted(installed.keys() - expected.keys())))
if expected != {name: installed.get(name) for name in expected}:
    raise SystemExit("installed tool closure differs from lock: " + json.dumps({
        "expected": expected,
        "installed": {name: installed.get(name) for name in expected},
    }, sort_keys=True))
site_roots = {
    pathlib.Path(sysconfig.get_path(kind)).resolve()
    for kind in ("purelib", "platlib")
}
outside = {}
for name, item in zip(installed_names, distributions, strict=True):
    location = pathlib.Path(item.locate_file("")).resolve()
    if not any(location.is_relative_to(root) for root in site_roots):
        outside[name] = str(location)
if outside:
    raise SystemExit("bootstrap distribution loaded outside its venv: "
                     + json.dumps(outside, sort_keys=True))
import pip
pip_origin = pathlib.Path(pip.__file__).resolve()
if not any(pip_origin.is_relative_to(root) for root in site_roots):
    raise SystemExit(f"pip imported outside the bootstrap venv: {pip_origin}")
print(json.dumps(expected, sort_keys=True))
"""


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _clean_environment(
        isolation_root: Path, executable_directory: Path,
        *, parent_environment: dict[str, str] | None = None) -> dict[str, str]:
    """Construct the minimal network-capable environment used by bootstrap."""
    parent = os.environ if parent_environment is None else parent_environment
    isolation_root = isolation_root.resolve()
    home = isolation_root / "home"
    temp = isolation_root / "tmp"
    cache = isolation_root / "cache"
    config = isolation_root / "config"
    for directory in (home, temp, cache, config):
        directory.mkdir(parents=True, exist_ok=True)
    parent_path = parent.get("PATH")
    if not isinstance(parent_path, str) or not parent_path:
        raise SystemExit("bootstrap requires an explicit nonempty parent PATH")
    git = shutil.which("git", path=parent_path)
    if git is None:
        raise SystemExit("bootstrap requires Git on the parent executable path")
    path_entries = [
        str(executable_directory.resolve()),
        str(Path(git).resolve().parent),
    ]
    environment: dict[str, str] = {}
    if os.name == "nt":
        system_root = parent.get("SystemRoot") or parent.get("WINDIR")
        if not system_root:
            raise SystemExit("cannot construct isolated Windows bootstrap environment")
        system_root_path = Path(system_root).resolve()
        environment.update({
            "SystemRoot": str(system_root_path),
            "WINDIR": str(system_root_path),
            "COMSPEC": str(system_root_path / "System32" / "cmd.exe"),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        })
        path_entries.extend([
            str(system_root_path / "System32"),
            str(system_root_path),
        ])
    else:
        path_entries.extend(["/usr/bin", "/bin"])
        environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    environment.update({
        "PATH": os.pathsep.join(dict.fromkeys(path_entries)),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(config),
        "LOCALAPPDATA": str(cache),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "TMP": str(temp),
        "TEMP": str(temp),
        "TMPDIR": str(temp),
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_CACHE_DIR": str(cache / "pip"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "CCE_RELEASE_ENVIRONMENT": "bootstrap-isolated",
    })
    return environment


def _release_verifier():
    path = ROOT / ".github" / "scripts" / "verify_distributions.py"
    spec = importlib.util.spec_from_file_location("cce_bootstrap_process_runner", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the bounded release process runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_checked(
        command: list[str], *, environment: dict[str, str], label: str,
        timeout_seconds: int) -> None:
    """Run one bootstrap child with bounded output, time, and descendants."""
    result = _release_verifier()._run_checked(
        command,
        cwd=ROOT,
        environment=environment,
        label=label,
        timeout_seconds=timeout_seconds,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def _install_toolchain(python: Path, environment: dict[str, str]) -> None:
    _run_checked(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--force-reinstall",
            "--require-hashes",
            "--only-binary=:all:",
            "-r",
            str(LOCK),
        ],
        environment=environment,
        label="hash-locked tool installation",
        timeout_seconds=TOOL_INSTALL_TIMEOUT_SECONDS,
    )
    _run_checked(
        [str(python), "-m", "pip", "check"],
        environment=environment,
        label="tool dependency consistency",
        timeout_seconds=TOOL_CHECK_TIMEOUT_SECONDS,
    )
    _run_checked(
        [str(python), "-c", _CLOSURE_PROBE, str(LOCK)],
        environment=environment,
        label="exact tool-closure verification",
        timeout_seconds=TOOL_CHECK_TIMEOUT_SECONDS,
    )
    _run_checked(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-build-isolation",
            "-e",
            str(ROOT),
        ],
        environment=environment,
        label="local package installation",
        timeout_seconds=LOCAL_INSTALL_TIMEOUT_SECONDS,
    )


def _bootstrap_pip(python: Path, environment: dict[str, str]) -> None:
    """Install the interpreter-bundled pip under the release process limits."""
    _run_checked(
        [str(python), "-Im", "ensurepip", "--upgrade", "--default-pip"],
        environment=environment,
        label="interpreter ensurepip bootstrap",
        timeout_seconds=ENSUREPIP_TIMEOUT_SECONDS,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--release", action="store_true")
    mode.add_argument("--artifacts-only", action="store_true")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="cce-tools-") as temp:
        environment_root = Path(temp) / "venv"
        venv.EnvBuilder(with_pip=False, clear=True).create(environment_root)
        python = _venv_python(environment_root)
        environment = _clean_environment(
            Path(temp) / "process-environment", python.parent)
        _bootstrap_pip(python, environment)
        _install_toolchain(python, environment)
        command = [str(python), str(ROOT / ".github/scripts/run_gates.py")]
        if args.release:
            command.append("--release")
        elif args.artifacts_only:
            command.append("--artifacts-only")
        _run_checked(
            command,
            environment=environment,
            label="canonical gate sequence",
            timeout_seconds=GATE_RUNNER_TIMEOUT_SECONDS,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
