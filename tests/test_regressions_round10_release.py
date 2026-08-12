"""Regression coverage for the hermetic release toolchain and source gate."""

import gzip
import importlib.util
import io
import os
import re
import stat
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_LOCKED_TOOLS = {
    "attrs",
    "build",
    "colorama",
    "iniconfig",
    "jsonschema",
    "jsonschema-specifications",
    "packaging",
    "pip",
    "pluggy",
    "pygments",
    "pyproject-hooks",
    "pytest",
    "referencing",
    "rpds-py",
    "ruff",
    "setuptools",
    "typing-extensions",
}


def _load_release_script(name):
    path = ROOT / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"cce_{name}_release_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _requirement_blocks(text):
    blocks = []
    current = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current and line.startswith("    "):
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def test_release_tool_closure_is_exactly_pinned_and_sha256_locked():
    lock = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
    blocks = _requirement_blocks(lock)
    names = set()

    for block in blocks:
        first = block.splitlines()[0]
        assert "==" in first, f"unpinned requirement: {first}"
        name = first.split("==", 1)[0].strip().lower()
        names.add(name)
        assert re.search(r"--hash=sha256:[0-9a-f]{64}(?:\s|$)", block), (
            f"unhashed requirement: {name}")

    assert names == EXPECTED_LOCKED_TOOLS


def test_lock_inputs_match_declared_direct_build_and_development_tools():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = set(config["build-system"]["requires"])
    declared.update(config["project"]["optional-dependencies"]["dev"])
    inputs = {
        line.strip()
        for line in (ROOT / "requirements-dev.in").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert inputs == declared
    locked = {
        block.splitlines()[0].split("==", 1)[0].strip().lower():
        block.splitlines()[0].split("==", 1)[1].split(None, 1)[0]
        for block in _requirement_blocks(
            (ROOT / "requirements-dev.lock").read_text(encoding="utf-8"))
    }
    for requirement in inputs:
        name, version = requirement.split("==", 1)
        assert locked.get(name.lower()) == version, (
            f"declared {requirement}, locked {locked.get(name.lower())!r}")
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "include requirements-dev.in requirements-dev.lock" in manifest


def test_every_automated_tool_install_uses_the_lock_and_no_resolution():
    justfile = (ROOT / "justfile").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8")
    bootstrap = (ROOT / ".github" / "scripts" / "bootstrap_tools.py").read_text(
        encoding="utf-8")
    builder = (ROOT / ".github" / "scripts" / "build_distributions.py").read_text(
        encoding="utf-8")

    assert (
        "--force-reinstall --require-hashes --only-binary=:all: "
        "-r requirements-dev.lock"
    ) in justfile
    assert "--no-deps --no-build-isolation -e ." in justfile
    assert "cache: pip" not in ci + release
    assert "cache-dependency-path:" not in ci + release
    assert 'install -e ".[dev]"' not in justfile + ci + release
    assert '"--no-isolation"' in builder
    assert '"--force-reinstall"' in bootstrap
    assert '"--require-hashes"' in bootstrap
    assert '"--only-binary=:all:"' in bootstrap
    assert '"--no-deps"' in bootstrap
    assert '"--no-build-isolation"' in bootstrap
    assert "apt-get" not in ci + release
    assert "run: just" not in ci + release
    assert "pip install" not in ci + release
    assert ci.count("python .github/scripts/bootstrap_tools.py") == 4
    assert "python .github/scripts/bootstrap_tools.py --release" in release


def test_build_backend_source_mutation_fails_closed(tmp_path, monkeypatch):
    builder = _load_release_script("build_distributions")
    snapshots = iter([
        {"causal_continuity_engine/api.py": "before"},
        {"causal_continuity_engine/api.py": "after"},
    ])

    class Verifier:
        @staticmethod
        def _require_exact_git_source(source_root):
            del source_root

        @staticmethod
        def _expected_sdist_source_payload(source_root):
            del source_root
            return {}

        @staticmethod
        def _require_source_payload_matches_git_index(source_root, payload):
            del source_root, payload

        @staticmethod
        def _validated_source_names(names, *, label):
            del label
            return set(names)

    monkeypatch.setattr(builder, "_source_snapshot", lambda *args: next(snapshots))
    monkeypatch.setattr(builder, "_release_verifier", lambda: Verifier)
    monkeypatch.setattr(builder, "_run_backend", lambda *args, **kwargs: None)

    with pytest.raises(SystemExit, match="build backend changed") as caught:
        builder._build(tmp_path / "dist", "315532800")
    assert "causal_continuity_engine/api.py" in str(caught.value)


def test_build_backend_uses_bounded_release_process_runner(tmp_path, monkeypatch):
    builder = _load_release_script("build_distributions")
    calls = []

    class Verifier:
        @staticmethod
        def _run_checked(command, **options):
            calls.append((command, options))

    monkeypatch.setattr(builder, "_release_verifier", lambda: Verifier)
    environment = {"CCE_RELEASE_ENVIRONMENT": "build-isolated"}

    builder._run_backend("sdist", tmp_path, tmp_path / "dist", environment)

    assert calls[0][0][:4] == [sys.executable, "-m", "build", "--sdist"]
    assert calls[0][1] == {
        "cwd": tmp_path,
        "environment": environment,
        "label": "sdist build backend",
        "timeout_seconds": builder.BUILD_BACKEND_TIMEOUT_SECONDS,
    }


def test_captured_release_source_is_bound_to_git_blob_bytes(tmp_path, monkeypatch):
    verifier = _load_release_script("verify_distributions")
    body = b"reviewed bytes\n"
    git_object = f"blob {len(body)}\0".encode("ascii") + body
    object_id = verifier.hashlib.sha1(
        git_object, usedforsecurity=False).hexdigest()
    monkeypatch.setattr(
        verifier, "_git_index_entries",
        lambda source_root: {"README.md": ("100644", object_id)})

    verifier._require_source_payload_matches_git_index(
        tmp_path, {"README.md": body})
    with pytest.raises(SystemExit, match="captured release source bytes differ"):
        verifier._require_source_payload_matches_git_index(
            tmp_path, {"README.md": b"substituted bytes\n"})
    with pytest.raises(SystemExit, match="inventory differs"):
        verifier._require_source_payload_matches_git_index(tmp_path, {})


def test_isolated_backend_source_materializer_rejects_escape(tmp_path):
    builder = _load_release_script("build_distributions")
    source = tmp_path / "source"
    builder._materialize_source_payload(
        source, {"nested/owned.txt": b"reviewed\n"})
    assert (source / "nested" / "owned.txt").read_bytes() == b"reviewed\n"

    with pytest.raises(SystemExit, match="not empty"):
        builder._materialize_source_payload(source, {"second.txt": b"x"})
    with pytest.raises(SystemExit, match="invalid captured source"):
        builder._materialize_source_payload(
            tmp_path / "escape-source", {"../outside.txt": b"x"})
    for index, payload in enumerate((
        {1: b"x"},
        {"not-bytes.txt": "x"},
        {"..\\outside.txt": b"x"},
        {"nested//alias.txt": b"x"},
        {"case.txt": b"x", "CASE.TXT": b"y"},
        {"file": b"x", "file/child.txt": b"y"},
        {"CON": b"x"},
        {"trailing.": b"x"},
        {"control\x1f.txt": b"x"},
        {"Dir/a.txt": b"x", "dir/b.txt": b"y"},
        {"Dir": b"x", "dir/child.txt": b"y"},
        {"bad?.txt": b"x"},
    )):
        destination = tmp_path / f"invalid-source-{index}"
        with pytest.raises(SystemExit, match="invalid captured source"):
            builder._materialize_source_payload(
                destination, payload)
        assert not destination.exists()
    assert not (tmp_path / "outside.txt").exists()


def test_bootstrap_and_build_environments_do_not_inherit_parent_credentials(
        tmp_path):
    bootstrap = _load_release_script("bootstrap_tools")
    builder = _load_release_script("build_distributions")
    parent = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "CCE_RELEASE_SECRET_CANARY": "must-not-cross-boundary",
        "HTTPS_PROXY": "http://must-not-cross-boundary.invalid",
        "PIP_INDEX_URL": "https://must-not-cross-boundary.invalid/simple",
        "SOURCE_DATE_EPOCH": "1",
    }
    bootstrap_env = bootstrap._clean_environment(
        tmp_path / "bootstrap", Path(sys.executable).parent,
        parent_environment=parent)
    build_env = builder._clean_build_environment(
        tmp_path / "build", Path(sys.executable).parent,
        parent_environment=parent)

    for environment in (bootstrap_env, build_env):
        assert "CCE_RELEASE_SECRET_CANARY" not in environment
        assert "HTTPS_PROXY" not in environment
        assert "PIP_INDEX_URL" not in environment
        assert "SOURCE_DATE_EPOCH" not in environment
        assert Path(environment["HOME"]).resolve().is_relative_to(tmp_path.resolve())
        assert Path(environment["PIP_CACHE_DIR"]).resolve().is_relative_to(
            tmp_path.resolve())
    assert "PIP_NO_INDEX" not in bootstrap_env
    assert build_env["PIP_NO_INDEX"] == "1"


@pytest.mark.parametrize("parent", [{}, {"PATH": ""}, {"PATH": None}])
def test_bootstrap_and_build_reject_missing_or_empty_parent_path(
        tmp_path, parent):
    bootstrap = _load_release_script("bootstrap_tools")
    builder = _load_release_script("build_distributions")

    with pytest.raises(SystemExit, match="explicit nonempty parent PATH"):
        bootstrap._clean_environment(
            tmp_path / "bootstrap-missing-path", Path(sys.executable).parent,
            parent_environment=parent)
    with pytest.raises(SystemExit, match="explicit nonempty parent PATH"):
        builder._clean_build_environment(
            tmp_path / "build-missing-path", Path(sys.executable).parent,
            parent_environment=parent)


def test_backend_wheel_preflight_rejects_duplicates_before_normalizing(tmp_path):
    builder = _load_release_script("build_distributions")
    wheel = tmp_path / "duplicate.whl"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("package/module.py", b"first")
            archive.writestr("package/module.py", b"second")

    with pytest.raises(SystemExit, match="duplicate archive entries"):
        builder._normalize_wheel(wheel, 1700000000)
    assert not wheel.with_suffix(".whl.normalized").exists()


@pytest.mark.parametrize(
    "name, info_mutator, diagnostic",
    [
        ("package/", None, "must not contain directory entries"),
        (
            "package/link.py",
            lambda info: (
                setattr(info, "create_system", 3),
                setattr(info, "external_attr", stat.S_IFLNK << 16),
            ),
            "non-regular member",
        ),
    ],
)
def test_backend_wheel_preflight_rejects_directory_and_special_members(
        tmp_path, name, info_mutator, diagnostic):
    builder = _load_release_script("build_distributions")
    wheel = tmp_path / "unsafe.whl"
    info = zipfile.ZipInfo(name)
    if info_mutator is not None:
        info_mutator(info)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(info, b"payload")

    with pytest.raises(SystemExit, match=diagnostic):
        builder._bounded_backend_wheel_payloads(wheel)


def test_backend_wheel_preflight_applies_member_bound_before_read(tmp_path):
    builder = _load_release_script("build_distributions")
    verifier = _load_release_script("verify_distributions")
    verifier.MAX_WHEEL_MEMBER_BYTES = 4
    builder._release_verifier = lambda: verifier
    wheel = tmp_path / "large.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("package/module.py", b"12345")

    with pytest.raises(SystemExit, match="member exceeds the size limit"):
        builder._bounded_backend_wheel_payloads(wheel)


def test_backend_wheel_compressed_input_is_bounded_before_zip_parse(
        tmp_path):
    builder = _load_release_script("build_distributions")
    verifier = _load_release_script("verify_distributions")
    verifier.MAX_WHEEL_ARCHIVE_BYTES = 4
    builder._release_verifier = lambda: verifier
    wheel = tmp_path / "oversized.whl"
    wheel.write_bytes(b"12345")

    with pytest.raises(SystemExit, match="compressed archive exceeds the size limit"):
        builder._bounded_backend_wheel_payloads(wheel)


def test_backend_archive_read_tolerates_path_descriptor_ctime_view_skew(
        tmp_path, monkeypatch):
    builder = _load_release_script("build_distributions")
    archive = tmp_path / "stable.whl"
    archive.write_bytes(b"stable archive bytes")
    real_lstat = builder.os.lstat

    def skewed_path_stat(path):
        info = real_lstat(path)
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_size=info.st_size,
            st_mtime=info.st_mtime,
            st_mtime_ns=info.st_mtime_ns,
            st_ctime=info.st_ctime,
            st_ctime_ns=info.st_ctime_ns + 1,
            st_file_attributes=getattr(info, "st_file_attributes", 0),
            st_reparse_tag=getattr(info, "st_reparse_tag", 0),
        )

    monkeypatch.setattr(builder.os, "lstat", skewed_path_stat)
    assert builder._bounded_physical_file_bytes(
        archive, 1024, label="backend archive") == b"stable archive bytes"


def test_backend_sdist_expansion_is_bounded_before_tar_parse(tmp_path):
    builder = _load_release_script("build_distributions")
    verifier = _load_release_script("verify_distributions")
    verifier.MAX_SDIST_TAR_BYTES = 32
    builder._release_verifier = lambda: verifier
    sdist = tmp_path / "expanded.tar.gz"
    with gzip.open(sdist, "wb") as archive:
        archive.write(b"0" * 64)

    with pytest.raises(SystemExit, match="decompressed tar exceeds the size limit"):
        builder._normalize_sdist(sdist, 1700000000)
    assert not sdist.with_suffix(".gz.normalized").exists()


def test_backend_sdist_rejects_trailing_separator_before_output(tmp_path):
    builder = _load_release_script("build_distributions")
    sdist = tmp_path / "unsafe.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("causal_continuity_engine-0.1.0/")
        member.type = tarfile.REGTYPE
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))

    with pytest.raises(SystemExit, match="trailing separators"):
        builder._normalize_sdist(sdist, 1700000000)
    assert not sdist.with_suffix(".gz.normalized").exists()


def test_release_checks_clean_tree_before_and_after_backend_execution():
    orchestrator = _load_release_script("run_gates")
    release_gates = (
        orchestrator.RELEASE_PREFIX
        + orchestrator.BASE_GATES
        + orchestrator.RELEASE_SUFFIX
    )
    labels = [label for label, _ in release_gates]
    assert labels[0] == "clean source before release"
    assert labels[-3:] == [
        "reproducible distributions",
        "distribution equivalence",
        "clean source after release",
    ]

    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    artifact_job = ci.split("\n  artifacts:", 1)[1].split("\n  ci:", 1)[0]
    assert "bootstrap_tools.py --artifacts-only" in artifact_job


def test_canonical_pytest_gates_treat_warnings_as_errors():
    orchestrator = _load_release_script("run_gates")
    test_command = dict(orchestrator.BASE_GATES)["tests"]
    assert test_command[:5] == (
        sys.executable, "-W", "error", "-m", "pytest")

    verifier = _load_release_script("verify_distributions")
    wheel_command = verifier._wheel_behavior_test_command(
        Path("wheel-python"), Path("owned-audit"),
        ["behavior.py", "conformance.py"])
    assert wheel_command[:5] == [
        "wheel-python", "-W", "error", "-P", "-c"]
    assert wheel_command[5] == verifier._AUDIT_MODULE_LAUNCHER
    assert wheel_command[6:] == [
        str(Path("owned-audit").resolve()), "pytest",
        "--import-mode=importlib", "-q", "behavior.py", "conformance.py",
    ]


def test_canonical_benchmark_gate_uses_the_owned_direct_file():
    orchestrator = _load_release_script("run_gates")
    assert dict(orchestrator.BASE_GATES)["benchmark"] == (
        sys.executable, "-W", "error", "benchmarks/continuitybench/run.py")


def test_direct_benchmark_loader_resolves_only_its_sibling_scenarios():
    runner_path = ROOT / "benchmarks" / "continuitybench" / "run.py"
    import_path = list(sys.path)
    spec = importlib.util.spec_from_file_location(
        "cce_direct_benchmark_test", runner_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    assert module.ALL_SCENARIOS
    assert sys.path == import_path


def test_direct_benchmark_loader_rejects_a_redirected_sibling(tmp_path):
    source = ROOT / "benchmarks" / "continuitybench" / "run.py"
    sandbox = tmp_path / "continuitybench"
    sandbox.mkdir()
    runner_path = sandbox / "run.py"
    runner_path.write_bytes(source.read_bytes())
    target = tmp_path / "redirected_scenarios.py"
    target.write_text("ALL_SCENARIOS = ()\n", encoding="utf-8")
    try:
        (sandbox / "scenarios.py").symlink_to(target)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    spec = importlib.util.spec_from_file_location(
        "cce_redirected_benchmark_test", runner_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    with pytest.raises(ImportError, match="physical regular file"):
        spec.loader.exec_module(module)


@pytest.mark.parametrize(
    ("directory_mode", "directory_attributes", "scenario_mode",
     "scenario_attributes", "message"),
    [
        (stat.S_IFDIR, 0x400, stat.S_IFREG, 0, "physical directory"),
        (stat.S_IFDIR, 0, stat.S_IFREG, 0x400, "physical regular file"),
        (stat.S_IFDIR, 0, stat.S_IFDIR, 0, "physical regular file"),
    ],
)
def test_direct_benchmark_loader_rejects_nonphysical_stat_views(
        tmp_path, monkeypatch, directory_mode, directory_attributes,
        scenario_mode, scenario_attributes, message):
    runner_path = ROOT / "benchmarks" / "continuitybench" / "run.py"
    spec = importlib.util.spec_from_file_location(
        "cce_physical_benchmark_test", runner_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "__file__", str(tmp_path / "run.py"))
    views = iter([
        SimpleNamespace(
            st_mode=directory_mode,
            st_file_attributes=directory_attributes),
        SimpleNamespace(
            st_mode=scenario_mode,
            st_file_attributes=scenario_attributes),
    ])
    monkeypatch.setattr(module.os, "lstat", lambda _path: next(views))

    with pytest.raises(ImportError, match=message):
        module._direct_scenarios_path()


def _load_direct_benchmark_runner(name):
    runner_path = ROOT / "benchmarks" / "continuitybench" / "run.py"
    spec = importlib.util.spec_from_file_location(name, runner_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_benchmark_run_cleans_workdirs_after_success_and_between_runs(
        monkeypatch):
    runner = _load_direct_benchmark_runner("cce_benchmark_cleanup_success")
    cleaned = []

    class Workdir:
        def __init__(self, name):
            self.name = name

        def cleanup(self):
            cleaned.append(self.name)

    calls = []

    def scenario():
        name = f"workdir-{len(calls)}"
        calls.append(name)
        runner.scenarios_module._WORKDIRS.append(Workdir(name))
        assert name not in cleaned
        return {"name": name, "checks": [("passed", True)], "metrics": {}}

    monkeypatch.setattr(runner, "ALL_SCENARIOS", [scenario])
    for _ in range(2):
        assert runner.run()["scenarios"][0]["passed"] is True
        assert runner.scenarios_module._WORKDIRS == []

    assert cleaned == ["workdir-0", "workdir-1"]


def test_benchmark_run_cleans_workdirs_when_a_scenario_raises(monkeypatch):
    runner = _load_direct_benchmark_runner("cce_benchmark_cleanup_failure")
    cleaned = []

    def scenario():
        runner.scenarios_module._WORKDIRS.append(
            SimpleNamespace(cleanup=lambda: cleaned.append("failed-workdir")))
        raise RuntimeError("planted scenario failure")

    monkeypatch.setattr(runner, "ALL_SCENARIOS", [scenario])
    # The raise used to propagate out of run(), which cleaned up correctly but
    # abandoned the run and emitted no metrics at all. It is now recorded as a
    # failed scenario instead. Cleanup — the property this test is named for —
    # is unchanged, and is what the assertions below still pin.
    report = runner.run()

    (result,) = report["scenarios"]
    assert result["crashed"] is True
    assert result["passed"] is False
    assert "planted scenario failure" in result["checks"][0][0]

    assert cleaned == ["failed-workdir"]
    assert runner.scenarios_module._WORKDIRS == []


def test_ci_fan_in_requires_linux_windows_macos_and_artifacts():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    macos_job = ci.split("\n  macos:", 1)[1].split("\n  artifacts:", 1)[0]
    fan_in = ci.split("\n  ci:", 1)[1]

    assert "runs-on: macos-15" in macos_job
    assert 'python-version: "3.14"' in macos_job
    assert "Native macOS ARM64 portability gate" in macos_job
    assert "python .github/scripts/bootstrap_tools.py" in macos_job
    assert "needs: [test, windows, macos, artifacts]" in fan_in
    for result in ("TEST_RESULT", "WINDOWS_RESULT", "MACOS_RESULT", "ARTIFACT_RESULT"):
        assert f'test "${result}" = "success"' in fan_in


def test_fresh_bootstrap_forces_every_locked_artifact_and_checks_closure(
        monkeypatch):
    bootstrap = _load_release_script("bootstrap_tools")
    calls = []

    def fake_run(command, *, environment, label, timeout_seconds):
        assert environment == {"clean": "environment"}
        calls.append((command, label, timeout_seconds))

    monkeypatch.setattr(bootstrap, "_run_checked", fake_run)
    bootstrap._install_toolchain(
        Path("fresh-venv-python"), {"clean": "environment"})

    install = calls[0][0]
    assert install[:5] == [
        "fresh-venv-python", "-m", "pip", "install", "--force-reinstall"]
    assert "--require-hashes" in install
    assert "--only-binary=:all:" in install
    assert calls[1][0][-2:] == ["pip", "check"]
    assert calls[2][1] == "exact tool-closure verification"
    assert calls[3][1] == "local package installation"
    assert [call[2] for call in calls] == [
        bootstrap.TOOL_INSTALL_TIMEOUT_SECONDS,
        bootstrap.TOOL_CHECK_TIMEOUT_SECONDS,
        bootstrap.TOOL_CHECK_TIMEOUT_SECONDS,
        bootstrap.LOCAL_INSTALL_TIMEOUT_SECONDS,
    ]


def test_interpreter_pip_bootstrap_is_explicit_and_bounded(monkeypatch):
    bootstrap = _load_release_script("bootstrap_tools")
    calls = []

    def fake_run(command, *, environment, label, timeout_seconds):
        calls.append((command, environment, label, timeout_seconds))

    monkeypatch.setattr(bootstrap, "_run_checked", fake_run)
    bootstrap._bootstrap_pip(Path("fresh-venv-python"), {"clean": "environment"})

    assert calls == [(
        [
            "fresh-venv-python",
            "-Im",
            "ensurepip",
            "--upgrade",
            "--default-pip",
        ],
        {"clean": "environment"},
        "interpreter ensurepip bootstrap",
        bootstrap.ENSUREPIP_TIMEOUT_SECONDS,
    )]
    source = (ROOT / ".github" / "scripts" / "bootstrap_tools.py").read_text(
        encoding="utf-8")
    assert "EnvBuilder(with_pip=False, clear=True)" in source
    assert "EnvBuilder(with_pip=True" not in source


def test_artifact_verifier_pip_bootstrap_is_explicit_and_bounded(monkeypatch):
    verifier = _load_release_script("verify_distributions")
    calls = []

    def fake_run(command, **options):
        calls.append((command, options))

    monkeypatch.setattr(verifier, "_run_checked", fake_run)
    verifier._bootstrap_venv_pip(
        Path("fresh-wheel-python"), Path("isolated-work"),
        {"clean": "environment"})

    assert calls == [(
        [
            "fresh-wheel-python",
            "-Im",
            "ensurepip",
            "--upgrade",
            "--default-pip",
        ],
        {
            "cwd": Path("isolated-work"),
            "environment": {"clean": "environment"},
            "label": "artifact verifier ensurepip bootstrap",
            "timeout_seconds": verifier.ENSUREPIP_TIMEOUT_SECONDS,
        },
    )]
    source = (ROOT / ".github" / "scripts" / "verify_distributions.py").read_text(
        encoding="utf-8")
    assert "EnvBuilder(with_pip=False)" in source
    assert "EnvBuilder(with_pip=True" not in source


def test_artifact_runtime_probe_removes_installation_only_tools(monkeypatch):
    verifier = _load_release_script("verify_distributions")
    calls = []

    def fake_run(command, **options):
        calls.append((command, options))

    monkeypatch.setattr(verifier, "_run_checked", fake_run)
    verifier._remove_venv_bootstrap_tools(
        Path("fresh-wheel-python"), Path("isolated-work"),
        {"clean": "environment"})

    assert calls == [(
        [
            "fresh-wheel-python",
            "-Im",
            "pip",
            "uninstall",
            "--yes",
            "setuptools",
            "pip",
        ],
        {
            "cwd": Path("isolated-work"),
            "environment": {"clean": "environment"},
            "label": "artifact verifier bootstrap-tool removal",
            "timeout_seconds": 120,
        },
    )]
    assert 'for bootstrap_tool in ("pip", "setuptools")' in verifier._IMPORT_PROBE


def test_checked_in_gate_runner_stops_at_first_failure(monkeypatch):
    orchestrator = _load_release_script("run_gates")
    calls = []

    class Completed:
        stdout = ""
        stderr = ""

    class Runner:
        @staticmethod
        def _run_checked(command, **options):
            assert options["cwd"] == orchestrator.ROOT
            assert options["timeout_seconds"] == (
                orchestrator.DEFAULT_GATE_TIMEOUT_SECONDS)
            calls.append(command)
            if command == ["two"]:
                raise SystemExit("planted bounded failure")
            return Completed()

    monkeypatch.setattr(orchestrator, "_release_verifier", lambda: Runner)
    assert orchestrator._run((
        ("first", ("one",)),
        ("failing", ("two",)),
        ("must not run", ("three",)),
    )) == 1
    assert calls == [["one"], ["two"]]


def test_gate_runner_forces_utf8_child_environment_without_mutating_caller(
        monkeypatch):
    orchestrator = _load_release_script("run_gates")
    monkeypatch.setenv("PYTHONIOENCODING", "cp1252")
    monkeypatch.setenv("PYTHONUTF8", "0")
    caller_environment = dict(orchestrator.os.environ)
    captured = []

    class Runner:
        @staticmethod
        def _run_checked(_command, **options):
            captured.append(options["environment"])
            return SimpleNamespace(stdout="", stderr="")

    monkeypatch.setattr(orchestrator, "_release_verifier", lambda: Runner)
    assert orchestrator._run((("fixture", ("child",)),)) == 0

    assert captured[0]["PYTHONIOENCODING"] == "utf-8"
    assert captured[0]["PYTHONUTF8"] == "1"
    assert captured[0] is not orchestrator.os.environ
    assert dict(orchestrator.os.environ) == caller_environment


def test_release_publication_is_serialized_repo_bound_and_retryable():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8")
    publish = workflow.split("\n  publish:", 1)[1]

    assert "group: ${{ github.workflow }}-${{ github.ref }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "GH_REPO: ${{ github.repository }}" in publish
    assert "gh release upload \"$GITHUB_REF_NAME\" dist/* --clobber" in publish
    assert "gh release download \"$GITHUB_REF_NAME\"" in publish
    assert "cmp --silent \"$artifact\"" in publish
    assert "gh release create \"$GITHUB_REF_NAME\" dist/*" not in publish
    assert publish.index("gh release create") < publish.index("gh release upload")
    assert publish.index("gh release upload") < publish.index("gh release download")
    assert publish.index("gh release download") < publish.index("gh release edit")


def test_attribution_scan_exempts_only_its_three_enforcement_files():
    workflow = (
        ROOT / ".github" / "workflows" / "no-ai-attribution.yml"
    ).read_text(encoding="utf-8")
    pre_commit = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    expected = {
        ":(exclude).githooks/pre-commit",
        ":(exclude).githooks/commit-msg",
        ":(exclude).github/workflows/no-ai-attribution.yml",
    }

    for source in (workflow, pre_commit):
        assert all(item in source for item in expected)
        assert ":(exclude).githooks'" not in source
        assert ":(exclude).github'" not in source


def test_attribution_scans_distinguish_no_match_from_command_failure():
    workflow = (
        ROOT / ".github" / "workflows" / "no-ai-attribution.yml"
    ).read_text(encoding="utf-8")
    pre_commit = (ROOT / ".githooks" / "pre-commit").read_text(
        encoding="utf-8")
    commit_msg = (ROOT / ".githooks" / "commit-msg").read_text(
        encoding="utf-8")

    assert "set -euo pipefail" in workflow
    assert 'for sha in "$BASE_SHA" "$HEAD_SHA"' in workflow
    assert 'git cat-file -e "$BASE_SHA^{commit}"' in workflow
    assert '|| git_grep_status=$?' in workflow
    assert '*) echo "git grep failed' in workflow
    assert "git log --format='%B%n%an%n%ae' | grep" not in workflow
    assert '|| git_grep_status=$?' in pre_commit
    assert '*)\n        echo "ERROR: git grep failed' in pre_commit
    assert 'git var GIT_AUTHOR_IDENT >> "$identity_input" || exit 1' in commit_msg
    assert '|| grep_status=$?' in commit_msg


def test_unknown_repository_visibility_cannot_skip_public_controls():
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8")
    dependency = (
        ROOT / ".github" / "workflows" / "dependency-review.yml"
    ).read_text(encoding="utf-8")

    for workflow in (release, dependency):
        assert "Classify repository visibility without a falsy default" in workflow
        assert "private|internal)" in workflow
        assert "unknown repository visibility:" in workflow
    assert "if: steps.visibility.outputs.public == 'true'" in release
    assert "if: github.event.repository.visibility == 'public'" not in release
    assert "if: steps.visibility.outputs.enabled == 'true'" in dependency
    assert "if: github.event.repository.visibility == 'public'" not in dependency


def test_precommit_hooks_are_frozen_to_full_commit_shas():
    config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    revisions = [
        line.split("#", 1)[0].split(":", 1)[1].strip()
        for line in config.splitlines()
        if line.lstrip().startswith("rev:")
    ]

    assert len(revisions) == 3
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for revision in revisions)
