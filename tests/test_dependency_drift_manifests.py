"""Lockfiles and NuGet dependency manifests carry named dependency drift."""

import pytest

from tests.test_dependency_drift_precision import PROJECT, _assume, _attest, _push, _status
from tests.test_dependency_drift_precision import engine as engine
from tests.test_instrument_validation import _good


@pytest.mark.parametrize("path,package", [
    ("uv.lock", "requests"),
    ("frontend/yarn.lock", "axios"),
    ("frontend/pnpm-lock.yaml", "axios"),
])
def test_lockfile_only_bump_blocks_dependent_completion(tmp_path, path, package):
    instance, task, _, _ = _good(tmp_path)
    try:
        assumption = _assume(instance, f"the {package} library remains compatible")
        instance.graph.put_edge(
            edge_type="assumes", src_id=task.id, dst_id=assumption.id,
            tenant_id=instance.tenant_id, project_id=PROJECT)
        report = _push(instance, f"Bump {package} from 1.0 to 2.0", paths=(path,))
        assert _status(instance, assumption.id) == "invalidated"
        assert len(report["invalidations"]) == 1
        proof = _attest(instance, task.id)
        assert proof["status"] == "verified"
        with pytest.raises(PermissionError, match="unresolved invalidation control state"):
            instance.complete_task(PROJECT, task.id, proof=proof)
    finally:
        instance.close()


@pytest.mark.parametrize("path", [
    "Directory.Packages.props", "Directory.Build.props", "src/packages.config",
    "src/packages.lock.json", "src/App.csproj", "src/App.fsproj", "src/App.vbproj",
    "src/App.nuspec",
])
def test_nuget_manifests_identify_named_packages(engine, path):
    assumption = _assume(engine, "the OpenTelemetry library remains compatible")
    (notice,) = _push(engine, "Bump OpenTelemetry from 1.0 to 2.0", paths=(path,))[
        "invalidations"]
    assert _status(engine, assumption.id) == "invalidated"
    assert _status(engine, notice) == "open"


def test_real_nuget_multiname_subject_uses_its_actual_manifest(engine):
    # https://github.com/dependabot/dependabot-core/commit/a6e4af749dbba761ceb3f184e8657059c0ffcc14
    packages = ("OpenTelemetry", "OpenTelemetry.Exporter.OpenTelemetryProtocol")
    assumptions = [_assume(engine, f"the {package} library remains compatible", package)
                   for package in packages]
    report = _push(engine, "Bump " + " and ".join(packages),
                   paths=("nuget/helpers/lib/NuGetUpdater/Directory.Packages.props",))
    assert len(report["invalidations"]) == 2
    assert all(_status(engine, item.id) == "invalidated" for item in assumptions)


def test_uv_lock_uses_python_package_normalization(engine):
    assumption = _assume(engine, "the requests_oauthlib library remains compatible")
    _push(engine, "Bump requests-oauthlib from 1.0 to 2.0", paths=("uv.lock",))
    assert _status(engine, assumption.id) == "invalidated"


@pytest.mark.parametrize("path", [
    "uv.lock.md", "src/App.csproj.bak", "Directory.Packages.props.txt",
])
def test_similar_nonmanifest_names_do_not_trigger_drift(engine, path):
    assumption = _assume(engine)
    assert _push(engine, "Bump requests from 1.0 to 2.0", paths=(path,))["invalidations"] == []
    assert _status(engine, assumption.id) == "active"
