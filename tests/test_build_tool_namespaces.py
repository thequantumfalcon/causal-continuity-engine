"""The pinned build tool must reject path-like legacy namespace metadata."""

from zipfile import ZipFile

import pytest
from setuptools.wheel import Wheel


def _wheel(tmp_path, namespaces):
    path = tmp_path / "namespace_probe-1.0-py3-none-any.whl"
    with ZipFile(path, "w") as archive:
        archive.writestr(
            "namespace_probe-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(
            "namespace_probe-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: namespace-probe\nVersion: 1.0\n",
        )
        archive.writestr(
            "namespace_probe-1.0.dist-info/namespace_packages.txt", namespaces)
    return Wheel(str(path))


@pytest.mark.parametrize("case", ["absolute", "empty_component"])
def test_legacy_wheel_rejects_invalid_namespace(tmp_path, case):
    destination = tmp_path / "destination"
    outside = tmp_path / "outside"
    outside.mkdir()
    canary = outside / "canary.txt"
    canary.write_bytes(b"unchanged")
    namespace = str(outside.resolve()) if case == "absolute" else "probe\nprobe..child"

    with pytest.raises(ValueError, match="invalid namespace package name"):
        _wheel(tmp_path, namespace + "\n").install_as_egg(str(destination))

    assert sorted(path.name for path in outside.iterdir()) == ["canary.txt"]
    assert canary.read_bytes() == b"unchanged"


def test_legacy_wheel_accepts_dotted_namespace(tmp_path):
    destination = tmp_path / "destination"
    _wheel(tmp_path, "probe\nprobe.child\n").install_as_egg(str(destination))

    assert (destination / "probe" / "__init__.py").is_file()
    assert (destination / "probe" / "child" / "__init__.py").is_file()
    assert (destination / "EGG-INFO" / "PKG-INFO").is_file()
