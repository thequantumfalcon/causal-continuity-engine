"""Assertions executed specifically inside the installed-wheel audit process."""

import os
from pathlib import Path

import pytest


def test_installed_wheel_audit_receives_only_isolated_process_state():
    if os.environ.get("CCE_RELEASE_ENVIRONMENT") != "isolated":
        pytest.skip("installed-wheel environment assertion")

    assert "PYTHONPATH" not in os.environ
    assert os.environ["PIP_NO_INDEX"] == "1"
    forbidden_fragments = ("TOKEN", "SECRET", "CREDENTIAL", "PROXY")
    assert not {
        name for name in os.environ
        if any(fragment in name.upper() for fragment in forbidden_fragments)
    }
    home = Path(os.environ["HOME"]).resolve()
    assert Path(os.environ["USERPROFILE"]).resolve() == home
    assert home.name == "home"
    for name in (
            "TMP", "TEMP", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
            "PIP_CACHE_DIR"):
        assert Path(os.environ[name]).resolve().is_relative_to(home.parent)
