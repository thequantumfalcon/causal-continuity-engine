"""A renamed symlink must not bypass the existing command-indirection guard."""

import os
import shlex
import sys

import pytest

from causal_continuity_engine.verifiers import (
    UnsafeCommandError,
    VerifierRunner,
    VerifierSpec,
    check_command_safety,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell/symlink execution fixture")


@pytest.mark.parametrize("chain", [False, True])
def test_absolute_alias_to_shell_is_refused(tmp_path, chain):
    alias = tmp_path / "local-check"
    alias.symlink_to("/bin/sh")
    if chain:
        outer = tmp_path / "outer-check"
        outer.symlink_to(alias)
        alias = outer
    with pytest.raises(UnsafeCommandError, match="delegates"):
        check_command_safety(shlex.quote(str(alias)) + " -c true", require_absolute=True)


def test_runner_does_not_execute_the_renamed_shell(tmp_path):
    alias = tmp_path / "local-check"
    alias.symlink_to("/bin/sh")
    outcome = VerifierRunner(None, tmp_path).run(VerifierSpec(
        name="renamed-shell", command=shlex.quote(str(alias)) + " -c true", pinned=True))
    assert outcome.result == "inconclusive"
    assert "delegates" in outcome.details


def test_python_interpreter_symlink_remains_supported(tmp_path):
    alias = tmp_path / "python-check"
    alias.symlink_to(sys.executable)
    check_command_safety(shlex.quote(str(alias)) + " -m pytest", require_absolute=True)


def test_unresolvable_symlink_is_refused(tmp_path):
    alias = tmp_path / "loop"
    alias.symlink_to(alias)
    with pytest.raises(UnsafeCommandError, match="resolve"):
        check_command_safety(shlex.quote(str(alias)), require_absolute=True)
