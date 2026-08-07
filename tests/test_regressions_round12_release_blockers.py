import contextlib
import io
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

import causal_continuity_engine.cli as cli
from causal_continuity_engine.core import sha256_hex
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.store import Store
from causal_continuity_engine.verifiers import (
    _MAX_OUTPUT,
    _TRUNCATION_MARKER,
    VerifierRunner,
    VerifierSpec,
)

_POLICY_GAP = "policy:proof-required-without-required-verifiers"


def test_proof_required_without_verifiers_is_an_explicit_signed_blocker(tmp_path):
    engine = Engine(tmp_path / "continuity.db", workdir=tmp_path)
    project_id = "prj_no_verifier_basis"
    try:
        engine.create_project("default-policy", project_id=project_id)
        packet = engine.resume_packet(project_id)

        result = engine.continuity_check(project_id)
        receipt = result["continuity_receipt"]
        predicate = next(
            item for item in receipt["blockers"]
            if item["predicate"] == "required_verifiers_current"
        )

        assert result["conclusion"] == "failure"
        assert packet["trust"]["gaps"] == [_POLICY_GAP]
        assert packet["trust"]["gaps"] == result["verifier_gaps"]
        assert result["verifier_gaps"] == [_POLICY_GAP]
        assert receipt["decision_state"]["verifier_gaps"] == [_POLICY_GAP]
        assert predicate["observed"] == [_POLICY_GAP]
        assert predicate["required"] == []
        assert not predicate["satisfied"]
        assert engine.verify_continuity_receipt(
            project_id, receipt)["verdict"] == "CURRENT"
    finally:
        engine.close()


def test_zero_verifiers_can_be_green_only_when_proof_policy_is_disabled(tmp_path):
    engine = Engine(tmp_path / "continuity-disabled.db", workdir=tmp_path)
    project_id = "prj_proof_explicitly_disabled"
    try:
        engine.create_project(
            "proof-disabled", project_id=project_id,
            config={
                "require_proof_for": [],
                "required_verifiers": [],
                "min_evidence_grade": None,
            },
        )
        packet = engine.resume_packet(project_id)

        result = engine.continuity_check(project_id)
        assert result["conclusion"] == "success"
        assert packet["trust"]["gaps"] == []
        assert _POLICY_GAP not in packet["trust"]["gaps"]
        assert result["verifier_gaps"] == []
    finally:
        engine.close()


def _run_init(root: Path) -> None:
    with contextlib.redirect_stdout(io.StringIO()):
        cli.main(["--dir", str(root), "--json", "init"])


def test_init_rejects_a_symlinked_local_trust_root_before_writing(
        tmp_path, capsys):
    target = tmp_path / "redirect-target"
    target.mkdir()
    cce_dir = tmp_path / ".cce"
    try:
        cce_dir.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(SystemExit) as exc_info:
        _run_init(tmp_path)
    assert exc_info.value.code == 2
    assert "physical directory" in capsys.readouterr().err
    assert list(target.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_init_rejects_a_windows_junction_before_writing(tmp_path, capsys):
    target = tmp_path / "junction-target"
    target.mkdir()
    cce_dir = tmp_path / ".cce"
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(cce_dir), str(target)],
        capture_output=True, text=True, check=False,
    )
    if created.returncode:
        pytest.skip(f"junction creation is unavailable: {created.stderr}")
    try:
        with pytest.raises(SystemExit) as exc_info:
            _run_init(tmp_path)
        assert exc_info.value.code == 2
        assert "physical directory" in capsys.readouterr().err
        assert list(target.iterdir()) == []
    finally:
        os.rmdir(cce_dir)


def test_init_refuses_preseeded_secrets_without_changing_them(tmp_path):
    cce_dir = tmp_path / ".cce"
    secrets_dir = cce_dir / "secrets"
    secrets_dir.mkdir(parents=True)
    attacker_key = secrets_dir / "signing.key"
    attacker_key.write_bytes(b"attacker-controlled")
    before_mode = stat.S_IMODE(cce_dir.stat().st_mode)

    with pytest.raises(SystemExit) as stopped:
        _run_init(tmp_path)

    assert stopped.value.code == 1
    assert attacker_key.read_bytes() == b"attacker-controlled"
    assert stat.S_IMODE(cce_dir.stat().st_mode) == before_mode
    assert not (cce_dir / "cce.db").exists()
    assert not (cce_dir / "meta.json").exists()


def test_failed_init_cleans_only_staging_and_retry_succeeds(tmp_path, monkeypatch):
    def fail_after_database_creation(*args, **kwargs):
        raise RuntimeError("injected init failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(cli.Engine, "create_project", fail_after_database_creation)
        with pytest.raises(RuntimeError, match="injected init failure"):
            _run_init(tmp_path)

    assert not (tmp_path / ".cce").exists()
    assert list(tmp_path.glob(".cce-init-*")) == []

    _run_init(tmp_path)
    assert (tmp_path / ".cce" / "meta.json").is_file()
    assert list(tmp_path.glob(".cce-init-*")) == []


def test_noisy_verifier_output_is_bounded_deterministic_and_persisted(tmp_path):
    (tmp_path / "noisy.py").write_text(
        "import sys\n"
        "sys.stdout.buffer.write(b'A' * (1024 * 1024))\n"
        "sys.stderr.buffer.write(b'B' * (1024 * 1024))\n",
        encoding="utf-8",
    )
    command = f'"{sys.executable}" noisy.py'
    store = Store(tmp_path / "evidence.db")
    try:
        runner = VerifierRunner(store, tmp_path)
        first = runner.run(VerifierSpec(
            name="noisy", command=command, pinned=True, timeout_seconds=10))
        second = runner.run(VerifierSpec(
            name="noisy", command=command, pinned=True, timeout_seconds=10))

        assert first.result == second.result == "passed"
        assert first.output == second.output
        assert first.output_digest == second.output_digest
        assert first.output is not None
        assert len(first.output) == _MAX_OUTPUT
        assert first.output.endswith(_TRUNCATION_MARKER)
        assert first.output_digest == sha256_hex(first.output)
        assert store.get_evidence(first.evidence_digest) == first.output
    finally:
        store.close()


def test_timeout_kills_the_verifier_descendant_tree(tmp_path):
    marker = tmp_path / "descendant-survived.txt"
    (tmp_path / "timeout_child.py").write_text(
        "import pathlib, sys, time\n"
        "time.sleep(2)\n"
        "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (tmp_path / "timeout_parent.py").write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, 'timeout_child.py', sys.argv[1]])\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    command = (
        f'"{sys.executable}" timeout_parent.py "{marker.as_posix()}"')

    outcome = VerifierRunner(None, tmp_path).run(VerifierSpec(
        name="timeout-tree", command=command, pinned=True, timeout_seconds=1))

    assert outcome.result == "inconclusive"
    assert "timeout after 1s" in outcome.details
    time.sleep(2.5)
    assert not marker.exists()
