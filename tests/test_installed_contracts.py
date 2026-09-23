"""Deciding contracts shared by source and distribution-owned artifact tests.

These tests preserve local-capability authority, not human authentication, and
prove configured obligation currency rather than verifier semantic adequacy.
"""

import os
import sys
import sysconfig
from pathlib import Path

import pytest

from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.core import digest_obj
from causal_continuity_engine.engine import Engine
from tests import authority_helpers
from tests import test_obligation_completeness as obligations

PROJECT = obligations.PROJECT


def assert_contract_origins(*helper_modules):
    """Bind source tests to their checkout, installed tests to the owned wheel."""
    test_file = Path(__file__).resolve()
    test_root = test_file.parents[1]
    runtime = Path(engine_module.__file__).resolve()
    modules = (authority_helpers, obligations, *helper_modules)
    installed_root = Path(sys.prefix).resolve() / "share/causal-continuity-engine/audit"
    if test_root == installed_root or os.environ.get("CCE_RELEASE_ENVIRONMENT") == "isolated":
        assert os.environ.get("CCE_RELEASE_ENVIRONMENT") == "isolated"
        assert test_root == installed_root
        site_root = Path(sysconfig.get_path("purelib")).resolve()
        assert site_root.is_relative_to(Path(sys.prefix).resolve())
        assert runtime == site_root / "causal_continuity_engine/engine.py"
        for module in modules:
            path = Path(module.__file__).resolve()
            assert path.parent == test_root / "tests"
    else:
        assert runtime == test_root / "causal_continuity_engine/engine.py"
        for module in modules:
            assert Path(module.__file__).resolve().parent == test_root / "tests"


@pytest.fixture(autouse=True)
def contract_origin():
    assert_contract_origins()


@pytest.mark.parametrize("module", [engine_module, authority_helpers], ids=["runtime", "helper"])
def test_origin_guard_rejects_a_foreign_module(tmp_path, monkeypatch, module):
    monkeypatch.setattr(module, "__file__", str(tmp_path / "foreign.py"))
    with pytest.raises(AssertionError):
        assert_contract_origins()


@pytest.fixture
def engine(tmp_path):
    (tmp_path / "deliverable.txt").write_text("archive checksums retained\n", encoding="utf-8")
    config = {
        "max_autonomy_level": 2, "require_proof_for": ["task_complete"],
        "min_evidence_grade": "C", "required_verifiers": [{
            "name": "deliverable-check",
            "command": obligations._python_command(
                "from pathlib import Path; "
                "assert Path('deliverable.txt').read_text() == 'archive checksums retained\\n'"),
            "expect_fail_command": obligations._python_command("raise SystemExit(1)"),
            "artifacts": ["deliverable.txt"],
        }],
    }
    instance = Engine(tmp_path / "contracts.sqlite3", workdir=tmp_path)
    instance.create_project("Installed contracts", project_id=PROJECT,
                            capture_mode="full", config=config)
    instance.policy.grant(project_id=PROJECT, level=2, granted_by="lead")
    instance.policy.set_project_config(PROJECT, config)
    try:
        yield instance
    finally:
        instance.close()


@pytest.mark.parametrize("damage", ["text", "digest", "actor"])
def test_confirmation_refuses_unreviewed_operands_and_revocation_withholds(engine, damage):
    proposal = obligations._propose(engine, *obligations.OBLIGATIONS[0], "review")
    request = {"operation": "confirm", "request_id": "approve-review",
               "tenant_id": engine.tenant_id, "project_id": PROJECT, **proposal}
    invalid = dict(request)
    if damage == "text":
        invalid["text"] = "The exporter must delete archive checksums."
    elif damage == "digest":
        invalid["expected_proposal_digest"] = "sha256:" + "0" * 64
    else:
        invalid["actor"] = "owner-local"
    before = tuple(engine.store._conn.iterdump())
    with pytest.raises(ValueError, match="fields|bind"):
        engine.record_authority_decision(PROJECT, invalid)
    assert tuple(engine.store._conn.iterdump()) == before
    receipt = engine.record_authority_decision(PROJECT, request)
    member = receipt["confirmation_id"]
    assert engine.authority_is_current(engine.graph.get(member))
    assert [item["node_id"] for item in engine.resume_packet(PROJECT)["mandatory_control"]] == [
        member]
    binding = engine.authority_confirmation(PROJECT, member)
    binding.pop("authority_scope")
    engine.record_authority_decision(PROJECT, {
        "operation": "revoke", "request_id": "revoke-review",
        "tenant_id": engine.tenant_id, "project_id": PROJECT, **binding})
    assert not engine.authority_is_current(engine.graph.get(member))
    assert engine.resume_packet(PROJECT)["mandatory_control"] == []


def test_task_proof_covers_unlinked_controls_and_rejects_changed_basis(engine):
    task = authority_helpers.confirmed_task(engine, PROJECT).id
    controls = [obligations._confirm(engine, kind, text, kind)
                for kind, text in obligations.OBLIGATIONS]
    proof = obligations._attest(engine, task)
    basis = engine._obligation_basis(PROJECT, task)
    assert {item["node_id"] for item in basis["obligations"]} == set(controls)
    assert {item["entity_type"] for item in basis["obligations"]} == {
        "requirement", "constraint", "decision", "assumption"}
    commitment, = [item for item in proof["inputs"]
                   if item["name"] == "continuity:obligations:" + task]
    assert commitment["digest"] == digest_obj(basis)
    added = obligations._confirm(
        engine, "requirement", "The indexer must preserve Unicode names.", "added")
    assert not engine.proof_currency(PROJECT, task, proof)["current"]
    before = engine.graph.get(task), obligations._spent(engine)
    with pytest.raises(PermissionError, match="no longer describes"):
        engine.complete_task(PROJECT, task, proof=proof)
    assert (engine.graph.get(task), obligations._spent(engine)) == before
    fresh = obligations._attest(engine, task)
    assert {item["node_id"] for item in engine._obligation_basis(
        PROJECT, task)["obligations"]} == {*controls, added}
    assert engine.complete_task(PROJECT, task, proof=fresh)["status"] == "verified"
    assert engine.graph.get(task)["status"] == "verified"


def test_project_and_task_packet_membership_and_watermarks_are_distinct(engine):
    alpha = authority_helpers.confirmed_task(engine, PROJECT, text="Package the alpha archive").id
    beta = authority_helpers.confirmed_task(engine, PROJECT, text="Package the beta archive").id
    scopes = [{"kind": "global"}, {"kind": "tasks", "task_ids": [alpha]},
              {"kind": "tasks", "task_ids": [beta]},
              {"kind": "tasks", "task_ids": sorted([alpha, beta])}]
    controls = [obligations._confirm(engine, kind, text, kind, scope=scope)
                for (kind, text), scope in zip(obligations.OBLIGATIONS, scopes, strict=True)]
    assert all(engine.packet_is_stale(PROJECT, task_id=target) for target in (None, alpha, beta))
    first = engine.resume_packet(PROJECT, task_id=alpha)
    assert not engine.packet_is_stale(PROJECT, task_id=alpha)
    assert engine.packet_is_stale(PROJECT) and engine.packet_is_stale(PROJECT, task_id=beta)
    second = engine.resume_packet(PROJECT, task_id=beta)
    assert engine.packet_is_stale(PROJECT)
    project = engine.resume_packet(PROJECT, target={"task_id": alpha, "issue_number": 42})
    for packet, target, expected in (
            (first, alpha, {controls[0], controls[1], controls[3]}),
            (second, beta, {controls[0], controls[2], controls[3]}),
            (project, None, set(controls))):
        assert packet["complete"] is True and packet["schema_version"] == "cce.resume.v2"
        assert packet["scope"] == ({"kind": "project"} if target is None
                                   else {"kind": "task", "task_id": target})
        assert {item["node_id"] for item in packet["mandatory_control"]} == expected
        assert packet["authority_set_digest"] == digest_obj(packet["mandatory_control"])
        assert not engine.packet_is_stale(PROJECT, task_id=target)
    rows = engine.store._conn.execute(
        "SELECT scope_key,packet_id FROM packet_watermark WHERE project_id=?",
        (PROJECT,)).fetchall()
    assert dict(rows) == {"project": project["packet_id"],
                          "task:" + alpha: first["packet_id"], "task:" + beta: second["packet_id"]}
