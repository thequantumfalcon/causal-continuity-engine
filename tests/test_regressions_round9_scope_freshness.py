"""Regressions for final scope, freshness, migration, and webhook boundaries."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from causal_continuity_engine.core import Signer
from causal_continuity_engine.engine import Engine

TENANT = "ten_round9"
PROJECT = "prj_round9"
REPOSITORY_ID = 424242
INSTALLATION_ID = 515151


def _command(script: str) -> str:
    return f'"{Path(sys.executable).as_posix()}" -c "{script}"'


def _artifact_config() -> dict:
    return {
        "required_verifiers": [{
            "name": "artifact-check",
            "command": _command("raise SystemExit(0)"),
            "artifacts": ["deliverable.txt"],
        }],
    }


def _github_payload(*, repository_id: int = REPOSITORY_ID,
                    repository: str = "owner/repo",
                    installation_id: int = INSTALLATION_ID) -> dict:
    return {
        "action": "opened",
        "repository": {"id": repository_id, "full_name": repository},
        "installation": {"id": installation_id},
        "issue": {
            "number": 1,
            "title": "Bound delivery",
            "body": "This issue belongs to the configured repository.",
            "author_association": "OWNER",
            "state": "open",
            "labels": [],
            "created_at": "2026-08-04T12:00:00Z",
            "updated_at": "2026-08-04T12:00:00Z",
        },
    }


def test_packet_stales_when_declared_artifact_bytes_change(tmp_path):
    artifact = tmp_path / "deliverable.txt"
    artifact.write_text("first", encoding="utf-8")
    engine = Engine(tmp_path / "cce.db", tenant_id=TENANT,
                    signer=Signer.generate("packet-freshness"), workdir=tmp_path)
    engine.create_project("packet", project_id=PROJECT,
                          config=_artifact_config())

    packet = engine.resume_packet(PROJECT)
    assert packet["project_state_basis"]["control_basis_digest"]
    assert not engine.packet_is_stale(PROJECT)

    artifact.write_text("second", encoding="utf-8")
    assert engine.packet_is_stale(PROJECT), \
        "a packet must commit to the current bytes its verifier declares"
    engine.close()


def test_resume_paths_reject_a_foreign_tenant_project(tmp_path):
    database = tmp_path / "shared.db"
    owner = Engine(database, tenant_id="ten_owner")
    owner.create_project("owner", project_id=PROJECT)
    owner.close()

    foreign = Engine(database, tenant_id="ten_foreign")
    with pytest.raises(PermissionError, match="tenant|project|scope"):
        foreign.resume_packet(PROJECT)
    with pytest.raises(PermissionError, match="tenant|project|scope"):
        foreign.packet_is_stale(PROJECT)
    with pytest.raises(PermissionError, match="tenant|project|scope"):
        foreign.composer.compose(tenant_id="ten_foreign", project_id=PROJECT)
    foreign.close()


def test_resume_composer_excludes_same_project_id_nodes_from_other_tenant(tmp_path):
    engine = Engine(tmp_path / "cce.db", tenant_id=TENANT)
    engine.create_project("scoped", project_id=PROJECT)
    engine.graph.put_node(
        entity_type="constraint", tenant_id="ten_intruder", project_id=PROJECT,
        status="active", data={"statement": "foreign tenant control"})

    packet = engine.resume_packet(PROJECT)
    summaries = {
        item["summary"] for item in packet["authority"]["active_constraints"]}
    assert "foreign tenant control" not in summaries
    engine.close()


def test_capsule_import_challenges_invalidations_created_after_export(tmp_path):
    engine = Engine(tmp_path / "cce.db", tenant_id=TENANT)
    # This test plants post-export invalidation drift, not proof-policy drift.
    # Begin from an explicitly proof-free migration baseline.
    engine.create_project(
        "capsule", project_id=PROJECT,
        config={"require_proof_for": []})
    engine.graph.put_node(
        entity_type="artifact", tenant_id=TENANT, project_id=PROJECT,
        status="recorded", data={"kind": "environment", "python": "3.13"})
    capsule = engine.capsules.export(
        tenant_id=TENANT, project_id=PROJECT, session_id=None,
        source_model="source", source_runtime="runtime",
        target_adapter="target", signer=engine.signer)
    assert engine.capsules.challenge(capsule)["passed"]

    invalidation = engine.graph.put_node(
        entity_type="invalidation", tenant_id=TENANT, project_id=PROJECT,
        status="open", data={
            "trigger_type": "dependency_drift",
            "severity": "high",
            "target_node_id": PROJECT,
        })
    result = engine.capsules.import_capsule(
        capsule, signer=engine.signer, target_model="target",
        target_runtime="runtime", expected_tenant_id=TENANT,
        expected_project_id=PROJECT)

    assert not result["challenge"]["passed"]
    assert invalidation.id in {
        item["node_id"] for item in result["challenge"]["conflicts"]}
    assert result["challenge"]["enforced_ceiling"] == 1
    engine.close()


def test_github_ingestion_requires_an_immutable_repository_binding(tmp_path):
    engine = Engine(tmp_path / "cce.db", tenant_id=TENANT)
    engine.create_project("unbound", project_id=PROJECT,
                          repository="owner/repo")

    with pytest.raises(PermissionError, match="repository.*id|bound"):
        engine.ingest_github(
            PROJECT, "issues", "unbound-delivery", _github_payload())
    assert engine.store.events(PROJECT) == []
    engine.close()


def test_github_ingestion_rejects_same_name_with_another_numeric_id(tmp_path):
    engine = Engine(tmp_path / "cce.db", tenant_id=TENANT)
    engine.create_project(
        "bound", project_id=PROJECT, repository="owner/repo",
        repository_id=REPOSITORY_ID)

    with pytest.raises(PermissionError, match="repository.*id|match"):
        engine.ingest_github(
            PROJECT, "issues", "wrong-id",
            _github_payload(repository_id=REPOSITORY_ID + 1))
    assert engine.store.events(PROJECT) == []
    engine.close()


def test_github_binding_survives_repository_rename_and_pins_installation(tmp_path):
    engine = Engine(tmp_path / "cce.db", tenant_id=TENANT)
    project = engine.create_project(
        "bound", project_id=PROJECT, repository="owner/old-name",
        repository_id=REPOSITORY_ID,
        github_installation_id=INSTALLATION_ID)
    assert project["data"]["repository_id"] == REPOSITORY_ID
    assert project["data"]["github_installation_id"] == INSTALLATION_ID

    assert engine.ingest_github(
        PROJECT, "issues", "renamed",
        _github_payload(repository="owner/new-name")) is not None
    with pytest.raises(PermissionError, match="installation"):
        engine.ingest_github(
            PROJECT, "issues", "wrong-installation",
            _github_payload(installation_id=INSTALLATION_ID + 1))
    assert len(engine.store.events(PROJECT)) == 1
    engine.close()
