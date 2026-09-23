"""Owner-local authority requests use the existing physical trust boundary."""

from __future__ import annotations

import json
import os
import sqlite3
from types import SimpleNamespace

import pytest

import causal_continuity_engine.cli as cli


def _init(tmp_path, capsys):
    cli.main(["--dir", str(tmp_path), "--json", "init"])
    return json.loads(capsys.readouterr().out)["project_id"]


def _request_file(tmp_path, request):
    path = tmp_path / "authority.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    return path


def _invoke(tmp_path, path):
    cli.main([
        "--dir", str(tmp_path), "authority", "--request", str(path),
    ])


def _assert_refused(tmp_path, path, capsys):
    with pytest.raises(SystemExit) as refused:
        _invoke(tmp_path, path)
    assert refused.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "error: invalid authority request\n"


@pytest.mark.parametrize("raw", [
    b'{"private-secret":1,"private-secret":2}',
    b'{"note":NaN}',
    b'{"note":Infinity}',
    b'{"note":1e999}',
    b'{"note":"\\ud800"}',
    b'\xef\xbb\xbf{}',
    b'\xff',
    b'{"private-secret":',
    b'[]',
    b'null',
    b'false',
    b'"private-secret"',
    b'[' * 2_000 + b'0' + b']' * 2_000,
])
def test_authority_rejects_malformed_json_before_open(
        tmp_path, capsys, monkeypatch, raw):
    path = tmp_path / "private-secret.json"
    path.write_bytes(raw)

    def unexpected_open(*args, **kwargs):
        pytest.fail("malformed input must not open project state")

    monkeypatch.setattr(cli, "_engine", unexpected_open)
    _assert_refused(tmp_path, path, capsys)


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "oversized"])
def test_authority_requires_bounded_physical_file_before_open(
        tmp_path, capsys, monkeypatch, kind):
    path = tmp_path / "private-secret.json"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = _request_file(tmp_path, {})
        try:
            path.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
    elif kind == "oversized":
        path.write_bytes(b" " * 65_537)

    def unexpected_open(*args, **kwargs):
        pytest.fail("unsafe input must not open project state")

    monkeypatch.setattr(cli, "_engine", unexpected_open)
    _assert_refused(tmp_path, path, capsys)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
def test_authority_refuses_fifo_without_blocking(tmp_path, capsys, monkeypatch):
    path = tmp_path / "private-secret.fifo"
    os.mkfifo(path)

    def unexpected_open(*args, **kwargs):
        pytest.fail("special input must not open project state")

    monkeypatch.setattr(cli, "_engine", unexpected_open)
    _assert_refused(tmp_path, path, capsys)


@pytest.mark.parametrize("size", [65_535, 65_536])
def test_authority_file_limit_includes_exact_boundary(
        tmp_path, capsys, monkeypatch, size):
    project_id = _init(tmp_path, capsys)
    path = tmp_path / "authority.json"
    path.write_bytes(b"{}" + b" " * (size - 2))
    opened = []

    def reject_request(engine, bound_project, request):
        opened.append(engine)
        assert bound_project == project_id
        assert request == {}
        raise ValueError("private-secret")

    monkeypatch.setattr(
        cli.Engine, "record_authority_decision", reject_request, raising=False)
    _assert_refused(tmp_path, path, capsys)
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].store._conn.execute("SELECT 1")


@pytest.mark.parametrize("error", [ValueError, PermissionError])
def test_authority_binds_metadata_scope_and_redacts_rejection(
        tmp_path, capsys, monkeypatch, error):
    project_id = _init(tmp_path, capsys)
    request = {"project_id": "prj_foreign", "text": "private-secret"}
    path = _request_file(tmp_path, request)
    calls = []

    def reject_request(engine, bound_project, supplied):
        calls.append((engine, bound_project, supplied))
        raise error("private-secret")

    monkeypatch.setattr(
        cli.Engine, "record_authority_decision", reject_request, raising=False)
    _assert_refused(tmp_path, path, capsys)
    assert len(calls) == 1
    assert calls[0][1:] == (project_id, request)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        calls[0][0].store._conn.execute("SELECT 1")


def test_authority_direct_adapter_closes_engine_on_rejection(
        tmp_path, capsys, monkeypatch):
    _init(tmp_path, capsys)
    path = _request_file(tmp_path, {})
    opened = []

    def reject_request(engine, project_id, request):
        opened.append(engine)
        raise ValueError("private-secret")

    monkeypatch.setattr(
        cli.Engine, "record_authority_decision", reject_request, raising=False)
    with pytest.raises(SystemExit) as refused:
        cli.cmd_authority(SimpleNamespace(dir=str(tmp_path), request=str(path)))
    assert refused.value.code == 2
    assert capsys.readouterr().err == "error: invalid authority request\n"
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].store._conn.execute("SELECT 1")


@pytest.mark.parametrize("kind", [
    "missing-key", "invalid-key", "linked-key", "linked-state",
])
def test_authority_requires_existing_physical_signing_material(
        tmp_path, capsys, monkeypatch, kind):
    _init(tmp_path, capsys)
    path = _request_file(tmp_path, {})
    control = tmp_path / ".cce"
    key = control / "secrets" / "signing.key"
    if kind == "missing-key":
        key.rename(key.with_name("preserved-signing.key"))
    elif kind == "invalid-key":
        key.write_bytes(b"not-a-32-byte-signing-key")
    else:
        target = key if kind == "linked-key" else control
        preserved = target.with_name(f"preserved-{target.name}")
        target.rename(preserved)
        try:
            target.symlink_to(preserved, target_is_directory=kind == "linked-state")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")

    def unexpected_record(*args, **kwargs):
        pytest.fail("invalid trust material must not reach authority production")

    monkeypatch.setattr(
        cli.Engine, "record_authority_decision", unexpected_record, raising=False)
    with pytest.raises(SystemExit) as refused:
        _invoke(tmp_path, path)
    assert refused.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "error:" in output.err


@pytest.mark.skipif(os.name == "nt", reason="POSIX private-file boundary")
@pytest.mark.parametrize("kind", ["mode", "owner"])
def test_authority_requires_private_owner_signing_key(
        tmp_path, capsys, monkeypatch, kind):
    _init(tmp_path, capsys)
    path = _request_file(tmp_path, {})
    key = tmp_path / ".cce" / "secrets" / "signing.key"
    if kind == "mode":
        key.chmod(0o644)
    else:
        owner = os.geteuid()
        monkeypatch.setattr(cli.os, "geteuid", lambda: owner + 1)

    def unexpected_record(*args, **kwargs):
        pytest.fail("foreign or public key must not reach authority production")

    monkeypatch.setattr(
        cli.Engine, "record_authority_decision", unexpected_record, raising=False)
    with pytest.raises(SystemExit) as refused:
        _invoke(tmp_path, path)
    assert refused.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert ("mode 0600" if kind == "mode" else "current user") in output.err


def test_authority_checks_compatibility_before_reading_signing_key(
        tmp_path, capsys, monkeypatch):
    _init(tmp_path, capsys)
    path = _request_file(tmp_path, {})

    def refused_projection(database_path):
        raise ValueError("preserved incompatible projection")

    def unexpected_key_read(*args, **kwargs):
        pytest.fail("compatibility refusal must precede signing key reads")

    monkeypatch.setattr(
        cli, "_assert_processor_projection_compatible_path", refused_projection)
    monkeypatch.setattr(cli, "_read_private", unexpected_key_read)
    with pytest.raises(SystemExit) as refused:
        _invoke(tmp_path, path)
    assert refused.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "preserved incompatible projection" in output.err


def test_authority_request_is_not_a_stdin_surface(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _assert_refused(tmp_path, "-", capsys)


def _proposal_request(tmp_path, project_id, kind, text, request_id):
    engine, meta = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        engine.ingest_human_decision(
            project_id, actor="operator", decision=text,
            request_id=f"source-{request_id}")
        proposals = [
            node for node in engine.graph.current(
                project_id, "claim", tenant_id=meta["tenant_id"])
            if node["data"].get("proposed_kind") == kind
        ]
        assert len(proposals) == 1
        proposal = engine.authority_proposal(project_id, proposals[0]["node_id"])
        return {
            "operation": "confirm", "request_id": request_id,
            "tenant_id": meta["tenant_id"], "project_id": project_id,
            **proposal,
        }
    finally:
        engine.close()


@pytest.mark.parametrize(("kind", "text"), [
    ("requirement", "The exporter must retain exact row order."),
    ("constraint", "The exporter must never expose stored credentials."),
    ("decision", "We decided to retain the output schema."),
    ("assumption", "We assume the work tree is stable."),
    ("task", "- [ ] Retain exact row order."),
])
def test_authority_cli_records_real_proposal_and_retry(tmp_path, capsys, kind, text):
    project_id = _init(tmp_path, capsys)
    request = _proposal_request(tmp_path, project_id, kind, text, "approval-one")
    path = _request_file(tmp_path, request)

    _invoke(tmp_path, path)

    output = capsys.readouterr()
    assert output.err == ""
    receipt = json.loads(output.out)
    assert set(receipt) == {
        "operation", "event_id", "confirmation_id", "recorded_at", "request_digest",
    }
    assert receipt["operation"] == "confirm"
    assert text not in output.out
    engine, _ = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        confirmed = engine.graph.get(
            receipt["confirmation_id"], tenant_id=engine.tenant_id,
            project_id=project_id, entity_type=kind)
        assert confirmed["data"]["statement"] == request["text"]
        assert engine.authority_confirmation(project_id, receipt["confirmation_id"])
        before = list(engine.store._conn.iterdump())
    finally:
        engine.close()

    _invoke(tmp_path, path)

    assert json.loads(capsys.readouterr().out) == receipt
    engine, _ = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        assert list(engine.store._conn.iterdump()) == before
    finally:
        engine.close()


@pytest.mark.parametrize("mutation", ["project", "tenant", "actor", "unknown"])
def test_authority_cli_real_producer_refuses_scope_and_actor_claims(
        tmp_path, capsys, mutation):
    project_id = _init(tmp_path, capsys)
    request = _proposal_request(
        tmp_path, project_id, "requirement",
        "The exporter must retain exact row order.", "approval-one")
    if mutation in {"project", "tenant"}:
        request[f"{mutation}_id"] = "foreign"
    elif mutation == "actor":
        request["actor"] = "owner-local"
    else:
        request["private-secret"] = "private-secret"
    path = _request_file(tmp_path, request)
    engine, _ = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        before = list(engine.store._conn.iterdump())
    finally:
        engine.close()

    _assert_refused(tmp_path, path, capsys)

    engine, _ = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        assert list(engine.store._conn.iterdump()) == before
    finally:
        engine.close()


def test_authority_cli_records_scope_replacement_and_revocation(tmp_path, capsys):
    project_id = _init(tmp_path, capsys)
    task_request = _proposal_request(
        tmp_path, project_id, "task", "- [ ] Retain exact row order.", "approve-task")
    _invoke(tmp_path, _request_file(tmp_path, task_request))
    task = json.loads(capsys.readouterr().out)
    request = _proposal_request(
        tmp_path, project_id, "requirement",
        "The exporter must retain exact row order.", "approve-requirement")
    _invoke(tmp_path, _request_file(tmp_path, request))
    receipt = json.loads(capsys.readouterr().out)
    scope = {"kind": "tasks", "task_ids": [task["confirmation_id"]]}

    for operation in ("replace_scope", "revoke"):
        engine, meta = cli._engine(SimpleNamespace(dir=str(tmp_path)))
        try:
            confirmation = engine.authority_confirmation(
                project_id, receipt["confirmation_id"])
            if operation == "revoke":
                assert confirmation["authority_scope"] == scope
        finally:
            engine.close()
        request = {
            "operation": operation, "request_id": operation,
            "tenant_id": meta["tenant_id"], "project_id": project_id,
            "confirmation_id": receipt["confirmation_id"],
            "expected_confirmation_version": confirmation["expected_confirmation_version"],
            "expected_confirmation_digest": confirmation["expected_confirmation_digest"],
        }
        if operation == "replace_scope":
            request["authority_scope"] = scope

        _invoke(tmp_path, _request_file(tmp_path, request))

        output = capsys.readouterr()
        assert output.err == ""
        next_receipt = json.loads(output.out)
        assert next_receipt["operation"] == operation
        assert next_receipt["confirmation_id"] == receipt["confirmation_id"]
        assert next_receipt["event_id"] != receipt["event_id"]
        receipt = next_receipt


def test_authority_cli_rejects_float_version_before_normalization(tmp_path, capsys):
    project_id = _init(tmp_path, capsys)
    request = _proposal_request(
        tmp_path, project_id, "requirement",
        "The exporter must retain exact row order.", "approval-one")
    request["expected_proposal_version"] = float(request["expected_proposal_version"])
    path = _request_file(tmp_path, request)
    before = _authority_snapshot(tmp_path)

    _assert_refused(tmp_path, path, capsys)

    assert _authority_snapshot(tmp_path) == before


def _authority_snapshot(tmp_path):
    engine, _ = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        return tuple(engine.store._conn.iterdump())
    finally:
        engine.close()


def _operation_request(tmp_path, capsys, operation):
    project_id = _init(tmp_path, capsys)
    request = _proposal_request(
        tmp_path, project_id, "requirement",
        "The exporter must retain exact row order.", "approval-one")
    if operation == "confirm":
        return request
    _invoke(tmp_path, _request_file(tmp_path, request))
    receipt = json.loads(capsys.readouterr().out)
    engine, _ = cli._engine(SimpleNamespace(dir=str(tmp_path)))
    try:
        binding = engine.authority_confirmation(project_id, receipt["confirmation_id"])
    finally:
        engine.close()
    request = {key: request[key] for key in ("tenant_id", "project_id")}
    request.update(operation=operation, request_id="next-operation", **binding)
    if operation == "revoke":
        request.pop("authority_scope")
    return request


@pytest.mark.parametrize(("operation", "missing"), [
    (operation, field)
    for operation, fields in (
        ("confirm", ("proposal_id", "expected_proposal_version",
                     "expected_proposal_digest", "proposed_kind", "text")),
        ("revoke", ("confirmation_id", "expected_confirmation_version",
                    "expected_confirmation_digest")),
        ("replace_scope", ("confirmation_id", "expected_confirmation_version",
                           "expected_confirmation_digest", "authority_scope")),
    )
    for field in ("operation", "request_id", "tenant_id", "project_id", *fields)
])
def test_authority_cli_missing_required_field_has_no_effect(
        tmp_path, capsys, operation, missing):
    request = _operation_request(tmp_path, capsys, operation)
    request.pop(missing)
    before = _authority_snapshot(tmp_path)

    _assert_refused(tmp_path, _request_file(tmp_path, request), capsys)

    assert _authority_snapshot(tmp_path) == before


@pytest.mark.parametrize("patch", [
    {"operation": None}, {"operation": []}, {"operation": "approve"},
    {"request_id": "not/an/identifier"}, {"proposal_id": ""},
    {"expected_proposal_version": True}, {"expected_proposal_version": "1"},
    {"expected_proposal_version": 0}, {"expected_proposal_version": None},
    {"expected_proposal_digest": "sha256:" + "A" * 64},
    {"expected_proposal_digest": "sha256:" + "a" * 63},
    {"proposed_kind": []}, {"proposed_kind": "claim"},
    {"text": ""}, {"text": " "}, {"text": "x" * 4097},
    {"text": "private\nsecret"},
    {"note": ""}, {"note": "x" * 1025}, {"note": False}, {"note": {}},
    {"note": "private\u202esecret"},
    {"authority_scope": None}, {"authority_scope": {}},
    {"authority_scope": {"kind": "global", "task_ids": []}},
    {"authority_scope": {"kind": "tasks", "task_ids": "tsk_one"}},
    {"authority_scope": {"kind": "tasks", "task_ids": []}},
    {"authority_scope": {"kind": "tasks", "task_ids": ["tsk_one", "tsk_one"]}},
    {"authority_scope": {"kind": "tasks", "task_ids": [True]}},
    {"authority_scope": {"kind": "tasks", "task_ids": [f"tsk_{i}" for i in range(129)]}},
    {"schema_version": "cce.authority-decision.v1"},
    {"operator_label": "owner-local"}, {"authorization_basis": "local_store_capability"},
    {"recorded_at": "2026-09-22T00:00:00.000000Z"},
    {"confirmation_id": "req_other"},
])
def test_authority_cli_closed_grammar_refuses_without_effect(tmp_path, capsys, patch):
    request = _operation_request(tmp_path, capsys, "confirm")
    request.update(patch)
    before = _authority_snapshot(tmp_path)

    _assert_refused(tmp_path, _request_file(tmp_path, request), capsys)

    assert _authority_snapshot(tmp_path) == before


@pytest.mark.parametrize("operation", ["revoke", "replace_scope"])
@pytest.mark.parametrize("version", [True, 1.0, "1", 0, None])
def test_authority_cli_lifecycle_version_is_exact_integer(
        tmp_path, capsys, operation, version):
    request = _operation_request(tmp_path, capsys, operation)
    request["expected_confirmation_version"] = version
    before = _authority_snapshot(tmp_path)

    _assert_refused(tmp_path, _request_file(tmp_path, request), capsys)

    assert _authority_snapshot(tmp_path) == before


@pytest.mark.parametrize(("operation", "patch"), [
    ("revoke", {"authority_scope": {"kind": "global"}}),
    ("revoke", {"proposal_id": "clm_other"}),
    ("revoke", {"proposed_kind": "requirement"}),
    ("revoke", {"text": "private-secret"}),
    ("replace_scope", {"proposal_id": "clm_other"}),
    ("replace_scope", {"proposed_kind": "requirement"}),
    ("replace_scope", {"text": "private-secret"}),
])
def test_authority_cli_operation_inapplicable_field_refuses(
        tmp_path, capsys, operation, patch):
    request = _operation_request(tmp_path, capsys, operation)
    request.update(patch)
    before = _authority_snapshot(tmp_path)

    _assert_refused(tmp_path, _request_file(tmp_path, request), capsys)

    assert _authority_snapshot(tmp_path) == before


def test_authority_cli_normalized_retry_and_conflicting_identity(tmp_path, capsys):
    request = _operation_request(tmp_path, capsys, "confirm")
    _invoke(tmp_path, _request_file(tmp_path, request))
    receipt = json.loads(capsys.readouterr().out)
    before = _authority_snapshot(tmp_path)
    request.update(note=None, authority_scope={"kind": "global"})

    _invoke(tmp_path, _request_file(tmp_path, request))

    assert json.loads(capsys.readouterr().out) == receipt
    assert _authority_snapshot(tmp_path) == before
    request["note"] = "Different inert context still changes the request identity."

    _assert_refused(tmp_path, _request_file(tmp_path, request), capsys)

    assert _authority_snapshot(tmp_path) == before


def test_authority_cli_note_exact_length_positive(tmp_path, capsys):
    request = _operation_request(tmp_path, capsys, "confirm")
    request["note"] = "x" * 1024

    _invoke(tmp_path, _request_file(tmp_path, request))

    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out)["operation"] == "confirm"
    assert request["note"] not in output.out
