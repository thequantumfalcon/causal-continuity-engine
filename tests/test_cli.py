"""Operator-facing CLI contracts for policy and continuity receipts."""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import causal_continuity_engine.cli as cli_module
from causal_continuity_engine.cli import cmd_check, main
from causal_continuity_engine.policy import PolicyEngine
from causal_continuity_engine.store import Store


def _init(tmp_path: Path, capsys) -> str:
    main(["--dir", str(tmp_path), "--json", "init"])
    return json.loads(capsys.readouterr().out)["project_id"]


def _configure(tmp_path: Path, capsys, project_id: str, config: dict):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(config), encoding="utf-8")
    main([
        "--dir", str(tmp_path), "--json", "policy", "configure",
        "--project", project_id, "--file", str(policy_file),
    ])
    return json.loads(capsys.readouterr().out)


def _snapshot_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def test_policy_engine_rejects_unknown_and_malformed_control_state():
    store = Store(":memory:")
    policy = PolicyEngine(store)
    try:
        policy.set_project_config("prj_operator", {})
        before = policy.project_config("prj_operator")
        with pytest.raises(ValueError, match="unknown project policy"):
            policy.set_project_config(
                "prj_operator", {"run_this_command": "anything"})
        with pytest.raises(ValueError, match="required_verifiers"):
            policy.set_project_config(
                "prj_operator", {"required_verifiers": "unit-tests"})
        assert policy.project_config("prj_operator") == before
    finally:
        store.close()


def test_policy_configure_is_file_only_project_bound_and_validated(tmp_path, capsys):
    project_id = _init(tmp_path, capsys)
    marker = tmp_path / "must-not-run"
    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete"],
        "required_verifiers": [{
            "name": "operator-check",
            "command": shlex.join([
                sys.executable, "-c",
                f"from pathlib import Path; Path({str(marker)!r}).touch()",
            ]),
        }],
        "trusted_verifier_apps": [{
            "app_id": 15368, "slug": "github-actions"}],
    }

    configured = _configure(tmp_path, capsys, project_id, config)

    assert configured["project_id"] == project_id
    persisted = configured["config"]["required_verifiers"][0]
    assert persisted["name"] == "operator-check"
    assert persisted["kind"] == "command"
    assert persisted["command"] == config["required_verifiers"][0]["command"]
    assert not marker.exists()  # configuration persists text; it never executes it

    bad = tmp_path / "bad-policy.json"
    bad.write_text(
        json.dumps({"trusted_verifier_apps": [""]}), encoding="utf-8")
    with pytest.raises(SystemExit) as invalid:
        main([
            "--dir", str(tmp_path), "policy", "configure",
            "--project", project_id, "--file", str(bad),
        ])
    assert invalid.value.code == 2
    assert "trusted_verifier_apps" in capsys.readouterr().err

    malformed = tmp_path / "malformed-verifier.json"
    malformed.write_text(
        json.dumps({"required_verifiers": "operator-check"}),
        encoding="utf-8")
    with pytest.raises(SystemExit) as malformed_verifier:
        main([
            "--dir", str(tmp_path), "policy", "configure",
            "--project", project_id, "--file", str(malformed),
        ])
    assert malformed_verifier.value.code == 2
    assert "required_verifiers" in capsys.readouterr().err

    unknown = tmp_path / "unknown-policy.json"
    unknown.write_text(json.dumps({"run_this_command": "anything"}),
                       encoding="utf-8")
    with pytest.raises(SystemExit) as unknown_field:
        main([
            "--dir", str(tmp_path), "policy", "configure",
            "--project", project_id, "--file", str(unknown),
        ])
    assert unknown_field.value.code == 2
    assert "unknown project policy" in capsys.readouterr().err

    duplicate = tmp_path / "duplicate-policy.json"
    duplicate.write_text(
        '{"max_autonomy_level":1,"max_autonomy_level":2}',
        encoding="utf-8")
    with pytest.raises(SystemExit) as duplicate_field:
        main([
            "--dir", str(tmp_path), "policy", "configure",
            "--project", project_id, "--file", str(duplicate),
        ])
    assert duplicate_field.value.code == 2
    assert "duplicate JSON object key" in capsys.readouterr().err

    with pytest.raises(SystemExit) as cross_project:
        main([
            "--dir", str(tmp_path), "policy", "configure",
            "--project", "prj_elsewhere", "--file",
            str(tmp_path / "policy.json"),
        ])
    assert cross_project.value.code == 2
    assert "local CCE project" in capsys.readouterr().err


def test_policy_cli_rejects_excessive_json_nesting_cleanly(tmp_path, capsys):
    project_id = _init(tmp_path, capsys)
    policy_file = tmp_path / "deep-policy.json"
    policy_file.write_text(
        "[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")

    with pytest.raises(SystemExit) as rejected:
        main([
            "--dir", str(tmp_path), "policy", "configure",
            "--project", project_id, "--file", str(policy_file),
        ])
    assert rejected.value.code == 2
    error = capsys.readouterr().err
    assert "JSON nesting exceeds supported depth" in error
    assert "Traceback" not in error


def test_receipt_export_and_three_way_verification_exit_codes(tmp_path, capsys):
    project_id = _init(tmp_path, capsys)
    _configure(tmp_path, capsys, project_id, {
        "max_autonomy_level": 2,
        "require_proof_for": [],
        "required_verifiers": [],
        "min_evidence_grade": None,
    })
    main([
        "--dir", str(tmp_path), "--json", "resume", "--format", "json",
    ])
    capsys.readouterr()

    receipt_file = tmp_path / "continuity-receipt.json"
    main([
        "--dir", str(tmp_path), "--json", "check",
        "--export-receipt", str(receipt_file),
    ])
    exported = json.loads(capsys.readouterr().out)
    receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    assert receipt == exported["continuity_receipt"]

    main([
        "--dir", str(tmp_path), "--json", "check",
        "--verify-receipt", str(receipt_file),
    ])
    assert json.loads(capsys.readouterr().out)["verdict"] == "CURRENT"

    _configure(tmp_path, capsys, project_id, {
        "max_autonomy_level": 1,
        "require_proof_for": [],
        "required_verifiers": [],
        "min_evidence_grade": None,
    })
    with pytest.raises(SystemExit) as historical:
        main([
            "--dir", str(tmp_path), "--json", "check",
            "--verify-receipt", str(receipt_file),
        ])
    assert historical.value.code == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == \
        "AUTHENTIC_HISTORICAL"

    receipt["decision"] = "failure"
    forged_file = tmp_path / "forged-receipt.json"
    forged_file.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(SystemExit) as invalid:
        main([
            "--dir", str(tmp_path), "--json", "check",
            "--verify-receipt", str(forged_file),
        ])
    assert invalid.value.code == 4
    assert json.loads(capsys.readouterr().out)["verdict"] == "INVALID"


@pytest.mark.parametrize(
    ("conclusion", "expected_exit"),
    [
        ("success", None),
        ("failure", 1),
        ("action_required", 1),
        ("cancelled", 1),
        ("neutral", 1),
    ],
)
def test_check_exits_zero_only_for_literal_success(
        monkeypatch, capsys, conclusion, expected_exit):
    class StubEngine:
        closed = False

        def continuity_check(self, project_id):
            assert project_id == "prj_cli_exit"
            return {
                "conclusion": conclusion,
                "open_invalidations": [],
            }

        def close(self):
            self.closed = True

    engine = StubEngine()
    monkeypatch.setattr(
        "causal_continuity_engine.cli._engine",
        lambda args: (engine, {"project_id": "prj_cli_exit"}),
    )
    args = SimpleNamespace(
        verify_receipt=None, export_receipt=None, json=True)

    if expected_exit is None:
        cmd_check(args)
    else:
        with pytest.raises(SystemExit) as stopped:
            cmd_check(args)
        assert stopped.value.code == expected_exit

    assert engine.closed
    assert json.loads(capsys.readouterr().out)["conclusion"] == conclusion


def test_documented_bound_repository_quickstart_reaches_success(
        tmp_path, capsys):
    main([
        "--dir", str(tmp_path), "--json", "init",
        "--repo", "octo/demo", "--repo-id", "123456789",
    ])
    project_id = json.loads(capsys.readouterr().out)["project_id"]

    issue_file = tmp_path / "issue.json"
    issue_file.write_text(json.dumps({
        "action": "opened",
        "repository": {"id": 123456789, "full_name": "octo/demo"},
        "issue": {
            "number": 42,
            "state": "open",
            "author_association": "OWNER",
            "created_at": "2026-07-31T10:00:00Z",
            "updated_at": "2026-07-31T10:00:00Z",
            "title": "Exporter must stream rows instead of buffering",
            "body": (
                "We assume the upstream feed is ordered by timestamp. "
                "The exporter must not hold the whole result set in memory."
            ),
        },
    }), encoding="utf-8")
    main([
        "--dir", str(tmp_path), "--json", "ingest",
        "--event", "issues", "--delivery-id", "d1",
        "--file", str(issue_file),
    ])
    capsys.readouterr()

    push_file = tmp_path / "push.json"
    push_file.write_text(json.dumps({
        "ref": "refs/heads/main",
        "before": "0" * 40,
        "after": "1" * 40,
        "created": True,
        "deleted": False,
        "forced": False,
        "commits": [],
        "repository": {"id": 123456789, "full_name": "octo/demo"},
    }), encoding="utf-8")
    main([
        "--dir", str(tmp_path), "--json", "ingest",
        "--event", "push", "--delivery-id", "d2",
        "--file", str(push_file),
    ])
    push_report = json.loads(capsys.readouterr().out)
    assert push_report["created"] == []
    assert push_report["invalidations"] == []
    assert push_report["conflicts"] == []

    main([
        "--dir", str(tmp_path), "--json", "resume",
        "--token-budget", "1500", "--format", "json",
    ])
    initial_packet = json.loads(capsys.readouterr().out)
    assert initial_packet["trust"]["gaps"] == [
        "policy:proof-required-without-required-verifiers"]
    assert 0 < initial_packet["token_estimate"] <= 1500

    main([
        "--dir", str(tmp_path), "--json", "policy", "grant",
        "--level", "2", "--by", "operator", "--reason", "quickstart",
    ])
    capsys.readouterr()

    config = {
        "max_autonomy_level": 2,
        "require_proof_for": ["task_complete", "pr_ready"],
        "required_verifiers": [{
            "name": "json-check",
            "command": shlex.join([
                sys.executable, "-c",
                "import json;json.load(open('issue.json',encoding='utf-8'))",
            ]),
            "expect_fail_command": shlex.join([
                sys.executable, "-c", "import json;json.loads('{')",
            ]),
            "artifacts": ["issue.json"],
        }],
        "min_evidence_grade": "C",
    }
    _configure(tmp_path, capsys, project_id, config)

    main(["--dir", str(tmp_path), "--json", "verify"])
    proof = json.loads(capsys.readouterr().out)
    assert proof["status"] == "verified"

    # Policy, grant, and verification records all stale the earlier packet.
    # The documented second resume is therefore a required gate step.
    main([
        "--dir", str(tmp_path), "--json", "resume",
        "--token-budget", "1500", "--format", "json",
    ])
    current_packet = json.loads(capsys.readouterr().out)
    assert current_packet["trust"]["required_verifiers"] == ["json-check"]
    assert current_packet["trust"]["gaps"] == []

    main(["--dir", str(tmp_path), "--json", "check"])
    check = json.loads(capsys.readouterr().out)
    assert check["conclusion"] == "success"


def test_removed_verifier_selector_is_usage_error_without_state_change(
        tmp_path, capsys):
    _init(tmp_path, capsys)
    before = _snapshot_files(tmp_path / ".cce")

    with pytest.raises(SystemExit) as stopped:
        main([
            "--dir", str(tmp_path), "verify",
            "--verifier", "formerly-selectable",
        ])

    assert stopped.value.code == 2
    captured = capsys.readouterr()
    assert "unrecognized arguments: --verifier" in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""
    assert _snapshot_files(tmp_path / ".cce") == before


def test_invalid_metadata_is_rejected_before_legacy_migration_writes(
        tmp_path, capsys):
    _init(tmp_path, capsys)
    cce = tmp_path / ".cce"
    meta_path = cce / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    key = (cce / meta["signing_key_file"]).read_bytes()
    meta["tenant_id"] = "../outside"
    meta["signing_key_hex"] = key.hex()
    meta.pop("signing_key_file")
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    before = _snapshot_files(cce)

    with pytest.raises(SystemExit) as stopped:
        main(["--dir", str(tmp_path), "assumptions"])

    assert stopped.value.code == 2
    assert "invalid CCE metadata" in capsys.readouterr().err
    assert _snapshot_files(cce) == before


def test_invalid_signing_key_cannot_provision_runtime_secrets_or_rewrite_meta(
        tmp_path, capsys):
    _init(tmp_path, capsys)
    cce = tmp_path / ".cce"
    meta_path = cce / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    key_path = cce / meta["signing_key_file"]
    for field in ("api_token_file", "webhook_secret_file"):
        (cce / meta.pop(field)).unlink()
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    key_path.write_bytes(b"not-32-bytes")
    if os.name != "nt":
        key_path.chmod(0o600)
        meta_path.chmod(0o600)
    before = _snapshot_files(cce)

    with pytest.raises(SystemExit) as stopped:
        main(["--dir", str(tmp_path), "assumptions"])

    assert stopped.value.code == 2
    assert "signing key must be exactly 32 bytes" in capsys.readouterr().err
    assert _snapshot_files(cce) == before


def test_oversized_ingest_is_rejected_before_engine_or_event_mutation(
        tmp_path, capsys, monkeypatch):
    _init(tmp_path, capsys)
    payload = tmp_path / "oversized.json"
    payload.write_bytes(b"{" + b" " * 64 + b"}")
    monkeypatch.setattr(cli_module, "_MAX_INGEST_BYTES", 32)
    before = _snapshot_files(tmp_path / ".cce")

    with pytest.raises(SystemExit) as stopped:
        main([
            "--dir", str(tmp_path), "ingest", "--event", "push",
            "--delivery-id", "bounded-1", "--file", str(payload),
        ])

    assert stopped.value.code == 2
    error = capsys.readouterr().err
    assert "32-byte limit" in error
    assert "Traceback" not in error
    assert _snapshot_files(tmp_path / ".cce") == before


@pytest.mark.parametrize(
    ("limit_name", "command", "expected_exit"),
    [
        ("_MAX_POLICY_BYTES", [
            "policy", "configure", "--project", "{project}", "--file", "{file}",
        ], 2),
        ("_MAX_RECEIPT_BYTES", [
            "check", "--verify-receipt", "{file}",
        ], 4),
        ("_MAX_ANCHOR_BYTES", [
            "audit", "check-anchor", "--anchor", "{file}",
        ], 2),
    ],
)
def test_oversized_external_documents_fail_before_store_open_or_write(
        tmp_path, capsys, monkeypatch, limit_name, command, expected_exit):
    project_id = _init(tmp_path, capsys)
    external = tmp_path / "oversized-input.json"
    external.write_bytes(b"{" + b" " * 64 + b"}")
    monkeypatch.setattr(cli_module, limit_name, 16)
    arguments = [
        value.format(project=project_id, file=str(external))
        for value in command
    ]
    before = _snapshot_files(tmp_path / ".cce")

    with pytest.raises(SystemExit) as stopped:
        main(["--dir", str(tmp_path), *arguments])

    assert stopped.value.code == expected_exit
    assert _snapshot_files(tmp_path / ".cce") == before


def test_read_only_cli_open_does_not_rewrite_current_store(tmp_path, capsys):
    _init(tmp_path, capsys)
    before = _snapshot_files(tmp_path / ".cce")

    main(["--dir", str(tmp_path), "assumptions"])

    capsys.readouterr()
    assert _snapshot_files(tmp_path / ".cce") == before


@pytest.mark.parametrize(
    "arguments",
    [
        ["migrate", "validate"],
        ["audit", "check-anchor"],
        ["policy", "grant"],
        ["policy", "revoke"],
        ["policy", "grant", "--level", "4"],
        ["resume", "--token-budget", "0"],
        ["resume", "--token-budget", "100001"],
    ],
)
def test_conditional_and_bounded_arguments_fail_at_usage_boundary(
        tmp_path, capsys, arguments):
    before = _snapshot_files(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        main(["--dir", str(tmp_path), *arguments])
    assert stopped.value.code == 2
    assert "Traceback" not in capsys.readouterr().err
    assert _snapshot_files(tmp_path) == before


def test_installation_binding_requires_repository_id_before_init(
        tmp_path, capsys):
    with pytest.raises(SystemExit) as stopped:
        main([
            "--dir", str(tmp_path), "init",
            "--repo", "octo/demo", "--github-installation-id", "42",
        ])
    assert stopped.value.code == 2
    assert not (tmp_path / ".cce").exists()
    assert "requires --repo-id" in capsys.readouterr().err


@pytest.mark.parametrize(
    "option", ["--repo-id", "--github-installation-id"])
def test_github_numeric_ids_above_signed_64_bit_never_initialize(
        tmp_path, capsys, option):
    arguments = ["--dir", str(tmp_path), "init", option, str(2**63)]
    if option == "--github-installation-id":
        arguments.extend(["--repo-id", "1"])
    with pytest.raises(SystemExit) as stopped:
        main(arguments)
    assert stopped.value.code == 2
    assert "signed 64-bit" in capsys.readouterr().err
    assert not (tmp_path / ".cce").exists()


@pytest.mark.parametrize(
    "relative",
    ["meta.json", "cce.db", "secrets/signing.key"],
)
def test_public_json_outputs_cannot_replace_internal_trust_state(
        tmp_path, capsys, relative):
    _init(tmp_path, capsys)
    cce = tmp_path / ".cce"
    before = _snapshot_files(cce)
    target = cce.joinpath(*relative.split("/"))

    with pytest.raises(SystemExit) as stopped:
        main([
            "--dir", str(tmp_path), "check",
            "--export-receipt", str(target),
        ])

    assert stopped.value.code == 2
    assert "trust directory" in capsys.readouterr().err
    assert _snapshot_files(cce) == before


@pytest.mark.parametrize(
    "bad_value",
    [float("nan"), "\ud800", {1: "integer-key"}],
    ids=["non-finite", "surrogate", "non-string-key"],
)
def test_strict_json_output_is_all_or_nothing_and_closes_engine(
        tmp_path, capsys, monkeypatch, bad_value):
    class StubGraph:
        @staticmethod
        def current(*args, **kwargs):
            return [{
                "node_id": "asm_bad", "status": "active",
                "criticality": "high", "confidence": bad_value,
                "data": {"statement": "bad number"},
            }]

    class StubEngine:
        tenant_id = "ten_stub"
        graph = StubGraph()
        closed = False

        def close(self):
            self.closed = True

    engine = StubEngine()

    def open_stub(args):
        args._opened_engines.append(engine)
        return engine, {"project_id": "prj_stub"}

    monkeypatch.setattr(cli_module, "_engine", open_stub)
    with pytest.raises(SystemExit) as stopped:
        main(["--dir", str(tmp_path), "--json", "assumptions"])

    assert stopped.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "non-canonical JSON" in captured.err
    assert "Traceback" not in captured.err
    assert engine.closed


def test_human_resume_visibly_escapes_issue_body_terminal_controls(
        tmp_path, capsys):
    main([
        "--dir", str(tmp_path), "init", "--repo", "octo/demo",
        "--repo-id", "123",
    ])
    capsys.readouterr()
    issue = tmp_path / "terminal-issue.json"
    dangerous = "The terminal must display ESC\x1b[2J BEL\x07 and bidi\u202e safely"
    issue.write_text(json.dumps({
        "action": "opened",
        "repository": {"id": 123, "full_name": "octo/demo"},
        "issue": {
            "number": 1, "state": "open", "title": "terminal safety",
            "body": dangerous, "author_association": "OWNER",
            "created_at": "2026-08-04T12:00:00Z",
        },
    }), encoding="utf-8")
    main([
        "--dir", str(tmp_path), "ingest", "--event", "issues",
        "--delivery-id", "terminal-1", "--file", str(issue),
    ])
    capsys.readouterr()

    main(["--dir", str(tmp_path), "resume"])

    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "\x07" not in output
    assert "\u202e" not in output
    assert "\\u001b[2J" in output
    assert "\\u0007" in output
    assert "\\u202e" in output


def test_human_sanitizer_preserves_layout_but_escapes_cr_and_surrogate():
    assert cli_module._sanitize_human("a\n\tb\r\ud800") == \
        "a\n\tb\\u000d\\ud800"


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "mkfifo"),
    reason="POSIX FIFO race coverage",
)
def test_bounded_reader_regular_file_to_fifo_swap_is_nonblocking(
        tmp_path, monkeypatch):
    source = tmp_path / "payload.json"
    source.write_text("{}", encoding="utf-8")
    original_open = cli_module.os.open
    swapped = False

    def swap_before_open(path, flags, mode=0o777):
        nonlocal swapped
        if Path(path) == source and not swapped:
            swapped = True
            source.unlink()
            os.mkfifo(source)
        return original_open(path, flags, mode)

    monkeypatch.setattr(cli_module.os, "open", swap_before_open)
    with pytest.raises(ValueError, match="changed before|physical regular"):
        cli_module._read_bounded_file(source, 1024, label="payload")
    assert swapped
