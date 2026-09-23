"""Minimum packet contracts runnable from the distribution-owned audit tree.

Source success is not installed success. The shared origin assertion retains
separate exact source and isolated-wheel layouts without disabling either.
"""

import sys

import pytest

from causal_continuity_engine import core, lamport
from causal_continuity_engine.core import Signer, canonical_json
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.lamport import LamportSigner
from causal_continuity_engine.resume import PacketBudgetExceeded
from tests import authority_helpers
from tests import test_packet_byte_transports as transports
from tests.test_installed_contracts import assert_contract_origins

local = transports.local


@pytest.fixture(autouse=True)
def packet_contract_origin():
    assert_contract_origins(
        sys.modules[__name__], transports, authority_helpers,
        sys.modules[transports.LocalAPI.__module__])


@pytest.mark.parametrize("fmt", ["json", "markdown"])
def test_installed_cli_bytes_and_refusal_preserve_state(local, fmt):
    transports.test_cli_exact_output_and_fixed_refusal_preserve_existing_watermark(local, fmt)


def test_installed_http_body_bytes_refusal_and_recovery(local):
    transports.test_http_body_is_exact_bound_and_budget_error_is_fixed_422(local)


@pytest.mark.parametrize("fmt", ["json", "markdown"])
def test_installed_mcp_frame_bytes_refusal_and_recovery(local, fmt):
    transports.test_mcp_whole_frame_bound_and_recovery_without_writes(
        local, fmt, 'quote-"-slash-\\-café-雪')


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
def test_installed_one_byte_refusal_never_signs_or_changes_state(tmp_path, monkeypatch, scheme):
    signer = (Signer.generate('installed-"\\-é') if scheme == "hmac"
              else LamportSigner('installed-"\\-é'))
    engine = Engine(tmp_path / "crypto.sqlite3", signer=signer, workdir=tmp_path)
    project = "prj_installed_packet_crypto"
    try:
        engine.create_project("Installed packet crypto", project_id=project,
                              capture_mode="full", config={"require_proof_for": []})
        task = authority_helpers.confirmed_task(
            engine, project, text="Package the installed checksum archive")
        module, name = (core.hmac, "new") if scheme == "hmac" else (lamport, "generate_keypair")
        original = getattr(module, name)
        calls = []

        def observe(*args, **kwargs):
            calls.append(True)
            return original(*args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(module, name, observe)
            packet = engine.resume_packet(project, task_id=task["node_id"])
        assert calls == [True]
        assert signer.verify(packet)
        assert len(canonical_json(packet).encode("utf-8")) <= transports.DEFAULT
        assert {node["node_id"] for node in packet["open_work"]["tasks"]} == {task["node_id"]}
        before = tuple(engine.store._conn.iterdump())
        issued = list(getattr(signer, "issued_fingerprints", []))
        registered = set(getattr(signer, "registered_fingerprints", set()))
        calls.clear()
        with monkeypatch.context() as patch:
            patch.setattr(module, name, observe)
            with pytest.raises(PacketBudgetExceeded) as raised:
                engine.resume_packet(project, task_id=task["node_id"], max_response_bytes=1)
        assert str(raised.value) == "Complete packet exceeds max_response_bytes."
        assert calls == []
        assert tuple(engine.store._conn.iterdump()) == before
        assert list(getattr(signer, "issued_fingerprints", [])) == issued
        assert set(getattr(signer, "registered_fingerprints", set())) == registered
        with monkeypatch.context() as patch:
            patch.setattr(module, name, observe)
            recovered = engine.resume_packet(project, task_id=task["node_id"])
        assert calls == [True]
        assert recovered["scope"] == packet["scope"]
        assert signer.verify(recovered)
        if scheme == "lamport":
            fingerprint = recovered["signature"]["fingerprint"]
            assert signer.issued_fingerprints == [*issued, fingerprint]
            assert signer.registered_fingerprints == registered | {fingerprint}
    finally:
        engine.close()
