"""Literal strict-byte contract; old unsupported APIs are capability baselines.

These tests exercise public Engine outputs, not a private size-estimation helper.
Runtime graph extensions are privileged fixture inputs, never prose approval.
"""

import copy
from pathlib import Path

import pytest

from causal_continuity_engine import core, lamport, resume
from causal_continuity_engine import engine as engine_module
from causal_continuity_engine.capsule import CapsuleError, CapsuleManager
from causal_continuity_engine.core import Signer, canonical_json
from causal_continuity_engine.engine import Engine
from causal_continuity_engine.lamport import LamportSigner
from tests.test_packet_scope_wire import _packet, _seal_packet, _validator
from tests.test_task_packets import _confirm, _task

PROJECT = "prj_byte_bounds"
DEFAULT_CAP = 131_072
MAX_CAP = 1_048_576
FORMATS = (
    "engine-json", "engine-markdown", "cli-json", "cli-markdown",
    "http-json", "mcp-json", "mcp-markdown",
)


@pytest.fixture
def make_engine(tmp_path, request):
    assert Path(engine_module.__file__).resolve() == (
        Path.cwd() / "causal_continuity_engine" / "engine.py")

    def make(scheme="hmac", key_id="local"):
        signer = (Signer.generate(key_id) if scheme == "hmac" else LamportSigner(key_id))
        instance = Engine(signer=signer, workdir=tmp_path)
        request.addfinalizer(instance.close)
        instance.create_project(
            "Byte bounds", project_id=PROJECT, capture_mode="full",
            config={"require_proof_for": []})
        task = _task(instance, "bounded", project_id=PROJECT)
        requirement = _confirm(
            instance, "requirement", "The bounded exporter must preserve checksums.",
            "bounded-control", project_id=PROJECT)
        return instance, task, requirement

    return make


def _budget_error():
    # Runtime lookup keeps the old implementation collectible as a baseline.
    error = getattr(resume, "PacketBudgetExceeded", None)
    assert isinstance(error, type) and issubclass(error, Exception)
    return error


def _encoded(packet):
    return canonical_json(packet).encode("utf-8")


def _database(engine):
    return tuple(engine.store._conn.iterdump())


def _signer_state(signer):
    return (list(getattr(signer, "issued_fingerprints", [])),
            set(getattr(signer, "registered_fingerprints", set())))


def _observe_crypto(monkeypatch, scheme, calls, intervention=None):
    module, name = (core.hmac, "new") if scheme == "hmac" else (lamport, "generate_keypair")
    original = getattr(module, name)

    def observed(*args, **kwargs):
        calls.append(True)
        if intervention is not None:
            intervention()
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, observed)


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
@pytest.mark.parametrize("key_id", ["local", 'key-"\\-é-😀', '"\\é😀' * 64],
                         ids=["plain", "escaped", "max-lamport-characters"])
def test_real_signed_small_task_fits_strict_default(make_engine, monkeypatch, scheme, key_id):
    engine, task, requirement = make_engine(scheme, key_id)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls)
        packet = engine.resume_packet(PROJECT, task_id=task.id)
    assert calls == [True]
    assert packet["max_response_bytes"] == DEFAULT_CAP
    assert packet["response_format"] == "engine-json"
    assert len(_encoded(packet)) <= DEFAULT_CAP
    assert packet["signature"]["key_id"] == key_id
    assert engine.signer.verify(packet)
    assert requirement.id in {item["node_id"] for item in packet["mandatory_control"]}
    assert task.id in {item["node_id"] for item in packet["open_work"]["tasks"]}
    _validator("cce.resume.v2.json").validate(packet)
    if scheme == "lamport":
        fingerprint = packet["signature"]["fingerprint"]
        assert engine.signer.issued_fingerprints == [fingerprint]
        assert fingerprint in engine.signer.registered_fingerprints


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
def test_real_engine_markdown_fits_its_declared_default(make_engine, monkeypatch, scheme):
    engine, task, requirement = make_engine(scheme, 'markdown-"\\-é')
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls)
        markdown = engine.resume_packet(PROJECT, task_id=task.id, fmt="markdown")
    assert calls == [True]
    assert len(markdown.encode("utf-8")) <= DEFAULT_CAP
    assert "engine-markdown" in markdown
    assert str(DEFAULT_CAP) in markdown
    assert requirement["data"]["statement"] in markdown


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
def test_exact_boundary_includes_cap_digits_and_signed_output(make_engine, monkeypatch, scheme):
    engine, task, _ = make_engine(scheme, 'boundary-"\\-😀')
    error = _budget_error()
    # Find the smallest admitted public result, including any optional trimming.
    # This measures the cap field's own digits instead of subtracting a guessed
    # signature overhead or assuming that changing the limit preserves size.
    lower, upper = 1, DEFAULT_CAP
    while lower < upper:
        cap = (lower + upper) // 2
        try:
            packet = engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=cap)
        except error:
            lower = cap + 1
        else:
            assert len(_encoded(packet)) <= cap
            upper = cap
    packet = engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=lower)
    assert len(_encoded(packet)) == lower
    assert packet["max_response_bytes"] == lower
    assert engine.signer.verify(packet)
    larger = engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=lower + 1)
    assert len(_encoded(larger)) <= lower + 1
    before, signer_before = _database(engine), _signer_state(engine.signer)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls)
        with pytest.raises(error, match="^Complete packet exceeds max_response_bytes\\.$"):
            engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=lower - 1)
    assert calls == []
    assert _database(engine) == before
    assert _signer_state(engine.signer) == signer_before


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
def test_one_byte_refuses_before_crypto_and_preserves_old_state(make_engine, monkeypatch, scheme):
    engine, task, _ = make_engine(scheme)
    engine.resume_packet(PROJECT, task_id=task.id)
    before, signer_before = _database(engine), _signer_state(engine.signer)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls)
        with pytest.raises(_budget_error()):
            engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=1)
    assert calls == []
    assert _database(engine) == before
    assert _signer_state(engine.signer) == signer_before


@pytest.mark.parametrize("cap", [True, False, 0, -1, MAX_CAP + 1, 1.0, "131072", None])
def test_invalid_byte_operand_refuses_without_mutation(make_engine, cap):
    engine, task, _ = make_engine()
    before = _database(engine)
    with pytest.raises(ValueError):
        engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=cap)
    assert _database(engine) == before


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
@pytest.mark.parametrize("defect", ["subclass", "instance_sign"])
def test_unreviewed_signer_refuses_without_invoking_it(make_engine, scheme, defect):
    engine, task, _ = make_engine(scheme)
    engine.resume_packet(PROJECT, task_id=task.id)
    calls = []
    base = Signer if scheme == "hmac" else LamportSigner
    if defect == "subclass":
        class Unreviewed(base):
            def sign(self, obj):
                calls.append(True)
                return super().sign(obj)

        engine.signer = (Unreviewed("local", b"x" * 32) if scheme == "hmac"
                         else Unreviewed("local"))
    else:
        original = engine.signer.sign

        def unreviewed(obj):
            calls.append(True)
            return original(obj)

        engine.signer.sign = unreviewed
    before, signer_before = _database(engine), _signer_state(engine.signer)
    with pytest.raises(ValueError, match="^unsupported packet signing contract$"):
        engine.resume_packet(PROJECT, task_id=task.id)
    assert calls == []
    assert _database(engine) == before
    assert _signer_state(engine.signer) == signer_before


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
def test_signer_metadata_and_nested_target_are_frozen_before_crypto(
        make_engine, monkeypatch, scheme):
    engine, task, _ = make_engine(scheme, 'snapshot-"\\-é')
    original_key_id = engine.signer.key_id
    verifier = (Signer(original_key_id, bytes(engine.signer._key)) if scheme == "hmac"
                else LamportSigner(original_key_id))
    target = {"nested": {"label": "original bounded target"}}
    expected_target = copy.deepcopy(target)

    def mutate_exposed_state():
        engine.signer.key_id = "changed-" * 30_000
        engine.signer.algorithm = "changed-algorithm"
        target["nested"]["label"] = "changed-" * 30_000

    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls, mutate_exposed_state)
        packet = engine.resume_packet(PROJECT, task_id=task.id, target=target)
    assert calls == [True]
    assert target != expected_target
    assert packet["target"] == packet["mission"]["target"] == expected_target
    assert packet["signature"]["key_id"] == original_key_id
    assert packet["signature"]["algorithm"] == verifier.algorithm
    assert len(_encoded(packet)) <= DEFAULT_CAP
    assert verifier.verify(packet)


def test_optional_context_can_trim_but_mandatory_content_is_identical(make_engine):
    engine, task, _ = make_engine()
    engine.graph.put_node(
        entity_type="artifact", tenant_id=engine.tenant_id, project_id=PROJECT,
        status="recorded", data={"kind": "environment", "details": "e" * 80_000})
    full = engine.resume_packet(
        PROJECT, task_id=task.id, token_budget=100_000, max_response_bytes=MAX_CAP)
    packet = engine.resume_packet(
        PROJECT, task_id=task.id, token_budget=100_000, max_response_bytes=20_000)
    assert len(_encoded(full)) > 20_000 >= len(_encoded(packet))
    assert full["environment"] != packet["environment"]
    for field in ("mandatory_control", "authority", "open_work", "trust"):
        assert packet[field] == full[field]
    assert any(item.get("section") == "environment" and item.get("count", 0) > 0
               for item in packet["omissions"])


def test_all_global_mandatory_payload_cannot_escape_the_default(make_engine, monkeypatch):
    engine, task, _ = make_engine("lamport")
    engine.resume_packet(PROJECT, task_id=task.id)
    engine.graph.put_node(
        entity_type="requirement", tenant_id=engine.tenant_id, project_id=PROJECT,
        status="active", data={"statement": "Preserve global checksums.",
                               "large_note": "g" * 150_000})
    before, signer_before = _database(engine), _signer_state(engine.signer)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, "lamport", calls)
        with pytest.raises(_budget_error()):
            engine.resume_packet(PROJECT, task_id=task.id, token_budget=100_000)
    assert calls == []
    assert _database(engine) == before
    assert _signer_state(engine.signer) == signer_before


def test_task_scope_fits_when_unrelated_confirmed_control_makes_project_too_large(make_engine):
    engine, first, global_requirement = make_engine()
    second = _task(engine, "other", project_id=PROJECT)
    scoped = _confirm(
        engine, "requirement", "The separate archive must retain every checksum.",
        "other-control", scope={"kind": "tasks", "task_ids": [second.id]}, project_id=PROJECT)
    # A privileged semantic extension remains fully committed to this real grant.
    engine.graph.put_node(
        node_id=scoped.id, entity_type="requirement", tenant_id=engine.tenant_id,
        project_id=PROJECT, data={"large_note": "s" * 150_000})
    with pytest.raises(_budget_error()):
        engine.resume_packet(PROJECT, token_budget=100_000)
    packet = engine.resume_packet(PROJECT, task_id=first.id, token_budget=100_000)
    assert len(_encoded(packet)) <= DEFAULT_CAP
    assert {item["node_id"] for item in packet["mandatory_control"]} == {global_requirement.id}
    assert first.id in {item["node_id"] for item in packet["open_work"]["tasks"]}
    assert second.id not in {item["node_id"] for item in packet["open_work"]["tasks"]}
    with pytest.raises(_budget_error()):
        engine.resume_packet(PROJECT, task_id=second.id, token_budget=100_000)


@pytest.mark.parametrize("response_format", FORMATS)
def test_wire_declares_a_closed_representation_not_external_size_verification(response_format):
    packet = _packet()
    packet.update(max_response_bytes=1, response_format=response_format)
    _seal_packet(packet)
    # The shared wire parser has no transport wrapper. It validates declaration
    # shape, not an external output size or a live Engine completeness witness.
    CapsuleManager._validate_resume_packet(packet)
    _validator("cce.resume.v2.json").validate(packet)


@pytest.mark.parametrize("field,value", [
    ("max_response_bytes", False), ("max_response_bytes", 0),
    ("max_response_bytes", MAX_CAP + 1), ("max_response_bytes", 1.5),
    ("response_format", "json"), ("response_format", "ENGINE-JSON"),
    ("response_format", None),
])
def test_wire_refuses_invalid_byte_contract_fields(field, value):
    packet = _packet()
    packet.update(max_response_bytes=DEFAULT_CAP, response_format="engine-json")
    packet[field] = value
    _seal_packet(packet)
    with pytest.raises(CapsuleError):
        CapsuleManager._validate_resume_packet(packet)
    assert not _validator("cce.resume.v2.json").is_valid(packet)


# Supplemental review controls are frozen and compared separately from the
# original 43-case capability baseline; they do not replace that evidence.
@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
def test_supplemental_markdown_exact_boundary_and_no_sign_refusal(
        make_engine, monkeypatch, scheme):
    engine, task, _ = make_engine(scheme, 'markdown-boundary-"\\-😀')
    error = _budget_error()
    lower, upper = 1, DEFAULT_CAP
    while lower < upper:
        cap = (lower + upper) // 2
        try:
            result = engine.resume_packet(
                PROJECT, task_id=task.id, fmt="markdown", max_response_bytes=cap)
        except error:
            lower = cap + 1
        else:
            assert len(result.encode("utf-8")) <= cap
            upper = cap
    result = engine.resume_packet(
        PROJECT, task_id=task.id, fmt="markdown", max_response_bytes=lower)
    assert len(result.encode("utf-8")) == lower
    assert f"engine-markdown | max bytes: {lower}" in result
    larger = engine.resume_packet(
        PROJECT, task_id=task.id, fmt="markdown", max_response_bytes=lower + 1)
    assert len(larger.encode("utf-8")) <= lower + 1
    before, signer_before = _database(engine), _signer_state(engine.signer)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls)
        with pytest.raises(error, match="^Complete packet exceeds max_response_bytes\\.$"):
            engine.resume_packet(
                PROJECT, task_id=task.id, fmt="markdown", max_response_bytes=lower - 1)
    assert calls == []
    assert _database(engine) == before
    assert _signer_state(engine.signer) == signer_before


@pytest.mark.parametrize("scheme", ["hmac", "lamport"])
@pytest.mark.parametrize("cap", [True, False, 0, -1, MAX_CAP + 1, 1.0, "131072", None])
def test_supplemental_invalid_operand_is_not_budget_refusal_or_signing(
        make_engine, monkeypatch, scheme, cap):
    engine, task, _ = make_engine(scheme)
    engine.resume_packet(PROJECT, task_id=task.id)
    before, signer_before = _database(engine), _signer_state(engine.signer)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls)
        with pytest.raises(ValueError) as raised:
            engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=cap)
    assert type(raised.value) is ValueError
    assert str(raised.value) == "max_response_bytes must be an integer from 1 to 1048576"
    assert calls == []
    assert _database(engine) == before
    assert _signer_state(engine.signer) == signer_before


def test_supplemental_large_valid_hmac_key_is_measured_not_arbitrarily_capped(
        make_engine, monkeypatch):
    engine, task, _ = make_engine()
    engine.resume_packet(PROJECT, task_id=task.id)
    engine.signer.key_id = '"\\é😀' * 20_000
    assert len(_encoded(engine.signer.key_id)) > DEFAULT_CAP
    before = _database(engine)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, "hmac", calls)
        with pytest.raises(_budget_error()):
            engine.resume_packet(PROJECT, task_id=task.id)
        assert calls == []
        assert _database(engine) == before
        packet = engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=MAX_CAP)
    assert calls == [True]
    assert packet["signature"]["key_id"] == engine.signer.key_id
    assert DEFAULT_CAP < len(_encoded(packet)) <= MAX_CAP
    assert engine.signer.verify(packet)


@pytest.mark.parametrize("field", ["max_response_bytes", "response_format"])
def test_supplemental_wire_requires_each_byte_contract_field(field):
    packet = _packet()
    packet.update(max_response_bytes=DEFAULT_CAP, response_format="engine-json")
    del packet[field]
    _seal_packet(packet)
    with pytest.raises(CapsuleError):
        CapsuleManager._validate_resume_packet(packet)
    assert not _validator("cce.resume.v2.json").is_valid(packet)


@pytest.mark.parametrize("scheme,key_id", [
    ("hmac", ""), ("hmac", " "),
    ("lamport", ""), ("lamport", " "), ("lamport", "k" * 257),
], ids=["hmac-empty", "hmac-whitespace", "lamport-empty", "lamport-whitespace",
        "lamport-overlong"])
@pytest.mark.parametrize("cap", [1, DEFAULT_CAP], ids=["one-byte", "default"])
def test_invalid_signer_metadata_refuses_before_budget_or_crypto(
        make_engine, monkeypatch, scheme, key_id, cap):
    engine, task, _ = make_engine(scheme)
    engine.resume_packet(PROJECT, task_id=task.id)
    engine.signer.key_id = key_id
    before, signer_before = _database(engine), _signer_state(engine.signer)
    calls = []
    with monkeypatch.context() as patch:
        _observe_crypto(patch, scheme, calls)
        with pytest.raises(ValueError) as raised:
            engine.resume_packet(PROJECT, task_id=task.id, max_response_bytes=cap)
    assert type(raised.value) is ValueError
    assert str(raised.value) == "unsupported packet signing contract"
    assert calls == []
    assert _database(engine) == before
    assert _signer_state(engine.signer) == signer_before
