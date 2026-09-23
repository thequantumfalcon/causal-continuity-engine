"""Proof-v2 wire controls; live obligation correctness belongs to Engine tests."""

from __future__ import annotations

import copy
import hashlib
import json
import runpy
from pathlib import Path

import pytest

from causal_continuity_engine import SCHEMA_VERSIONS
from causal_continuity_engine.core import Signer, digest_obj
from causal_continuity_engine.proof import (
    ProofEnvelope,
    from_intoto,
    to_intoto,
    validate_envelope_shape,
    verify_envelope,
)
from tests.schema_validation import draft202012_validator

ROOT = Path(__file__).resolve().parent.parent
KEY = bytes.fromhex("71" * 32)
TASKS = ["tsk_wire_a", "tsk_wire_b"]
PREFIX = "continuity:obligations:"


@pytest.fixture(scope="module")
def independent():
    return runpy.run_path(str(ROOT / "verifiers" / "verify_proof.py"))


def _builder(tasks=TASKS, *, inputs_first=False):
    builder = ProofEnvelope(
        tenant_id="tenant_wire", project_id="prj_wire", intent_type="task_complete",
        intent_statement="wire fixture, not a live-state witness", actor={"name": "test"})
    if not inputs_first:
        builder.set_continuity(task_ids=list(tasks))
    for task in tasks:
        builder.add_input(PREFIX + task, digest_obj({"task": task}), kind="continuity")
    if inputs_first:
        builder.set_continuity(task_ids=list(tasks))
    builder.set_policy_decision({"decision": "allow"})
    builder.add_verification({"verifier": "fixture", "result": "passed",
                              "source": "executed"})
    return builder


def _proof():
    return _builder().finalize(Signer("wire", KEY), required_verifiers=["fixture"])


def _reseal(proof):
    proof["proof_digest"] = digest_obj({
        key: value for key, value in proof.items() if key not in ("signature", "proof_digest")})
    proof["signature"] = Signer("wire", KEY).sign(proof)
    return proof


@pytest.mark.parametrize("inputs_first", [False, True])
def test_v2_builder_orders_and_independent_expected_scope(independent, inputs_first):
    proof = _builder(inputs_first=inputs_first).finalize(
        Signer("wire", KEY), required_verifiers=["fixture"])
    assert proof["schema_version"] == SCHEMA_VERSIONS["proof"] == "cce.proof.v2"
    assert not validate_envelope_shape(proof)
    assert verify_envelope(proof, Signer("wire", KEY))["valid"]
    for task in TASKS:
        result = independent["verify"](
            proof, hmac_key=KEY, tenant="tenant_wire", project="prj_wire", task=task)
        assert result["verdict"] == "VALID", result
    wrong = independent["verify"](proof, hmac_key=KEY, task="tsk_elsewhere")
    assert wrong["verdict"] == "INVALID"
    assert "E_UNBOUND" in wrong["errors"]


def test_final_missing_commitment_refuses_before_signing():
    builder = _builder(tasks=[])
    builder.set_continuity(task_ids=[TASKS[0]])

    class NeverSign:
        def sign(self, payload):
            pytest.fail("incomplete obligation coverage reached signing")

    with pytest.raises(ValueError, match="obligation"):
        builder.finalize(NeverSign(), required_verifiers=["fixture"])


@pytest.mark.parametrize("mutation", [
    "missing", "duplicate", "other-task", "wrong-kind", "empty-suffix",
    "invalid-id", "extra-suffix", "extra-field", "draft-missing", "duplicate-new-digest",
    "duplicate-task",
])
def test_authentic_malformed_obligation_wire_refuses(independent, mutation):
    proof = _proof()
    item = proof["inputs"][0]
    if mutation in ("missing", "draft-missing"):
        proof["inputs"].pop(0)
        if mutation == "draft-missing":
            proof["status"] = "draft"
    elif mutation in ("duplicate", "duplicate-new-digest"):
        duplicate = copy.deepcopy(item)
        if mutation == "duplicate-new-digest":
            duplicate["digest"] = digest_obj("different commitment")
        proof["inputs"].append(duplicate)
    elif mutation == "duplicate-task":
        proof["continuity_links"]["task_ids"].append(TASKS[0])
    elif mutation == "other-task":
        item["name"] = PREFIX + "tsk_elsewhere"
    elif mutation == "wrong-kind":
        item["kind"] = "declared"
    elif mutation == "empty-suffix":
        item["name"] = PREFIX
    elif mutation == "invalid-id":
        item["name"] = PREFIX + "task/child"
    elif mutation == "extra-suffix":
        item["name"] += ":extra"
    else:
        item["scope"] = {"kind": "global"}
    _reseal(proof)
    assert validate_envelope_shape(proof), mutation
    assert not verify_envelope(proof, Signer("wire", KEY))["shape_ok"]
    result = independent["verify"](proof, hmac_key=KEY, task=TASKS[0])
    assert result["verdict"] == "INVALID"
    assert result["errors"] == ["E_SHAPE"]


def test_v1_is_not_reinterpreted_as_current_proof(independent):
    proof = _proof()
    proof["schema_version"] = "cce.proof.v1"
    _reseal(proof)
    assert validate_envelope_shape(proof)
    assert independent["verify"](proof, hmac_key=KEY)["errors"] == ["E_SHAPE"]
    with pytest.raises(ValueError):
        to_intoto(proof)


def test_v2_predicate_round_trip_is_lossless():
    proof = _proof()
    statement = to_intoto(proof)
    assert statement["predicateType"].endswith("/v0.2.0/schemas/cce.proof-predicate.v2.json")
    assert from_intoto(statement) == proof
    historical = copy.deepcopy(statement)
    historical["predicateType"] = historical["predicateType"].replace(
        "/v0.2.0/schemas/cce.proof-predicate.v2", "/v0.1.0/schemas/cce.proof-predicate.v1")
    with pytest.raises(ValueError):
        from_intoto(historical)


@pytest.mark.parametrize("field,value", [
    ("schema_version", "cce.proof.v1"),
    ("subject", [{"name": "silently overwritten", "digest": digest_obj("different")}]),
])
def test_intoto_import_does_not_discard_forbidden_predicate_fields(field, value):
    statement = to_intoto(_proof())
    statement["predicate"][field] = value
    with pytest.raises(ValueError):
        from_intoto(statement)


def test_task_identity_is_the_public_grammar_not_a_generated_prefix(independent):
    task = "Custom.Task~1"
    proof = _builder(tasks=[task]).finalize(Signer("wire", KEY), ["fixture"])
    assert not validate_envelope_shape(proof)
    assert independent["verify"](proof, hmac_key=KEY, task=task)["verdict"] == "VALID"


def test_no_typed_task_requires_no_obligation_commitment(independent):
    proof = _builder(tasks=[]).finalize(Signer("wire", KEY), ["fixture"])
    assert proof["inputs"] == []
    assert not validate_envelope_shape(proof)
    assert independent["verify"](proof, hmac_key=KEY)["verdict"] == "VALID"
    assert independent["verify"](proof, hmac_key=KEY, task=TASKS[0])["errors"] == ["E_UNBOUND"]


@pytest.mark.parametrize("name,kind", [
    (PREFIX, "continuity"), (PREFIX + "bad/id", "continuity"),
    (PREFIX + TASKS[0], "declared"),
])
def test_reserved_syntax_refuses_atomically_during_builder_updates(name, kind):
    builder = _builder(tasks=[])
    before = copy.deepcopy(builder.body)
    with pytest.raises(ValueError, match="obligation"):
        builder.add_input(name, digest_obj("basis"), kind=kind)
    assert builder.body == before


@pytest.mark.parametrize("name,kind", [
    (PREFIX, "continuity"), (PREFIX + "bad/id", "continuity"),
    (PREFIX + TASKS[0], "declared"),
])
def test_reserved_syntax_is_rejected_by_v2_schema(name, kind):
    proof = _proof()
    proof["inputs"][0].update(name=name, kind=kind)
    schema = json.loads((ROOT / "schemas" / "cce.proof.v2.json").read_text())
    assert not draft202012_validator(schema).is_valid(proof)


def test_reserved_schema_name_has_no_terminal_newline_alias(independent):
    proof = _proof()
    proof["inputs"][0]["name"] += "\n"
    _reseal(proof)
    schema = json.loads((ROOT / "schemas" / "cce.proof.v2.json").read_text())
    assert not draft202012_validator(schema).is_valid(proof)
    assert validate_envelope_shape(proof)
    assert independent["verify"](proof, hmac_key=KEY)["errors"] == ["E_SHAPE"]


@pytest.mark.parametrize("name", ["input_item_wrong_type", "task_id_under_unrelated_field"])
def test_original_corpus_shape_defects_are_not_masked_by_obligation_coverage(name):
    vector = json.loads((ROOT / "vectors" / (name + ".json")).read_text())
    proof = vector["envelope"]
    assert validate_envelope_shape(proof)
    if name == "input_item_wrong_type":
        assert proof["inputs"].count(42) == 1
        proof["inputs"].remove(42)
        assert proof["continuity_links"]["task_ids"]
    else:
        assert set(proof["continuity_links"]) == {"unrelated_ids"}
        proof["continuity_links"] = {}
    # Remove only the named planted shape defect: the remaining final shape
    # must be healthy, not still red under the newly introduced coverage rule.
    assert not validate_envelope_shape(proof)


def test_v2_schema_and_old_schema_version_boundary():
    proof = _proof()
    new_schema = json.loads((ROOT / "schemas" / "cce.proof.v2.json").read_text())
    old_schema = json.loads((ROOT / "schemas" / "cce.proof.v1.json").read_text())
    draft202012_validator(new_schema).validate(proof)
    assert not draft202012_validator(old_schema).is_valid(proof)
    for name, expected in {
        "cce.proof.v1.json": "25ce242747404093601eeea223fcfa61bec2826328083d6c5c95056c62300c56",
        "cce.proof-predicate.v1.json":
            "b33b3821097b8bec2377129b35c21335b8f8284dc75c78063618d12d48e7a80e",
    }.items():
        assert hashlib.sha256((ROOT / "schemas" / name).read_bytes()).hexdigest() == expected
