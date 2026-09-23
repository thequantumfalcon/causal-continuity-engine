"""The normative receipt profile must describe the live producer, not its archive."""

import copy
import json
import re
from pathlib import Path

import pytest

from causal_continuity_engine import SCHEMA_VERSIONS
from causal_continuity_engine.core import digest_obj
from causal_continuity_engine.engine import _CONTINUITY_PAYLOAD_TYPE, Engine
from tests.schema_validation import draft202012_validator

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "prj_receipt_spec"


def _schema(version):
    return json.loads((ROOT / "schemas" / f"{version}.json").read_text(encoding="utf-8"))


def _intro():
    spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    return spec.split("## 12. ", 1)[1].split("### 12.1 ", 1)[0]


def _reseal(engine, receipt):
    receipt.pop("signature", None)
    receipt["receipt_digest"] = digest_obj({
        key: value for key, value in receipt.items() if key != "receipt_digest"})
    receipt["signature"] = engine.signer.sign(receipt)
    assert engine.signer.verify(receipt)


@pytest.fixture
def live_receipt(tmp_path):
    engine = Engine(tmp_path / "receipt.sqlite3", workdir=tmp_path)
    try:
        engine.create_project("Receipt specification", project_id=PROJECT)
        engine.resume_packet(PROJECT)
        receipt = engine.continuity_check(PROJECT)["continuity_receipt"]
        schema = _schema(SCHEMA_VERSIONS["continuity_receipt"])
        draft202012_validator(schema).validate(receipt)
        assert engine.verify_continuity_receipt(
            PROJECT, receipt, expected_scope={"kind": "project"})["verdict"] == "CURRENT"
        yield engine, receipt, schema
    finally:
        engine.close()


@pytest.mark.parametrize("field, pattern", [
    ("schema_version", r"`(cce\.continuity-receipt\.v\d+)`"),
    ("payload_type", r"`(https://[^`]+/cce\.continuity-receipt\.v\d+\.json)`"),
])
def test_spec_live_receipt_identity_matches_producer_and_schema(live_receipt, field, pattern):
    engine, receipt, schema = live_receipt
    assert receipt[field] == schema["properties"][field]["const"]
    assert receipt["schema_version"] == SCHEMA_VERSIONS["continuity_receipt"]
    assert receipt["payload_type"] == _CONTINUITY_PAYLOAD_TYPE == schema["$id"]
    wrong_domain = copy.deepcopy(receipt)
    wrong_domain["payload_type"] = _schema(
        SCHEMA_VERSIONS["historical_continuity_receipt"])["$id"]
    _reseal(engine, wrong_domain)
    verdict = engine.verify_continuity_receipt(PROJECT, wrong_domain)
    assert verdict["verdict"] == "INVALID"
    assert "payload domain" in verdict["reason"]
    documented = re.search(pattern, _intro())
    assert documented is not None, f"SPEC §12 does not declare receipt {field}"
    assert documented.group(1) == receipt[field], f"SPEC §12 has stale receipt {field}"


def test_spec_project_scope_matches_schema_and_expected_scope_gate(live_receipt):
    engine, receipt, schema = live_receipt
    assert receipt["scope"] == schema["properties"]["scope"]["const"]
    assert "scope" in schema["required"]
    verdict = engine.verify_continuity_receipt(
        PROJECT, receipt, expected_scope={"kind": "task", "task_id": "tsk_other"})
    assert verdict["verdict"] == "INVALID"
    assert "expected project scope" in verdict["reason"]
    documented = re.search(r"`scope` MUST be exactly\s+`([^`]+)`", _intro())
    assert documented is not None, "SPEC §12 omits the required project-only receipt scope"
    assert json.loads(documented.group(1)) == receipt["scope"]


def test_spec_archived_receipt_profile_is_not_live_evidence(live_receipt):
    engine, receipt, _ = live_receipt
    historical = SCHEMA_VERSIONS["historical_continuity_receipt"]
    schema = _schema(historical)
    archived_shape = copy.deepcopy(receipt)
    archived_shape["schema_version"] = historical
    archived_shape["payload_type"] = schema["$id"]
    archived_shape.pop("scope")
    _reseal(engine, archived_shape)
    draft202012_validator(schema).validate(archived_shape)
    assert engine.verify_continuity_receipt(PROJECT, archived_shape)["verdict"] == "INVALID"
    documented = re.search(
        r"`(cce\.continuity-receipt\.v\d+)` is retained only for historical interpretation",
        _intro())
    assert documented is not None, "SPEC §12 does not distinguish the archived receipt profile"
    assert documented.group(1) == historical
