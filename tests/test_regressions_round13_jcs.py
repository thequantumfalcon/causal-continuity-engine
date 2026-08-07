"""RFC 8785 canonical-byte regressions for every digest/signature path."""

from __future__ import annotations

import json
import runpy
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from causal_continuity_engine.core import canonical_json, strict_json_loads
from causal_continuity_engine.policy import PolicyEngine

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verifiers" / "verify_proof.py"
INDEPENDENT = runpy.run_path(str(VERIFIER))
independent_canonical = INDEPENDENT["canonical"]
IndependentSpecError = INDEPENDENT["SpecError"]


# RFC 8785 Appendix B, excluding the three rows whose required result is an
# error (NaN and the two infinities).  Values are constructed from bits so the
# test never asks a host decimal parser to decide which binary64 was intended.
RFC_8785_FINITE_NUMBERS = (
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
)


def test_rfc_8785_appendix_b_finite_table_cannot_silently_shrink():
    assert len(RFC_8785_FINITE_NUMBERS) == 24
    assert len({bits for bits, _ in RFC_8785_FINITE_NUMBERS}) == 24


@pytest.mark.parametrize(("bits", "expected"), RFC_8785_FINITE_NUMBERS)
def test_both_implementations_match_every_finite_rfc_8785_number(bits, expected):
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    assert canonical_json(value) == expected
    assert independent_canonical(value) == expected


def test_both_implementations_match_the_rfc_8785_primitive_sample():
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": "\u20ac$\x0f\nA'B\"\\\\\"/",
        "literals": [None, True, False],
    }
    expected = (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonical_json(value) == expected
    assert independent_canonical(value) == expected


def test_both_implementations_use_raw_utf16_code_unit_key_order():
    value = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    expected_keys = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"]
    encoded = canonical_json(value)
    assert list(json.loads(encoded)) == expected_keys
    assert independent_canonical(value) == encoded


def test_astral_key_precedes_later_bmp_key_under_utf16_not_codepoint_order():
    value = {"\ue000": "bmp", "\U0001f600": "astral"}
    expected = '{"\U0001f600":"astral","\ue000":"bmp"}'
    assert canonical_json(value) == expected
    assert independent_canonical(value) == expected


def test_both_implementations_escape_every_ascii_control_exactly():
    value = "".join(chr(codepoint) for codepoint in range(0x20))
    expected = '"' + "".join((
        "\\u0000", "\\u0001", "\\u0002", "\\u0003",
        "\\u0004", "\\u0005", "\\u0006", "\\u0007",
        "\\b", "\\t", "\\n", "\\u000b", "\\f", "\\r",
        "\\u000e", "\\u000f", "\\u0010", "\\u0011",
        "\\u0012", "\\u0013", "\\u0014", "\\u0015",
        "\\u0016", "\\u0017", "\\u0018", "\\u0019",
        "\\u001a", "\\u001b", "\\u001c", "\\u001d",
        "\\u001e", "\\u001f",
    )) + '"'
    assert canonical_json(value) == expected
    assert independent_canonical(value) == expected


def test_both_implementations_preserve_unicode_without_normalization():
    value = {"\u00e9": "composed", "e\u0301": "decomposed"}
    expected = '{"e\u0301":"decomposed","\u00e9":"composed"}'
    assert canonical_json(value) == expected
    assert independent_canonical(value) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_both_implementations_reject_nonfinite_numbers(value):
    with pytest.raises(ValueError, match="non-finite"):
        canonical_json(value)
    with pytest.raises(IndependentSpecError, match="E_CJSON"):
        independent_canonical(value)


@pytest.mark.parametrize("value", ["\ud800", "\ufdd0", "\U0010ffff"])
def test_both_implementations_reject_non_i_json_unicode(value):
    with pytest.raises(ValueError, match="non-I-JSON Unicode"):
        canonical_json(value)
    with pytest.raises(IndependentSpecError, match="E_CJSON"):
        independent_canonical(value)


def test_wider_integer_is_rejected_instead_of_silently_rounded():
    value = 9_007_199_254_740_993
    with pytest.raises(ValueError, match="not exactly representable as binary64"):
        canonical_json(value)
    with pytest.raises(IndependentSpecError, match="E_CJSON"):
        independent_canonical(value)
    with pytest.raises(ValueError, match="not exactly representable as binary64"):
        strict_json_loads(str(value))


def test_exact_binary64_integer_beyond_safe_integer_range_is_supported():
    value = 2**68
    expected = "295147905179352830000"
    assert canonical_json(value) == expected
    assert independent_canonical(value) == expected
    assert strict_json_loads(str(value)) == value


def test_runtime_rejects_non_string_object_keys_and_duplicate_wire_names():
    with pytest.raises(TypeError, match="object key"):
        canonical_json({1: "not a JSON object name"})
    with pytest.raises(IndependentSpecError, match="E_CJSON"):
        independent_canonical({1: "not a JSON object name"})
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        strict_json_loads('{"same":1,"same":2}')


def test_strict_parser_accepts_a_valid_escaped_surrogate_pair():
    assert strict_json_loads('"\\ud83d\\ude00"') == "\U0001f600"


def test_strict_parser_normalizes_excessive_nesting_to_value_error():
    raw = "[" * 2_000 + "0" + "]" * 2_000
    with pytest.raises(ValueError, match="JSON nesting exceeds supported depth"):
        strict_json_loads(raw)


@pytest.mark.parametrize("value", [9_007_199_254_740_993, "\ufdd0"])
def test_policy_rejects_non_jcs_extension_values_before_persistence(value):
    config = {
        "required_verifiers": [{
            "name": "extension-check",
            "kind": "value-oracle",
            "expected_properties": {"values": {"invalid": value}},
        }],
    }
    with pytest.raises(ValueError, match="finite canonical JSON"):
        PolicyEngine.validate_project_config(config)


@pytest.mark.parametrize(
    "body",
    [
        '{"bad":9007199254740993}',
        '{"bad":1e400}',
        '{"bad":"\\ud800"}',
        '{"bad":"\\ufdd0"}',
    ],
)
def test_standalone_verifier_rejects_invalid_i_json_before_shape(tmp_path, body):
    path = tmp_path / "invalid-i-json.json"
    path.write_text(body, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path), "--json"],
        capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    result = json.loads(proc.stdout)[0]
    assert result["verdict"] == "INVALID"
    assert result["errors"] == ["E_CJSON"]
