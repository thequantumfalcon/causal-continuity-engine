"""Cross-implementation conformance (SPEC.md).

The reference implementation in `causal_continuity_engine/` and the independent verifier in
`verifiers/verify_proof.py` must agree on every vector. The verifier imports
nothing from `causal_continuity_engine` — if it did, a shared bug would produce agreement that
means nothing.

The corpus is GENERATED from the reference, so it cannot be written to agree
with a verifier that is wrong; and a drift check fails the build when the
reference changes what it emits without the corpus being regenerated.

What this establishes: the specification is unambiguous enough to
reimplement from, and neither implementation has a defect the other lacks.
What it does NOT establish: implementation independence. Both have one
author. See the note at the top of SPEC.md.
"""

from __future__ import annotations

import builtins
import copy
import json
import os
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from causal_continuity_engine.core import Signer, digest_obj
from causal_continuity_engine.proof import (
    ProofEnvelope,
    evaluate_status,
    validate_envelope_shape,
    verify_envelope,
)
from tests.schema_validation import (
    draft202012_validator,
    repository_format_checker,
    stdlib_rfc3339_datetime,
)

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"
VERIFIER = ROOT / "verifiers" / "verify_proof.py"
PROOF_SCHEMA = ROOT / "schemas" / "cce.proof.v1.json"
TIMESTAMP_KEY = bytes.fromhex(
    "7cce0000000000000000000000000000000000000000000000000000000000ff")


def _load():
    return [json.loads(p.read_text())
            for p in sorted(VECTORS.glob("*.json")) if p.name != "index.json"]


VECTOR_CASES = _load()


def _run_process(vector) -> tuple[subprocess.CompletedProcess, dict]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(vector["envelope"], fh)
        path = fh.name
    cmd = [sys.executable, str(VERIFIER), path, "--json"]
    ctx = vector["context"]
    if ctx.get("hmac_key_hex"):
        cmd += ["--hmac-key-hex", ctx["hmac_key_hex"]]
    for fp in ctx.get("fingerprints", []):
        cmd += ["--fingerprint", fp]
    if ctx.get("expect_project"):
        cmd += ["--expect-project", ctx["expect_project"]]
    if ctx.get("expect_task"):
        cmd += ["--expect-task", ctx["expect_task"]]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.stdout, f"verifier produced nothing: {proc.stderr}"
    return proc, json.loads(proc.stdout)[0]


def _run(vector) -> dict:
    return _run_process(vector)[1]


def test_the_corpus_is_not_empty():
    assert len(VECTOR_CASES) >= 15, "the corpus has shrunk unexpectedly"
    verdicts = {v["expected_verdict"] for v in VECTOR_CASES}
    assert {"VALID", "INVALID", "INCOMPLETE", "UNVERIFIED"} <= verdicts, \
        "a corpus with no honest-negative, undecidable or valid case " \
        "proves little"


def test_timestamp_and_empty_required_boundaries_are_committed():
    names = {vector["name"] for vector in VECTOR_CASES}
    assert {
        "created_at_noncanonical_offset",
        "created_at_invalid_calendar_date",
        "empty_required_authoritative_pass",
        "empty_required_no_results",
        "empty_required_self_asserted_pass",
        "empty_required_authoritative_failure",
    } <= names


@pytest.mark.parametrize("vector", VECTOR_CASES,
                         ids=[v["name"] for v in VECTOR_CASES])
def test_independent_verifier_agrees(vector):
    result = _run(vector)
    assert result["verdict"] == vector["expected_verdict"], (
        f"{vector['name']}: reference says {vector['expected_verdict']}, "
        f"independent verifier says {result['verdict']} "
        f"(errors: {result['errors']})")
    expected = set(vector["expected_errors"])
    observed = set(result["errors"])
    assert expected <= observed, (
        f"{vector['name']}: expected error codes {sorted(expected - observed)} "
        f"were not raised; got {sorted(observed)}")


_ENUM_PATHS = {
    "status": ("status",),
    "policy_decision.decision": ("policy_decision", "decision"),
    "verifications.result": ("verifications", 0, "result"),
    "verifications.source": ("verifications", 0, "source"),
    "verifications.control.status": (
        "verifications", 0, "control", "status"),
}


def _replace_path(document: dict, path: tuple, value) -> None:
    target = document
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value


@pytest.mark.parametrize(
    "bad_value", [[], {}, None, 7],
    ids=["array", "object", "null", "number"],
)
@pytest.mark.parametrize("field", _ENUM_PATHS)
def test_proof_enum_shape_is_total_across_all_json_types(field, bad_value):
    """Unhashable enum values are shape failures, never validator crashes."""
    vector = copy.deepcopy(next(
        item for item in VECTOR_CASES if item["name"] == "valid_hmac"))
    _replace_path(vector["envelope"], _ENUM_PATHS[field], bad_value)

    errors = validate_envelope_shape(vector["envelope"])
    assert errors, field
    reference = verify_envelope(vector["envelope"], signer=None)
    assert not reference["valid"]
    assert not reference["shape_ok"]

    process, independent = _run_process(vector)
    assert process.returncode == 1, process.stderr
    assert independent["verdict"] == "INVALID"
    assert independent["errors"] == ["E_SHAPE"]
    assert independent["status"] is None


@pytest.mark.parametrize(
    "bad_id", ["id/child", "id%2Fchild", "..", "é", "a" * 129],
    ids=["slash", "percent", "dot-segment", "unicode", "too-long"],
)
@pytest.mark.parametrize(
    "field",
    [
        "tenant_id", "project_id", "action_id",
        "action_intent.requirement_ids", "continuity_links.task_ids",
    ],
)
def test_proof_public_identifiers_match_schema_and_both_verifiers(
        field, bad_id):
    vector = copy.deepcopy(next(
        item for item in VECTOR_CASES if item["name"] == "valid_hmac"))
    envelope = vector["envelope"]
    if field == "action_intent.requirement_ids":
        envelope["action_intent"]["requirement_ids"] = [bad_id]
    elif field == "continuity_links.task_ids":
        envelope["continuity_links"]["task_ids"] = [bad_id]
    else:
        envelope[field] = bad_id

    assert not _proof_schema_validator().is_valid(envelope)
    assert validate_envelope_shape(envelope)
    assert not verify_envelope(envelope, signer=None)["shape_ok"]
    process, independent = _run_process(vector)
    assert process.returncode == 1
    assert independent["verdict"] == "INVALID"
    assert independent["errors"] == ["E_SHAPE"]


def test_the_verifier_imports_nothing_from_reference_package():
    """Agreement is only evidence if the implementations are separate."""
    source = VERIFIER.read_text()
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            assert "causal_continuity_engine" not in stripped.split("#")[0], \
                f"the independent verifier imports the reference: {stripped}"


def test_the_corpus_is_current():
    """Drift guard: regenerating must produce what is committed."""
    proc = subprocess.run([sys.executable, "vectors/generate.py", "--check"],
                          cwd=str(ROOT), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_fresh_generation_is_self_consistent_on_the_native_platform():
    """Exercise generator commands; --check alone only reads committed files."""
    generator = runpy.run_path(str(VECTORS / "generate.py"))
    reference_verdict = generator["reference_verdict"]
    disagreements = [
        (vector["name"], vector["expected_verdict"], reference_verdict(vector))
        for vector in generator["build"]()
        if reference_verdict(vector) != vector["expected_verdict"]
    ]
    assert not disagreements, disagreements


def test_exit_codes_match_verdicts(tmp_path):
    """A caller scripting the verifier must be able to trust $?."""
    expectations = {"VALID": 0, "INVALID": 1, "UNVERIFIED": 2,
                    "INCOMPLETE": 3}          # SPEC §10.1
    for verdict, code in expectations.items():
        vector = next((v for v in VECTOR_CASES
                       if v["expected_verdict"] == verdict), None)
        assert vector is not None, f"no {verdict} vector to test with"
        path = tmp_path / "v.json"
        path.write_text(json.dumps(vector["envelope"]))
        cmd = [sys.executable, str(VERIFIER), str(path)]
        ctx = vector["context"]
        if ctx.get("hmac_key_hex"):
            cmd += ["--hmac-key-hex", ctx["hmac_key_hex"]]
        for fp in ctx.get("fingerprints", []):
            cmd += ["--fingerprint", fp]
        if ctx.get("expect_project"):
            cmd += ["--expect-project", ctx["expect_project"]]
        if ctx.get("expect_task"):
            cmd += ["--expect-task", ctx["expect_task"]]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == code, (
            f"{vector['name']} ({verdict}) exited {proc.returncode}, "
            f"expected {code}")


def test_invalid_dominates_in_a_batch(tmp_path):
    """SPEC §10.1. A CI gate keyed on exit 1 must not miss a forgery that
    happens to share a run with a merely-incomplete envelope."""
    def pick(verdict):
        v = next(x for x in VECTOR_CASES if x["expected_verdict"] == verdict)
        path = tmp_path / f"{v['name']}.json"
        path.write_text(json.dumps(v["envelope"]))
        return v, path

    invalid, invalid_path = pick("INVALID")
    _, incomplete_path = pick("INCOMPLETE")
    key = invalid["context"].get("hmac_key_hex")
    cmd = [sys.executable, str(VERIFIER), str(invalid_path),
           str(incomplete_path)] + (["--hmac-key-hex", key] if key else [])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 1, (
        f"a batch containing an INVALID exited {proc.returncode}; "
        f"the forgery would be missed\n{proc.stdout}")


@pytest.mark.parametrize(
    "body", ['{"schema_version":"cce.proof.v1","status":"draft",'
             '"status":"verified"}',
             '{"schema_version":"cce.proof.v1","confidence":NaN}'])
def test_independent_verifier_rejects_ambiguous_or_nonfinite_json(tmp_path, body):
    path = tmp_path / "ambiguous.json"
    path.write_text(body, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path), "--json"],
        capture_output=True, text=True)
    assert proc.returncode == 1
    result = json.loads(proc.stdout)[0]
    assert result["verdict"] == "INVALID"
    assert "E_CJSON" in result["errors"]


def test_independent_verifier_rejects_excessive_json_nesting_cleanly(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path), "--json"],
        capture_output=True, text=True)
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    result = json.loads(proc.stdout)[0]
    assert result["verdict"] == "INVALID"
    assert result["errors"] == ["E_CJSON"]
    assert result["status"] is None


def _standalone_verifier_module():
    namespace = runpy.run_path(
        str(VERIFIER), run_name="cce_standalone_verifier_boundary_test")
    # runpy returns a copy; function globals are the verifier's live namespace.
    return namespace["main"].__globals__


def _run_standalone_input(path, *extra):
    process = subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *extra, "--json"],
        capture_output=True, text=True, timeout=10)
    assert process.stdout, process.stderr
    return process, json.loads(process.stdout)[0]


def test_independent_verifier_rejects_oversized_proof_without_truncation(
        tmp_path):
    module = _standalone_verifier_module()
    limit = module["MAX_PROOF_BYTES"]
    path = tmp_path / "oversized.json"
    with path.open("wb") as stream:
        stream.seek(limit)
        stream.write(b"x")

    process, result = _run_standalone_input(path)

    assert process.returncode == 1
    assert result["verdict"] == "INVALID"
    assert result["errors"] == ["E_CJSON"]
    assert result["detail"] == (
        f"E_CJSON: proof input exceeds the {limit}-byte limit")


def test_independent_verifier_accepts_exact_proof_byte_cap(tmp_path):
    module = _standalone_verifier_module()
    limit = module["MAX_PROOF_BYTES"]
    path = tmp_path / "exact-limit.json"
    path.write_bytes(b"0" + (b" " * (limit - 1)))

    assert module["_read_proof_bytes"](str(path)) == path.read_bytes()


def test_independent_verifier_binary_reader_preserves_every_input_byte(
        tmp_path):
    module = _standalone_verifier_module()
    path = tmp_path / "binary-proof.json"
    payload = b'{"line":"one\r\ntwo"}\r\n\x1a\x00\xff'
    path.write_bytes(payload)

    assert module["_read_proof_bytes"](str(path)) == payload


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        (b'{"schema_version":', "E_CJSON: proof input is not strict JSON"),
        (b"\xff", "E_CJSON: proof input is not strict UTF-8"),
    ],
)
def test_independent_verifier_reports_deterministic_cjson_input_failure(
        tmp_path, body, detail):
    path = tmp_path / "malformed.json"
    path.write_bytes(body)

    process, result = _run_standalone_input(path)

    assert process.returncode == 1
    assert "Traceback" not in process.stderr
    assert result == {
        "verdict": "INVALID",
        "errors": ["E_CJSON"],
        "detail": detail,
        "checks": {},
        "status": None,
        "file": str(path),
    }


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="host has no FIFO support")
def test_independent_verifier_rejects_fifo_without_blocking(tmp_path):
    path = tmp_path / "proof.pipe"
    os.mkfifo(path)

    process, result = _run_standalone_input(path)

    assert process.returncode == 1
    assert result["errors"] == ["E_CJSON"]
    assert "physical regular file" in result["detail"]


def test_independent_verifier_rejects_directory_input(tmp_path):
    process, result = _run_standalone_input(tmp_path)

    assert process.returncode == 1
    assert result["errors"] == ["E_CJSON"]
    assert "physical regular file" in result["detail"]


def test_independent_verifier_rejects_symlink_input(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "proof.json"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("host cannot create an unprivileged file symlink")

    process, result = _run_standalone_input(link)

    assert process.returncode == 1
    assert result["errors"] == ["E_CJSON"]
    assert "physical regular file" in result["detail"]


def test_independent_verifier_rejects_reparse_metadata_before_open(
        tmp_path, monkeypatch):
    module = _standalone_verifier_module()
    path = tmp_path / "proof.json"
    path.write_text("{}", encoding="utf-8")
    native_lstat = module["os"].lstat

    class ReparseStat:
        def __init__(self, original):
            self._original = original
            self.st_file_attributes = (
                getattr(original, "st_file_attributes", 0)
                | module["_REPARSE_POINT"]
            )

        def __getattr__(self, name):
            return getattr(self._original, name)

    monkeypatch.setattr(
        module["os"], "lstat",
        lambda candidate: ReparseStat(native_lstat(candidate)))
    with pytest.raises(module["SpecError"], match="physical regular file") as caught:
        module["_read_proof_bytes"](str(path))
    assert caught.value.code == "E_CJSON"


def test_independent_verifier_caps_path_patterns_and_pattern_bytes(
        monkeypatch, capsys):
    module = _standalone_verifier_module()
    monkeypatch.setitem(module, "MAX_PATH_PATTERNS", 2)
    assert module["main"](["one", "two", "three", "--json"]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "proof input usage error: at most 2 proof path patterns are allowed\n")

    monkeypatch.setitem(module, "MAX_PATTERN_BYTES", 4)
    assert module["main"](["12345", "--json"]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "proof input usage error: proof path pattern exceeds the "
        "4-byte limit\n")


def test_independent_verifier_caps_deduplicated_glob_batch(
        tmp_path, monkeypatch, capsys):
    module = _standalone_verifier_module()
    for index in range(3):
        (tmp_path / f"{index}.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(module, "MAX_BATCH_FILES", 2)
    monkeypatch.setitem(module, "MAX_GLOB_MATCHES", 10)

    assert module["main"]([str(tmp_path / "*.json"), "--json"]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "proof input usage error: proof batch exceeds the 2-file limit\n")


def test_independent_verifier_caps_glob_match_count(
        tmp_path, monkeypatch, capsys):
    module = _standalone_verifier_module()
    for index in range(3):
        (tmp_path / f"{index}.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(module, "MAX_BATCH_FILES", 10)
    monkeypatch.setitem(module, "MAX_GLOB_MATCHES", 2)

    assert module["main"]([str(tmp_path / "*.json"), "--json"]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "proof input usage error: glob expansion exceeds the "
        "2-match limit\n")


def test_independent_verifier_caps_glob_scan_count(
        tmp_path, monkeypatch, capsys):
    module = _standalone_verifier_module()
    for index in range(3):
        (tmp_path / f"{index}.txt").write_text("", encoding="utf-8")
    monkeypatch.setitem(module, "MAX_GLOB_SCAN_ENTRIES", 2)

    assert module["main"]([str(tmp_path / "*.json"), "--json"]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "proof input usage error: glob expansion exceeds the "
        "2-entry scan limit\n")


def test_independent_verifier_deduplicates_overlapping_glob_matches(
        tmp_path, monkeypatch, capsys):
    module = _standalone_verifier_module()
    for index in range(2):
        (tmp_path / f"{index}.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(module, "MAX_GLOB_MATCHES", 2)
    monkeypatch.setitem(module, "MAX_BATCH_FILES", 2)

    assert module["main"]([
        str(tmp_path / "*.json"),
        str(tmp_path / "?.json"),
        "--json",
    ]) == 1
    captured = capsys.readouterr()
    assert len(json.loads(captured.out)) == 2
    assert captured.err == ""


def test_independent_verifier_deduplicates_equivalent_literal_paths(
        tmp_path, monkeypatch, capsys):
    module = _standalone_verifier_module()
    path = tmp_path / "proof.json"
    path.write_text("{}", encoding="utf-8")
    equivalent = str(tmp_path) + os.sep + "." + os.sep + path.name
    monkeypatch.setitem(module, "MAX_BATCH_FILES", 1)

    assert module["main"]([str(path), equivalent, "--json"]) == 1
    captured = capsys.readouterr()
    results = json.loads(captured.out)
    assert len(results) == 1
    assert results[0]["file"] == str(path)
    assert captured.err == ""


def test_independent_verifier_rejects_descriptor_change_while_reading(
        tmp_path, monkeypatch):
    module = _standalone_verifier_module()
    path = tmp_path / "proof.json"
    path.write_text('{"schema_version":"cce.proof.v1"}', encoding="utf-8")
    native_fstat = module["os"].fstat
    calls = 0

    class ChangedStat:
        def __init__(self, original):
            self._original = original
            self.st_mtime_ns = (
                getattr(
                    original, "st_mtime_ns",
                    int(original.st_mtime * 1_000_000_000))
                + 1
            )

        def __getattr__(self, name):
            return getattr(self._original, name)

    def changed_after_read(descriptor):
        nonlocal calls
        calls += 1
        observed = native_fstat(descriptor)
        return ChangedStat(observed) if calls == 2 else observed

    monkeypatch.setattr(module["os"], "fstat", changed_after_read)
    with pytest.raises(module["SpecError"], match="changed while") as caught:
        module["_read_proof_bytes"](str(path))
    assert caught.value.code == "E_CJSON"


def test_runtime_proof_verification_contains_deep_free_form_json():
    envelope = copy.deepcopy(next(
        item["envelope"] for item in VECTOR_CASES
        if item["name"] == "valid_hmac"))
    actor = {}
    cursor = actor
    for _ in range(2_000):
        child = {}
        cursor["nested"] = child
        cursor = child
    envelope["actor"] = actor

    result = verify_envelope(envelope, signer=None)
    assert not result["valid"]
    assert result["status"] == "invalid"
    assert "canonical I-JSON" in result["reason"]


def test_a_stranger_cannot_be_told_a_forgery_is_genuine():
    """SPEC §5. Without the HMAC secret an untouched envelope and a forged
    one are indistinguishable, so neither may read VALID."""
    genuine = next(v for v in VECTOR_CASES
                   if v["name"] == "unverified_hmac_no_key")
    forged = next(v for v in VECTOR_CASES
                  if v["name"] == "unverified_forged_body_no_key")
    assert forged["envelope"]["action_intent"]["statement"] != \
        genuine["envelope"]["action_intent"]["statement"], \
        "the forged vector is not actually forged"
    for vector in (genuine, forged):
        result = _run(vector)
        assert result["verdict"] == "UNVERIFIED", vector["name"]
        assert result["checks"]["C2_signature"] == "SKIPPED"
        assert result["checks"]["C3_authenticity"] == "SKIPPED", \
            "authenticity was reported without a verified signature"
        assert result["status"] is None, \
            "the envelope's own status was echoed as if established"


def _emitted_timestamp_proof():
    signer = Signer("timestamp-conformance", TIMESTAMP_KEY)
    envelope = ProofEnvelope(
        tenant_id="ten_timestamp",
        project_id="prj_timestamp",
        intent_type="task_complete",
        intent_statement="validate canonical timestamp",
        actor={"agent": "conformance"},
    )
    envelope.add_verification({
        "verifier": "optional-check",
        "result": "passed",
        "source": "executed",
    })
    return envelope.finalize(signer, []), signer


def _proof_schema_validator():
    schema = json.loads(PROOF_SCHEMA.read_text(encoding="utf-8"))
    return draft202012_validator(schema)


def test_schema_datetime_checker_is_stdlib_owned_without_optional_package(
        monkeypatch):
    """The locked harness must not inherit an optional ambient checker."""
    attempted = []
    native_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.partition(".")[0] == "rfc3339_validator":
            attempted.append(name)
            raise AssertionError("optional RFC 3339 package was imported")
        return native_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    checker = repository_format_checker()
    implementation, _raises = checker.checkers["date-time"]
    assert implementation is stdlib_rfc3339_datetime
    assert checker.conforms("2024-02-29T04:05:06.123456Z", "date-time")
    assert not checker.conforms("2026-02-30T04:05:06.123456Z", "date-time")
    assert attempted == []


def test_emitted_created_at_passes_schema_and_both_verifiers():
    envelope, signer = _emitted_timestamp_proof()

    _proof_schema_validator().validate(envelope)
    assert validate_envelope_shape(envelope) == []
    assert verify_envelope(envelope, signer)["valid"]
    result = _run({
        "envelope": envelope,
        "context": {"hmac_key_hex": TIMESTAMP_KEY.hex()},
    })
    assert result["verdict"] == "VALID"
    assert result["errors"] == []


def test_non_ascii_hmac_value_is_a_signature_failure_in_both_verifiers():
    envelope, signer = _emitted_timestamp_proof()
    envelope["signature"]["value"] = "é" * 64

    assert signer.verify(envelope) is False
    assert verify_envelope(envelope, signer)["valid"] is False
    result = _run({
        "envelope": envelope,
        "context": {"hmac_key_hex": TIMESTAMP_KEY.hex()},
    })
    assert result["verdict"] == "INVALID"
    assert result["checks"]["C2_signature"] == "FAIL"
    assert "E_SIGNATURE" in result["errors"]
    assert "E_CJSON" not in result["errors"]


@pytest.mark.parametrize("created_at", [
    "2026-08-04T04:05:06Z",
    "2026-08-04T04:05:06.123456+00:00",
    "2026-02-30T04:05:06.123456Z",
    "2026-08-04T04:05:60.123456Z",
    "2026-08-04t04:05:06.123456z",
])
def test_noncanonical_created_at_fails_schema_and_both_verifiers(
        tmp_path, created_at):
    envelope, signer = _emitted_timestamp_proof()
    envelope["created_at"] = created_at
    envelope["proof_digest"] = digest_obj({
        key: value for key, value in envelope.items()
        if key not in ("signature", "proof_digest")
    })
    envelope["signature"] = signer.sign(envelope)

    schema_errors = list(_proof_schema_validator().iter_errors(envelope))
    assert schema_errors
    assert any(
        "created_at" in error for error in validate_envelope_shape(envelope))
    result = _run({
        "envelope": envelope,
        "context": {"hmac_key_hex": TIMESTAMP_KEY.hex()},
    })
    assert result["verdict"] == "INVALID"
    assert "E_SHAPE" in result["errors"]


@pytest.mark.parametrize(
    ("verifications", "expected_status", "expected_passes"),
    [
        ([], "incomplete", []),
        ([{
            "verifier": "claimed",
            "result": "passed",
            "source": "self_asserted",
        }], "incomplete", []),
        ([{
            "verifier": "observed",
            "result": "passed",
            "source": "executed",
        }], "verified", ["observed"]),
        ([
            {
                "verifier": "first",
                "result": "passed",
                "source": "executed",
            },
            {
                "verifier": "second",
                "result": "passed",
                "source": "verifier_authoritative",
            },
        ], "verified", ["first", "second"]),
        ([
            {
                "verifier": "passed",
                "result": "passed",
                "source": "executed",
            },
            {
                "verifier": "skipped",
                "result": "skipped",
                "source": "verifier_authoritative",
            },
        ], "incomplete", ["passed"]),
    ],
)
def test_empty_required_is_nonvacuous_and_needs_only_authoritative_passes(
        verifications, expected_status, expected_passes):
    status, summary = evaluate_status(verifications, [])

    assert status == expected_status
    assert summary["required"] == []
    assert summary["unbacked_self_assertions"] == []
    assert summary["missing"] == []
    assert summary["skipped"] == []
    assert summary["passed"] == expected_passes
