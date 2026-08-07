"""Direct-library release boundaries reject malformed values before effects."""

from __future__ import annotations

import hashlib
import hmac
import json
import shlex
import sys

import pytest

from causal_continuity_engine.core import Signer, sha256_hex
from causal_continuity_engine.engine import AttestationInputError, Engine
from causal_continuity_engine.github import WebhookPayloadError
from causal_continuity_engine.proof import ProofEnvelope, evaluate_status
from causal_continuity_engine.store import Store
from causal_continuity_engine.verifiers import VerifierSpec

TENANT = "ten_release_boundary"
PROJECT = "prj_release_boundary"


def _engine(tmp_path, *, executable=False):
    config = {"max_autonomy_level": 2} if executable else None
    engine = Engine(
        tmp_path / "cce.db", tenant_id=TENANT,
        signer=Signer.generate("release-boundary"), workdir=tmp_path)
    try:
        engine.create_project(
            "release boundary", project_id=PROJECT, config=config)
        if executable:
            engine.policy.grant(
                project_id=PROJECT, level=2, granted_by="operator")
        return engine
    except BaseException:
        engine.close()
        raise


@pytest.mark.parametrize("signer", [False, 0, "", {}, []])
def test_engine_rejects_malformed_signer_before_opening_storage(
        tmp_path, signer):
    database = tmp_path / "must-not-open.db"

    with pytest.raises(ValueError, match="signer"):
        Engine(database, tenant_id=TENANT, signer=signer)
    assert not database.exists()


def test_engine_preserves_an_explicit_falsey_signer(tmp_path):
    class FalseySigner(Signer):
        def __bool__(self):
            return False

    signer = FalseySigner("falsey-signer", b"x" * 32)
    engine = Engine(
        tmp_path / "falsey-signer.db", tenant_id=TENANT, signer=signer)
    try:
        assert engine.signer is signer
    finally:
        engine.close()


@pytest.mark.parametrize("now", ["", 0, False, {}, []])
def test_active_grants_rejects_explicit_malformed_now_without_writes(
        tmp_path, now):
    engine = _engine(tmp_path)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="now must be an ISO-8601"):
            engine.policy.active_grants(PROJECT, now=now)
        assert engine.store._conn.total_changes == before
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        ("grant", {
            "project_id": PROJECT, "level": 1, "granted_by": "bad\nactor",
        }),
        ("grant", {
            "project_id": PROJECT, "level": 1, "granted_by": "operator",
            "reason": False,
        }),
        ("revoke", {
            "grant_id": "bad/id", "actor": "operator",
        }),
        ("revoke", {
            "grant_id": "grt_missing", "actor": "bad\nactor",
        }),
        ("downgrade", {
            "project_id": PROJECT, "trigger": "failed_proof", "actor": False,
        }),
        ("clear_downgrades", {
            "project_id": PROJECT, "actor": "bad\nactor",
        }),
    ],
)
def test_policy_control_mutators_reject_unsafe_public_values_without_writes(
        tmp_path, method, kwargs):
    engine = _engine(tmp_path)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError):
            getattr(engine.policy, method)(**kwargs)
        assert engine.store._conn.total_changes == before
        assert engine.store.audit_entries("policy.grant") == []
        assert engine.store.audit_entries("policy.revoke") == []
        assert engine.store.audit_entries("policy.downgrade") == []
        assert engine.store.audit_entries("policy.clear_downgrades") == []
    finally:
        engine.close()


@pytest.mark.parametrize("action_id", ["", 0, False, {}, []])
def test_proof_envelope_rejects_explicit_falsy_action_id(action_id):
    with pytest.raises(ValueError, match="action_id"):
        ProofEnvelope(
            tenant_id=TENANT, project_id=PROJECT, action_id=action_id,
            intent_type="task_complete", intent_statement="done",
            actor={"agent": "test"})


@pytest.mark.parametrize("requirement_ids", ["", 0, False, {}])
def test_proof_envelope_rejects_falsy_wrong_requirement_collection(
        requirement_ids):
    with pytest.raises(ValueError, match="requirement_ids"):
        ProofEnvelope(
            tenant_id=TENANT, project_id=PROJECT,
            intent_type="task_complete", intent_statement="done",
            actor={"agent": "test"}, requirement_ids=requirement_ids)


@pytest.mark.parametrize("required", ["", 0, False, {}])
def test_evaluate_status_rejects_falsy_wrong_required_collection(required):
    observed_pass = [{
        "verifier": "ci", "result": "passed", "source": "executed"}]
    with pytest.raises(ValueError, match="required_verifiers"):
        evaluate_status(observed_pass, required)


def test_evaluate_status_accepts_an_explicit_empty_required_array():
    status, summary = evaluate_status([{
        "verifier": "ci", "result": "passed", "source": "executed"}], [])
    assert status == "verified"
    assert summary["required"] == []


class _SignerSpy:
    calls = 0

    def sign(self, _body):
        self.calls += 1
        raise AssertionError("malformed draft reached signer")


@pytest.mark.parametrize(
    ("field", "value"),
    [("environment", []), ("verifications", None)],
)
def test_finalize_preflights_mutated_draft_before_signer(field, value):
    envelope = ProofEnvelope(
        tenant_id=TENANT, project_id=PROJECT,
        intent_type="task_complete", intent_statement="done",
        actor={"agent": "test"})
    envelope.body[field] = value
    signer = _SignerSpy()

    with pytest.raises(ValueError, match="proof draft is invalid"):
        envelope.finalize(signer, [])
    assert signer.calls == 0


_MALFORMED_OPTIONAL_COLLECTIONS = [
    (field, value)
    for field, invalid_values in {
        "continuity": ["", 0, False, []],
        "subjects": ["", 0, False, {}],
        "inputs": ["", 0, False, {}],
        "environment": ["", 0, False, []],
        "verifier_specs": ["", 0, False, {}],
        "verification_outcomes": ["", 0, False, {}],
    }.items()
    for value in invalid_values
]


@pytest.mark.parametrize(("field", "value"), _MALFORMED_OPTIONAL_COLLECTIONS)
def test_attest_rejects_falsy_wrong_collections_before_execution_or_write(
        tmp_path, field, value):
    engine = _engine(tmp_path, executable=True)
    marker = tmp_path / "must-not-run"
    spec = VerifierSpec(
        name="must-not-run",
        command=shlex.join([
            sys.executable, "-c",
            f"from pathlib import Path; Path({str(marker)!r}).touch()",
        ]))
    kwargs = {
        "continuity": {},
        "subjects": [],
        "inputs": [],
        "environment": {},
        "verifier_specs": [spec],
        "verification_outcomes": [],
    }
    kwargs[field] = value
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(AttestationInputError):
            engine.attest_action(
                PROJECT, intent_type="task_complete",
                intent_statement="done", actor={"agent": "test"},
                **kwargs)
        assert not marker.exists()
        assert engine.store._conn.total_changes == before
        assert engine.store.audit_entries("verifier.run") == []
        assert engine.graph.current(PROJECT, "action") == []
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("continuity", {}),
        ("subjects", []),
        ("inputs", []),
        ("environment", {}),
        ("verifier_specs", []),
        ("verification_outcomes", []),
        ("requirement_ids", []),
    ],
)
def test_attest_accepts_explicit_empty_values_of_the_declared_type(
        tmp_path, field, value):
    engine = _engine(tmp_path)
    try:
        proof = engine.attest_action(
            PROJECT, intent_type="task_complete", intent_statement="done",
            actor={"agent": "test"}, **{field: value})
        assert proof["status"] == "incomplete"
    finally:
        engine.close()


def test_proof_builder_validates_subject_and_input_at_mutation_boundary():
    envelope = ProofEnvelope(
        tenant_id=TENANT, project_id=PROJECT,
        intent_type="task_complete", intent_statement="done",
        actor={"agent": "test"})
    with pytest.raises(ValueError, match="subject digest"):
        envelope.add_subject("subject", "not-a-digest")
    with pytest.raises(ValueError, match="input name"):
        envelope.add_input("bad\nname", sha256_hex("value"))


@pytest.mark.parametrize(
    ("method", "args", "kwargs"),
    [
        ("set_environment", (), {"runtime": float("nan")}),
        ("add_execution", (), {"tool": "", "exit_code": 0}),
        ("add_execution", (), {"tool": "runner", "exit_code": False}),
        ("add_execution", (), {"tool": "runner", "started_at": ""}),
        ("add_verification", ([],), {}),
        ("add_verification", ({
            "verifier": "tests", "result": "passed", "source": "invented",
        },), {}),
        ("set_policy_decision", ([],), {}),
        ("set_policy_decision", ({"decision": "maybe"},), {}),
        ("set_continuity", (), {"task_ids": ["bad/id"]}),
        ("set_continuity", (), {"unknown": []}),
        ("set_evidence_context", (), {"unpinned_required": ""}),
        ("set_evidence_context", (), {"unknown": []}),
    ],
)
def test_proof_builder_rejects_malformed_nested_updates_atomically(
        method, args, kwargs):
    envelope = ProofEnvelope(
        tenant_id=TENANT, project_id=PROJECT,
        intent_type="task_complete", intent_statement="done",
        actor={"agent": "test"})
    before = json.loads(json.dumps(envelope.body))

    with pytest.raises(ValueError):
        getattr(envelope, method)(*args, **kwargs)
    assert envelope.body == before


def test_finalize_rejects_malformed_signer_output_atomically():
    class MalformedSigner:
        def sign(self, _body):
            return {"key_id": "key", "algorithm": "", "value": "signature"}

    envelope = ProofEnvelope(
        tenant_id=TENANT, project_id=PROJECT,
        intent_type="task_complete", intent_statement="done",
        actor={"agent": "test"})
    before = json.loads(json.dumps(envelope.body))

    with pytest.raises(ValueError, match="signed proof is invalid"):
        envelope.finalize(MalformedSigner(), [])
    assert envelope.body == before


@pytest.mark.parametrize("artifacts", ["", 0, False, {}])
def test_probe_evidence_rejects_wrong_artifact_collection_without_audit(
        tmp_path, artifacts):
    engine = _engine(tmp_path)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="artifacts must be a list"):
            engine.probe_evidence(PROJECT, artifacts=artifacts)
        assert engine.store._conn.total_changes == before
        assert engine.store.audit_entries("evidence.mutation_probe") == []
    finally:
        engine.close()


def test_probe_evidence_accepts_an_explicit_empty_artifact_array(tmp_path):
    engine = _engine(tmp_path)
    try:
        report = engine.probe_evidence(PROJECT, artifacts=[])
        assert report.artifacts == []
        assert len(engine.store.audit_entries("evidence.mutation_probe")) == 1
    finally:
        engine.close()


def _push_payload(after: str = "b" * 40):
    return {
        "ref": "refs/heads/main",
        "before": "a" * 40,
        "after": after,
        "forced": False,
        "deleted": False,
        "created": False,
        "commits": [],
        "repository": {"id": 424242, "full_name": "owner/repo"},
        "installation": {"id": 9191},
    }


def _bound_engine(tmp_path):
    engine = _engine(tmp_path)
    engine.bind_github_repository(
        PROJECT, repository_id=424242, repository="owner/repo",
        github_installation_id=9191)
    return engine


@pytest.mark.parametrize(
    "secret",
    ["", "short", b"x" * 31, b"x" * 4097, 7, bytearray(b"x" * 32)],
)
def test_direct_webhook_rejects_invalid_secret_before_any_write(
        tmp_path, secret):
    engine = _bound_engine(tmp_path)
    payload = _push_payload()
    raw = json.dumps(payload, separators=(",", ":")).encode()
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="webhook_secret"):
            engine.ingest_github(
                PROJECT, "push", "direct-secret", payload,
                raw_body=raw, signature_header="sha256=" + "0" * 64,
                webhook_secret=secret)
        assert engine.store._conn.total_changes == before
        assert engine.store.events(PROJECT) == []
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("raw_body", None, "raw_body"),
        ("raw_body", "not-bytes", "raw_body"),
        ("raw_body", bytearray(b"{}"), "raw_body"),
        ("raw_body", "__oversized_bytes__", "raw_body"),
        ("signature_header", None, "signature_header"),
        ("signature_header", b"sha256=bad", "signature_header"),
    ],
)
def test_direct_webhook_rejects_invalid_signed_operands_before_any_write(
        tmp_path, field, value, message):
    engine = _bound_engine(tmp_path)
    payload = _push_payload()
    kwargs = {
        "raw_body": json.dumps(payload).encode(),
        "signature_header": "sha256=" + "0" * 64,
        "webhook_secret": "s" * 32,
    }
    if value == "__oversized_bytes__":
        value = b"x" * (1024 * 1024 + 1)
    kwargs[field] = value
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match=message):
            engine.ingest_github(
                PROJECT, "push", "direct-operands", payload, **kwargs)
        assert engine.store._conn.total_changes == before
        assert engine.store.events(PROJECT) == []
    finally:
        engine.close()


def test_direct_webhook_cannot_authenticate_one_body_and_process_another(
        tmp_path):
    engine = _bound_engine(tmp_path)
    supplied = _push_payload("b" * 40)
    signed = _push_payload("c" * 40)
    raw = json.dumps(signed, separators=(",", ":")).encode()
    secret = b"s" * 32
    signature = "sha256=" + hmac.new(
        secret, raw, hashlib.sha256).hexdigest()
    before_audit = len(engine.store.audit_entries())
    try:
        with pytest.raises(
                WebhookPayloadError,
                match="does not match the signed webhook body"):
            engine.ingest_github(
                PROJECT, "push", "direct-mismatch", supplied,
                raw_body=raw, signature_header=signature,
                webhook_secret=secret)
        assert engine.store.events(PROJECT) == []
        rejected = engine.store.audit_entries("webhook.rejected")
        assert len(engine.store.audit_entries()) == before_audit + 1
        assert len(rejected) == 1
    finally:
        engine.close()


def _append_store_event(store, tenant_id, project_id, key):
    return store.append_event(
        tenant_id=tenant_id, project_id=project_id,
        source_type="agent_trace", idempotency_key=key,
        payload={"key": key}, authority="agent_inference")


def test_store_events_empty_identifier_cannot_disable_scope_filter():
    store = Store(":memory:")
    try:
        _append_store_event(store, "ten_one", "prj_one", "one")
        _append_store_event(store, "ten_one", "prj_two", "two")
        _append_store_event(store, "ten_two", "prj_three", "three")

        assert len(store.events()) == 3
        assert [event["project_id"] for event in store.events("prj_one")] == [
            "prj_one"]
        assert {event["project_id"] for event in store.events(
            tenant_id="ten_one")} == {"prj_one", "prj_two"}
        with pytest.raises(ValueError, match="project_id"):
            store.events(project_id="")
        with pytest.raises(ValueError, match="tenant_id"):
            store.events(tenant_id="")
    finally:
        store.close()


@pytest.mark.parametrize("since_seq", [True, -1, 1.5, "0"])
def test_store_events_rejects_invalid_sequence_cursor(since_seq):
    store = Store(":memory:")
    try:
        with pytest.raises(ValueError, match="since_seq"):
            store.events(since_seq=since_seq)
    finally:
        store.close()


@pytest.mark.parametrize("session_id", ["", 0, False, [], {}])
def test_resume_rejects_explicit_falsy_session_instead_of_selecting_latest(
        tmp_path, session_id):
    engine = _engine(tmp_path)
    engine.graph.put_node(
        entity_type="session", tenant_id=TENANT, project_id=PROJECT,
        data={"model": "local"}, status="active")
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="session_id"):
            engine.composer.compose(
                tenant_id=TENANT, project_id=PROJECT,
                session_id=session_id, signer=engine.signer)
        assert engine.store._conn.total_changes == before
    finally:
        engine.close()


@pytest.mark.parametrize("foreign", [False, True])
def test_resume_rejects_missing_or_foreign_session_scope(tmp_path, foreign):
    engine = _engine(tmp_path)
    session_id = "ses_foreign" if foreign else "ses_missing"
    if foreign:
        engine.create_project("foreign", project_id="prj_foreign")
        engine.graph.put_node(
            entity_type="session", tenant_id=TENANT,
            project_id="prj_foreign", node_id=session_id,
            data={"model": "foreign"}, status="active")
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(PermissionError, match="bound project"):
            engine.composer.compose(
                tenant_id=TENANT, project_id=PROJECT,
                session_id=session_id, signer=engine.signer)
        assert engine.store._conn.total_changes == before
    finally:
        engine.close()


def test_resume_explicit_local_session_is_preserved(tmp_path):
    engine = _engine(tmp_path)
    session = engine.graph.put_node(
        entity_type="session", tenant_id=TENANT, project_id=PROJECT,
        data={"model": "local"}, status="active")
    try:
        packet = engine.composer.compose(
            tenant_id=TENANT, project_id=PROJECT,
            session_id=session.id, signer=engine.signer)
        assert packet["continuity_lineage"]["source_session"] == session.id
    finally:
        engine.close()


def test_resume_packet_shape_is_preflighted_before_signer(tmp_path):
    engine = _engine(tmp_path)
    engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        data={"title": 7}, status="open")
    signer = _SignerSpy()
    try:
        with pytest.raises(ValueError, match="resume summary"):
            engine.composer.compose(
                tenant_id=TENANT, project_id=PROJECT, signer=signer)
        assert signer.calls == 0
    finally:
        engine.close()


@pytest.mark.parametrize("fmt", [None, "", "yaml", 0, False, []])
def test_engine_resume_rejects_unknown_format_before_watermark_write(
        tmp_path, fmt):
    engine = _engine(tmp_path)
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="resume format"):
            engine.resume_packet(PROJECT, fmt=fmt)
        assert engine.store._conn.total_changes == before
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("session_id", "", "session_id"),
        ("session_id", 0, "session_id"),
        ("session_id", False, "session_id"),
        ("session_id", [], "session_id"),
        ("span_id", "", "span_id"),
        ("span_id", "bad\nspan", "span_id"),
        ("span_id", "s" * 129, "span_id"),
        ("payload", "", "payload"),
        ("payload", 0, "payload"),
        ("payload", False, "payload"),
        ("payload", [], "payload"),
        ("payload", {"message": 7}, "message"),
        ("payload", {"message": "__oversized_message__"}, "at most 65536"),
        ("payload", {"score": float("nan")}, "finite canonical JSON"),
        ("observed_at", "not-a-time", "observed_at"),
    ],
)
def test_agent_trace_rejects_malformed_input_before_event_append(
        tmp_path, field, value, message):
    engine = _engine(tmp_path)
    kwargs = {
        "session_id": None,
        "span_id": "trace-span",
        "payload": {"message": "safe"},
    }
    if value == {"message": "__oversized_message__"}:
        value = {"message": "m" * 65_537}
    kwargs[field] = value
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match=message):
            engine.ingest_agent_trace(PROJECT, **kwargs)
        assert engine.store._conn.total_changes == before
        assert engine.store.events(PROJECT) == []
    finally:
        engine.close()


@pytest.mark.parametrize("foreign", [False, True])
def test_agent_trace_rejects_missing_or_foreign_session_before_append(
        tmp_path, foreign):
    engine = _engine(tmp_path)
    session_id = "ses_foreign_trace" if foreign else "ses_missing_trace"
    if foreign:
        engine.create_project("foreign", project_id="prj_foreign_trace")
        engine.graph.put_node(
            entity_type="session", tenant_id=TENANT,
            project_id="prj_foreign_trace", node_id=session_id,
            data={"model": "foreign"}, status="active")
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="requested project"):
            engine.ingest_agent_trace(
                PROJECT, session_id=session_id, span_id="trace-span",
                payload={"message": "safe"})
        assert engine.store._conn.total_changes == before
        assert engine.store.events(PROJECT) == []
    finally:
        engine.close()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("actor", "", "actor"),
        ("actor", "bad\nactor", "control character"),
        ("actor", 7, "actor"),
        ("decision", "", "decision"),
        ("decision", "bad\ndecision", "control character"),
        ("decision", 7, "decision"),
        ("scope", "", "scope"),
        ("scope", False, "scope"),
        ("scope", [], "scope"),
        ("scope", {"score": float("inf")}, "finite canonical JSON"),
        ("request_id", "", "request_id"),
        ("request_id", 0, "request_id"),
        ("request_id", False, "request_id"),
        ("request_id", [], "request_id"),
    ],
)
def test_human_decision_rejects_malformed_input_before_event_append(
        tmp_path, field, value, message):
    engine = _engine(tmp_path)
    kwargs = {
        "actor": "operator",
        "decision": "approve",
        "scope": {},
        "request_id": "decision-request",
    }
    kwargs[field] = value
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match=message):
            engine.ingest_human_decision(PROJECT, **kwargs)
        assert engine.store._conn.total_changes == before
        assert engine.store.events(PROJECT) == []
    finally:
        engine.close()


@pytest.mark.parametrize("method", ["complete", "bind"])
@pytest.mark.parametrize("actor", ["", "bad\nactor", 7, False])
def test_human_actor_mutations_reject_unsafe_actor_before_write(
        tmp_path, method, actor):
    engine = _engine(tmp_path)
    task = engine.graph.put_node(
        entity_type="task", tenant_id=TENANT, project_id=PROJECT,
        data={"title": "task"}, status="open")
    before = engine.store._conn.total_changes
    try:
        with pytest.raises(ValueError, match="actor|control character"):
            if method == "complete":
                engine.complete_task(PROJECT, task.id, actor=actor)
            else:
                engine.bind_github_repository(
                    PROJECT, repository_id=424242, actor=actor)
        assert engine.store._conn.total_changes == before
    finally:
        engine.close()
