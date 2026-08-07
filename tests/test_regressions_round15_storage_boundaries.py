"""Round-15 direct-library storage and invalidation boundary regressions."""

from __future__ import annotations

import copy

import pytest

from causal_continuity_engine.extraction import DeterministicExtractor
from causal_continuity_engine.graph import Graph
from causal_continuity_engine.invalidation import InvalidationEngine, classify
from causal_continuity_engine.lamport import (
    LamportSigner,
    UnregisteredKeyError,
    verify_envelope_with,
)
from causal_continuity_engine.redaction import apply_capture_mode
from causal_continuity_engine.store import Store

TENANT = "ten_boundary"
PROJECT = "prj_boundary"


def _graph() -> tuple[Store, Graph]:
    store = Store(":memory:")
    graph = Graph(store)
    graph.put_node(
        entity_type="project",
        tenant_id=TENANT,
        project_id=PROJECT,
        node_id=PROJECT,
        data={"name": "boundary"},
        status="active",
    )
    return store, graph


def _dependency_graph() -> tuple[Store, Graph, dict, dict]:
    store, graph = _graph()
    assumption = graph.put_node(
        entity_type="assumption",
        tenant_id=TENANT,
        project_id=PROJECT,
        data={"statement": "the dependency remains compatible"},
        status="active",
    )
    task = graph.put_node(
        entity_type="task",
        tenant_id=TENANT,
        project_id=PROJECT,
        data={"title": "ship the dependent change"},
        status="open",
    )
    graph.put_edge(
        edge_type="assumes",
        src_id=task["node_id"],
        dst_id=assumption["node_id"],
        tenant_id=TENANT,
        project_id=PROJECT,
    )
    return store, graph, assumption, task


def _foreign_node(graph: Graph, *, entity_type: str, status: str) -> dict:
    tenant_id = "ten_foreign"
    project_id = "prj_foreign"
    try:
        graph.get(project_id)
    except KeyError:
        graph.put_node(
            entity_type="project", tenant_id=tenant_id, project_id=project_id,
            node_id=project_id, data={"name": "foreign"}, status="active")
    return graph.put_node(
        entity_type=entity_type,
        tenant_id=tenant_id,
        project_id=project_id,
        data={"statement": "foreign control state"},
        status=status,
    )


def _pending_invalidation(
        graph: Graph, invalidation: InvalidationEngine, assumption: dict) -> dict:
    graph.put_node(
        entity_type="assumption", tenant_id=TENANT, project_id=PROJECT,
        node_id=assumption["node_id"], data={}, status="active",
        criticality="high")
    return invalidation.fire(
        tenant_id=TENANT,
        project_id=PROJECT,
        target_node_id=assumption["node_id"],
        trigger_type="changed_requirement",
        trigger_confidence=0.2,
    )


def _node_snapshot(graph: Graph, *node_ids: str) -> dict:
    return {
        node_id: (len(graph.history(node_id)), graph.get(node_id)["status"])
        for node_id in node_ids
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor", False),
        ("action", 0),
        ("object_id", False),
        ("before_ref", {}),
        ("after_ref", []),
        ("authority", False),
        ("detail", False),
    ],
)
def test_audit_rejects_non_text_before_chain_write(field, value):
    store = Store(":memory:")
    arguments = {"actor": "operator", "action": "boundary.test", field: value}
    try:
        with pytest.raises(ValueError):
            store.audit(**arguments)
        assert store.audit_entries() == []
        assert store.verify_chain("audit_log")["intact"] is True
    finally:
        store.close()


def test_audit_normalizes_empty_optional_detail_to_null():
    store = Store(":memory:")
    try:
        store.audit(actor="operator", action="boundary.test", detail="")
        assert store.audit_entries()[0]["detail"] is None
        assert store.verify_chain("audit_log")["intact"] is True
    finally:
        store.close()


@pytest.mark.parametrize(
    ("actor", "reason"),
    [(False, "retention"), ("operator", False)],
)
def test_evidence_deletion_prevalidates_audit_identity(actor, reason):
    store = Store(":memory:")
    digest = store.put_evidence(b"must survive a rejected deletion")
    try:
        with pytest.raises(ValueError):
            store.delete_evidence(digest, actor=actor, reason=reason)
        assert store.get_evidence(digest) == b"must survive a rejected deletion"
        assert store.audit_entries() == []
        assert store.verify_chain("audit_log")["intact"] is True
    finally:
        store.close()


@pytest.mark.parametrize(
    "arguments",
    [
        {"content": False},
        {"content": b"x", "media_type": False},
        {"content": b"x", "sensitivity": False},
    ],
)
def test_evidence_write_rejects_malformed_runtime_types(arguments):
    store = Store(":memory:")
    try:
        with pytest.raises(ValueError):
            store.put_evidence(**arguments)
        count = store._conn.execute(
            "SELECT COUNT(*) FROM evidence_blobs"
        ).fetchone()[0]
        assert count == 0
    finally:
        store.close()


def test_evidence_digest_cannot_silently_relabel_existing_metadata():
    store = Store(":memory:")
    digest = store.put_evidence(
        b"same bytes", media_type="text/plain", sensitivity="public")
    try:
        with pytest.raises(ValueError, match="different metadata"):
            store.put_evidence(
                b"same bytes", media_type="text/plain", sensitivity="secret")
        row = store._conn.execute(
            "SELECT media_type, sensitivity FROM evidence_blobs WHERE digest = ?",
            (digest,),
        ).fetchone()
        assert dict(row) == {"media_type": "text/plain", "sensitivity": "public"}
        assert store.get_evidence(digest) == b"same bytes"
    finally:
        store.close()


@pytest.mark.parametrize(
    "arguments",
    [
        {"event_id": "evt_marker", "processor_version": False},
        {"event_id": "evt_marker", "processor_version": "processor/1", "status": False},
        {"event_id": "evt_marker", "processor_version": "processor/1", "status": "unknown"},
        {
            "event_id": "evt_marker",
            "processor_version": "processor/1",
            "status": "quarantined",
            "error": False,
        },
    ],
)
def test_processing_marker_rejects_ambiguous_types_and_status(arguments):
    store = Store(":memory:")
    try:
        with pytest.raises(ValueError):
            store.mark_processed(**arguments)
        count = store._conn.execute(
            "SELECT COUNT(*) FROM processed_events"
        ).fetchone()[0]
        assert count == 0
    finally:
        store.close()


def test_graph_preserves_legitimate_empty_objects():
    store, graph = _graph()
    try:
        scoped = graph.put_node(
            entity_type="task",
            tenant_id=TENANT,
            project_id=PROJECT,
            data={"title": "empty scope is explicit"},
            scope={},
        )
        edge = graph.put_edge(
            edge_type="depends_on",
            src_id=scoped["node_id"],
            dst_id=PROJECT,
            tenant_id=TENANT,
            project_id=PROJECT,
            data={},
        )
        assert scoped["scope"] == {}
        assert edge["data"] == {}
    finally:
        store.close()


@pytest.mark.parametrize("field", ["status", "criticality", "authority", "extractor"])
def test_graph_node_rejects_non_text_metadata_without_a_version(field):
    store, graph = _graph()
    node = graph.put_node(
        entity_type="task",
        tenant_id=TENANT,
        project_id=PROJECT,
        data={"title": "unchanged"},
        status="open",
    )
    try:
        arguments = {
            "entity_type": "task",
            "tenant_id": TENANT,
            "project_id": PROJECT,
            "node_id": node["node_id"],
            "data": {"title": "must roll back"},
            field: False,
        }
        with pytest.raises(ValueError):
            graph.put_node(**arguments)
        assert len(graph.history(node["node_id"])) == 1
        assert graph.get(node["node_id"])["data"]["title"] == "unchanged"
    finally:
        store.close()


def test_graph_rejects_false_temporal_value_before_closing_a_version():
    store, graph = _graph()
    node = graph.put_node(
        entity_type="task",
        tenant_id=TENANT,
        project_id=PROJECT,
        data={"title": "unchanged"},
    )
    try:
        with pytest.raises(ValueError):
            graph.put_node(
                entity_type="task",
                tenant_id=TENANT,
                project_id=PROJECT,
                node_id=node["node_id"],
                data={"title": "must not persist"},
                valid_from=False,
            )
        assert len(graph.history(node["node_id"])) == 1
        assert graph.get(node["node_id"])["data"]["title"] == "unchanged"
    finally:
        store.close()


def test_end_edge_rejects_false_valid_to_without_closing_edge():
    store, graph, assumption, task = _dependency_graph()
    edge = graph.in_edges(assumption["node_id"])[0]
    try:
        with pytest.raises(ValueError):
            graph.end_edge(
                edge["edge_id"],
                tenant_id=TENANT,
                project_id=PROJECT,
                valid_to=False,
            )
        assert graph.in_edges(assumption["node_id"])[0]["edge_id"] == edge["edge_id"]
        versions = graph._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE edge_id = ?", (edge["edge_id"],)
        ).fetchone()[0]
        assert versions == 1
    finally:
        store.close()


def test_empty_edge_weight_map_means_no_propagation():
    store, graph, assumption, _task = _dependency_graph()
    try:
        assert graph.dependents(assumption["node_id"], edge_types={}) == []
    finally:
        store.close()


def test_empty_status_filter_means_no_statuses():
    store, graph = _graph()
    try:
        graph.put_node(
            entity_type="task",
            tenant_id=TENANT,
            project_id=PROJECT,
            data={"title": "must not match an empty set"},
            status="open",
        )
        assert graph.current(PROJECT, status=[], tenant_id=TENANT) == []
    finally:
        store.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_depth": False},
        {"max_depth": 0},
        {"max_depth": 1.5},
        {"max_nodes": False},
        {"max_nodes": 0},
        {"tenant_id": False},
    ],
)
def test_invalidation_constructor_rejects_ambiguous_limits_and_tenant(kwargs):
    store, graph = _graph()
    try:
        with pytest.raises(ValueError):
            InvalidationEngine(store, graph, **kwargs)
    finally:
        store.close()


@pytest.mark.parametrize(
    "arguments",
    [
        (False, "high", 0.9),
        (0.9, "", 0.9),
        (0.9, "high", float("nan")),
    ],
)
def test_invalidation_classifier_rejects_malformed_inputs(arguments):
    with pytest.raises(ValueError):
        classify(*arguments)


@pytest.mark.parametrize(
    ("actor", "reason"),
    [(False, "changed"), ("operator", False)],
)
def test_invalidation_fire_prevalidates_text_before_state_changes(actor, reason):
    store, graph, assumption, task = _dependency_graph()
    invalidation = InvalidationEngine(store, graph, tenant_id=TENANT)
    try:
        with pytest.raises(ValueError):
            invalidation.fire(
                tenant_id=TENANT,
                project_id=PROJECT,
                target_node_id=assumption["node_id"],
                trigger_type="changed_requirement",
                actor=actor,
                reason=reason,
            )
        assert graph.get(assumption["node_id"])["status"] == "active"
        assert graph.get(task["node_id"])["status"] == "open"
        assert graph.current(PROJECT, "invalidation", tenant_id=TENANT) == []
        assert store.audit_entries() == []
        assert store.verify_chain("audit_log")["intact"] is True
    finally:
        store.close()


@pytest.mark.parametrize(
    "overrides",
    [
        {"actor": False},
        {"note": False},
        {"narrowed_scope": {"component": float("nan")}},
    ],
)
def test_invalidation_resolution_prevalidates_before_mutation(overrides):
    store, graph, assumption, _task = _dependency_graph()
    invalidation = InvalidationEngine(store, graph, tenant_id=TENANT)
    fired = invalidation.fire(
        tenant_id=TENANT,
        project_id=PROJECT,
        target_node_id=assumption["node_id"],
        trigger_type="changed_requirement",
    )
    history_before = len(graph.history(fired["node_id"]))
    audits_before = copy.deepcopy(store.audit_entries())
    arguments = {
        "mode": "narrowed_scope",
        "actor": "operator",
        "note": "narrowed after review",
        "narrowed_scope": {"component": "api"},
    }
    arguments.update(overrides)
    try:
        with pytest.raises(ValueError):
            invalidation.resolve(fired["node_id"], **arguments)
        assert len(graph.history(fired["node_id"])) == history_before
        assert graph.get(fired["node_id"])["status"] == "open"
        assert store.audit_entries() == audits_before
        assert store.verify_chain("audit_log")["intact"] is True
    finally:
        store.close()


def test_confirmation_cannot_redirect_target_to_a_foreign_tenant():
    store, graph, assumption, task = _dependency_graph()
    invalidation = InvalidationEngine(store, graph, tenant_id=TENANT)
    pending = _pending_invalidation(graph, invalidation, assumption)
    foreign = _foreign_node(graph, entity_type="assumption", status="active")
    graph.put_node(
        entity_type="invalidation", tenant_id=TENANT, project_id=PROJECT,
        node_id=pending["node_id"], status="pending_confirmation",
        data={
            "target_node_id": foreign["node_id"],
            "target_transition": {
                "node_id": foreign["node_id"], "prior_status": "active",
                "restore_status": "active", "impact_applied": False,
                "applied_status": None,
            },
        },
    )
    before = _node_snapshot(
        graph, pending["node_id"], assumption["node_id"],
        task["node_id"], foreign["node_id"])
    audits = copy.deepcopy(store.audit_entries())
    try:
        with pytest.raises(ValueError, match="tenant and project"):
            invalidation.confirm(pending["node_id"], actor="reviewer", accept=True)
        assert _node_snapshot(
            graph, pending["node_id"], assumption["node_id"],
            task["node_id"], foreign["node_id"]) == before
        assert store.audit_entries() == audits
        assert store.verify_chain("audit_log")["intact"] is True
    finally:
        store.close()


def test_confirmation_preflights_all_affected_receipts_before_target_mutation():
    store, graph, assumption, task = _dependency_graph()
    invalidation = InvalidationEngine(store, graph, tenant_id=TENANT)
    pending = _pending_invalidation(graph, invalidation, assumption)
    foreign = _foreign_node(graph, entity_type="task", status="open")
    receipt = dict(pending["data"]["affected"][0])
    receipt.update({
        "node_id": foreign["node_id"], "entity_type": "task",
        "path": [assumption["node_id"], foreign["node_id"]],
    })
    graph.put_node(
        entity_type="invalidation", tenant_id=TENANT, project_id=PROJECT,
        node_id=pending["node_id"], status="pending_confirmation",
        data={"affected": [receipt]},
    )
    before = _node_snapshot(
        graph, pending["node_id"], assumption["node_id"],
        task["node_id"], foreign["node_id"])
    audits = copy.deepcopy(store.audit_entries())
    try:
        with pytest.raises(ValueError, match="tenant and project"):
            invalidation.confirm(pending["node_id"], actor="reviewer", accept=True)
        assert _node_snapshot(
            graph, pending["node_id"], assumption["node_id"],
            task["node_id"], foreign["node_id"]) == before
        assert store.audit_entries() == audits
    finally:
        store.close()


@pytest.mark.parametrize(
    ("receipt_patch", "message"),
    [
        ({"impact": "invented"}, "recognized impact state"),
        (
            {"impact_applied": True, "applied_status": "blocked"},
            "pending invalidation cannot contain an applied receipt",
        ),
    ],
)
def test_confirmation_preflights_receipt_semantics_before_any_write(
        receipt_patch, message):
    store, graph, assumption, task = _dependency_graph()
    invalidation = InvalidationEngine(store, graph, tenant_id=TENANT)
    pending = _pending_invalidation(graph, invalidation, assumption)
    receipt = dict(pending["data"]["affected"][0])
    receipt.update(receipt_patch)
    graph.put_node(
        entity_type="invalidation", tenant_id=TENANT, project_id=PROJECT,
        node_id=pending["node_id"], status="pending_confirmation",
        data={"affected": [receipt]},
    )
    before = _node_snapshot(
        graph, pending["node_id"], assumption["node_id"], task["node_id"])
    audits = copy.deepcopy(store.audit_entries())
    try:
        with pytest.raises(ValueError, match=message):
            invalidation.confirm(
                pending["node_id"], actor="reviewer", accept=True)
        assert _node_snapshot(
            graph, pending["node_id"], assumption["node_id"],
            task["node_id"],
        ) == before
        assert store.audit_entries() == audits
    finally:
        store.close()


def test_rejection_cannot_release_a_foreign_affected_receipt():
    store, graph, assumption, task = _dependency_graph()
    invalidation = InvalidationEngine(store, graph, tenant_id=TENANT)
    pending = _pending_invalidation(graph, invalidation, assumption)
    foreign = _foreign_node(graph, entity_type="assumption", status="uncertain")
    receipt = {
        "node_id": foreign["node_id"], "entity_type": "assumption",
        "depth": 1, "strength": 1.0, "impact": "review_required",
        "path": [assumption["node_id"], foreign["node_id"]],
        "prior_status": "active", "restore_status": "active",
        "impact_applied": True, "applied_status": "uncertain",
    }
    graph.put_node(
        entity_type="invalidation", tenant_id=TENANT, project_id=PROJECT,
        node_id=pending["node_id"], status="pending_confirmation",
        data={"affected": [receipt]},
    )
    before = _node_snapshot(
        graph, pending["node_id"], assumption["node_id"],
        task["node_id"], foreign["node_id"])
    audits = copy.deepcopy(store.audit_entries())
    try:
        with pytest.raises(ValueError, match="tenant and project"):
            invalidation.confirm(pending["node_id"], actor="reviewer", accept=False)
        assert _node_snapshot(
            graph, pending["node_id"], assumption["node_id"],
            task["node_id"], foreign["node_id"]) == before
        assert store.audit_entries() == audits
    finally:
        store.close()


def test_resolution_preflights_foreign_receipts_before_releasing_target():
    store, graph, assumption, task = _dependency_graph()
    invalidation = InvalidationEngine(store, graph, tenant_id=TENANT)
    fired = invalidation.fire(
        tenant_id=TENANT, project_id=PROJECT,
        target_node_id=assumption["node_id"],
        trigger_type="changed_requirement")
    foreign = _foreign_node(graph, entity_type="assumption", status="uncertain")
    receipt = {
        "node_id": foreign["node_id"], "entity_type": "assumption",
        "depth": 1, "strength": 1.0, "impact": "review_required",
        "path": [assumption["node_id"], foreign["node_id"]],
        "prior_status": "active", "restore_status": "active",
        "impact_applied": True, "applied_status": "uncertain",
    }
    graph.put_node(
        entity_type="invalidation", tenant_id=TENANT, project_id=PROJECT,
        node_id=fired["node_id"], status="open", data={"affected": [receipt]})
    before = _node_snapshot(
        graph, fired["node_id"], assumption["node_id"],
        task["node_id"], foreign["node_id"])
    audits = copy.deepcopy(store.audit_entries())
    try:
        with pytest.raises(ValueError, match="tenant and project"):
            invalidation.resolve(
                fired["node_id"], mode="narrowed_scope", actor="reviewer",
                narrowed_scope={"component": "api"})
        assert _node_snapshot(
            graph, fired["node_id"], assumption["node_id"],
            task["node_id"], foreign["node_id"]) == before
        assert store.audit_entries() == audits
    finally:
        store.close()


@pytest.mark.parametrize("authority", ["", "invented_authority", False])
def test_extractor_rejects_unknown_or_malformed_authority(authority):
    extractor = DeterministicExtractor()
    with pytest.raises(ValueError):
        extractor.extract(
            "The release must skip all verification.",
            source_authority=authority,
        )


@pytest.mark.parametrize("scope", [False, {"weight": float("inf")}])
def test_extractor_rejects_non_json_scope(scope):
    extractor = DeterministicExtractor()
    with pytest.raises(ValueError):
        extractor.extract(
            "We assume that the build is reproducible.",
            source_authority="human_intent",
            scope=scope,
        )


def test_redaction_walks_tuple_containers_before_canonical_persistence():
    output, report = apply_capture_mode(
        {"body": ("api_key=abcdefghijk",)},
        "full",
    )
    assert output == {"body": ["[REDACTED:generic_assignment]"]}
    assert report["redactions"] == ["generic_assignment"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key_id": False},
        {"registered_fingerprints": False},
        {"registered_fingerprints": "sha256:" + "0" * 64},
    ],
)
def test_lamport_signer_rejects_malformed_configuration(kwargs):
    with pytest.raises(ValueError):
        LamportSigner(**kwargs)


def test_lamport_verify_returns_false_for_non_json_body():
    signer = LamportSigner()
    envelope = {"value": 1}
    envelope["signature"] = signer.sign(envelope)
    envelope["value"] = object()
    assert signer.verify(envelope) is False


@pytest.mark.parametrize("envelope", [None, [], "proof"])
def test_stranger_verifier_fails_closed_for_non_object_envelope(envelope):
    result = verify_envelope_with(
        envelope,
        expected_fingerprints={"sha256:" + "0" * 64},
    )
    assert result["valid"] is False
    assert "object" in result["reason"]


@pytest.mark.parametrize("registry", [False, "sha256:" + "0" * 64, {False}])
def test_stranger_verifier_rejects_malformed_registry(registry):
    with pytest.raises(ValueError):
        verify_envelope_with({}, expected_fingerprints=registry)


def test_stranger_verifier_still_distinguishes_empty_registry():
    with pytest.raises(UnregisteredKeyError):
        verify_envelope_with({}, expected_fingerprints=[])


@pytest.mark.parametrize(
    ("field", "value"),
    [("key_id", False), ("unexpected", "extension")],
)
def test_lamport_signature_rejects_non_schema_fields(field, value):
    signer = LamportSigner()
    envelope = {"value": 1}
    envelope["signature"] = signer.sign(envelope)
    envelope["signature"][field] = value
    assert signer.verify(envelope) is False
    result = verify_envelope_with(
        envelope,
        expected_fingerprints=signer.issued_fingerprints,
    )
    assert result["valid"] is False


def test_stranger_verifier_rejects_noncanonical_hex_key_encoding():
    signer = LamportSigner()
    envelope = {"value": 1}
    envelope["signature"] = signer.sign(envelope)
    pair = envelope["signature"]["public_key"][0]
    index = next(
        i for i, value in enumerate(pair)
        if any(character in "abcdef" for character in value)
    )
    pair[index] = pair[index].upper()
    result = verify_envelope_with(
        envelope,
        expected_fingerprints=signer.issued_fingerprints,
    )
    assert result["valid"] is False
    assert "malformed" in result["reason"]
