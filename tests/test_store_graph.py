"""Store + graph: immutability, idempotency, bi-temporal queries, traversal."""

import pytest

from causal_continuity_engine.core import Signer, sha256_hex, utcnow
from causal_continuity_engine.graph import Graph, TraversalBudgetExceeded
from causal_continuity_engine.store import DuplicateEventError, PayloadMismatchError, Store

TEN, PRJ = "ten_t", "prj_t"


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


@pytest.fixture
def graph(store):
    return Graph(store)


def _event(store, key="k1", payload=None, **kw):
    return store.append_event(
        tenant_id=TEN, project_id=PRJ, source_type="test",
        idempotency_key=key, payload=payload or {"a": 1},
        authority="repository_authoritative", **kw)


class TestEventStore:
    def test_append_and_get(self, store):
        ev = _event(store)
        assert ev["event_id"].startswith("evt_")
        assert ev["payload"] == {"a": 1}
        assert ev["payload_digest"].startswith("sha256:")
        assert store.get_event(ev["event_id"])["seq"] == 1

    def test_duplicate_same_payload_raises_benign(self, store):
        _event(store, "dup")
        with pytest.raises(DuplicateEventError):
            _event(store, "dup")
        assert len(store.events(PRJ)) == 1

    def test_redelivery_with_changed_payload_flagged(self, store):
        _event(store, "dup", {"a": 1})
        with pytest.raises(PayloadMismatchError):
            _event(store, "dup", {"a": 2})
        assert len(store.payload_mismatches()) == 1
        assert len(store.events(PRJ)) == 1

    def test_evidence_content_addressed(self, store):
        d1 = store.put_evidence("hello")
        d2 = store.put_evidence("hello")
        assert d1 == d2 == sha256_hex("hello")
        assert store.get_evidence(d1) == b"hello"

    def test_evidence_deletion_keeps_audit(self, store):
        d = store.put_evidence("secret data")
        assert store.delete_evidence(d, actor="admin", reason="gdpr")
        assert store.get_evidence(d) is None
        entries = store.audit_entries("evidence.delete")
        assert len(entries) == 1 and entries[0]["object_id"] == d

    def test_quarantine_tracking(self, store):
        ev = _event(store)
        store.mark_processed(ev["event_id"], "v1", "quarantined", "boom")
        assert store.quarantined("v1")[0]["event_id"] == ev["event_id"]


class TestGraph:
    def test_versioning_supersedes_not_overwrites(self, graph):
        n = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "s1"}, status="proposed")
        n2 = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                            node_id=n.id, data={}, status="active")
        assert n2["version"] == 2 and n2["status"] == "active"
        hist = graph.history(n.id)
        assert [h["version"] for h in hist] == [1, 2]
        assert hist[0]["tx_to"] is not None       # closed, not deleted
        assert hist[0]["status"] == "proposed"    # history intact
        assert n2["data"]["statement"] == "s1"    # carry-forward merge

    def test_as_of_transaction_time(self, graph):
        n = graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "x"}, status="recorded")
        t_between = utcnow()
        graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                       node_id=n.id, data={}, status="superseded")
        assert graph.get(n.id)["status"] == "superseded"
        assert graph.get(n.id, as_of_tx=t_between)["status"] == "recorded"
        assert len(graph.as_of(PRJ, t_between, "claim")) == 1
        assert graph.as_of(PRJ, t_between, "claim")[0]["status"] == "recorded"

    def test_dependents_direction_and_bounds(self, graph):
        a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={"statement": "assumption A"}, status="active")
        t = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                           data={"title": "task T"}, status="open")
        d = graph.put_node(entity_type="decision", tenant_id=TEN, project_id=PRJ,
                           data={"title": "decision D"}, status="accepted")
        graph.put_edge(edge_type="assumes", src_id=t.id, dst_id=a.id,
                       tenant_id=TEN, project_id=PRJ)
        graph.put_edge(edge_type="depends_on", src_id=d.id, dst_id=t.id,
                       tenant_id=TEN, project_id=PRJ)
        deps = graph.dependents(a.id)
        ids = {x["node_id"] for x in deps}
        assert ids == {t.id, d.id}
        by_id = {x["node_id"]: x for x in deps}
        assert by_id[t.id]["depth"] == 1 and by_id[d.id]["depth"] == 2
        assert by_id[d.id]["strength"] < by_id[t.id]["strength"]
        # depth bound
        assert graph.dependents(a.id, max_depth=1) and \
            all(x["depth"] <= 1 for x in graph.dependents(a.id, max_depth=1))

    def test_traversal_node_budget(self, graph):
        hub = graph.put_node(entity_type="assumption", tenant_id=TEN,
                             project_id=PRJ, data={"statement": "hub"},
                             status="active")
        for i in range(30):
            t = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                               data={"title": f"t{i}"}, status="open")
            graph.put_edge(edge_type="assumes", src_id=t.id, dst_id=hub.id,
                           tenant_id=TEN, project_id=PRJ)
        with pytest.raises(TraversalBudgetExceeded):
            graph.dependents(hub.id, max_nodes=10)

    def test_edge_versioning_dedupe(self, graph):
        a = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                           data={}, status="open")
        b = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={}, status="active")
        e1 = graph.put_edge(edge_type="assumes", src_id=a.id, dst_id=b.id,
                            tenant_id=TEN, project_id=PRJ)
        e2 = graph.put_edge(edge_type="assumes", src_id=a.id, dst_id=b.id,
                            tenant_id=TEN, project_id=PRJ, strength=0.5)
        assert e1["edge_id"] == e2["edge_id"] and e2["version"] == 2
        assert len(graph.out_edges(a.id, {"assumes"})) == 1

    def test_provenance_trail(self, store, graph):
        ev = _event(store, "prov")
        evidence = graph.put_node(entity_type="evidence", tenant_id=TEN,
                                  project_id=PRJ, data={"name": "ci log"},
                                  status="recorded", event_id=ev["event_id"])
        claim = graph.put_node(entity_type="claim", tenant_id=TEN, project_id=PRJ,
                               data={"statement": "tests pass"}, status="recorded",
                               event_id=ev["event_id"])
        graph.put_edge(edge_type="derived_from", src_id=claim.id, dst_id=evidence.id,
                       tenant_id=TEN, project_id=PRJ)
        trail = graph.provenance(claim.id)
        assert trail["versions"][0]["source"]["source_type"] == "test"
        assert any(s["node_id"] == evidence.id for s in trail["sources"])

    def test_causal_path(self, graph):
        a = graph.put_node(entity_type="assumption", tenant_id=TEN, project_id=PRJ,
                           data={}, status="active")
        b = graph.put_node(entity_type="task", tenant_id=TEN, project_id=PRJ,
                           data={}, status="open")
        graph.put_edge(edge_type="assumes", src_id=b.id, dst_id=a.id,
                       tenant_id=TEN, project_id=PRJ)
        path = graph.causal_path(a.id, b.id)
        assert path and path[-1]["to"] == b.id


class TestSigner:
    def test_sign_verify_and_tamper(self):
        s = Signer.generate()
        obj = {"a": 1, "b": [1, 2]}
        obj["signature"] = s.sign(obj)
        assert s.verify(obj)
        obj["a"] = 2
        assert not s.verify(obj)
