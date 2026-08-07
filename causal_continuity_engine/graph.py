"""Bi-temporal causal graph engine (CCG-002..CCG-008).

Graph rows are projections of the event log: every write carries the
event_id that caused it plus extractor/rule version and confidence
(CCG-006, CCG-007). Nodes and edges are append/version operations — a new
version closes the previous row's transaction time; nothing is deleted
(supersede, don't overwrite).

Two time axes per row (ADR-003):
  valid_from/valid_to  — when the fact holds in the project world
  tx_from/tx_to        — when CCE believed/recorded it

Traversal is bounded by project, edge depth, node count, and edge types
(CCG-008).

Node and edge identity is immutable after first insertion.  Versioning may
change a fact's attributes or validity, never its entity type, tenant,
project, endpoints, or relation type.  Traversal derives its scope from the
anchor node so a malformed legacy edge cannot bridge projects.  This is an
application boundary in the SQLite reference; hosted storage still needs RLS
and database constraints (ADR-011).
"""

from __future__ import annotations

import math
from collections import deque

from .core import (
    canonical_json,
    is_rfc3339_datetime,
    new_id,
    strict_json_loads,
    utcnow,
    validate_public_identifier,
)
from .ontology import EDGE_TYPES, ENTITY_TYPES, PROPAGATION_EDGES
from .store import serialized_access

_GRAPH_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    row_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id      TEXT NOT NULL,
    version      INTEGER NOT NULL,
    entity_type  TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    project_id   TEXT NOT NULL,
    status       TEXT,
    criticality  TEXT,
    authority    TEXT,
    confidence   REAL,
    scope        TEXT,
    data         TEXT NOT NULL,
    valid_from   TEXT,
    valid_to     TEXT,
    tx_from      TEXT NOT NULL,
    tx_to        TEXT,
    event_id     TEXT,
    extractor    TEXT,
    extractor_version TEXT,
    UNIQUE (node_id, version)
);
CREATE INDEX IF NOT EXISTS idx_nodes_current ON nodes(project_id, entity_type, tx_to);
CREATE INDEX IF NOT EXISTS idx_nodes_id ON nodes(node_id, tx_to);

CREATE TABLE IF NOT EXISTS edges (
    row_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    edge_id     TEXT NOT NULL,
    version     INTEGER NOT NULL,
    edge_type   TEXT NOT NULL,
    src_id      TEXT NOT NULL,
    dst_id      TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    project_id  TEXT NOT NULL,
    strength    REAL NOT NULL DEFAULT 1.0,
    data        TEXT,
    valid_from  TEXT,
    valid_to    TEXT,
    tx_from     TEXT NOT NULL,
    tx_to       TEXT,
    event_id    TEXT,
    UNIQUE (edge_id, version)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(project_id, src_id, tx_to);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(project_id, dst_id, tx_to);
"""


def _validate_optional_text(name: str, value) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string or null")
    try:
        canonical_json(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError(f"{name} must be I-JSON text: {exc}") from None
    return value


def _validate_optional_datetime(name: str, value) -> str | None:
    if value is None:
        return None
    if not is_rfc3339_datetime(value):
        raise ValueError(f"{name} must be an RFC 3339 date-time or null")
    return value


class Node(dict):
    @property
    def id(self) -> str:
        return self["node_id"]


class TraversalBudgetExceeded(Exception):
    pass


class Graph:
    """Projection layer over a Store's SQLite connection."""

    def __init__(self, store):
        self.store = store
        self._conn = store._conn
        self._lock = store._lock
        with self._lock, self._conn:
            self._conn.executescript(_GRAPH_SCHEMA)

    # ------------------------------------------------------------------ write

    def put_node(
        self,
        *,
        entity_type: str,
        tenant_id: str,
        project_id: str,
        data: dict,
        node_id: str | None = None,
        status: str | None = None,
        criticality: str | None = None,
        authority: str | None = None,
        confidence: float | None = None,
        scope: dict | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        event_id: str | None = None,
        extractor: str | None = None,
        extractor_version: str | None = None,
    ) -> Node:
        """Create a node or append a new version of an existing node."""
        if not isinstance(entity_type, str) or entity_type not in ENTITY_TYPES:
            raise ValueError(f"unknown entity type {entity_type!r}")
        tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        project_id = validate_public_identifier(project_id, field="project_id")
        if node_id is not None:
            node_id = validate_public_identifier(node_id, field="node_id")
        if event_id is not None:
            event_id = validate_public_identifier(event_id, field="event_id")
        status = _validate_optional_text("node status", status)
        criticality = _validate_optional_text("node criticality", criticality)
        authority = _validate_optional_text("node authority", authority)
        extractor = _validate_optional_text("node extractor", extractor)
        extractor_version = _validate_optional_text(
            "node extractor_version", extractor_version)
        valid_from = _validate_optional_datetime("node valid_from", valid_from)
        valid_to = _validate_optional_datetime("node valid_to", valid_to)
        if not isinstance(data, dict):
            raise ValueError("node data must be an object")
        if scope is not None and not isinstance(scope, dict):
            raise ValueError("node scope must be an object or null")
        if confidence is not None and (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not math.isfinite(confidence)
                or not 0 <= confidence <= 1):
            raise ValueError("node confidence must be finite and between 0 and 1")
        # Validate before closing the previous version.  The merged value is
        # encoded again below after carry-forward.
        canonical_json(data)
        if scope is not None:
            canonical_json(scope)
        now = utcnow()
        with self.store.write_scope():
            self._require_event_scope(event_id, tenant_id, project_id)
            if node_id is None:
                node_id = new_id(entity_type if entity_type in
                                 ("assumption", "decision", "claim", "requirement",
                                  "task", "action", "evidence", "verification",
                                  "session", "invalidation", "plan", "outcome",
                                  "artifact", "constraint", "skill", "evaluation",
                                  "checkpoint", "failure")
                                 else "node")
                version = 1
                prev = None
            else:
                prev = self._current_row("nodes", "node_id", node_id)
                version = (prev["version"] + 1) if prev else 1
            if prev is not None:
                identity = (entity_type, tenant_id, project_id)
                previous_identity = (
                    prev["entity_type"], prev["tenant_id"], prev["project_id"])
                if identity != previous_identity:
                    raise ValueError(
                        f"immutable node identity for {node_id}: "
                        f"existing {previous_identity!r}, requested {identity!r}")
                self._conn.execute(
                    "UPDATE nodes SET tx_to = ? WHERE row_id = ?", (now, prev["row_id"])
                )
                # carry forward unspecified fields from the previous version
                status = status if status is not None else prev["status"]
                criticality = criticality if criticality is not None else prev["criticality"]
                authority = authority if authority is not None else prev["authority"]
                confidence = confidence if confidence is not None else prev["confidence"]
                scope = scope if scope is not None else (
                    strict_json_loads(prev["scope"]) if prev["scope"] else None
                )
                valid_from = valid_from if valid_from is not None else prev["valid_from"]
                # valid_to must carry forward like every other field: a status
                # transition on a fact that was valid only until T must not
                # silently reopen its validity to forever (ADR-003). Widening
                # requires an explicit valid_to, or a new superseding node.
                valid_to = valid_to if valid_to is not None else prev["valid_to"]
                merged = strict_json_loads(prev["data"])
                merged.update(data)
                data = merged
            encoded_scope = canonical_json(scope) if scope is not None else None
            encoded_data = canonical_json(data)
            self._conn.execute(
                "INSERT INTO nodes (node_id, version, entity_type, tenant_id, project_id,"
                " status, criticality, authority, confidence, scope, data, valid_from,"
                " valid_to, tx_from, tx_to, event_id, extractor, extractor_version)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    node_id, version, entity_type, tenant_id, project_id, status,
                    criticality, authority, confidence,
                    encoded_scope, encoded_data,
                    valid_from if valid_from is not None else now,
                    valid_to, now, None, event_id,
                    extractor, extractor_version,
                ),
            )
        return self.get(
            node_id, tenant_id=tenant_id, project_id=project_id,
            entity_type=entity_type)

    def put_edge(
        self,
        *,
        edge_type: str,
        src_id: str,
        dst_id: str,
        tenant_id: str,
        project_id: str,
        strength: float = 1.0,
        data: dict | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        event_id: str | None = None,
        edge_id: str | None = None,
    ) -> dict:
        if not isinstance(edge_type, str) or edge_type not in EDGE_TYPES:
            raise ValueError(f"unknown edge type {edge_type!r}")
        tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        project_id = validate_public_identifier(project_id, field="project_id")
        src_id = validate_public_identifier(src_id, field="src_id")
        dst_id = validate_public_identifier(dst_id, field="dst_id")
        if edge_id is not None:
            edge_id = validate_public_identifier(edge_id, field="edge_id")
        if event_id is not None:
            event_id = validate_public_identifier(event_id, field="event_id")
        valid_from = _validate_optional_datetime("edge valid_from", valid_from)
        valid_to = _validate_optional_datetime("edge valid_to", valid_to)
        if (isinstance(strength, bool)
                or not isinstance(strength, (int, float))
                or not math.isfinite(strength)
                or not 0 <= strength <= 1):
            raise ValueError("edge strength must be finite and between 0 and 1")
        if data is not None and not isinstance(data, dict):
            raise ValueError("edge data must be an object or null")
        encoded_data = canonical_json(data) if data is not None else None
        now = utcnow()
        with self.store.write_scope():
            self._require_event_scope(event_id, tenant_id, project_id)
            src = self._reference_scope(src_id)
            dst = self._reference_scope(dst_id)
            expected_scope = (tenant_id, project_id)
            if src is None or dst is None or \
                    src != expected_scope or dst != expected_scope:
                raise ValueError(
                    "edge endpoints must belong to the edge tenant and project: "
                    f"{tenant_id}/{project_id}")
            if edge_id is None:
                existing = self._conn.execute(
                    "SELECT * FROM edges WHERE tenant_id = ? AND project_id = ? AND"
                    " edge_type = ? AND"
                    " src_id = ? AND dst_id = ? AND tx_to IS NULL",
                    (tenant_id, project_id, edge_type, src_id, dst_id),
                ).fetchone()
                if existing:
                    edge_id = existing["edge_id"]
            prev = self._current_row("edges", "edge_id", edge_id) if edge_id else None
            if edge_id is None:
                edge_id = new_id("edge")
            version = (prev["version"] + 1) if prev else 1
            if prev is not None:
                identity = (
                    edge_type, src_id, dst_id, tenant_id, project_id)
                previous_identity = (
                    prev["edge_type"], prev["src_id"], prev["dst_id"],
                    prev["tenant_id"], prev["project_id"])
                if identity != previous_identity:
                    raise ValueError(
                        f"immutable edge identity for {edge_id}: "
                        f"existing {previous_identity!r}, requested {identity!r}")
                self._conn.execute(
                    "UPDATE edges SET tx_to = ? WHERE row_id = ?", (now, prev["row_id"])
                )
            self._conn.execute(
                "INSERT INTO edges (edge_id, version, edge_type, src_id, dst_id, tenant_id,"
                " project_id, strength, data, valid_from, valid_to, tx_from, tx_to, event_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    edge_id, version, edge_type, src_id, dst_id, tenant_id, project_id,
                    strength, encoded_data,
                    valid_from if valid_from is not None else now,
                    valid_to, now, None, event_id,
                ),
            )
            row = self._current_row("edges", "edge_id", edge_id)
        return self._edge_dict(row)

    def end_edge(
        self,
        edge_id: str,
        *,
        tenant_id: str,
        project_id: str,
        event_id: str | None = None,
        valid_to: str | None = None,
    ):
        """Close an edge's validity (supersede-style, history preserved)."""
        edge_id = validate_public_identifier(edge_id, field="edge_id")
        tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        project_id = validate_public_identifier(project_id, field="project_id")
        if event_id is not None:
            event_id = validate_public_identifier(event_id, field="event_id")
        valid_to = _validate_optional_datetime("edge valid_to", valid_to)
        now = utcnow()
        with self.store.write_scope():
            self._require_event_scope(event_id, tenant_id, project_id)
            prev = self._current_row("edges", "edge_id", edge_id)
            if prev is None:
                raise KeyError(edge_id)
            if (prev["tenant_id"], prev["project_id"]) != (tenant_id, project_id):
                raise PermissionError(
                    f"edge {edge_id} does not belong to {tenant_id}/{project_id}")
            self._conn.execute("UPDATE edges SET tx_to = ? WHERE row_id = ?", (now, prev["row_id"]))
            self._conn.execute(
                "INSERT INTO edges (edge_id, version, edge_type, src_id, dst_id, tenant_id,"
                " project_id, strength, data, valid_from, valid_to, tx_from, tx_to, event_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    edge_id, prev["version"] + 1, prev["edge_type"], prev["src_id"],
                    prev["dst_id"], prev["tenant_id"], prev["project_id"], prev["strength"],
                    prev["data"], prev["valid_from"],
                    valid_to if valid_to is not None else now,
                    now, None, event_id,
                ),
            )

    # ------------------------------------------------------------------- read

    @serialized_access
    def _current_row(self, table: str, key: str, value: str):
        return self._conn.execute(
            f"SELECT * FROM {table} WHERE {key} = ? AND tx_to IS NULL", (value,)
        ).fetchone()

    @serialized_access
    def _reference_scope(self, reference_id: str) -> tuple[str, str] | None:
        """Scope of a graph node or canonical event provenance reference."""
        node = self._current_row("nodes", "node_id", reference_id)
        if node is not None:
            return node["tenant_id"], node["project_id"]
        try:
            event = self.store.get_event(reference_id)
        except KeyError:
            return None
        return event["tenant_id"], event["project_id"]

    def _require_event_scope(
            self, event_id: str | None, tenant_id: str, project_id: str) -> None:
        if event_id is None:
            return
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("event provenance id must be a non-empty string or null")
        try:
            self.store.get_event(
                event_id, tenant_id=tenant_id, project_id=project_id)
        except KeyError:
            raise ValueError(
                "event provenance must belong to the graph tenant and project: "
                f"{tenant_id}/{project_id}") from None

    @serialized_access
    def get(
        self,
        node_id: str,
        as_of_tx: str | None = None,
        *,
        tenant_id: str | None = None,
        project_id: str | None = None,
        entity_type: str | None = None,
    ) -> Node:
        """Return one node, optionally requiring its immutable identity.

        Callers acting on a named project should pass ``project_id``.  The
        optional form preserves internal id-only lookups where the project is
        subsequently derived from the node rather than supplied by a caller.
        """
        if as_of_tx is None:
            row = self._current_row("nodes", "node_id", node_id)
        else:
            row = self._conn.execute(
                "SELECT * FROM nodes WHERE node_id = ? AND tx_from <= ? AND"
                " (tx_to IS NULL OR tx_to > ?) ORDER BY version DESC LIMIT 1",
                (node_id, as_of_tx, as_of_tx),
            ).fetchone()
        if row is None or \
                (tenant_id is not None and row["tenant_id"] != tenant_id) or \
                (project_id is not None and row["project_id"] != project_id) or \
                (entity_type is not None and row["entity_type"] != entity_type):
            raise KeyError(node_id)
        return self._node_dict(row)

    @serialized_access
    def history(
            self, node_id: str, *, tenant_id: str | None = None,
            project_id: str | None = None) -> list[Node]:
        q = "SELECT * FROM nodes WHERE node_id = ?"
        args: list = [node_id]
        if tenant_id is not None:
            q += " AND tenant_id = ?"
            args.append(tenant_id)
        if project_id is not None:
            q += " AND project_id = ?"
            args.append(project_id)
        rows = self._conn.execute(q + " ORDER BY version", args).fetchall()
        return [self._node_dict(r) for r in rows]

    @serialized_access
    def current(
        self,
        project_id: str,
        entity_type: str | None = None,
        status: str | list[str] | None = None,
        valid_at: str | None = None,
        *,
        tenant_id: str | None = None,
    ) -> list[Node]:
        project_id = validate_public_identifier(project_id, field="project_id")
        if tenant_id is not None:
            tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        if entity_type is not None and (
                not isinstance(entity_type, str) or entity_type not in ENTITY_TYPES):
            raise ValueError(f"unknown entity type {entity_type!r}")
        statuses: list[str] | None = None
        if status is not None:
            if isinstance(status, str):
                statuses = [status]
            elif isinstance(status, list):
                statuses = list(status)
            else:
                raise ValueError("status filter must be a string, list, or null")
            if any(not isinstance(item, str) or not item for item in statuses):
                raise ValueError("status filter values must be non-empty strings")
            if not statuses:
                return []
        valid_at = _validate_optional_datetime("valid_at", valid_at)
        q = "SELECT * FROM nodes WHERE project_id = ? AND tx_to IS NULL"
        args: list = [project_id]
        if tenant_id is not None:
            q += " AND tenant_id = ?"
            args.append(tenant_id)
        if entity_type is not None:
            q += " AND entity_type = ?"
            args.append(entity_type)
        if statuses is not None:
            q += " AND status IN (%s)" % ",".join("?" * len(statuses))
            args.extend(statuses)
        if valid_at is not None:
            q += " AND (valid_from IS NULL OR valid_from <= ?)" \
                 " AND (valid_to IS NULL OR valid_to > ?)"
            args.extend([valid_at, valid_at])
        return [self._node_dict(r) for r in self._conn.execute(q + " ORDER BY row_id", args)]

    @serialized_access
    def as_of(
            self, project_id: str, tx_time: str,
            entity_type: str | None = None, *,
            tenant_id: str | None = None) -> list[Node]:
        """Project belief state as known at transaction time (CCG-004)."""
        project_id = validate_public_identifier(project_id, field="project_id")
        if tenant_id is not None:
            tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        if not is_rfc3339_datetime(tx_time):
            raise ValueError("tx_time must be an RFC 3339 date-time")
        if entity_type is not None and (
                not isinstance(entity_type, str) or entity_type not in ENTITY_TYPES):
            raise ValueError(f"unknown entity type {entity_type!r}")
        q = ("SELECT * FROM nodes WHERE project_id = ? AND tx_from <= ? AND"
             " (tx_to IS NULL OR tx_to > ?)")
        args: list = [project_id, tx_time, tx_time]
        if tenant_id is not None:
            q += " AND tenant_id = ?"
            args.append(tenant_id)
        if entity_type is not None:
            q += " AND entity_type = ?"
            args.append(entity_type)
        return [self._node_dict(r) for r in self._conn.execute(q, args)]

    @serialized_access
    def out_edges(self, node_id: str, edge_types: set[str] | None = None,
                  valid_at: str | None = None) -> list[dict]:
        return self._edges_for("src_id", node_id, edge_types, valid_at)

    @serialized_access
    def in_edges(self, node_id: str, edge_types: set[str] | None = None,
                 valid_at: str | None = None) -> list[dict]:
        return self._edges_for("dst_id", node_id, edge_types, valid_at)

    @serialized_access
    def _edges_for(self, col: str, node_id: str, edge_types,
                   valid_at: str | None = None) -> list[dict]:
        # Half-open valid-time window, matching the node-side filter in
        # current(): an edge with a future valid_to is still valid NOW.
        # Using "valid_to IS NULL" alone would hide bounded-but-live edges
        # from every traversal and silently shrink invalidation blast radius.
        node_id = validate_public_identifier(node_id, field="node_id")
        valid_at = _validate_optional_datetime("valid_at", valid_at)
        selected_edge_types: set[str] | None = None
        if edge_types is not None:
            if not isinstance(edge_types, (set, frozenset)):
                raise ValueError("edge_types must be a set or null")
            selected_edge_types = set(edge_types)
            if any(not isinstance(item, str) or item not in EDGE_TYPES
                   for item in selected_edge_types):
                raise ValueError("edge_types contains an unknown edge type")
            if not selected_edge_types:
                return []
        now = utcnow() if valid_at is None else valid_at
        anchor = self._reference_scope(node_id)
        if anchor is None:
            return []
        other_col = "dst_id" if col == "src_id" else "src_id"
        q = (f"SELECT * FROM edges WHERE {col} = ? AND tx_to IS NULL"
             " AND tenant_id = ? AND project_id = ?"
             " AND (EXISTS (SELECT 1 FROM nodes AS endpoint WHERE "
             f"endpoint.node_id = edges.{other_col} AND endpoint.tx_to IS NULL "
             "AND endpoint.tenant_id = edges.tenant_id "
             "AND endpoint.project_id = edges.project_id) "
             "OR EXISTS (SELECT 1 FROM events AS source_event WHERE "
             f"source_event.event_id = edges.{other_col} "
             "AND source_event.tenant_id = edges.tenant_id "
             "AND source_event.project_id = edges.project_id))"
             " AND (valid_from IS NULL OR valid_from <= ?)"
             " AND (valid_to IS NULL OR valid_to > ?)")
        args: list = [
            node_id, anchor[0], anchor[1], now, now]
        if selected_edge_types is not None:
            q += " AND edge_type IN (%s)" % ",".join(
                "?" * len(selected_edge_types))
            args.extend(sorted(selected_edge_types))
        return [self._edge_dict(r) for r in self._conn.execute(q, args)]

    @serialized_access
    def current_edges(
        self, project_id: str, *, event_derived_only: bool = False,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Canonical current edges in one project, in insertion order.

        ``event_derived_only`` is the replay-comparison surface: runtime edges
        without an event id are deliberately excluded, matching the stated
        event-derived rebuild limit in ADR-011.
        """
        project_id = validate_public_identifier(project_id, field="project_id")
        if tenant_id is not None:
            tenant_id = validate_public_identifier(tenant_id, field="tenant_id")
        if not isinstance(event_derived_only, bool):
            raise ValueError("event_derived_only must be a boolean")
        endpoint_scope = (
            "(EXISTS (SELECT 1 FROM nodes AS {alias}_node WHERE "
            "{alias}_node.node_id = edge.{column} AND {alias}_node.tx_to IS NULL "
            "AND {alias}_node.tenant_id = edge.tenant_id "
            "AND {alias}_node.project_id = edge.project_id) OR EXISTS ("
            "SELECT 1 FROM events AS {alias}_event WHERE "
            "{alias}_event.event_id = edge.{column} "
            "AND {alias}_event.tenant_id = edge.tenant_id "
            "AND {alias}_event.project_id = edge.project_id))")
        q = (
            "SELECT edge.* FROM edges AS edge WHERE edge.project_id = ? "
            "AND edge.tx_to IS NULL AND "
            + endpoint_scope.format(alias="src", column="src_id")
            + " AND "
            + endpoint_scope.format(alias="dst", column="dst_id"))
        args: list = [project_id]
        if tenant_id is not None:
            q += " AND edge.tenant_id = ?"
            args.append(tenant_id)
        if event_derived_only:
            q += " AND edge.event_id IS NOT NULL"
        rows = self._conn.execute(q + " ORDER BY edge.row_id", args).fetchall()
        return [self._edge_dict(row) for row in rows]

    # -------------------------------------------------------------- traversal

    @serialized_access
    def dependents(
        self,
        node_id: str,
        *,
        max_depth: int = 6,
        max_nodes: int = 500,
        edge_types: dict[str, float] | None = None,
        min_strength: float = 0.0,
    ) -> list[dict]:
        """Nodes causally downstream of node_id: anything that assumes,
        depends_on, derives from, or is verified against it, transitively.

        Follows dependency edges in reverse (in_edges): if T --assumes--> A,
        then invalidating A affects T. Bounded by depth and node count
        (CCG-008). Returns [{node_id, depth, path, strength}].
        """
        node_id = validate_public_identifier(node_id, field="node_id")
        for name, value in (("max_depth", max_depth), ("max_nodes", max_nodes)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if (isinstance(min_strength, bool)
                or not isinstance(min_strength, (int, float))
                or not math.isfinite(min_strength)
                or not 0 <= min_strength <= 1):
            raise ValueError("min_strength must be finite and between 0 and 1")
        if edge_types is None:
            weights = dict(PROPAGATION_EDGES)
        else:
            if not isinstance(edge_types, dict):
                raise ValueError("edge_types must be an object or null")
            weights = dict(edge_types)
            for edge_type, weight in weights.items():
                if not isinstance(edge_type, str) or edge_type not in EDGE_TYPES:
                    raise ValueError(f"unknown propagation edge type {edge_type!r}")
                if (isinstance(weight, bool)
                        or not isinstance(weight, (int, float))
                        or not math.isfinite(weight)
                        or not 0 <= weight <= 1):
                    raise ValueError(
                        "propagation edge weights must be finite and between 0 and 1")
        if not weights:
            return []
        seen: dict[str, float] = {node_id: 1.0}
        # One entry per DISTINCT node, holding its strongest path. A node
        # reachable by several routes must not appear twice: duplicates would
        # inflate the affected count that drives the human-confirmation gate
        # and the blocked-node severity rule, and would make the budget count
        # paths rather than nodes.
        best: dict[str, dict] = {}
        frontier = deque([(node_id, 0, 1.0, [node_id])])
        while frontier:
            current, depth, strength, path = frontier.popleft()
            if depth >= max_depth:
                continue
            for edge in self.in_edges(current, set(weights)):
                nxt = edge["src_id"]
                s = strength * weights[edge["edge_type"]] * edge["strength"]
                if s < min_strength:
                    continue
                if nxt in seen and seen[nxt] >= s:
                    continue
                seen[nxt] = s
                # Public invalidation packets define a causal path as an
                # identifier list. Edge provenance is already retained in
                # ``via_edge``; embedding display prose here made producer
                # output violate the published packet schema.
                new_path = path + [nxt]
                best[nxt] = {
                    "node_id": nxt,
                    "depth": depth + 1,
                    "strength": round(s, 4),
                    "path": new_path,
                    "via_edge": edge["edge_type"],
                }
                if len(best) > max_nodes:
                    raise TraversalBudgetExceeded(
                        f"blast radius exceeds {max_nodes} nodes from {node_id}"
                    )
                frontier.append((nxt, depth + 1, s, new_path))
        return sorted(best.values(), key=lambda d: (d["depth"], -d["strength"]))

    @serialized_access
    def causal_path(self, src_id: str, dst_id: str, max_depth: int = 8) -> list[dict] | None:
        """Shortest typed path src -> dst over current edges, either direction
        of causality (used for explanations)."""
        src_id = validate_public_identifier(src_id, field="src_id")
        dst_id = validate_public_identifier(dst_id, field="dst_id")
        if (isinstance(max_depth, bool) or not isinstance(max_depth, int)
                or max_depth < 0):
            raise ValueError("max_depth must be a non-negative integer")
        frontier = deque([(src_id, [])])
        seen = {src_id}
        while frontier:
            current, path = frontier.popleft()
            if len(path) >= max_depth:
                continue
            for edge in self.out_edges(current) + self.in_edges(current):
                nxt = edge["dst_id"] if edge["src_id"] == current else edge["src_id"]
                if nxt in seen:
                    continue
                seen.add(nxt)
                step = {
                    "from": current, "to": nxt, "edge_type": edge["edge_type"],
                    "direction": "out" if edge["src_id"] == current else "in",
                }
                if nxt == dst_id:
                    return path + [step]
                frontier.append((nxt, path + [step]))
        return None

    # ------------------------------------------------------------- provenance

    @serialized_access
    def provenance(self, node_id: str, max_depth: int = 10) -> dict:
        """Human-readable provenance trail (CCG-007): the node's versions,
        source events, and derived_from/supports chain."""
        node = self.get(node_id)
        trail = {
            "node_id": node_id,
            "entity_type": node["entity_type"],
            "current_version": node["version"],
            "extractor": node.get("extractor"),
            "extractor_version": node.get("extractor_version"),
            "versions": [],
            "sources": [],
        }
        for v in self.history(node_id):
            entry = {
                "version": v["version"], "tx_from": v["tx_from"], "tx_to": v["tx_to"],
                "status": v["status"], "event_id": v["event_id"],
            }
            if v["event_id"]:
                try:
                    ev = self.store.get_event(v["event_id"])
                    entry["source"] = {
                        "source_type": ev["source_type"], "source_id": ev["source_id"],
                        "authority": ev["authority"], "observed_at": ev["observed_at"],
                        "payload_digest": ev["payload_digest"],
                    }
                except KeyError:
                    pass
            trail["versions"].append(entry)
        frontier = deque([(node_id, 0)])
        seen = {node_id}
        while frontier:
            current, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            for edge in self.out_edges(current, {"derived_from"}) + \
                    self.in_edges(current, {"supports"}):
                src = edge["dst_id"] if edge["edge_type"] == "derived_from" else edge["src_id"]
                if src in seen:
                    continue
                seen.add(src)
                try:
                    src_node = self.get(src)
                    trail["sources"].append({
                        "node_id": src, "entity_type": src_node["entity_type"],
                        "relation": edge["edge_type"], "depth": depth + 1,
                        "summary": src_node["data"].get("statement")
                        or src_node["data"].get("title") or src_node["data"].get("name"),
                    })
                except KeyError:
                    continue
                frontier.append((src, depth + 1))
        return trail

    # ------------------------------------------------------------------ misc

    @staticmethod
    def _node_dict(row) -> Node:
        d = Node(dict(row))
        d["data"] = strict_json_loads(d["data"])
        d["scope"] = strict_json_loads(d["scope"]) if d["scope"] else None
        return d

    @staticmethod
    def _edge_dict(row) -> dict:
        d = dict(row)
        d["data"] = strict_json_loads(d["data"]) if d["data"] else None
        return d

    @serialized_access
    def stats(self, project_id: str) -> dict:
        n = self._conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE project_id = ? AND tx_to IS NULL", (project_id,)
        ).fetchone()[0]
        e = self._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE project_id = ? AND tx_to IS NULL", (project_id,)
        ).fetchone()[0]
        return {"nodes": n, "edges": e}
