"""
Data Object Lineage Tracking — ATF D-5.

Tracks the provenance and transformation history of data objects
flowing through the governance pipeline.

Microsoft's Agent OS provides action-level audit logs. Gavel adds
data-object-level lineage: every prompt, response, redacted variant,
evidence packet, and governance decision is a node in a directed
acyclic graph. Edges record how each object was derived, redacted,
enriched, or approved. This lets auditors answer "where did this
decision come from?" by tracing the full data ancestry.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class DataObject(BaseModel):
    """A tracked data object in the governance pipeline."""

    object_id: str = Field(default_factory=lambda: f"dobj-{uuid.uuid4().hex[:12]}")
    object_type: str  # e.g. "prompt", "response", "redacted_prompt", "evidence_packet", "governance_decision"
    content_hash: str  # SHA-256 hex digest of the object content
    created_by: str  # agent_id or system component
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    parent_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LineageEdge(BaseModel):
    """A transformation edge between two data objects."""

    edge_id: str = Field(default_factory=lambda: f"edge-{uuid.uuid4().hex[:12]}")
    source_id: str  # DataObject ID
    target_id: str  # DataObject ID
    transform_type: str  # e.g. "redacted", "enriched", "derived", "reviewed", "approved", "sandboxed"
    transformer: str  # component that performed the transform
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Lineage graph
# ---------------------------------------------------------------------------


class LineageGraph:
    """Directed acyclic graph of data-object lineage."""

    def __init__(self) -> None:
        self._objects: dict[str, DataObject] = {}
        self._edges: list[LineageEdge] = []
        self._edges_by_source: dict[str, list[LineageEdge]] = defaultdict(list)
        self._edges_by_target: dict[str, list[LineageEdge]] = defaultdict(list)

    # -- Mutators -----------------------------------------------------------

    def add_object(self, obj: DataObject) -> None:
        """Register a data object in the graph."""
        self._objects[obj.object_id] = obj

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        transform_type: str,
        transformer: str,
    ) -> LineageEdge:
        """Add a transformation edge. Both source and target must exist."""
        if source_id not in self._objects:
            raise KeyError(f"Source object not found: {source_id}")
        if target_id not in self._objects:
            raise KeyError(f"Target object not found: {target_id}")

        edge = LineageEdge(
            source_id=source_id,
            target_id=target_id,
            transform_type=transform_type,
            transformer=transformer,
        )
        self._edges.append(edge)
        self._edges_by_source[source_id].append(edge)
        self._edges_by_target[target_id].append(edge)
        return edge

    # -- Queries ------------------------------------------------------------

    def get_object(self, object_id: str) -> Optional[DataObject]:
        """Look up a data object by ID."""
        return self._objects.get(object_id)

    def get_edges(self, object_id: str) -> list[LineageEdge]:
        """Return all edges involving *object_id* (as source or target)."""
        as_source = self._edges_by_source.get(object_id, [])
        as_target = self._edges_by_target.get(object_id, [])
        return as_source + as_target

    # -- Traversals ---------------------------------------------------------

    def trace_upstream(self, object_id: str) -> list[DataObject]:
        """BFS upstream — all ancestors of *object_id*."""
        visited: set[str] = set()
        queue: deque[str] = deque()

        # Seed with direct parents via edges
        for e in self._edges_by_target.get(object_id, []):
            queue.append(e.source_id)

        result: list[DataObject] = []
        while queue:
            oid = queue.popleft()
            if oid in visited:
                continue
            visited.add(oid)
            obj = self._objects.get(oid)
            if obj:
                result.append(obj)
            for e in self._edges_by_target.get(oid, []):
                if e.source_id not in visited:
                    queue.append(e.source_id)
        return result

    def trace_downstream(self, object_id: str) -> list[DataObject]:
        """BFS downstream — all descendants of *object_id*."""
        visited: set[str] = set()
        queue: deque[str] = deque()

        for e in self._edges_by_source.get(object_id, []):
            queue.append(e.target_id)

        result: list[DataObject] = []
        while queue:
            oid = queue.popleft()
            if oid in visited:
                continue
            visited.add(oid)
            obj = self._objects.get(oid)
            if obj:
                result.append(obj)
            for e in self._edges_by_source.get(oid, []):
                if e.target_id not in visited:
                    queue.append(e.target_id)
        return result

    # -- Reporting ----------------------------------------------------------

    def get_full_lineage(self, object_id: str) -> dict[str, Any]:
        """Full lineage report for a single object."""
        obj = self.get_object(object_id)
        return {
            "object": obj,
            "upstream": self.trace_upstream(object_id),
            "downstream": self.trace_downstream(object_id),
            "edges": self.get_edges(object_id),
        }

    def export_dot(self) -> str:
        """Export the graph in Graphviz DOT format."""
        lines = ["digraph lineage {", '  rankdir=LR;']
        for oid, obj in self._objects.items():
            label = f"{obj.object_type}\\n{oid[:16]}"
            lines.append(f'  "{oid}" [label="{label}"];')
        for e in self._edges:
            label = f"{e.transform_type}\\n({e.transformer})"
            lines.append(f'  "{e.source_id}" -> "{e.target_id}" [label="{label}"];')
        lines.append("}")
        return "\n".join(lines)

    def verify_integrity(self) -> list[str]:
        """Check for orphaned edges, missing objects, and cycles."""
        issues: list[str] = []

        # Orphaned edges — reference non-existent objects
        for e in self._edges:
            if e.source_id not in self._objects:
                issues.append(f"Orphaned edge {e.edge_id}: source {e.source_id} not found")
            if e.target_id not in self._objects:
                issues.append(f"Orphaned edge {e.edge_id}: target {e.target_id} not found")

        # Cycle detection via topological sort (Kahn's algorithm)
        in_degree: dict[str, int] = {oid: 0 for oid in self._objects}
        adj: dict[str, list[str]] = {oid: [] for oid in self._objects}
        for e in self._edges:
            if e.source_id in self._objects and e.target_id in self._objects:
                adj[e.source_id].append(e.target_id)
                in_degree[e.target_id] += 1

        queue: deque[str] = deque(oid for oid, d in in_degree.items() if d == 0)
        visited = 0
        while queue:
            node = queue.popleft()
            visited += 1
            for child in adj[node]:
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)

        if visited < len(self._objects):
            issues.append("Cycle detected in lineage graph")

        return issues

    # -- Properties ---------------------------------------------------------

    @property
    def object_count(self) -> int:
        return len(self._objects)

    @property
    def edge_count(self) -> int:
        return len(self._edges)


# ---------------------------------------------------------------------------
# Convenience tracker for governance pipeline
# ---------------------------------------------------------------------------


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class LineageTracker:
    """High-level API for tracking data objects through the governance pipeline."""

    def __init__(self) -> None:
        self.graph = LineageGraph()

    def track_input(
        self,
        content: str,
        object_type: str,
        created_by: str,
        **metadata: Any,
    ) -> DataObject:
        """Create and register a new root data object (no parents)."""
        obj = DataObject(
            object_type=object_type,
            content_hash=_sha256(content),
            created_by=created_by,
            metadata=metadata,
        )
        self.graph.add_object(obj)
        return obj

    def track_transform(
        self,
        source_id: str,
        new_content: str,
        transform_type: str,
        transformer: str,
        object_type: str,
    ) -> DataObject:
        """Create a derived object from a single parent and add an edge."""
        obj = DataObject(
            object_type=object_type,
            content_hash=_sha256(new_content),
            created_by=transformer,
            parent_ids=[source_id],
        )
        self.graph.add_object(obj)
        self.graph.add_edge(source_id, obj.object_id, transform_type, transformer)
        return obj

    def track_derivation(
        self,
        parent_ids: list[str],
        new_content: str,
        object_type: str,
        created_by: str,
    ) -> DataObject:
        """Create a multi-parent derived object with edges from each parent."""
        obj = DataObject(
            object_type=object_type,
            content_hash=_sha256(new_content),
            created_by=created_by,
            parent_ids=list(parent_ids),
        )
        self.graph.add_object(obj)
        for pid in parent_ids:
            self.graph.add_edge(pid, obj.object_id, "derived", created_by)
        return obj

    def get_provenance(self, object_id: str) -> dict[str, Any]:
        """Full lineage report for an object."""
        return self.graph.get_full_lineage(object_id)
