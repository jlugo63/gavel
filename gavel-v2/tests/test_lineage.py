"""Tests for gavel.lineage — ATF D-5 data-object lineage tracking."""

from __future__ import annotations

import hashlib

import pytest

from gavel.lineage import (
    DataObject,
    LineageEdge,
    LineageGraph,
    LineageTracker,
)


# ---------------------------------------------------------------------------
# DataObject basics
# ---------------------------------------------------------------------------


class TestDataObject:
    def test_creation_defaults(self):
        obj = DataObject(
            object_type="prompt",
            content_hash="abc123",
            created_by="agent-1",
        )
        assert obj.object_id.startswith("dobj-")
        assert obj.object_type == "prompt"
        assert obj.parent_ids == []
        assert obj.metadata == {}
        assert obj.created_at is not None

    def test_explicit_fields(self):
        obj = DataObject(
            object_id="custom-id",
            object_type="response",
            content_hash="def456",
            created_by="agent-2",
            parent_ids=["p1", "p2"],
            metadata={"key": "value"},
        )
        assert obj.object_id == "custom-id"
        assert obj.parent_ids == ["p1", "p2"]
        assert obj.metadata["key"] == "value"


# ---------------------------------------------------------------------------
# LineageEdge basics
# ---------------------------------------------------------------------------


class TestLineageEdge:
    def test_creation(self):
        edge = LineageEdge(
            source_id="src",
            target_id="tgt",
            transform_type="redacted",
            transformer="privacy_scanner",
        )
        assert edge.edge_id.startswith("edge-")
        assert edge.source_id == "src"
        assert edge.target_id == "tgt"
        assert edge.transform_type == "redacted"
        assert edge.transformer == "privacy_scanner"


# ---------------------------------------------------------------------------
# LineageGraph
# ---------------------------------------------------------------------------


def _make_obj(oid: str, otype: str = "prompt") -> DataObject:
    return DataObject(
        object_id=oid,
        object_type=otype,
        content_hash=hashlib.sha256(oid.encode()).hexdigest(),
        created_by="test",
    )


class TestLineageGraph:
    def test_add_and_get_object(self):
        g = LineageGraph()
        obj = _make_obj("a")
        g.add_object(obj)
        assert g.get_object("a") is obj
        assert g.get_object("missing") is None
        assert g.object_count == 1

    def test_add_edge_validates_ids(self):
        g = LineageGraph()
        g.add_object(_make_obj("a"))
        g.add_object(_make_obj("b"))

        edge = g.add_edge("a", "b", "redacted", "privacy_scanner")
        assert edge.source_id == "a"
        assert g.edge_count == 1

    def test_add_edge_rejects_unknown_source(self):
        g = LineageGraph()
        g.add_object(_make_obj("b"))
        with pytest.raises(KeyError, match="Source object not found"):
            g.add_edge("missing", "b", "redacted", "scanner")

    def test_add_edge_rejects_unknown_target(self):
        g = LineageGraph()
        g.add_object(_make_obj("a"))
        with pytest.raises(KeyError, match="Target object not found"):
            g.add_edge("a", "missing", "redacted", "scanner")

    def test_get_edges(self):
        g = LineageGraph()
        g.add_object(_make_obj("a"))
        g.add_object(_make_obj("b"))
        g.add_object(_make_obj("c"))
        g.add_edge("a", "b", "redacted", "scanner")
        g.add_edge("b", "c", "enriched", "enricher")

        edges_b = g.get_edges("b")
        assert len(edges_b) == 2  # b is both target and source

    # -- Traversal: linear chain A -> B -> C --------------------------------

    def test_trace_upstream_linear(self):
        g = LineageGraph()
        for n in "abc":
            g.add_object(_make_obj(n))
        g.add_edge("a", "b", "t", "x")
        g.add_edge("b", "c", "t", "x")

        upstream = g.trace_upstream("c")
        ids = {o.object_id for o in upstream}
        assert ids == {"a", "b"}

    def test_trace_downstream_linear(self):
        g = LineageGraph()
        for n in "abc":
            g.add_object(_make_obj(n))
        g.add_edge("a", "b", "t", "x")
        g.add_edge("b", "c", "t", "x")

        downstream = g.trace_downstream("a")
        ids = {o.object_id for o in downstream}
        assert ids == {"b", "c"}

    # -- Traversal: diamond  A -> B, A -> C, B -> D, C -> D ----------------

    def test_trace_upstream_diamond(self):
        g = LineageGraph()
        for n in "abcd":
            g.add_object(_make_obj(n))
        g.add_edge("a", "b", "t", "x")
        g.add_edge("a", "c", "t", "x")
        g.add_edge("b", "d", "t", "x")
        g.add_edge("c", "d", "t", "x")

        upstream = g.trace_upstream("d")
        ids = {o.object_id for o in upstream}
        assert ids == {"a", "b", "c"}

    def test_trace_downstream_diamond(self):
        g = LineageGraph()
        for n in "abcd":
            g.add_object(_make_obj(n))
        g.add_edge("a", "b", "t", "x")
        g.add_edge("a", "c", "t", "x")
        g.add_edge("b", "d", "t", "x")
        g.add_edge("c", "d", "t", "x")

        downstream = g.trace_downstream("a")
        ids = {o.object_id for o in downstream}
        assert ids == {"b", "c", "d"}

    # -- Traversal: multi-parent  P1, P2 -> M ------------------------------

    def test_trace_upstream_multi_parent(self):
        g = LineageGraph()
        for n in ["p1", "p2", "m"]:
            g.add_object(_make_obj(n))
        g.add_edge("p1", "m", "derived", "combiner")
        g.add_edge("p2", "m", "derived", "combiner")

        upstream = g.trace_upstream("m")
        ids = {o.object_id for o in upstream}
        assert ids == {"p1", "p2"}

    # -- DOT export ---------------------------------------------------------

    def test_export_dot(self):
        g = LineageGraph()
        g.add_object(_make_obj("a", "prompt"))
        g.add_object(_make_obj("b", "redacted_prompt"))
        g.add_edge("a", "b", "redacted", "privacy_scanner")

        dot = g.export_dot()
        assert "digraph lineage" in dot
        assert '"a"' in dot
        assert '"b"' in dot
        assert '"a" -> "b"' in dot
        assert "redacted" in dot
        assert "privacy_scanner" in dot

    # -- Integrity verification ---------------------------------------------

    def test_verify_integrity_clean(self):
        g = LineageGraph()
        g.add_object(_make_obj("a"))
        g.add_object(_make_obj("b"))
        g.add_edge("a", "b", "t", "x")
        assert g.verify_integrity() == []

    def test_verify_integrity_orphaned_edge(self):
        g = LineageGraph()
        g.add_object(_make_obj("a"))
        g.add_object(_make_obj("b"))
        g.add_edge("a", "b", "t", "x")
        # Manually remove object to create orphan
        del g._objects["b"]
        issues = g.verify_integrity()
        assert any("orphan" in i.lower() or "not found" in i.lower() for i in issues)

    def test_verify_integrity_cycle(self):
        g = LineageGraph()
        g.add_object(_make_obj("a"))
        g.add_object(_make_obj("b"))
        # Manually create cycle by adding edges directly
        g._edges.append(LineageEdge(
            source_id="a", target_id="b", transform_type="t", transformer="x",
        ))
        g._edges.append(LineageEdge(
            source_id="b", target_id="a", transform_type="t", transformer="x",
        ))
        issues = g.verify_integrity()
        assert any("cycle" in i.lower() for i in issues)

    # -- Full lineage -------------------------------------------------------

    def test_get_full_lineage(self):
        g = LineageGraph()
        for n in "abc":
            g.add_object(_make_obj(n))
        g.add_edge("a", "b", "t", "x")
        g.add_edge("b", "c", "t", "x")

        report = g.get_full_lineage("b")
        assert report["object"].object_id == "b"
        assert len(report["upstream"]) == 1  # a
        assert len(report["downstream"]) == 1  # c
        assert len(report["edges"]) == 2  # a->b and b->c


# ---------------------------------------------------------------------------
# LineageTracker (convenience layer)
# ---------------------------------------------------------------------------


class TestLineageTracker:
    def test_track_input(self):
        t = LineageTracker()
        obj = t.track_input("hello world", "prompt", "user-1")
        assert obj.object_type == "prompt"
        assert obj.created_by == "user-1"
        assert obj.parent_ids == []
        assert t.graph.object_count == 1

    def test_content_hash_determinism(self):
        t = LineageTracker()
        obj1 = t.track_input("same content", "prompt", "a")
        obj2 = t.track_input("same content", "prompt", "b")
        assert obj1.content_hash == obj2.content_hash

        expected = hashlib.sha256("same content".encode()).hexdigest()
        assert obj1.content_hash == expected

    def test_track_transform(self):
        t = LineageTracker()
        src = t.track_input("raw prompt with PII", "prompt", "user-1")
        redacted = t.track_transform(
            source_id=src.object_id,
            new_content="raw prompt with [REDACTED]",
            transform_type="redacted",
            transformer="privacy_scanner",
            object_type="redacted_prompt",
        )
        assert redacted.parent_ids == [src.object_id]
        assert t.graph.edge_count == 1
        assert t.graph.object_count == 2

    def test_track_derivation_multi_parent(self):
        t = LineageTracker()
        p1 = t.track_input("evidence A", "evidence_packet", "blastbox")
        p2 = t.track_input("evidence B", "evidence_packet", "blastbox")

        combined = t.track_derivation(
            parent_ids=[p1.object_id, p2.object_id],
            new_content="combined evidence",
            object_type="governance_decision",
            created_by="evidence_reviewer",
        )
        assert set(combined.parent_ids) == {p1.object_id, p2.object_id}
        assert t.graph.edge_count == 2  # one edge per parent

    def test_get_provenance(self):
        t = LineageTracker()
        src = t.track_input("input", "prompt", "user")
        derived = t.track_transform(
            src.object_id, "output", "enriched", "enricher", "response",
        )
        prov = t.get_provenance(derived.object_id)
        assert prov["object"].object_id == derived.object_id
        assert len(prov["upstream"]) == 1
        assert prov["upstream"][0].object_id == src.object_id


class TestEdgeIndexing:
    """Verify that edge indexes are consistent with the flat edge list."""

    def test_indexes_populated_on_add_edge(self):
        g = LineageGraph()
        g.add_object(_make_obj("a"))
        g.add_object(_make_obj("b"))
        g.add_edge("a", "b", "redacted", "scanner")
        assert len(g._edges_by_source["a"]) == 1
        assert len(g._edges_by_target["b"]) == 1
        assert g._edges_by_source["a"][0].target_id == "b"
        assert g._edges_by_target["b"][0].source_id == "a"

    def test_indexes_match_flat_list(self):
        g = LineageGraph()
        for n in "abcde":
            g.add_object(_make_obj(n))
        g.add_edge("a", "b", "t", "x")
        g.add_edge("a", "c", "t", "x")
        g.add_edge("b", "d", "t", "x")
        g.add_edge("c", "d", "t", "x")
        g.add_edge("d", "e", "t", "x")

        # Verify source index covers all edges from each node
        for e in g._edges:
            assert e in g._edges_by_source[e.source_id]
            assert e in g._edges_by_target[e.target_id]

    def test_get_edges_uses_indexes(self):
        g = LineageGraph()
        for n in "abc":
            g.add_object(_make_obj(n))
        g.add_edge("a", "b", "t", "x")
        g.add_edge("b", "c", "t", "x")
        edges_b = g.get_edges("b")
        assert len(edges_b) == 2
        sources = {e.source_id for e in edges_b}
        targets = {e.target_id for e in edges_b}
        assert "a" in sources or "b" in sources
        assert "b" in targets or "c" in targets

    def test_traversal_with_many_edges(self):
        """Build a wide graph and verify traversal still works with indexes."""
        g = LineageGraph()
        g.add_object(_make_obj("root"))
        children = []
        for i in range(50):
            cid = f"child-{i}"
            g.add_object(_make_obj(cid))
            g.add_edge("root", cid, "derived", "gen")
            children.append(cid)

        downstream = g.trace_downstream("root")
        assert len(downstream) == 50

        # Each child should trace back to root
        for cid in children[:5]:
            upstream = g.trace_upstream(cid)
            assert len(upstream) == 1
            assert upstream[0].object_id == "root"

    def test_full_pipeline_lineage(self):
        """End-to-end: prompt -> redacted -> sandboxed -> reviewed -> approved."""
        t = LineageTracker()

        prompt = t.track_input("deploy model X to production", "prompt", "agent-42")
        redacted = t.track_transform(
            prompt.object_id, "deploy model X to production",
            "redacted", "privacy_scanner", "redacted_prompt",
        )
        evidence = t.track_transform(
            redacted.object_id, '{"exit_code": 0, "diff": "..."}',
            "sandboxed", "blastbox", "evidence_packet",
        )
        review = t.track_transform(
            evidence.object_id, '{"verdict": "PASS"}',
            "reviewed", "evidence_reviewer", "governance_decision",
        )
        approval = t.track_transform(
            review.object_id, '{"approved": true}',
            "approved", "supervisor", "governance_decision",
        )

        # Trace full upstream from the approval
        upstream = t.graph.trace_upstream(approval.object_id)
        upstream_ids = {o.object_id for o in upstream}
        assert prompt.object_id in upstream_ids
        assert redacted.object_id in upstream_ids
        assert evidence.object_id in upstream_ids
        assert review.object_id in upstream_ids
        assert len(upstream) == 4

        # Trace full downstream from the prompt
        downstream = t.graph.trace_downstream(prompt.object_id)
        assert len(downstream) == 4

        # Integrity check
        assert t.graph.verify_integrity() == []
