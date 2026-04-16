"""Tests for gavel.export_bundles — compliance bundle builder."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from gavel.compliance_export import (
    BundleBuilder,
    BundleTarget,
    build_eu_ai_act_bundle,
)


def _window() -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    return end - timedelta(days=30), end


class TestBuilder:
    def test_empty_bundle_has_controls_but_no_files(self):
        start, end = _window()
        b = BundleBuilder(
            target=BundleTarget.SOC2,
            scope="tenant:acme",
            window_start=start,
            window_end=end,
        )
        bundle = b.build()
        assert bundle.target == BundleTarget.SOC2
        assert len(bundle.files) == 0
        # All SOC2 controls are present but uncovered.
        assert bundle.coverage_summary()["gap"] == len(bundle.controls)
        assert len(bundle.gaps()) == len(bundle.controls)

    def test_add_json_file_hashes_deterministically(self):
        start, end = _window()
        b = BundleBuilder(
            target=BundleTarget.ISO_42001,
            scope="all",
            window_start=start,
            window_end=end,
        )
        f1 = b.add_json_file("foo.json", {"x": 1, "y": 2})
        # Different builder, same content → same hash.
        b2 = BundleBuilder(
            target=BundleTarget.ISO_42001,
            scope="all",
            window_start=start,
            window_end=end,
        )
        f2 = b2.add_json_file("foo.json", {"y": 2, "x": 1})
        assert f1.sha256 == f2.sha256

    def test_evidence_for_links_control(self):
        start, end = _window()
        b = BundleBuilder(
            target=BundleTarget.EU_AI_ACT,
            scope="all",
            window_start=start,
            window_end=end,
        )
        b.add_json_file("chain/events.json", [], evidence_for=["Art. 12"])
        bundle = b.build()
        art12 = next(c for c in bundle.controls if c.control_id == "Art. 12")
        assert "chain/events.json" in art12.file_paths

    def test_unknown_control_rejected(self):
        start, end = _window()
        b = BundleBuilder(
            target=BundleTarget.SOC2,
            scope="all",
            window_start=start,
            window_end=end,
        )
        with pytest.raises(KeyError):
            b.add_json_file("foo.json", {}, evidence_for=["NONSENSE"])

    def test_attach_module_evidence_covers_control(self):
        start, end = _window()
        b = BundleBuilder(
            target=BundleTarget.EU_AI_ACT,
            scope="all",
            window_start=start,
            window_end=end,
        )
        b.attach_module_evidence(
            "Art. 14",
            ["gavel.separation", "gavel.tiers"],
            notes="structural separation of powers",
        )
        bundle = b.build()
        art14 = next(c for c in bundle.controls if c.control_id == "Art. 14")
        assert "gavel.separation" in art14.gavel_module_refs
        assert bundle.coverage_summary()["covered"] == 1


class TestManifestHash:
    def test_manifest_hash_is_content_addressed(self):
        start, end = _window()
        b1 = BundleBuilder(
            target=BundleTarget.SOC2,
            scope="all",
            window_start=start,
            window_end=end,
        )
        b1.add_json_file("a.json", {"v": 1})
        b1.add_json_file("b.json", {"v": 2})
        bundle1 = b1.build()

        b2 = BundleBuilder(
            target=BundleTarget.SOC2,
            scope="all",
            window_start=start,
            window_end=end,
        )
        # Insert in reverse order — manifest should still be identical.
        b2.add_json_file("b.json", {"v": 2})
        b2.add_json_file("a.json", {"v": 1})
        bundle2 = b2.build()

        assert bundle1.manifest_sha256 == bundle2.manifest_sha256
        assert bundle1.manifest_sha256  # non-empty

    def test_manifest_changes_when_content_changes(self):
        start, end = _window()
        b1 = BundleBuilder(
            target=BundleTarget.SOC2,
            scope="all",
            window_start=start,
            window_end=end,
        )
        b1.add_json_file("a.json", {"v": 1})
        h1 = b1.build().manifest_sha256

        b2 = BundleBuilder(
            target=BundleTarget.SOC2,
            scope="all",
            window_start=start,
            window_end=end,
        )
        b2.add_json_file("a.json", {"v": 2})
        h2 = b2.build().manifest_sha256

        assert h1 != h2


class TestEuAiActAssembler:
    def test_end_to_end_bundle(self):
        start, end = _window()
        bundle = build_eu_ai_act_bundle(
            scope="agent:x",
            window_start=start,
            window_end=end,
            chain_events=[{"event": "PROPOSED"}],
            enrollment_records=[{"agent_id": "agent:x"}],
            incidents=[],
            annex_iv_markdown="# Annex IV\nTechnical documentation",
            qms_markdown="# QMS\nQuality manual",
            compliance_matrix={"applicable_regulations": ["eu_ai_act"]},
            fria_packet={"status": "NOTIFIED"},
        )
        paths = {f.path for f in bundle.files}
        assert "chain/events.json" in paths
        assert "enrollment/records.json" in paths
        assert "incidents/registry.json" in paths
        assert "technical-documentation/annex-iv.md" in paths
        assert "quality-management/qms-manual.md" in paths
        assert "compliance/matrix.json" in paths
        assert "fria/packet.json" in paths

        summary = bundle.coverage_summary()
        assert summary["covered"] >= 7  # each added control contributes
        assert bundle.manifest_sha256

    def test_optional_artifacts_omitted(self):
        start, end = _window()
        bundle = build_eu_ai_act_bundle(
            scope="agent:x",
            window_start=start,
            window_end=end,
            chain_events=[],
            enrollment_records=[],
            incidents=[],
            annex_iv_markdown="x",
            qms_markdown="y",
        )
        paths = {f.path for f in bundle.files}
        assert "compliance/matrix.json" not in paths
        assert "fria/packet.json" not in paths
