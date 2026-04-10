"""Tests for gavel.compliance_export — SOC 2, ISO 42001, EU AI Act bundles."""

from __future__ import annotations

import pytest

from gavel.compliance_export import (
    ComplianceBundle,
    ComplianceExporter,
    ComplianceFramework,
    ControlEvidence,
    ControlStatus,
)


def _full_context() -> dict:
    return {
        "chain_count": 42,
        "has_rbac": True,
        "has_audit_trail": True,
        "has_enrollment": True,
        "has_separation_of_powers": True,
        "has_evidence_review": True,
        "has_monitoring": True,
        "has_killswitch": True,
        "incident_count": 3,
        "has_fria": True,
        "has_qms": True,
        "has_data_governance": True,
    }


def _minimal_context() -> dict:
    return {}


class TestSOC2Bundle:
    def test_generates_16_controls(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.SOC2)
        assert len(bundle.controls) == 16

    def test_full_context_high_coverage(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.SOC2)
        met = sum(1 for c in bundle.controls if c.status == ControlStatus.MET)
        assert met >= 12

    def test_minimal_context_lower_coverage(self):
        exporter = ComplianceExporter(_minimal_context())
        bundle = exporter.export(ComplianceFramework.SOC2)
        met = sum(1 for c in bundle.controls if c.status == ControlStatus.MET)
        assert met < 10

    def test_bundle_hash_is_set(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.SOC2)
        assert bundle.bundle_hash
        assert len(bundle.bundle_hash) == 64

    def test_summary_computed(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.SOC2)
        assert "total_controls" in bundle.summary
        assert bundle.summary["total_controls"] == 16
        assert "coverage_pct" in bundle.summary

    def test_framework_version(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.SOC2)
        assert "SOC 2" in bundle.framework_version


class TestISO42001Bundle:
    def test_generates_19_controls(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.ISO_42001)
        assert len(bundle.controls) == 19

    def test_full_context_high_coverage(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.ISO_42001)
        met = sum(1 for c in bundle.controls if c.status == ControlStatus.MET)
        assert met >= 12

    def test_control_ids_match_iso(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.ISO_42001)
        ids = [c.control_id for c in bundle.controls]
        assert "4.1" in ids
        assert "10.2" in ids

    def test_framework_version(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.ISO_42001)
        assert "42001" in bundle.framework_version


class TestEUAIActBundle:
    def test_generates_12_controls(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.EU_AI_ACT)
        assert len(bundle.controls) == 12

    def test_article_ids(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.EU_AI_ACT)
        ids = [c.control_id for c in bundle.controls]
        assert "Art.9" in ids
        assert "Art.73" in ids

    def test_full_context_high_coverage(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.EU_AI_ACT)
        met = sum(1 for c in bundle.controls if c.status == ControlStatus.MET)
        assert met >= 10


class TestExportAll:
    def test_exports_all_three_frameworks(self):
        exporter = ComplianceExporter(_full_context())
        bundles = exporter.export_all()
        assert len(bundles) == 3
        frameworks = {b.framework for b in bundles}
        assert frameworks == {ComplianceFramework.SOC2, ComplianceFramework.ISO_42001, ComplianceFramework.EU_AI_ACT}


class TestBundleIntegrity:
    def test_bundle_hash_changes_with_content(self):
        e1 = ComplianceExporter(_full_context())
        e2 = ComplianceExporter(_minimal_context())
        b1 = e1.export(ComplianceFramework.SOC2)
        b2 = e2.export(ComplianceFramework.SOC2)
        assert b1.bundle_hash != b2.bundle_hash

    def test_bundle_id_unique(self):
        exporter = ComplianceExporter(_full_context())
        b1 = exporter.export(ComplianceFramework.SOC2)
        b2 = exporter.export(ComplianceFramework.SOC2)
        assert b1.bundle_id != b2.bundle_id

    def test_finalize_idempotent(self):
        exporter = ComplianceExporter(_full_context())
        bundle = exporter.export(ComplianceFramework.SOC2)
        hash1 = bundle.bundle_hash
        bundle.finalize()
        assert bundle.bundle_hash == hash1
