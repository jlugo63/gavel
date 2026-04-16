"""Tests for EU AI Act compliance features — Annex III classification,
prohibited practice detection, Annex IV documentation, transparency,
and incident reporting.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

# Import new compliance types
from gavel.enrollment import (
    HighRiskCategory,
    classify_risk_category,
    detect_prohibited_practices,
    EnrollmentRegistry,
)
from gavel.constitution import Constitution, InvariantClass
from gavel.compliance import (
    AnnexIVGenerator,
    ComplianceStatus,
    IncidentSeverity,
    IncidentStatus,
    IncidentReport,
    IncidentClassifier,
    IncidentRegistry,
)
from conftest import _valid_application, _make_enrollment_registry, _make_incident_registry


# ══════════════════════════════════════════════════════════════
# EU AI Act Article 6 + Annex III: Risk Category Classification
# ══════════════════════════════════════════════════════════════


class TestAnnexIIIClassification:
    """EU AI Act Article 6 + Annex III: Risk category auto-classification."""

    def test_no_risk_category_default(self):
        """Standard agent gets NONE classification."""
        app = _valid_application()
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.NONE

    def test_biometrics_detected(self):
        """Agent declaring facial recognition scope is classified as BIOMETRICS."""
        app = _valid_application()
        app.purpose.summary = "Agent for facial recognition access control"
        app.purpose.operational_scope = "biometric identification"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.BIOMETRICS

    def test_employment_detected(self):
        """Agent for CV screening is classified as EMPLOYMENT."""
        app = _valid_application()
        app.purpose.summary = "Automated CV screening and recruitment assistant"
        app.purpose.operational_scope = "hiring pipeline"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.EMPLOYMENT

    def test_critical_infrastructure_detected(self):
        app = _valid_application()
        app.purpose.summary = "Agent managing power grid distribution"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.CRITICAL_INFRASTRUCTURE

    def test_education_detected(self):
        app = _valid_application()
        app.purpose.summary = "Automated exam scoring system"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.EDUCATION

    def test_essential_services_detected(self):
        app = _valid_application()
        app.purpose.summary = "Credit scoring evaluation engine"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.ESSENTIAL_SERVICES

    def test_law_enforcement_detected(self):
        app = _valid_application()
        app.purpose.summary = "Crime prediction and risk assessment law enforcement tool"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.LAW_ENFORCEMENT

    def test_migration_detected(self):
        app = _valid_application()
        app.purpose.summary = "Visa processing automation"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.MIGRATION

    def test_justice_detected(self):
        app = _valid_application()
        app.purpose.summary = "Sentencing recommendation system"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.JUSTICE

    def test_prohibited_trumps_high_risk(self):
        """Prohibited practice detection takes priority over high-risk classification."""
        app = _valid_application()
        app.purpose.summary = "Social scoring system for citizen evaluation"
        category = classify_risk_category(app.purpose, app.capabilities)
        assert category == HighRiskCategory.PROHIBITED


# ══════════════════════════════════════════════════════════════
# EU AI Act Article 5: Prohibited AI Practices
# ══════════════════════════════════════════════════════════════


class TestProhibitedPracticeDetection:
    """EU AI Act Article 5: Prohibited AI practices must be blocked."""

    def test_social_scoring_blocked(self):
        app = _valid_application()
        app.purpose.summary = "Social scoring system for communities"
        violations = detect_prohibited_practices(app)
        assert len(violations) > 0
        assert any("Art. 5" in v for v in violations)

    def test_subliminal_manipulation_blocked(self):
        app = _valid_application()
        app.purpose.summary = "Agent using subliminal manipulation techniques"
        violations = detect_prohibited_practices(app)
        assert any("subliminal" in v.lower() for v in violations)

    def test_exploitation_blocked(self):
        app = _valid_application()
        app.purpose.summary = "Marketing agent to exploit elderly consumers"
        violations = detect_prohibited_practices(app)
        assert any("vulnerabilit" in v.lower() for v in violations)

    def test_biometric_surveillance_blocked(self):
        app = _valid_application()
        app.purpose.summary = "Real-time biometric identification in public spaces"
        violations = detect_prohibited_practices(app)
        assert any("biometric" in v.lower() for v in violations)

    def test_emotion_recognition_workplace_blocked(self):
        app = _valid_application()
        app.purpose.summary = "Emotion recognition workplace monitoring"
        violations = detect_prohibited_practices(app)
        assert len(violations) > 0

    def test_clean_application_passes(self):
        """Normal development agent has no prohibited practices."""
        app = _valid_application()
        violations = detect_prohibited_practices(app)
        assert len(violations) == 0

    async def test_prohibited_enrollment_rejected(self):
        """Enrollment registry rejects prohibited practices."""
        registry = _make_enrollment_registry()
        app = _valid_application()
        app.purpose.summary = "Social scoring and social credit evaluation"
        record = await registry.submit(app)
        assert record.status.value in ("INCOMPLETE", "REJECTED")
        assert any("art. 5" in v.lower() or "prohibited" in v.lower() for v in record.violations)


# ══════════════════════════════════════════════════════════════
# High-Risk Enrollment Validation
# ══════════════════════════════════════════════════════════════


class TestHighRiskEnrollmentValidation:
    """High-risk agents must meet enhanced enrollment requirements."""

    async def test_high_risk_needs_high_risk_tier(self):
        """High-risk category agent with standard risk_tier gets violation."""
        registry = _make_enrollment_registry()
        app = _valid_application()
        app.high_risk_category = HighRiskCategory.EMPLOYMENT
        app.purpose.summary = "CV screening and recruitment"
        # risk_tier defaults to "standard" — should trigger violation
        record = await registry.submit(app)
        assert any("high" in v.lower() or "risk" in v.lower() for v in record.violations)

    async def test_high_risk_needs_contact(self):
        """High-risk agents must provide deployer contact info."""
        registry = _make_enrollment_registry()
        app = _valid_application()
        app.high_risk_category = HighRiskCategory.ESSENTIAL_SERVICES
        app.purpose.summary = "Credit scoring evaluation"
        app.purpose.risk_tier = "high"
        app.owner_contact = ""  # Missing contact
        record = await registry.submit(app)
        assert any("contact" in v.lower() for v in record.violations)


# ══════════════════════════════════════════════════════════════
# Constitutional Article V: Prohibited Practices
# ══════════════════════════════════════════════════════════════


class TestConstitutionArticleV:
    """Constitutional Article V: Prohibited practices."""

    def test_article_v_exists(self):
        c = Constitution()
        inv = c.get_invariant("V.1")
        assert inv is not None
        assert "prohibited" in inv.text.lower()

    def test_article_v2_exists(self):
        c = Constitution()
        inv = c.get_invariant("V.2")
        assert inv is not None
        assert "annex iii" in inv.text.lower() or "high-risk" in inv.text.lower()

    def test_cedar_includes_prohibited_rule(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert "prohibited" in cedar.lower()


# ══════════════════════════════════════════════════════════════
# EU AI Act Article 73: Incident Severity Classification
# ══════════════════════════════════════════════════════════════


class TestIncidentClassification:
    """EU AI Act Article 73: Incident severity classification."""

    def test_kill_switch_is_critical(self):
        severity = IncidentClassifier.classify("kill_switch_activated", {})
        assert severity == IncidentSeverity.CRITICAL

    def test_chain_integrity_violation_is_critical(self):
        severity = IncidentClassifier.classify("chain_integrity_violated", {})
        assert severity == IncidentSeverity.CRITICAL

    def test_prohibited_practice_is_critical(self):
        severity = IncidentClassifier.classify("prohibited_practice_detected", {})
        assert severity == IncidentSeverity.CRITICAL

    def test_evidence_failure_is_serious(self):
        severity = IncidentClassifier.classify("evidence_review_failed", {})
        assert severity == IncidentSeverity.SERIOUS

    def test_scope_violation_is_serious(self):
        severity = IncidentClassifier.classify("scope_violation", {})
        assert severity == IncidentSeverity.SERIOUS

    def test_sla_timeout_is_standard(self):
        severity = IncidentClassifier.classify("sla_timeout", {})
        assert severity == IncidentSeverity.STANDARD

    def test_unknown_event_is_minor(self):
        severity = IncidentClassifier.classify("agent_heartbeat", {})
        assert severity == IncidentSeverity.MINOR

    def test_payload_contributes_to_classification(self):
        """Payload content should influence classification."""
        severity = IncidentClassifier.classify("governance_event", {"detail": "secrets_detected in output"})
        assert severity == IncidentSeverity.SERIOUS


# ══════════════════════════════════════════════════════════════
# Article 73 Reporting Deadlines
# ══════════════════════════════════════════════════════════════


class TestIncidentDeadlines:
    """Article 73 reporting deadlines."""

    def test_critical_2_day_deadline(self):
        now = datetime.now(timezone.utc)
        deadline = IncidentClassifier.compute_deadline(IncidentSeverity.CRITICAL, now)
        assert deadline is not None
        delta = deadline - now
        assert 1.9 < delta.total_seconds() / 86400 < 2.1

    def test_serious_2_day_deadline(self):
        now = datetime.now(timezone.utc)
        deadline = IncidentClassifier.compute_deadline(IncidentSeverity.SERIOUS, now)
        assert deadline is not None
        delta = deadline - now
        assert 1.9 < delta.total_seconds() / 86400 < 2.1

    def test_standard_15_day_deadline(self):
        now = datetime.now(timezone.utc)
        deadline = IncidentClassifier.compute_deadline(IncidentSeverity.STANDARD, now)
        assert deadline is not None
        delta = deadline - now
        assert 14.9 < delta.total_seconds() / 86400 < 15.1

    def test_minor_no_deadline(self):
        now = datetime.now(timezone.utc)
        deadline = IncidentClassifier.compute_deadline(IncidentSeverity.MINOR, now)
        assert deadline is None


# ══════════════════════════════════════════════════════════════
# Incident Lifecycle Management
# ══════════════════════════════════════════════════════════════


class TestIncidentRegistry:
    """Incident lifecycle management."""

    async def test_create_incident(self):
        registry = _make_incident_registry()
        incident = await registry.report(
            agent_id="agent:test",
            title="Test incident",
            description="Something happened",
            severity=IncidentSeverity.STANDARD,
        )
        assert incident.incident_id.startswith("inc-")
        assert incident.status == IncidentStatus.OPEN
        assert incident.deadline is not None

    async def test_get_incident(self):
        registry = _make_incident_registry()
        incident = await registry.report("agent:a", "Test", "Desc", IncidentSeverity.MINOR)
        retrieved = await registry.get(incident.incident_id)
        assert retrieved is not None
        assert retrieved.agent_id == "agent:a"

    async def test_get_by_agent(self):
        registry = _make_incident_registry()
        await registry.report("agent:a", "Inc 1", "Desc", IncidentSeverity.MINOR)
        await registry.report("agent:b", "Inc 2", "Desc", IncidentSeverity.MINOR)
        await registry.report("agent:a", "Inc 3", "Desc", IncidentSeverity.STANDARD)
        assert len(await registry.get_by_agent("agent:a")) == 2

    async def test_get_by_severity(self):
        registry = _make_incident_registry()
        await registry.report("agent:a", "Critical", "Desc", IncidentSeverity.CRITICAL)
        await registry.report("agent:a", "Minor", "Desc", IncidentSeverity.MINOR)
        assert len(await registry.get_by_severity(IncidentSeverity.CRITICAL)) == 1

    async def test_mark_reported(self):
        registry = _make_incident_registry()
        incident = await registry.report("agent:a", "Test", "Desc", IncidentSeverity.SERIOUS)
        updated = await registry.mark_reported(incident.incident_id)
        assert updated.status == IncidentStatus.REPORTED
        assert updated.reported_at is not None

    async def test_mark_resolved(self):
        registry = _make_incident_registry()
        incident = await registry.report("agent:a", "Test", "Desc", IncidentSeverity.STANDARD)
        updated = await registry.mark_resolved(incident.incident_id)
        assert updated.status == IncidentStatus.RESOLVED
        assert updated.resolved_at is not None

    async def test_overdue_detection(self):
        registry = _make_incident_registry()
        incident = await registry.report("agent:a", "Old", "Desc", IncidentSeverity.CRITICAL)
        # Manually backdate the deadline in the DB to make it overdue.
        from sqlalchemy import update
        from gavel.db.models import IncidentRow
        repo = registry._repo
        sm = repo._sessionmaker
        async with sm() as session:
            async with session.begin():
                await session.execute(
                    update(IncidentRow)
                    .where(IncidentRow.incident_id == incident.incident_id)
                    .values(deadline=datetime.now(timezone.utc) - timedelta(days=1))
                )
        overdue = await registry.get_overdue()
        assert len(overdue) == 1

    async def test_auto_classify_from_event(self):
        registry = _make_incident_registry()
        incident = await registry.report(
            agent_id="agent:a",
            title="Kill switch triggered",
            description="Agent suspended",
            event_type="kill_switch_activated",
        )
        assert incident.severity == IncidentSeverity.CRITICAL
        assert incident.deadline is not None


# ══════════════════════════════════════════════════════════════
# EU AI Act Annex IV: Technical Documentation Generation
# ══════════════════════════════════════════════════════════════


class TestAnnexIVGenerator:
    """EU AI Act Annex IV: Technical documentation generation."""

    def _make_enrollment_record(self):
        """Helper to create a mock enrollment record."""
        app = _valid_application()
        # Set EU AI Act fields if they exist
        if hasattr(app, "high_risk_category"):
            app.high_risk_category = HighRiskCategory.NONE
        if hasattr(app, "interaction_type"):
            app.interaction_type = "system_only"

        class MockRecord:
            def __init__(self, application):
                self.application = application
                self.agent_id = application.agent_id

        return MockRecord(app)

    def test_generates_all_9_sections(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        assert "sections" in doc
        sections = doc["sections"]
        assert "1_general_description" in sections
        assert "2_development_and_design" in sections
        assert "3_monitoring_and_control" in sections
        assert "4_performance_metrics" in sections
        assert "5_risk_management" in sections
        assert "6_lifecycle_changes" in sections
        assert "7_applied_standards" in sections
        assert "8_eu_declaration" in sections
        assert "9_post_market_monitoring" in sections

    def test_section_1_includes_agent_info(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        s1 = doc["sections"]["1_general_description"]
        assert s1["agent_id"] == "agent:test"
        assert s1["system_name"] == "Test Agent"
        assert "intended_purpose" in s1

    def test_section_3_includes_oversight(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        s3 = doc["sections"]["3_monitoring_and_control"]
        assert len(s3["human_oversight_mechanisms"]) > 0
        assert "logging_mechanism" in s3

    def test_section_5_includes_risk(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        s5 = doc["sections"]["5_risk_management"]
        assert "risk_classification" in s5
        assert "risk_mitigation_measures" in s5

    def test_section_7_references_standards(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        s7 = doc["sections"]["7_applied_standards"]
        assert len(s7["harmonised_standards"]) > 0
        assert len(s7["cryptographic_standards"]) > 0

    def test_section_9_post_market(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        s9 = doc["sections"]["9_post_market_monitoring"]
        assert "incident_reporting" in s9
        assert s9["incident_reporting"]["critical_deadline"] == "2 days (EU AI Act Article 73)"

    def test_compliance_status_compliant(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        assert doc["compliance_status"]["status"] in (
            ComplianceStatus.COMPLIANT, "compliant"
        )

    def test_no_enrollment_returns_incomplete(self):
        gen = AnnexIVGenerator()
        doc = gen.generate()
        s1 = doc["sections"]["1_general_description"]
        assert s1["status"] == "incomplete"

    def test_annex_iv_version_present(self):
        record = self._make_enrollment_record()
        gen = AnnexIVGenerator(enrollment_record=record)
        doc = gen.generate()
        assert doc["annex_iv_version"] == "1.0"
        assert "Regulation 2024/1689" in doc["regulation"]

    def test_with_constitution(self):
        record = self._make_enrollment_record()
        constitution = Constitution()
        gen = AnnexIVGenerator(enrollment_record=record, constitution=constitution)
        doc = gen.generate()
        s3 = doc["sections"]["3_monitoring_and_control"]
        assert len(s3["constitutional_invariants"]) >= 9  # at least original 9
