"""Tests for gavel.fria — EU AI Act Article 27 FRIA workflow."""

from __future__ import annotations

import pytest

from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    FallbackBehavior,
    HighRiskCategory,
    PurposeDeclaration,
    ResourceAllowlist,
)
from gavel.fria import (
    DeployerContext,
    FriaAssessment,
    FriaRegistry,
    FriaStatus,
    fria_required,
    validate_fria,
)


def _complete_fria(agent_id: str = "agent:credit") -> FriaAssessment:
    return FriaAssessment(
        agent_id=agent_id,
        deployer=DeployerContext(
            deployer_name="Acme Bank",
            deployer_type="private_annex_iii_5",
            jurisdiction="DE",
            contact_email="compliance@acme.example",
        ),
        process_description=(
            "The system is used to score individual loan applications "
            "from retail customers. Output feeds a credit decision workflow."
        ),
        usage_period="Continuous during business hours, EU working days",
        usage_frequency="Approx. 2,000 decisions per day",
        affected_categories=[
            "Individual loan applicants",
            "Existing credit customers under review",
        ],
        risks_of_harm=[
            "Indirect discrimination against protected classes",
            "Exclusion from essential credit services",
            "Automated decisions without meaningful explanation",
        ],
        human_oversight_measures=(
            "A compliance officer reviews all denials and all decisions "
            "flagged by the system's confidence threshold or protected-"
            "class monitor before the customer is notified."
        ),
        mitigation_measures=[
            "Quarterly disparate-impact audit",
            "Opt-out to manual review on request",
            "Post-hoc explanation engine attached to every denial",
        ],
        complaint_mechanism=(
            "Customers may file a complaint via the website form, by phone, "
            "or in branch. All complaints are investigated within 14 days."
        ),
    )


def _app(category: HighRiskCategory, interaction: str = "human_facing") -> EnrollmentApplication:
    return EnrollmentApplication(
        agent_id="agent:test",
        display_name="Test Agent",
        owner="owner",
        owner_contact="owner@example.com",
        budget_tokens=1000,
        purpose=PurposeDeclaration(
            summary="Score credit applications for retail banking customers",
            operational_scope="Credit scoring for loans",
            risk_tier="high",
        ),
        capabilities=CapabilityManifest(tools=["score"], file_system_access=True),
        resources=ResourceAllowlist(allowed_paths=["/var/data"]),
        boundaries=ActionBoundaries(allowed_actions=["read", "classify"]),
        fallback=FallbackBehavior(),
        high_risk_category=category,
        interaction_type=interaction,
    )


class TestFriaRequired:
    def test_essential_services_always_requires(self):
        app = _app(HighRiskCategory.ESSENTIAL_SERVICES, interaction="system_only")
        assert fria_required(app)

    def test_critical_infrastructure_excluded(self):
        app = _app(HighRiskCategory.CRITICAL_INFRASTRUCTURE)
        assert not fria_required(app)

    def test_none_category_not_required(self):
        app = _app(HighRiskCategory.NONE)
        assert not fria_required(app)

    def test_high_risk_human_facing_requires(self):
        app = _app(HighRiskCategory.EMPLOYMENT, interaction="human_facing")
        assert fria_required(app)

    def test_high_risk_system_only_not_required(self):
        app = _app(HighRiskCategory.EMPLOYMENT, interaction="system_only")
        assert not fria_required(app)


class TestValidator:
    def test_complete_fria_passes(self):
        result = validate_fria(_complete_fria())
        assert result.passed, result.missing_sections + result.shallow_sections
        assert not result.missing_sections

    def test_missing_process_description_fails(self):
        fria = _complete_fria()
        fria.process_description = ""
        result = validate_fria(fria)
        assert not result.passed
        assert any("27(1)(a)" in m for m in result.missing_sections)

    def test_missing_usage_period_fails(self):
        fria = _complete_fria()
        fria.usage_period = ""
        result = validate_fria(fria)
        assert not result.passed
        assert any("27(1)(b)" in m for m in result.missing_sections)

    def test_missing_affected_categories_fails(self):
        fria = _complete_fria()
        fria.affected_categories = []
        result = validate_fria(fria)
        assert any("27(1)(c)" in m for m in result.missing_sections)

    def test_shallow_risks_flagged(self):
        fria = _complete_fria()
        fria.risks_of_harm = ["Just one risk"]
        result = validate_fria(fria)
        assert any("27(1)(d)" in s for s in result.shallow_sections)

    def test_shallow_oversight_flagged(self):
        fria = _complete_fria()
        fria.human_oversight_measures = "yes"
        result = validate_fria(fria)
        assert any("27(1)(e)" in s for s in result.shallow_sections)

    def test_missing_complaint_mechanism_fails(self):
        fria = _complete_fria()
        fria.complaint_mechanism = ""
        result = validate_fria(fria)
        assert any("27(1)(f)" in m and "complaint" in m for m in result.missing_sections)

    def test_article_refs_always_populated(self):
        result = validate_fria(_complete_fria())
        assert "Art. 27(1)(a)" in result.article_references
        assert "Art. 27(1)(f)" in result.article_references


class TestRegistry:
    def test_attach_valid_fria_marks_complete(self):
        reg = FriaRegistry()
        result = reg.attach(_complete_fria())
        assert result.passed
        fria = reg.get("agent:credit")
        assert fria.status == FriaStatus.COMPLETE
        assert reg.has_valid("agent:credit")

    def test_attach_invalid_fria_marks_rejected(self):
        reg = FriaRegistry()
        bad = _complete_fria()
        bad.affected_categories = []
        result = reg.attach(bad)
        assert not result.passed
        assert reg.get("agent:credit").status == FriaStatus.REJECTED
        assert not reg.has_valid("agent:credit")

    def test_notify_authority_produces_packet(self):
        reg = FriaRegistry()
        reg.attach(_complete_fria())
        packet = reg.notify_authority("agent:credit")
        assert packet is not None
        assert packet.deployer_name == "Acme Bank"
        assert "process" in packet.summary
        assert reg.get("agent:credit").status == FriaStatus.NOTIFIED

    def test_notify_rejected_fria_returns_none(self):
        reg = FriaRegistry()
        bad = _complete_fria()
        bad.human_oversight_measures = ""
        reg.attach(bad)
        assert reg.notify_authority("agent:credit") is None

    def test_notify_unknown_agent_returns_none(self):
        reg = FriaRegistry()
        assert reg.notify_authority("agent:nobody") is None
