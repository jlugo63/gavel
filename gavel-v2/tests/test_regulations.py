"""Tests for gavel.regulations — multi-regulation compliance mapping."""

from __future__ import annotations

from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    FallbackBehavior,
    HighRiskCategory,
    PurposeDeclaration,
    ResourceAllowlist,
)
from gavel.regulations import (
    CoverageState,
    Regulation,
    build_matrix,
    classify_applicability,
)


def _app(
    category: HighRiskCategory = HighRiskCategory.NONE,
    interaction: str = "system_only",
    network: bool = False,
    execution: bool = False,
    synthetic: bool = False,
) -> EnrollmentApplication:
    return EnrollmentApplication(
        agent_id="agent:test",
        display_name="Test Agent",
        owner="owner",
        owner_contact="owner@example.com",
        budget_tokens=1000,
        purpose=PurposeDeclaration(
            summary="Test agent for regulation mapping test suite",
            operational_scope="internal ops",
            risk_tier="standard",
        ),
        capabilities=CapabilityManifest(
            tools=["edit"],
            network_access=network,
            execution_access=execution,
        ),
        resources=ResourceAllowlist(allowed_paths=["/tmp"]),
        boundaries=ActionBoundaries(allowed_actions=["read"]),
        fallback=FallbackBehavior(),
        high_risk_category=category,
        interaction_type=interaction,
        synthetic_content=synthetic,
    )


class TestApplicability:
    def test_ai_act_always_applies(self):
        regs = classify_applicability(_app())
        assert Regulation.EU_AI_ACT in regs

    def test_gdpr_applies_to_human_facing(self):
        regs = classify_applicability(_app(interaction="human_facing"))
        assert Regulation.GDPR in regs

    def test_gdpr_applies_to_employment_high_risk(self):
        regs = classify_applicability(_app(category=HighRiskCategory.EMPLOYMENT))
        assert Regulation.GDPR in regs

    def test_cra_applies_when_network_or_execution(self):
        regs = classify_applicability(_app(network=True))
        assert Regulation.CRA in regs
        regs = classify_applicability(_app(execution=True))
        assert Regulation.CRA in regs

    def test_cra_not_applied_to_pure_file_agent(self):
        regs = classify_applicability(_app())
        assert Regulation.CRA not in regs

    def test_nis2_applies_to_critical_infrastructure(self):
        regs = classify_applicability(_app(category=HighRiskCategory.CRITICAL_INFRASTRUCTURE))
        assert Regulation.NIS2 in regs

    def test_dsa_applies_when_synthetic_and_user_facing(self):
        regs = classify_applicability(_app(synthetic=True, interaction="human_facing"))
        assert Regulation.DSA in regs

    def test_dsa_not_applied_when_system_only(self):
        regs = classify_applicability(_app(synthetic=True, interaction="system_only"))
        assert Regulation.DSA not in regs


class TestMatrix:
    def test_simple_agent_matrix(self):
        matrix = build_matrix(_app())
        assert matrix.applicable_regulations == [Regulation.EU_AI_ACT]
        # Every obligation belongs to an applicable regulation
        for o in matrix.obligations:
            assert o.regulation in matrix.applicable_regulations

    def test_multi_reg_agent_matrix(self):
        matrix = build_matrix(_app(
            category=HighRiskCategory.EMPLOYMENT,
            interaction="human_facing",
            network=True,
        ))
        reg_set = set(matrix.applicable_regulations)
        assert Regulation.EU_AI_ACT in reg_set
        assert Regulation.GDPR in reg_set
        assert Regulation.CRA in reg_set

    def test_coverage_summary_sums(self):
        matrix = build_matrix(_app(
            category=HighRiskCategory.EMPLOYMENT,
            interaction="human_facing",
            network=True,
        ))
        summary = matrix.coverage_summary()
        assert sum(summary.values()) == len(matrix.obligations)
        assert summary[CoverageState.SATISFIED.value] >= 1

    def test_gaps_subset(self):
        matrix = build_matrix(_app(network=True))
        gaps = matrix.gaps()
        for g in gaps:
            assert g.coverage == CoverageState.GAP

    def test_by_regulation_groups_correctly(self):
        matrix = build_matrix(_app(
            category=HighRiskCategory.EMPLOYMENT,
            interaction="human_facing",
        ))
        grouped = matrix.by_regulation()
        assert Regulation.EU_AI_ACT.value in grouped
        assert all(
            all(o.regulation.value == reg_key for o in obs)
            for reg_key, obs in grouped.items()
        )

    def test_overlaps_documented_for_key_obligations(self):
        matrix = build_matrix(_app(
            category=HighRiskCategory.EMPLOYMENT,
            interaction="human_facing",
        ))
        # AI Act Art. 27 should declare overlap with GDPR Art. 35
        art_27 = next(
            o for o in matrix.obligations
            if o.regulation == Regulation.EU_AI_ACT and "Art. 27" in o.article
        )
        assert "gdpr:Art. 35" in art_27.overlaps_with

    def test_obligation_id_format(self):
        matrix = build_matrix(_app())
        ids = [o.obligation_id for o in matrix.obligations]
        assert all(":" in i for i in ids)
        assert all(i.startswith("eu_ai_act") for i in ids)
