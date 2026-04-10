"""Tests for gavel.data_governance — EU AI Act Art. 10 policy enforcement."""

from __future__ import annotations

from gavel.data_governance import (
    BiasMitigation,
    DataGovernancePolicy,
    DataGovernanceRegistry,
    DatasetDescriptor,
    DatasetRole,
    validate_policy,
)


def _complete_policy(agent_id: str = "agent:credit") -> DataGovernancePolicy:
    return DataGovernancePolicy(
        agent_id=agent_id,
        design_choices=(
            "Feature engineering excludes prohibited attributes; model is a gradient-boosted "
            "tree chosen for interpretability and monotonicity constraints."
        ),
        datasets=[
            DatasetDescriptor(
                name="retail_credit_2024",
                role=DatasetRole.TRAINING,
                origin="Internal loan book, Jan-Dec 2024",
                collection_process="Extracted from core banking DB via audited ETL",
                size_rows=250_000,
                representativeness_note="Mirrors retail applicant mix at national level",
            ),
            DatasetDescriptor(
                name="holdout_2024_q4",
                role=DatasetRole.VALIDATION,
                origin="Same source as training, last quarter held out",
                collection_process="Temporal split",
                size_rows=50_000,
            ),
        ],
        preparation_operations=[
            "Deduplication",
            "Missing-value imputation with category-specific medians",
            "Monotonic binning of continuous features",
        ],
        measurement_assumptions=(
            "Default probability is assumed to be stable over a 12-month window "
            "absent macroeconomic shocks."
        ),
        availability_assessment=(
            "Sample size is sufficient for every segment larger than 1% of the "
            "population; smaller segments are flagged for manual review."
        ),
        protected_attributes=["gender", "age_band", "nationality"],
        bias_examination=(
            "Disparate impact ratio computed across protected classes on the "
            "holdout set; all ratios fall within the 0.8-1.25 fairness band."
        ),
        bias_mitigations=[
            BiasMitigation(
                protected_attribute="gender",
                detection_method="disparate_impact_ratio",
                mitigation_action="reweighting at training time",
                monitoring_cadence="quarterly",
            ),
            BiasMitigation(
                protected_attribute="age_band",
                detection_method="demographic_parity",
                mitigation_action="monotonicity constraint on age feature",
                monitoring_cadence="quarterly",
            ),
            BiasMitigation(
                protected_attribute="nationality",
                detection_method="equal_opportunity",
                mitigation_action="post-processing threshold calibration",
                monitoring_cadence="monthly",
            ),
        ],
        data_gap_analysis=(
            "Self-employed applicants are under-represented; flagged as data gap "
            "and routed to manual review."
        ),
        relevance_claim="Training window aligns with intended deployment window",
        representativeness_claim="Sample matches national retail applicant mix",
        error_rate_bound=0.02,
        completeness_claim="All mandatory fields present in >99.5% of rows",
    )


class TestValidator:
    def test_complete_policy_passes(self):
        report = validate_policy(_complete_policy())
        assert report.passed, (
            report.missing_sections,
            report.shallow_sections,
            report.bias_gaps,
        )

    def test_missing_design_choices(self):
        p = _complete_policy()
        p.design_choices = ""
        report = validate_policy(p)
        assert not report.passed
        assert any("10(2)(a)" in m for m in report.missing_sections)

    def test_no_datasets(self):
        p = _complete_policy()
        p.datasets = []
        report = validate_policy(p)
        assert any("10(2)(b)" in m for m in report.missing_sections)

    def test_unmitigated_protected_attribute_flagged(self):
        p = _complete_policy()
        p.protected_attributes.append("disability")
        report = validate_policy(p)
        assert not report.passed
        assert any("disability" in g for g in report.bias_gaps)

    def test_error_rate_out_of_range_flagged(self):
        p = _complete_policy()
        p.error_rate_bound = 1.5
        report = validate_policy(p)
        assert any("10(3)" in s for s in report.shallow_sections)

    def test_missing_error_rate(self):
        p = _complete_policy()
        p.error_rate_bound = None
        report = validate_policy(p)
        assert any("error rate" in m.lower() for m in report.missing_sections)

    def test_article_refs_populated(self):
        report = validate_policy(_complete_policy())
        assert "Art. 10(2)(a)" in report.article_references
        assert "Art. 10(3)" in report.article_references


class TestRegistry:
    def test_attach_and_query(self):
        reg = DataGovernanceRegistry()
        report = reg.attach(_complete_policy())
        assert report.passed
        assert reg.is_compliant("agent:credit")
        assert reg.get("agent:credit") is not None

    def test_non_compliant_agent(self):
        reg = DataGovernanceRegistry()
        bad = _complete_policy()
        bad.protected_attributes = []
        bad.bias_examination = ""
        reg.attach(bad)
        assert not reg.is_compliant("agent:credit")
