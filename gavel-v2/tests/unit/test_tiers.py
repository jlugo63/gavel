"""Unit tests for TierPolicy — risk computation, tier mapping, requirements."""

from gavel.tiers import TierPolicy, RiskFactors, AutonomyTier, TIER_TABLE


class TestRiskComputation:
    def test_base_risk_only(self, tier_policy):
        factors = RiskFactors(action_type_base=0.3)
        risk = tier_policy.compute_risk(factors)
        assert risk == 0.3

    def test_production_adds_risk(self, tier_policy):
        base = RiskFactors(action_type_base=0.3)
        prod = RiskFactors(action_type_base=0.3, touches_production=True)
        assert tier_policy.compute_risk(prod) > tier_policy.compute_risk(base)

    def test_financial_adds_risk(self, tier_policy):
        base = RiskFactors(action_type_base=0.3)
        fin = RiskFactors(action_type_base=0.3, touches_financial=True)
        assert tier_policy.compute_risk(fin) > tier_policy.compute_risk(base)

    def test_pii_adds_risk(self, tier_policy):
        base = RiskFactors(action_type_base=0.3)
        pii = RiskFactors(action_type_base=0.3, touches_pii=True)
        assert tier_policy.compute_risk(pii) > tier_policy.compute_risk(base)

    def test_precedent_reduces_risk(self, tier_policy):
        no_precedent = RiskFactors(action_type_base=0.5)
        with_precedent = RiskFactors(action_type_base=0.5, precedent_count=15)
        assert tier_policy.compute_risk(with_precedent) < tier_policy.compute_risk(no_precedent)

    def test_risk_clamped_to_0_1(self, tier_policy):
        extreme = RiskFactors(
            action_type_base=0.9,
            touches_production=True,
            touches_financial=True,
            touches_pii=True,
            scope_breadth=1.0,
            time_of_day_risk=1.0,
        )
        risk = tier_policy.compute_risk(extreme)
        assert 0.0 <= risk <= 1.0

    def test_risk_never_negative(self, tier_policy):
        low = RiskFactors(action_type_base=0.0, precedent_count=100)
        assert tier_policy.compute_risk(low) >= 0.0


class TestTierMapping:
    def test_low_risk_is_supervised(self, tier_policy):
        tier = tier_policy.determine_tier(0.2)
        assert tier == AutonomyTier.SUPERVISED

    def test_medium_risk_is_semi_autonomous(self, tier_policy):
        tier = tier_policy.determine_tier(0.5)
        assert tier == AutonomyTier.SEMI_AUTONOMOUS

    def test_high_risk_is_autonomous(self, tier_policy):
        tier = tier_policy.determine_tier(0.75)
        assert tier == AutonomyTier.AUTONOMOUS

    def test_critical_risk(self, tier_policy):
        tier = tier_policy.determine_tier(0.95)
        assert tier == AutonomyTier.CRITICAL

    def test_boundary_0_4(self, tier_policy):
        # At exactly the threshold
        tier = tier_policy.determine_tier(0.4)
        assert tier == AutonomyTier.SEMI_AUTONOMOUS

    def test_boundary_0_7(self, tier_policy):
        tier = tier_policy.determine_tier(0.7)
        assert tier == AutonomyTier.AUTONOMOUS

    def test_boundary_0_9(self, tier_policy):
        tier = tier_policy.determine_tier(0.9)
        assert tier == AutonomyTier.CRITICAL


class TestTierRequirements:
    def test_supervised_requires_human(self):
        reqs = TIER_TABLE[AutonomyTier.SUPERVISED]
        assert reqs.requires_human_approval is True
        assert reqs.requires_blast_box is False

    def test_semi_autonomous_requires_evidence(self):
        reqs = TIER_TABLE[AutonomyTier.SEMI_AUTONOMOUS]
        assert reqs.requires_blast_box is True
        assert reqs.requires_evidence_review is True
        assert reqs.requires_human_approval is False

    def test_autonomous_requires_attestation(self):
        reqs = TIER_TABLE[AutonomyTier.AUTONOMOUS]
        assert reqs.requires_agent_attestation is True
        assert reqs.min_attestations >= 1
        assert reqs.requires_senior_agent is True

    def test_critical_requires_everything(self):
        reqs = TIER_TABLE[AutonomyTier.CRITICAL]
        assert reqs.requires_blast_box is True
        assert reqs.requires_evidence_review is True
        assert reqs.requires_agent_attestation is True
        assert reqs.min_attestations >= 2
        assert reqs.requires_human_approval is True
        assert reqs.requires_senior_agent is True

    def test_sla_increases_with_tier(self):
        t1 = TIER_TABLE[AutonomyTier.SEMI_AUTONOMOUS].sla_seconds
        t3 = TIER_TABLE[AutonomyTier.CRITICAL].sla_seconds
        assert t3 > t1


class TestFullEvaluation:
    def test_evaluate_returns_tuple(self, tier_policy):
        factors = RiskFactors(action_type_base=0.3, touches_production=True)
        tier, reqs, risk = tier_policy.evaluate(factors)
        assert isinstance(tier, AutonomyTier)
        assert isinstance(risk, float)
        assert reqs.tier == tier

    def test_fintech_scenario(self, tier_policy):
        """The payments-service scaling scenario from Scenario Zero."""
        factors = RiskFactors(
            action_type_base=0.3,
            touches_production=True,
            touches_financial=True,
        )
        tier, reqs, risk = tier_policy.evaluate(factors)
        assert risk == 0.65
        assert tier == AutonomyTier.SEMI_AUTONOMOUS
        assert reqs.requires_blast_box is True
