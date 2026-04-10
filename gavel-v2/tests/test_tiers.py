"""Tests for Tiered Autonomy — risk scoring and tier determination."""

from __future__ import annotations

import pytest

from gavel.tiers import AutonomyTier, RiskFactors, TierPolicy, TierRequirements, TIER_TABLE


class TestTierTable:
    def test_all_tiers_exist(self):
        for tier in AutonomyTier:
            assert tier in TIER_TABLE

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
        assert reqs.requires_senior_agent is True
        assert reqs.min_attestations >= 1

    def test_critical_requires_multi_sig(self):
        reqs = TIER_TABLE[AutonomyTier.CRITICAL]
        assert reqs.requires_human_approval is True
        assert reqs.requires_senior_agent is True
        assert reqs.min_attestations >= 2

    def test_sla_escalates_with_tier(self):
        """Higher tiers should generally have tighter SLAs (except CRITICAL which is longer)."""
        supervised_sla = TIER_TABLE[AutonomyTier.SUPERVISED].sla_seconds
        semi_sla = TIER_TABLE[AutonomyTier.SEMI_AUTONOMOUS].sla_seconds
        assert supervised_sla > semi_sla  # 3600 > 600


class TestRiskScoring:
    def setup_method(self):
        self.policy = TierPolicy()

    def test_zero_risk(self):
        factors = RiskFactors(action_type_base=0.0)
        risk = self.policy.compute_risk(factors)
        assert risk == 0.0

    def test_base_risk_passthrough(self):
        factors = RiskFactors(action_type_base=0.5)
        risk = self.policy.compute_risk(factors)
        assert risk >= 0.5

    def test_production_adds_risk(self):
        base = RiskFactors(action_type_base=0.3)
        prod = RiskFactors(action_type_base=0.3, touches_production=True)
        assert self.policy.compute_risk(prod) > self.policy.compute_risk(base)

    def test_financial_adds_risk(self):
        base = RiskFactors(action_type_base=0.3)
        fin = RiskFactors(action_type_base=0.3, touches_financial=True)
        assert self.policy.compute_risk(fin) > self.policy.compute_risk(base)

    def test_pii_adds_risk(self):
        base = RiskFactors(action_type_base=0.3)
        pii = RiskFactors(action_type_base=0.3, touches_pii=True)
        assert self.policy.compute_risk(pii) > self.policy.compute_risk(base)

    def test_cumulative_risk(self):
        """All flags together should produce high risk."""
        factors = RiskFactors(
            action_type_base=0.5,
            touches_production=True,
            touches_financial=True,
            touches_pii=True,
            scope_breadth=0.8,
        )
        risk = self.policy.compute_risk(factors)
        assert risk >= 0.9

    def test_precedent_reduces_risk(self):
        no_precedent = RiskFactors(action_type_base=0.5, precedent_count=0)
        high_precedent = RiskFactors(action_type_base=0.5, precedent_count=15)
        assert self.policy.compute_risk(high_precedent) < self.policy.compute_risk(no_precedent)

    def test_risk_clamped_0_1(self):
        low = RiskFactors(action_type_base=-0.5, precedent_count=100)
        assert self.policy.compute_risk(low) >= 0.0

        high = RiskFactors(
            action_type_base=0.9,
            touches_production=True,
            touches_financial=True,
            touches_pii=True,
            scope_breadth=1.0,
            time_of_day_risk=1.0,
        )
        assert self.policy.compute_risk(high) <= 1.0


class TestTierDetermination:
    def setup_method(self):
        self.policy = TierPolicy()

    def test_low_risk_supervised(self):
        assert self.policy.determine_tier(0.1) == AutonomyTier.SUPERVISED

    def test_medium_risk_semi_autonomous(self):
        assert self.policy.determine_tier(0.5) == AutonomyTier.SEMI_AUTONOMOUS

    def test_high_risk_autonomous(self):
        assert self.policy.determine_tier(0.8) == AutonomyTier.AUTONOMOUS

    def test_critical_risk(self):
        assert self.policy.determine_tier(0.95) == AutonomyTier.CRITICAL

    def test_boundary_values(self):
        """Test at exact threshold boundaries."""
        assert self.policy.determine_tier(0.0) == AutonomyTier.SUPERVISED
        assert self.policy.determine_tier(0.4) == AutonomyTier.SEMI_AUTONOMOUS
        assert self.policy.determine_tier(0.7) == AutonomyTier.AUTONOMOUS
        assert self.policy.determine_tier(0.9) == AutonomyTier.CRITICAL

    def test_just_below_threshold(self):
        assert self.policy.determine_tier(0.39) == AutonomyTier.SUPERVISED
        assert self.policy.determine_tier(0.69) == AutonomyTier.SEMI_AUTONOMOUS
        assert self.policy.determine_tier(0.89) == AutonomyTier.AUTONOMOUS


class TestFullEvaluation:
    def setup_method(self):
        self.policy = TierPolicy()

    def test_evaluate_returns_tuple(self):
        factors = RiskFactors(action_type_base=0.5)
        tier, reqs, risk = self.policy.evaluate(factors)
        assert isinstance(tier, AutonomyTier)
        assert isinstance(reqs, TierRequirements)
        assert isinstance(risk, float)

    def test_evaluate_low_risk_action(self):
        factors = RiskFactors(action_type_base=0.1)
        tier, reqs, risk = self.policy.evaluate(factors)
        assert tier == AutonomyTier.SUPERVISED
        assert reqs.requires_human_approval is True
        assert risk < 0.4

    def test_evaluate_critical_action(self):
        factors = RiskFactors(
            action_type_base=0.6,
            touches_production=True,
            touches_financial=True,
        )
        tier, reqs, risk = self.policy.evaluate(factors)
        assert tier == AutonomyTier.CRITICAL
        assert reqs.requires_human_approval is True
        assert reqs.min_attestations >= 2

    def test_custom_thresholds(self):
        """Custom thresholds should shift tier boundaries."""
        strict_policy = TierPolicy(risk_thresholds={
            AutonomyTier.SUPERVISED: 0.0,
            AutonomyTier.SEMI_AUTONOMOUS: 0.2,
            AutonomyTier.AUTONOMOUS: 0.4,
            AutonomyTier.CRITICAL: 0.6,
        })
        # 0.5 would be SEMI_AUTONOMOUS with defaults, but AUTONOMOUS with strict
        assert strict_policy.determine_tier(0.5) == AutonomyTier.AUTONOMOUS
