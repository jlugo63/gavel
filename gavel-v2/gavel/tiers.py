"""
Tiered Autonomy — mapping governance tiers to Microsoft's trust scores.

Microsoft's Agent Mesh has a 0-1000 trust scale with 5 behavioral tiers.
But trust != autonomy. A high-trust agent still shouldn't auto-deploy
to production without approval.

Gavel's tiers define what governance controls are REQUIRED at each level.
An agent's tier determines the approval workflow, not just whether the
action is allowed.

Tier 0: Human must approve everything.
Tier 1: Auto-approve if evidence review passes + low risk.
Tier 2: Agent attestation + human or senior agent approval.
Tier 3: Multi-sig (multiple independent reviewers + human).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class AutonomyTier(IntEnum):
    """Governance tiers — what controls are required."""

    SUPERVISED = 0       # Human approves everything
    SEMI_AUTONOMOUS = 1  # Auto-approve with evidence
    AUTONOMOUS = 2       # Agent attestation + approval
    CRITICAL = 3         # Multi-sig with human oversight


@dataclass
class TierRequirements:
    """What governance controls are required at each tier."""

    tier: AutonomyTier
    requires_blast_box: bool
    requires_evidence_review: bool
    requires_agent_attestation: bool
    min_attestations: int
    requires_human_approval: bool
    requires_senior_agent: bool
    sla_seconds: int  # max time before auto-deny
    description: str


# The tier policy table — defines governance requirements per tier.
TIER_TABLE: dict[AutonomyTier, TierRequirements] = {
    AutonomyTier.SUPERVISED: TierRequirements(
        tier=AutonomyTier.SUPERVISED,
        requires_blast_box=False,
        requires_evidence_review=False,
        requires_agent_attestation=False,
        min_attestations=0,
        requires_human_approval=True,
        requires_senior_agent=False,
        sla_seconds=3600,  # 1 hour — human will get to it
        description="Full human oversight. Agent can only propose.",
    ),
    AutonomyTier.SEMI_AUTONOMOUS: TierRequirements(
        tier=AutonomyTier.SEMI_AUTONOMOUS,
        requires_blast_box=True,
        requires_evidence_review=True,
        requires_agent_attestation=False,
        min_attestations=0,
        requires_human_approval=False,
        requires_senior_agent=False,
        sla_seconds=600,  # 10 minutes
        description="Auto-approve if evidence review passes and risk < threshold.",
    ),
    AutonomyTier.AUTONOMOUS: TierRequirements(
        tier=AutonomyTier.AUTONOMOUS,
        requires_blast_box=True,
        requires_evidence_review=True,
        requires_agent_attestation=True,
        min_attestations=1,
        requires_human_approval=False,
        requires_senior_agent=True,
        sla_seconds=600,  # 10 minutes
        description="Agent attestation + senior agent or human approval.",
    ),
    AutonomyTier.CRITICAL: TierRequirements(
        tier=AutonomyTier.CRITICAL,
        requires_blast_box=True,
        requires_evidence_review=True,
        requires_agent_attestation=True,
        min_attestations=2,
        requires_human_approval=True,
        requires_senior_agent=True,
        sla_seconds=1800,  # 30 minutes
        description="Multi-sig: multiple reviewers + human + senior agent.",
    ),
}


@dataclass
class RiskFactors:
    """Factors that contribute to risk scoring."""

    action_type_base: float = 0.0
    touches_production: bool = False
    touches_financial: bool = False
    touches_pii: bool = False
    scope_breadth: float = 0.0  # 0-1, how broad the scope is
    time_of_day_risk: float = 0.0  # higher at night
    precedent_count: int = 0  # how many similar past actions succeeded


class TierPolicy:
    """
    Computes the required governance tier for a proposed action.

    Uses risk factors to determine which tier applies, then returns
    the governance requirements for that tier.
    """

    def __init__(
        self,
        risk_thresholds: dict[AutonomyTier, float] | None = None,
    ):
        self.risk_thresholds = risk_thresholds or {
            AutonomyTier.SUPERVISED: 0.0,    # always allowed
            AutonomyTier.SEMI_AUTONOMOUS: 0.4,
            AutonomyTier.AUTONOMOUS: 0.7,
            AutonomyTier.CRITICAL: 0.9,
        }

    def compute_risk(self, factors: RiskFactors) -> float:
        """Compute a 0-1 risk score from factors."""
        risk = factors.action_type_base

        if factors.touches_production:
            risk += 0.2
        if factors.touches_financial:
            risk += 0.15
        if factors.touches_pii:
            risk += 0.15

        risk += factors.scope_breadth * 0.1
        risk += factors.time_of_day_risk * 0.1

        # Precedent reduces risk (familiarity)
        if factors.precedent_count > 10:
            risk -= 0.1
        elif factors.precedent_count > 5:
            risk -= 0.05

        return max(0.0, min(1.0, risk))

    def determine_tier(self, risk: float) -> AutonomyTier:
        """Map a risk score to a governance tier."""
        if risk >= self.risk_thresholds[AutonomyTier.CRITICAL]:
            return AutonomyTier.CRITICAL
        elif risk >= self.risk_thresholds[AutonomyTier.AUTONOMOUS]:
            return AutonomyTier.AUTONOMOUS
        elif risk >= self.risk_thresholds[AutonomyTier.SEMI_AUTONOMOUS]:
            return AutonomyTier.SEMI_AUTONOMOUS
        else:
            return AutonomyTier.SUPERVISED

    def get_requirements(self, tier: AutonomyTier) -> TierRequirements:
        return TIER_TABLE[tier]

    def evaluate(self, factors: RiskFactors) -> tuple[AutonomyTier, TierRequirements, float]:
        """
        Full evaluation: compute risk, determine tier, return requirements.
        Returns (tier, requirements, risk_score).
        """
        risk = self.compute_risk(factors)
        tier = self.determine_tier(risk)
        reqs = self.get_requirements(tier)
        return tier, reqs, risk
