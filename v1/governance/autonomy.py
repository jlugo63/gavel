"""
Tiered Autonomy Contract
Constitutional Reference: §I.3 — Tiered Autonomy

Tier 0: propose-only — agent can submit proposals, cannot execute
Tier 1: sandbox execution — approved actions run in Blast Box only
Tier 2: canary + attestations — (future) canary deployment with agent attestation
Tier 3: production + human approval — production execution with mandatory human sign-off
"""

from __future__ import annotations

from dataclasses import dataclass

from governance.identity import validate_actor


@dataclass
class TierPolicy:
    tier: int
    can_execute: bool
    requires_sandbox: bool
    requires_human_approval: bool
    description: str


TIER_POLICIES: dict[int, TierPolicy] = {
    0: TierPolicy(
        tier=0,
        can_execute=False,
        requires_sandbox=False,
        requires_human_approval=False,
        description="Propose-only: no execution permitted",
    ),
    1: TierPolicy(
        tier=1,
        can_execute=True,
        requires_sandbox=True,
        requires_human_approval=False,
        description="Sandbox execution: Blast Box only",
    ),
    2: TierPolicy(
        tier=2,
        can_execute=True,
        requires_sandbox=True,
        requires_human_approval=False,
        description="Canary + attestations (not yet implemented)",
    ),
    3: TierPolicy(
        tier=3,
        can_execute=True,
        requires_sandbox=False,
        requires_human_approval=True,
        description="Production execution with human approval",
    ),
}


def get_tier_policy(actor_id: str) -> TierPolicy:
    """Look up the actor's tier and return the corresponding TierPolicy.

    Raises ValueError for unknown or inactive actors.
    """
    identity = validate_actor(actor_id)
    tier = identity.tier
    if tier not in TIER_POLICIES:
        raise ValueError(f"Unknown tier {tier} for actor {actor_id}")
    return TIER_POLICIES[tier]


def check_execution_allowed(
    actor_id: str,
    has_human_approval: bool = False,
) -> tuple[bool, str]:
    """Check whether an actor is allowed to execute.

    Returns (allowed, reason).
    """
    policy = get_tier_policy(actor_id)

    if policy.tier == 0:
        return (False, "Tier 0: propose-only, execution not permitted")

    if policy.tier == 1:
        return (True, "Tier 1: sandbox execution permitted")

    if policy.tier == 2:
        return (False, "Tier 2: canary execution not yet implemented")

    if policy.tier == 3:
        if not has_human_approval:
            return (False, "Tier 3: requires human approval")
        return (True, "Tier 3: production execution with human approval")

    return (False, f"Unknown tier {policy.tier}")
