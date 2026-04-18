"""
Separation of Powers — the principle Microsoft's trust scoring doesn't enforce.

Microsoft's Agent Mesh gives agents a trust score (0-1000). A high-trust
agent can do more. But nothing prevents the SAME high-trust agent from
proposing, reviewing, AND approving its own action.

Gavel enforces that the proposer, reviewer, and approver must be distinct
principals. This is checked at chain-append time, not at policy-eval time.
It's a structural guarantee, not a policy decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ChainRole(str, Enum):
    PROPOSER = "proposer"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    EXECUTOR = "executor"
    OBSERVER = "observer"  # can read the chain but not participate


# Which roles are forbidden from being held by the same actor on one chain.
ROLE_EXCLUSIONS: dict[ChainRole, set[ChainRole]] = {
    ChainRole.PROPOSER: {ChainRole.REVIEWER, ChainRole.APPROVER},
    ChainRole.REVIEWER: {ChainRole.PROPOSER, ChainRole.APPROVER},
    ChainRole.APPROVER: {ChainRole.PROPOSER, ChainRole.REVIEWER},
    ChainRole.EXECUTOR: set(),   # executor can be same as approver (they carry out the approved action)
    ChainRole.OBSERVER: set(),   # observers have no exclusions
}


@dataclass
class RoleAssignment:
    actor_id: str
    role: ChainRole
    chain_id: str


class SeparationViolation(Exception):
    """Raised when an actor attempts a role that violates separation of powers."""

    def __init__(self, actor_id: str, attempted_role: ChainRole, existing_role: ChainRole, chain_id: str):
        self.actor_id = actor_id
        self.attempted_role = attempted_role
        self.existing_role = existing_role
        self.chain_id = chain_id
        super().__init__(
            f"Separation violation on chain {chain_id}: "
            f"{actor_id} has role '{existing_role.value}', "
            f"cannot also be '{attempted_role.value}'"
        )


class SeparationOfPowers:
    """
    Enforces that distinct governance roles on a chain are held by
    distinct principals. This is Constitutional Article III.

    Usage:
        sop = SeparationOfPowers()
        sop.assign("agent:monitor", ChainRole.PROPOSER, "c-8a3f")
        sop.assign("agent:reviewer", ChainRole.REVIEWER, "c-8a3f")  # OK
        sop.assign("agent:monitor", ChainRole.APPROVER, "c-8a3f")   # RAISES
    """

    def __init__(self):
        # chain_id -> {actor_id -> ChainRole}
        self._assignments: dict[str, dict[str, ChainRole]] = {}

    def assign(self, actor_id: str, role: ChainRole, chain_id: str) -> RoleAssignment:
        """
        Assign a role to an actor on a chain. Raises SeparationViolation
        if the assignment would violate the exclusion matrix.
        """
        chain_roles = self._assignments.setdefault(chain_id, {})

        existing_role = chain_roles.get(actor_id)
        if existing_role is not None:
            if existing_role == role:
                return RoleAssignment(actor_id=actor_id, role=role, chain_id=chain_id)
            # Article III.2: role is fixed at first participation
            raise SeparationViolation(actor_id, role, existing_role, chain_id)

        excluded_roles = ROLE_EXCLUSIONS.get(role, set())
        for existing_actor, existing_actor_role in chain_roles.items():
            if existing_actor == actor_id and existing_actor_role in excluded_roles:
                raise SeparationViolation(actor_id, role, existing_actor_role, chain_id)

        chain_roles[actor_id] = role
        return RoleAssignment(actor_id=actor_id, role=role, chain_id=chain_id)

    def validate_chain(self, chain_id: str) -> list[str]:
        """
        Validate that all role assignments on a chain satisfy separation.
        Returns list of violation descriptions.
        """
        violations = []
        chain_roles = self._assignments.get(chain_id, {})

        role_actors: dict[ChainRole, list[str]] = {}
        for actor_id, role in chain_roles.items():
            role_actors.setdefault(role, []).append(actor_id)

        for role, excluded in ROLE_EXCLUSIONS.items():
            actors_in_role = set(role_actors.get(role, []))
            for excl_role in excluded:
                actors_in_excluded = set(role_actors.get(excl_role, []))
                overlap = actors_in_role & actors_in_excluded
                if overlap:
                    violations.append(
                        f"III.1: {overlap} hold both '{role.value}' and '{excl_role.value}'"
                    )

        return violations

    def get_role(self, actor_id: str, chain_id: str) -> ChainRole | None:
        return self._assignments.get(chain_id, {}).get(actor_id)

    def get_chain_roster(self, chain_id: str) -> dict[str, str]:
        """Return {actor_id: role} for a chain."""
        return {
            aid: role.value
            for aid, role in self._assignments.get(chain_id, {}).items()
        }
