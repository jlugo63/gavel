"""Tests for Separation of Powers — Gavel's Constitutional Article III."""

from __future__ import annotations

import pytest

from gavel.separation import (
    ChainRole,
    ROLE_EXCLUSIONS,
    RoleAssignment,
    SeparationOfPowers,
    SeparationViolation,
)


# ---------------------------------------------------------------------------
# ChainRole enum
# ---------------------------------------------------------------------------

class TestChainRole:
    def test_all_roles_present(self):
        expected = {"proposer", "reviewer", "approver", "executor", "observer"}
        assert {r.value for r in ChainRole} == expected

    def test_roles_are_strings(self):
        for role in ChainRole:
            assert isinstance(role, str)
            assert role == role.value


# ---------------------------------------------------------------------------
# ROLE_EXCLUSIONS matrix
# ---------------------------------------------------------------------------

class TestRoleExclusions:
    def test_proposer_excluded_from_reviewer_and_approver(self):
        assert ChainRole.REVIEWER in ROLE_EXCLUSIONS[ChainRole.PROPOSER]
        assert ChainRole.APPROVER in ROLE_EXCLUSIONS[ChainRole.PROPOSER]

    def test_reviewer_excluded_from_proposer_and_approver(self):
        assert ChainRole.PROPOSER in ROLE_EXCLUSIONS[ChainRole.REVIEWER]
        assert ChainRole.APPROVER in ROLE_EXCLUSIONS[ChainRole.REVIEWER]

    def test_approver_excluded_from_proposer_and_reviewer(self):
        assert ChainRole.PROPOSER in ROLE_EXCLUSIONS[ChainRole.APPROVER]
        assert ChainRole.REVIEWER in ROLE_EXCLUSIONS[ChainRole.APPROVER]

    def test_executor_has_no_exclusions(self):
        assert ROLE_EXCLUSIONS[ChainRole.EXECUTOR] == set()

    def test_observer_has_no_exclusions(self):
        assert ROLE_EXCLUSIONS[ChainRole.OBSERVER] == set()

    def test_exclusion_symmetry(self):
        """If A excludes B, then B must exclude A."""
        for role, excluded in ROLE_EXCLUSIONS.items():
            for excl in excluded:
                assert role in ROLE_EXCLUSIONS[excl], (
                    f"{excl.value} should exclude {role.value} (symmetry)"
                )

    def test_every_role_has_entry(self):
        for role in ChainRole:
            assert role in ROLE_EXCLUSIONS


# ---------------------------------------------------------------------------
# SeparationOfPowers — valid assignments
# ---------------------------------------------------------------------------

class TestValidAssignments:
    def test_assign_returns_role_assignment(self):
        sop = SeparationOfPowers()
        result = sop.assign("agent:a", ChainRole.PROPOSER, "c-1")
        assert isinstance(result, RoleAssignment)
        assert result.actor_id == "agent:a"
        assert result.role == ChainRole.PROPOSER
        assert result.chain_id == "c-1"

    def test_distinct_actors_in_all_governance_roles(self):
        sop = SeparationOfPowers()
        sop.assign("agent:proposer", ChainRole.PROPOSER, "c-1")
        sop.assign("agent:reviewer", ChainRole.REVIEWER, "c-1")
        result = sop.assign("agent:approver", ChainRole.APPROVER, "c-1")
        assert result.role == ChainRole.APPROVER

    def test_same_role_reassignment_is_idempotent(self):
        sop = SeparationOfPowers()
        sop.assign("agent:obs", ChainRole.OBSERVER, "c-1")
        result = sop.assign("agent:obs", ChainRole.OBSERVER, "c-1")
        assert result.role == ChainRole.OBSERVER

    def test_executor_can_coexist_with_any_role(self):
        """Executor has no exclusions, so distinct actors can hold executor alongside anything."""
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.PROPOSER, "c-1")
        sop.assign("agent:b", ChainRole.EXECUTOR, "c-1")
        assert sop.get_role("agent:b", "c-1") == ChainRole.EXECUTOR

    def test_observer_can_coexist_with_any_role(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.APPROVER, "c-1")
        sop.assign("agent:b", ChainRole.OBSERVER, "c-1")
        assert sop.get_role("agent:b", "c-1") == ChainRole.OBSERVER

    def test_same_actor_different_chains(self):
        """An actor CAN hold different roles on different chains."""
        sop = SeparationOfPowers()
        sop.assign("agent:x", ChainRole.PROPOSER, "c-1")
        sop.assign("agent:x", ChainRole.REVIEWER, "c-2")
        sop.assign("agent:x", ChainRole.APPROVER, "c-3")
        assert sop.get_role("agent:x", "c-1") == ChainRole.PROPOSER
        assert sop.get_role("agent:x", "c-2") == ChainRole.REVIEWER
        assert sop.get_role("agent:x", "c-3") == ChainRole.APPROVER


# ---------------------------------------------------------------------------
# SeparationOfPowers — violations
# ---------------------------------------------------------------------------

class TestSeparationViolations:
    def test_proposer_cannot_be_reviewer(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.PROPOSER, "c-1")
        with pytest.raises(SeparationViolation) as exc:
            sop.assign("agent:a", ChainRole.REVIEWER, "c-1")
        assert exc.value.actor_id == "agent:a"
        assert exc.value.attempted_role == ChainRole.REVIEWER
        assert exc.value.existing_role == ChainRole.PROPOSER
        assert exc.value.chain_id == "c-1"

    def test_proposer_cannot_be_approver(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.PROPOSER, "c-1")
        with pytest.raises(SeparationViolation):
            sop.assign("agent:a", ChainRole.APPROVER, "c-1")

    def test_reviewer_cannot_be_proposer(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.REVIEWER, "c-1")
        with pytest.raises(SeparationViolation):
            sop.assign("agent:a", ChainRole.PROPOSER, "c-1")

    def test_reviewer_cannot_be_approver(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.REVIEWER, "c-1")
        with pytest.raises(SeparationViolation):
            sop.assign("agent:a", ChainRole.APPROVER, "c-1")

    def test_approver_cannot_be_proposer(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.APPROVER, "c-1")
        with pytest.raises(SeparationViolation):
            sop.assign("agent:a", ChainRole.PROPOSER, "c-1")

    def test_approver_cannot_be_reviewer(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.APPROVER, "c-1")
        with pytest.raises(SeparationViolation):
            sop.assign("agent:a", ChainRole.REVIEWER, "c-1")

    def test_violation_message_format(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.PROPOSER, "c-1")
        with pytest.raises(SeparationViolation, match="Separation violation on chain c-1"):
            sop.assign("agent:a", ChainRole.REVIEWER, "c-1")

    def test_actor_cannot_change_role_even_to_non_excluded(self):
        """Article III.2: role is fixed at first participation — even proposer->executor is blocked."""
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.PROPOSER, "c-1")
        with pytest.raises(SeparationViolation):
            sop.assign("agent:a", ChainRole.EXECUTOR, "c-1")

    def test_actor_cannot_change_role_observer_to_proposer(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.OBSERVER, "c-1")
        with pytest.raises(SeparationViolation):
            sop.assign("agent:a", ChainRole.PROPOSER, "c-1")


# ---------------------------------------------------------------------------
# validate_chain
# ---------------------------------------------------------------------------

class TestValidateChain:
    def test_valid_chain_no_violations(self):
        sop = SeparationOfPowers()
        sop.assign("agent:p", ChainRole.PROPOSER, "c-1")
        sop.assign("agent:r", ChainRole.REVIEWER, "c-1")
        sop.assign("agent:a", ChainRole.APPROVER, "c-1")
        assert sop.validate_chain("c-1") == []

    def test_validate_nonexistent_chain(self):
        sop = SeparationOfPowers()
        assert sop.validate_chain("c-doesnt-exist") == []

    def test_validate_chain_with_observer_and_executor(self):
        sop = SeparationOfPowers()
        sop.assign("agent:p", ChainRole.PROPOSER, "c-1")
        sop.assign("agent:r", ChainRole.REVIEWER, "c-1")
        sop.assign("agent:a", ChainRole.APPROVER, "c-1")
        sop.assign("agent:e", ChainRole.EXECUTOR, "c-1")
        sop.assign("agent:o", ChainRole.OBSERVER, "c-1")
        assert sop.validate_chain("c-1") == []


# ---------------------------------------------------------------------------
# get_role / get_chain_roster
# ---------------------------------------------------------------------------

class TestQueryMethods:
    def test_get_role_existing(self):
        sop = SeparationOfPowers()
        sop.assign("agent:a", ChainRole.PROPOSER, "c-1")
        assert sop.get_role("agent:a", "c-1") == ChainRole.PROPOSER

    def test_get_role_missing_actor(self):
        sop = SeparationOfPowers()
        assert sop.get_role("agent:ghost", "c-1") is None

    def test_get_role_missing_chain(self):
        sop = SeparationOfPowers()
        assert sop.get_role("agent:a", "c-nonexistent") is None

    def test_get_chain_roster(self):
        sop = SeparationOfPowers()
        sop.assign("agent:p", ChainRole.PROPOSER, "c-1")
        sop.assign("agent:r", ChainRole.REVIEWER, "c-1")
        roster = sop.get_chain_roster("c-1")
        assert roster == {"agent:p": "proposer", "agent:r": "reviewer"}

    def test_get_chain_roster_empty(self):
        sop = SeparationOfPowers()
        assert sop.get_chain_roster("c-unknown") == {}


# ---------------------------------------------------------------------------
# Multi-agent scenarios
# ---------------------------------------------------------------------------

class TestMultiAgentScenarios:
    def test_full_governance_pipeline(self):
        """Five-agent pipeline: propose, review, approve, execute, observe."""
        sop = SeparationOfPowers()
        for agent, role in [
            ("agent:p", ChainRole.PROPOSER),
            ("agent:r", ChainRole.REVIEWER),
            ("agent:a", ChainRole.APPROVER),
            ("agent:e", ChainRole.EXECUTOR),
            ("agent:o", ChainRole.OBSERVER),
        ]:
            sop.assign(agent, role, "c-pipeline")

        roster = sop.get_chain_roster("c-pipeline")
        assert len(roster) == 5
        assert sop.validate_chain("c-pipeline") == []

    def test_role_rotation_across_chains(self):
        """An agent can be proposer on chain-1, reviewer on chain-2, etc."""
        sop = SeparationOfPowers()
        sop.assign("agent:alice", ChainRole.PROPOSER, "c-1")
        sop.assign("agent:alice", ChainRole.REVIEWER, "c-2")
        sop.assign("agent:bob", ChainRole.REVIEWER, "c-1")
        sop.assign("agent:bob", ChainRole.PROPOSER, "c-2")
        assert sop.validate_chain("c-1") == []
        assert sop.validate_chain("c-2") == []

    def test_many_observers_on_one_chain(self):
        sop = SeparationOfPowers()
        sop.assign("agent:p", ChainRole.PROPOSER, "c-1")
        for i in range(10):
            sop.assign(f"agent:obs-{i}", ChainRole.OBSERVER, "c-1")
        roster = sop.get_chain_roster("c-1")
        assert len(roster) == 11  # 1 proposer + 10 observers
