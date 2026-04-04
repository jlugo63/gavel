"""Unit tests for Separation of Powers — role exclusions, violation detection."""

import pytest

from gavel.separation import (
    SeparationOfPowers,
    ChainRole,
    SeparationViolation,
    RoleAssignment,
    ROLE_EXCLUSIONS,
)


class TestRoleAssignment:
    def test_assign_proposer(self, separation):
        result = separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        assert isinstance(result, RoleAssignment)
        assert result.role == ChainRole.PROPOSER

    def test_assign_different_roles_different_actors(self, separation):
        separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        separation.assign("agent:b", ChainRole.REVIEWER, "c-1")
        separation.assign("agent:c", ChainRole.APPROVER, "c-1")
        roster = separation.get_chain_roster("c-1")
        assert roster == {
            "agent:a": "proposer",
            "agent:b": "reviewer",
            "agent:c": "approver",
        }

    def test_same_role_same_actor_is_ok(self, separation):
        separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        # Assigning same role again should not raise
        result = separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        assert result.role == ChainRole.PROPOSER

    def test_different_chains_are_independent(self, separation):
        separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        # Same agent can be reviewer on a different chain
        result = separation.assign("agent:a", ChainRole.REVIEWER, "c-2")
        assert result.role == ChainRole.REVIEWER


class TestSeparationEnforcement:
    def test_proposer_cannot_be_reviewer(self, separation):
        separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        with pytest.raises(SeparationViolation) as exc_info:
            separation.assign("agent:a", ChainRole.REVIEWER, "c-1")
        assert "proposer" in str(exc_info.value).lower()
        assert "reviewer" in str(exc_info.value).lower()

    def test_proposer_cannot_be_approver(self, separation):
        separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        with pytest.raises(SeparationViolation):
            separation.assign("agent:a", ChainRole.APPROVER, "c-1")

    def test_reviewer_cannot_be_proposer(self, separation):
        separation.assign("agent:a", ChainRole.REVIEWER, "c-1")
        with pytest.raises(SeparationViolation):
            separation.assign("agent:a", ChainRole.PROPOSER, "c-1")

    def test_reviewer_cannot_be_approver(self, separation):
        separation.assign("agent:a", ChainRole.REVIEWER, "c-1")
        with pytest.raises(SeparationViolation):
            separation.assign("agent:a", ChainRole.APPROVER, "c-1")

    def test_approver_cannot_be_proposer(self, separation):
        separation.assign("agent:a", ChainRole.APPROVER, "c-1")
        with pytest.raises(SeparationViolation):
            separation.assign("agent:a", ChainRole.PROPOSER, "c-1")

    def test_approver_cannot_be_reviewer(self, separation):
        separation.assign("agent:a", ChainRole.APPROVER, "c-1")
        with pytest.raises(SeparationViolation):
            separation.assign("agent:a", ChainRole.REVIEWER, "c-1")

    def test_observer_has_no_exclusions(self, separation):
        separation.assign("agent:a", ChainRole.OBSERVER, "c-1")
        # Observer can't switch to another role (Article III.2: role fixed at first participation)
        # But observer has no exclusions in the matrix
        # This tests the exclusion matrix, not the role-switching rule
        assert separation.get_role("agent:a", "c-1") == ChainRole.OBSERVER


class TestRoleExclusionMatrix:
    def test_proposer_excludes_reviewer_and_approver(self):
        excl = ROLE_EXCLUSIONS[ChainRole.PROPOSER]
        assert ChainRole.REVIEWER in excl
        assert ChainRole.APPROVER in excl

    def test_reviewer_excludes_proposer_and_approver(self):
        excl = ROLE_EXCLUSIONS[ChainRole.REVIEWER]
        assert ChainRole.PROPOSER in excl
        assert ChainRole.APPROVER in excl

    def test_executor_has_no_exclusions(self):
        assert ROLE_EXCLUSIONS[ChainRole.EXECUTOR] == set()

    def test_observer_has_no_exclusions(self):
        assert ROLE_EXCLUSIONS[ChainRole.OBSERVER] == set()


class TestValidateChain:
    def test_valid_chain(self, separation):
        separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        separation.assign("agent:b", ChainRole.REVIEWER, "c-1")
        separation.assign("agent:c", ChainRole.APPROVER, "c-1")
        violations = separation.validate_chain("c-1")
        assert violations == []

    def test_empty_chain(self, separation):
        violations = separation.validate_chain("c-nonexistent")
        assert violations == []

    def test_get_role(self, separation):
        separation.assign("agent:a", ChainRole.PROPOSER, "c-1")
        assert separation.get_role("agent:a", "c-1") == ChainRole.PROPOSER
        assert separation.get_role("agent:b", "c-1") is None
