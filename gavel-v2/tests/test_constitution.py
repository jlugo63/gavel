"""Tests for Constitutional Invariants — immutable governance rules."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from gavel.constitution import (
    CONSTITUTION,
    Constitution,
    Invariant,
    InvariantClass,
)


# ── InvariantClass Enum ───────────────────────────────────────────


class TestInvariantClass:
    def test_all_articles_defined(self):
        expected = {"I", "I.2", "II", "III", "IV", "V"}
        actual = {ic.value for ic in InvariantClass}
        assert actual == expected

    def test_enum_string_values(self):
        assert InvariantClass.IMMUTABILITY.value == "I"
        assert InvariantClass.AUTHORITY.value == "I.2"
        assert InvariantClass.OPERATIONAL.value == "II"
        assert InvariantClass.SEPARATION.value == "III"
        assert InvariantClass.HUMAN_OVERRIDE.value == "IV"
        assert InvariantClass.PROHIBITED.value == "V"


# ── Invariant Dataclass ──────────────────────────────────────────


class TestInvariant:
    def test_invariant_is_frozen(self):
        inv = Invariant(
            article=InvariantClass.IMMUTABILITY,
            section="1",
            text="Test invariant",
            enforcement="Test enforcement",
        )
        with pytest.raises(AttributeError):
            inv.text = "Modified"  # type: ignore[misc]

    def test_invariant_id_format(self):
        inv = Invariant(
            article=InvariantClass.SEPARATION,
            section="2",
            text="Test",
            enforcement="Test",
        )
        assert inv.id == "III.2"

    def test_invariant_id_authority(self):
        inv = Invariant(
            article=InvariantClass.AUTHORITY,
            section="1",
            text="No self-modification",
            enforcement="Cedar forbid",
        )
        assert inv.id == "I.2.1"


# ── CONSTITUTION List ────────────────────────────────────────────


class TestConstitutionList:
    def test_exactly_11_invariants(self):
        """The constitution defines exactly 11 invariants (9 original + 2 prohibited)."""
        assert len(CONSTITUTION) == 11

    def test_all_invariants_have_text(self):
        for inv in CONSTITUTION:
            assert inv.text, f"Invariant {inv.id} has no text"

    def test_all_invariants_have_enforcement(self):
        for inv in CONSTITUTION:
            assert inv.enforcement, f"Invariant {inv.id} has no enforcement"

    def test_invariant_ids_are_unique(self):
        ids = [inv.id for inv in CONSTITUTION]
        assert len(ids) == len(set(ids)), f"Duplicate invariant IDs: {ids}"

    def test_immutability_invariant_present(self):
        ids = [inv.id for inv in CONSTITUTION]
        assert "I.1" in ids

    def test_authority_invariants_present(self):
        ids = [inv.id for inv in CONSTITUTION]
        assert "I.2.1" in ids
        assert "I.2.2" in ids

    def test_operational_invariants_present(self):
        ids = [inv.id for inv in CONSTITUTION]
        assert "II.1" in ids
        assert "II.2" in ids

    def test_separation_invariants_present(self):
        ids = [inv.id for inv in CONSTITUTION]
        assert "III.1" in ids
        assert "III.2" in ids

    def test_human_override_invariants_present(self):
        ids = [inv.id for inv in CONSTITUTION]
        assert "IV.1" in ids
        assert "IV.2" in ids

    def test_prohibited_invariants_present(self):
        ids = [inv.id for inv in CONSTITUTION]
        assert "V.1" in ids
        assert "V.2" in ids

    def test_default_deny_invariant_text(self):
        """Article IV.2 — default-DENY behavior."""
        inv = next(i for i in CONSTITUTION if i.id == "IV.2")
        assert "deny" in inv.enforcement.lower()
        assert "default" in inv.enforcement.lower()

    def test_audit_immutability_invariant(self):
        inv = next(i for i in CONSTITUTION if i.id == "I.1")
        assert "append-only" in inv.text
        assert "SHA-256" in inv.enforcement

    def test_no_self_approval(self):
        inv = next(i for i in CONSTITUTION if i.id == "I.2.2")
        assert "approve" in inv.text.lower()
        assert "own" in inv.text.lower()

    def test_prohibited_eu_ai_act_article_5(self):
        inv = next(i for i in CONSTITUTION if i.id == "V.1")
        assert "Article 5" in inv.text
        assert "social scoring" in inv.text


# ── Constitution Class ────────────────────────────────────────────


class TestConstitutionClass:
    def test_invariants_loaded(self):
        c = Constitution()
        assert len(c.invariants) == 11

    def test_get_invariant_exists(self):
        c = Constitution()
        inv = c.get_invariant("I.1")
        assert inv is not None
        assert inv.article == InvariantClass.IMMUTABILITY

    def test_get_invariant_not_found(self):
        c = Constitution()
        assert c.get_invariant("X.99") is None

    def test_get_all_invariant_ids(self):
        c = Constitution()
        expected_ids = {inv.id for inv in CONSTITUTION}
        actual_ids = set(c.invariants.keys())
        assert actual_ids == expected_ids


# ── Chain Invariant Checking ──────────────────────────────────────


def _mock_chain(
    integrity_ok: bool = True,
    proposers: list[str] | None = None,
    reviewers: list[str] | None = None,
    approvers: list[str] | None = None,
) -> MagicMock:
    chain = MagicMock()
    chain.verify_integrity.return_value = integrity_ok
    chain.get_actors_by_role.side_effect = lambda role: {
        "proposer": proposers or [],
        "reviewer": reviewers or [],
        "approver": approvers or [],
    }.get(role, [])
    return chain


class TestCheckChainInvariants:
    def test_valid_chain_no_violations(self):
        c = Constitution()
        chain = _mock_chain(
            proposers=["agent:a"],
            reviewers=["agent:b"],
            approvers=["agent:c"],
        )
        violations = c.check_chain_invariants(chain)
        assert violations == []

    def test_hash_integrity_violation(self):
        c = Constitution()
        chain = _mock_chain(integrity_ok=False)
        violations = c.check_chain_invariants(chain)
        assert any("I.1" in v for v in violations)
        assert any("integrity" in v.lower() for v in violations)

    def test_proposer_reviewer_overlap(self):
        c = Constitution()
        chain = _mock_chain(
            proposers=["agent:a"],
            reviewers=["agent:a"],
            approvers=["agent:c"],
        )
        violations = c.check_chain_invariants(chain)
        assert any("III.1" in v and "Proposer" in v and "reviewer" in v for v in violations)

    def test_proposer_approver_overlap(self):
        c = Constitution()
        chain = _mock_chain(
            proposers=["agent:a"],
            reviewers=["agent:b"],
            approvers=["agent:a"],
        )
        violations = c.check_chain_invariants(chain)
        assert any("Proposer" in v and "approver" in v for v in violations)

    def test_reviewer_approver_overlap(self):
        c = Constitution()
        chain = _mock_chain(
            proposers=["agent:a"],
            reviewers=["agent:b"],
            approvers=["agent:b"],
        )
        violations = c.check_chain_invariants(chain)
        assert any("Reviewer" in v and "approver" in v for v in violations)

    def test_all_same_actor_multiple_violations(self):
        c = Constitution()
        chain = _mock_chain(
            proposers=["agent:x"],
            reviewers=["agent:x"],
            approvers=["agent:x"],
        )
        violations = c.check_chain_invariants(chain)
        separation_violations = [v for v in violations if "III.1" in v]
        assert len(separation_violations) == 3

    def test_empty_roles_no_separation_violation(self):
        c = Constitution()
        chain = _mock_chain(proposers=[], reviewers=[], approvers=[])
        violations = c.check_chain_invariants(chain)
        separation = [v for v in violations if "III.1" in v]
        assert separation == []

    def test_partial_roles_no_false_positive(self):
        """Only one role populated should not trigger separation violation."""
        c = Constitution()
        chain = _mock_chain(proposers=["agent:a"], reviewers=[], approvers=[])
        violations = c.check_chain_invariants(chain)
        separation = [v for v in violations if "III.1" in v]
        assert separation == []


# ── Cedar Policy Generation ──────────────────────────────────────


class TestCedarPolicies:
    def test_to_cedar_returns_string(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert isinstance(cedar, str)

    def test_cedar_contains_forbid_rules(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert "forbid(" in cedar

    def test_cedar_self_modification_rule(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert "ModifySelfConstraints" in cedar

    def test_cedar_self_approval_rule(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert "ApproveOwnProposal" in cedar

    def test_cedar_expired_token_rule(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert "token_expired" in cedar

    def test_cedar_used_token_rule(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert "token_used" in cedar

    def test_cedar_prohibited_practice_rule(self):
        c = Constitution()
        cedar = c.to_cedar_policies()
        assert "prohibited_practice" in cedar
        assert "V.1" in cedar
