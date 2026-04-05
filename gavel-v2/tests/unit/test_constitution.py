"""Unit tests for Constitution — invariant checks and Cedar generation."""

from gavel.chain import GovernanceChain, EventType
from gavel.constitution import Constitution, CONSTITUTION, InvariantClass


class TestConstitutionStructure:
    def test_all_invariants_loaded(self, constitution):
        assert len(constitution.invariants) == len(CONSTITUTION)

    def test_invariant_lookup_by_id(self, constitution):
        inv = constitution.get_invariant("I.1")
        assert inv is not None
        assert "append-only" in inv.text.lower()

    def test_invariant_has_enforcement(self, constitution):
        for inv in constitution.invariants.values():
            assert inv.enforcement != ""

    def test_immutability_article_exists(self, constitution):
        inv = constitution.get_invariant("I.1")
        assert inv.article == InvariantClass.IMMUTABILITY

    def test_separation_article_exists(self, constitution):
        inv = constitution.get_invariant("III.1")
        assert inv.article == InvariantClass.SEPARATION

    def test_human_override_article_exists(self, constitution):
        inv = constitution.get_invariant("IV.1")
        assert inv.article == InvariantClass.HUMAN_OVERRIDE

    def test_unknown_invariant_returns_none(self, constitution):
        assert constitution.get_invariant("X.99") is None


class TestChainInvariantChecks:
    def test_valid_chain_passes(self, constitution):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:monitor", "proposer")
        chain.append(EventType.REVIEW_ATTESTATION, "agent:reviewer", "reviewer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:approver", "approver")
        violations = constitution.check_chain_invariants(chain)
        assert violations == []

    def test_tampered_chain_detected(self, constitution):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.events[0].event_hash = "tampered"
        violations = constitution.check_chain_invariants(chain)
        assert any("I.1" in v for v in violations)

    def test_proposer_reviewer_overlap_detected(self, constitution):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:same", "proposer")
        chain.append(EventType.REVIEW_ATTESTATION, "agent:same", "reviewer")
        violations = constitution.check_chain_invariants(chain)
        assert any("III.1" in v for v in violations)

    def test_proposer_approver_overlap_detected(self, constitution):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:same", "proposer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:same", "approver")
        violations = constitution.check_chain_invariants(chain)
        assert any("III.1" in v for v in violations)

    def test_reviewer_approver_overlap_detected(self, constitution):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:proposer", "proposer")
        chain.append(EventType.REVIEW_ATTESTATION, "agent:same", "reviewer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:same", "approver")
        violations = constitution.check_chain_invariants(chain)
        assert any("III.1" in v for v in violations)

    def test_distinct_actors_pass(self, constitution):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.REVIEW_ATTESTATION, "agent:b", "reviewer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:c", "approver")
        violations = constitution.check_chain_invariants(chain)
        assert violations == []


class TestCedarGeneration:
    def test_generates_cedar_string(self, constitution):
        cedar = constitution.to_cedar_policies()
        assert isinstance(cedar, str)
        assert "forbid" in cedar

    def test_cedar_includes_self_modification_rule(self, constitution):
        cedar = constitution.to_cedar_policies()
        assert "ModifySelfConstraints" in cedar

    def test_cedar_includes_expired_token_rule(self, constitution):
        cedar = constitution.to_cedar_policies()
        assert "token_expired" in cedar

    def test_cedar_includes_approve_own_proposal(self, constitution):
        cedar = constitution.to_cedar_policies()
        assert "ApproveOwnProposal" in cedar
