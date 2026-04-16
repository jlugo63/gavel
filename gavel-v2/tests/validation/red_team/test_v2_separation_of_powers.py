"""
V2 — Separation of Powers Red-Team (Wave 2).

Goal: prove that Gavel's structural separation-of-powers guarantees hold
against realistic attacks. "Structural" is the key word: the guarantees
must be enforced at the primitive (chain-append, role-assign) level, not
as a policy decision that could be flipped by a config change.

Three attack scenarios:

  S1  Self-approval             — one actor tries to take proposer AND
                                   approver on the same chain.
  S2  Role swap                  — one actor first takes reviewer, then
                                   tries to promote itself to approver
                                   after observing that the chain needs one.
  S3  Round-robin collusion      — three agents (A, B, C) rotate roles
                                   across many chains: (A→B, B→C, C→A)×N.
                                   On each individual chain, separation
                                   is honored, but over time the group
                                   has reviewed itself exclusively.

Plus a mutual-approval test: pairs that repeatedly approve each other
must be flagged as MUTUAL_APPROVAL high severity.

Every attack must produce a deterministic, audit-ready detection — either
a raised SeparationViolation at assignment time (S1, S2) or a
CollusionFinding from the scanner (S3, mutual).
"""

from __future__ import annotations

import pytest

from gavel.collusion import (
    ChainParticipation,
    CollusionDetector,
    CollusionSeverity,
    CollusionSignal,
)
from gavel.separation import (
    ChainRole,
    SeparationOfPowers,
    SeparationViolation,
)


# ── S1: self-approval ─────────────────────────────────────────


class TestSelfApprovalRefused:
    """The single most important separation guarantee: no actor may hold
    both proposer and approver on the same chain."""

    def test_proposer_cannot_also_approve(self) -> None:
        sop = SeparationOfPowers()
        chain_id = "c-self-approve"
        sop.assign("agent:lone-wolf", ChainRole.PROPOSER, chain_id)
        with pytest.raises(SeparationViolation) as exc_info:
            sop.assign("agent:lone-wolf", ChainRole.APPROVER, chain_id)

        err = exc_info.value
        assert err.actor_id == "agent:lone-wolf"
        assert err.attempted_role == ChainRole.APPROVER
        assert err.existing_role == ChainRole.PROPOSER
        assert err.chain_id == chain_id
        # Audit-ready message: the exception string must include enough
        # context for a log reader to understand the attack.
        msg = str(err)
        assert "agent:lone-wolf" in msg
        assert "proposer" in msg
        assert "approver" in msg

    def test_proposer_cannot_also_review(self) -> None:
        sop = SeparationOfPowers()
        chain_id = "c-proposer-review"
        sop.assign("agent:lone-wolf", ChainRole.PROPOSER, chain_id)
        with pytest.raises(SeparationViolation):
            sop.assign("agent:lone-wolf", ChainRole.REVIEWER, chain_id)

    def test_reviewer_cannot_also_approve(self) -> None:
        sop = SeparationOfPowers()
        chain_id = "c-reviewer-approve"
        sop.assign("agent:reviewer", ChainRole.REVIEWER, chain_id)
        with pytest.raises(SeparationViolation):
            sop.assign("agent:reviewer", ChainRole.APPROVER, chain_id)


# ── S2: role swap after first participation ──────────────────


class TestRoleSwapRefused:
    """An actor's role on a chain is fixed at first participation
    (Constitutional Article III.2). Promotion attempts must fail."""

    def test_reviewer_cannot_upgrade_to_approver(self) -> None:
        sop = SeparationOfPowers()
        chain_id = "c-promote"
        sop.assign("agent:ambitious", ChainRole.REVIEWER, chain_id)
        # A second call with a different role must raise regardless of
        # whether that other role is explicitly in the exclusion matrix,
        # because an actor may hold exactly one role per chain.
        with pytest.raises(SeparationViolation) as exc_info:
            sop.assign("agent:ambitious", ChainRole.APPROVER, chain_id)
        assert exc_info.value.existing_role == ChainRole.REVIEWER
        # The reassignment did not take effect — role is still reviewer.
        assert sop.get_role("agent:ambitious", chain_id) == ChainRole.REVIEWER

    def test_idempotent_same_role_does_not_raise(self) -> None:
        """Re-asserting the same role for the same actor is allowed
        (observers often re-read the chain, for example)."""
        sop = SeparationOfPowers()
        chain_id = "c-observer"
        sop.assign("agent:watcher", ChainRole.OBSERVER, chain_id)
        # No raise — same role is idempotent.
        sop.assign("agent:watcher", ChainRole.OBSERVER, chain_id)
        assert sop.get_role("agent:watcher", chain_id) == ChainRole.OBSERVER


class TestLegitimateChainAccepted:
    """Sanity: a well-formed 3-principal chain assembles without raising."""

    def test_full_chain_with_distinct_principals(self) -> None:
        sop = SeparationOfPowers()
        chain_id = "c-legit"
        sop.assign("agent:proposer", ChainRole.PROPOSER, chain_id)
        sop.assign("agent:reviewer", ChainRole.REVIEWER, chain_id)
        sop.assign("agent:approver", ChainRole.APPROVER, chain_id)
        sop.assign("agent:executor", ChainRole.EXECUTOR, chain_id)
        # No violations — full roster is legit.
        assert sop.validate_chain(chain_id) == []
        roster = sop.get_chain_roster(chain_id)
        assert roster == {
            "agent:proposer": "proposer",
            "agent:reviewer": "reviewer",
            "agent:approver": "approver",
            "agent:executor": "executor",
        }


# ── S3: round-robin collusion across chains ──────────────────


class TestRoundRobinCollusion:
    """Three agents rotating roles across chains — on each individual
    chain, separation is honored, but the group has exclusively reviewed
    itself. This is the canonical "cross-chain" attack that per-chain
    separation alone cannot catch; collusion detection is the second line."""

    def test_three_agent_cycle_detected(self) -> None:
        det = CollusionDetector()

        # 3-agent round robin: (A, B), (B, C), (C, A) — repeating
        pattern = [
            ("agent:A", "agent:B"),
            ("agent:B", "agent:C"),
            ("agent:C", "agent:A"),
        ]

        # The detector requires the pattern to repeat at least twice
        # (repeats >= 2 in _detect_round_robin). Two full cycles = 6 chains.
        for cycle in range(2):
            for i, (proposer, approver) in enumerate(pattern):
                det.observe(ChainParticipation(
                    chain_id=f"c-rr-{cycle}-{i}",
                    proposer=proposer,
                    reviewers=[approver],
                    approver=approver,
                ))

        findings = det.scan()
        round_robin_findings = [
            f for f in findings if f.signal == CollusionSignal.ROUND_ROBIN
        ]
        assert round_robin_findings, (
            f"ROUND_ROBIN not detected after 6 rotating chains. Findings: "
            f"{[(f.signal, f.implicated) for f in findings]}"
        )

        finding = round_robin_findings[0]
        assert set(finding.implicated) == {"agent:A", "agent:B", "agent:C"}
        assert finding.severity in (CollusionSeverity.MEDIUM, CollusionSeverity.HIGH)
        assert finding.detail
        assert finding.suggested_action


# ── Mutual approval (pair attack) ──────────────────────────────


class TestMutualApprovalCollusion:
    """Pair (A, B) where A approves B ≥ 4 times AND B approves A ≥ 4 times
    must surface as MUTUAL_APPROVAL high severity."""

    def test_pair_approving_each_other_detected(self) -> None:
        det = CollusionDetector()

        # A proposes, B approves — 4 times
        for i in range(4):
            det.observe(ChainParticipation(
                chain_id=f"c-ma-ab-{i}",
                proposer="agent:Alpha",
                approver="agent:Beta",
            ))
        # B proposes, A approves — 4 times
        for i in range(4):
            det.observe(ChainParticipation(
                chain_id=f"c-ma-ba-{i}",
                proposer="agent:Beta",
                approver="agent:Alpha",
            ))

        findings = det.scan()
        mutual = [f for f in findings if f.signal == CollusionSignal.MUTUAL_APPROVAL]
        assert mutual, (
            f"MUTUAL_APPROVAL not detected after 8 rotating pair approvals. "
            f"Findings: {[(f.signal, f.implicated) for f in findings]}"
        )

        finding = mutual[0]
        assert sorted(finding.implicated) == ["agent:Alpha", "agent:Beta"]
        assert finding.severity == CollusionSeverity.HIGH
        # All 8 chains supporting the finding.
        assert len(finding.supporting_chains) == 8


# ── Control: legitimate diverse reviewing does NOT trigger ─────


class TestDiverseReviewingClean:
    """A proposer with 6 chains, each reviewed by a different principal,
    must NOT trigger any collusion signal. This is the negative control
    that pins the detector's false-positive boundary."""

    def test_diverse_reviewers_no_findings(self) -> None:
        det = CollusionDetector()
        for i in range(6):
            det.observe(ChainParticipation(
                chain_id=f"c-diverse-{i}",
                proposer="agent:Legit",
                approver=f"agent:Reviewer-{i}",
            ))
        findings = det.scan()
        assert findings == [], (
            f"FALSE POSITIVE: diverse reviewers triggered a finding: "
            f"{[(f.signal, f.implicated) for f in findings]}"
        )
