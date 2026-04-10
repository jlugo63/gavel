"""Tests for gavel.collusion — cross-chain collusion detection."""

from __future__ import annotations

from gavel.collusion import (
    ChainParticipation,
    CollusionDetector,
    CollusionSignal,
)


def _mk(chain_id: str, proposer: str, approver: str, reviewers=None) -> ChainParticipation:
    return ChainParticipation(
        chain_id=chain_id,
        proposer=proposer,
        approver=approver,
        reviewers=list(reviewers or []),
    )


class TestMutualApproval:
    def test_detects_mutual_pair(self):
        det = CollusionDetector()
        # A approves B 4 times
        for i in range(4):
            det.observe(_mk(f"c-ab-{i}", "agent:B", "agent:A"))
        # B approves A 4 times
        for i in range(4):
            det.observe(_mk(f"c-ba-{i}", "agent:A", "agent:B"))

        findings = det.scan()
        mutual = [f for f in findings if f.signal == CollusionSignal.MUTUAL_APPROVAL]
        assert mutual, "expected mutual approval finding"
        assert sorted(mutual[0].implicated) == ["agent:A", "agent:B"]
        assert len(mutual[0].supporting_chains) == 8

    def test_no_mutual_when_one_sided(self):
        det = CollusionDetector()
        for i in range(8):
            det.observe(_mk(f"c-{i}", "agent:B", "agent:A"))  # only one direction

        findings = det.scan()
        assert not any(f.signal == CollusionSignal.MUTUAL_APPROVAL for f in findings)

    def test_no_mutual_below_threshold(self):
        det = CollusionDetector()
        for i in range(3):  # 3 < _MIN_CHAINS_FOR_MUTUAL (4)
            det.observe(_mk(f"c-ab-{i}", "agent:B", "agent:A"))
        for i in range(3):
            det.observe(_mk(f"c-ba-{i}", "agent:A", "agent:B"))

        findings = det.scan()
        assert not any(f.signal == CollusionSignal.MUTUAL_APPROVAL for f in findings)

    def test_pair_reported_once(self):
        det = CollusionDetector()
        for i in range(5):
            det.observe(_mk(f"c-ab-{i}", "agent:B", "agent:A"))
        for i in range(5):
            det.observe(_mk(f"c-ba-{i}", "agent:A", "agent:B"))

        findings = det.scan()
        mutual = [f for f in findings if f.signal == CollusionSignal.MUTUAL_APPROVAL]
        assert len(mutual) == 1


class TestOneToOnePipeline:
    def test_detects_sole_approver(self):
        det = CollusionDetector()
        for i in range(6):
            det.observe(_mk(f"c-{i}", "agent:P", "agent:X"))

        findings = det.scan()
        pipe = [f for f in findings if f.signal == CollusionSignal.ONE_TO_ONE_PIPELINE]
        assert pipe, "expected pipeline finding"
        assert sorted(pipe[0].implicated) == ["agent:P", "agent:X"]

    def test_no_pipeline_when_diverse(self):
        det = CollusionDetector()
        approvers = ["agent:X", "agent:Y", "agent:Z"]
        for i in range(9):
            det.observe(_mk(f"c-{i}", "agent:P", approvers[i % 3]))

        findings = det.scan()
        assert not any(f.signal == CollusionSignal.ONE_TO_ONE_PIPELINE for f in findings)

    def test_no_pipeline_below_threshold(self):
        det = CollusionDetector()
        for i in range(5):  # 5 < _MIN_CHAINS_FOR_PIPELINE (6)
            det.observe(_mk(f"c-{i}", "agent:P", "agent:X"))

        findings = det.scan()
        assert not any(f.signal == CollusionSignal.ONE_TO_ONE_PIPELINE for f in findings)


class TestClosedClique:
    def test_detects_three_agent_closed_clique(self):
        det = CollusionDetector()
        # Three agents A, B, C reviewing each other many times.
        agents = ["agent:A", "agent:B", "agent:C"]
        chain = 0
        for _ in range(4):
            for proposer in agents:
                others = [a for a in agents if a != proposer]
                for reviewer in others:
                    det.observe(_mk(
                        f"c-{chain}", proposer, reviewer, reviewers=[reviewer]
                    ))
                    chain += 1

        findings = det.scan()
        cliques = [f for f in findings if f.signal == CollusionSignal.CLOSED_CLIQUE]
        assert cliques, "expected clique finding"
        # Implicated must be the 3-agent set
        assert any(set(f.implicated) == set(agents) for f in cliques)

    def test_no_clique_when_reviews_leak_outside(self):
        det = CollusionDetector()
        agents = ["agent:A", "agent:B", "agent:C"]
        outsiders = ["agent:D", "agent:E", "agent:F", "agent:G"]
        chain = 0
        # Mostly outside reviewers → low density
        for _ in range(6):
            for proposer in agents:
                for outsider in outsiders:
                    det.observe(_mk(
                        f"c-{chain}", proposer, outsider, reviewers=[outsider]
                    ))
                    chain += 1

        findings = det.scan()
        cliques = [f for f in findings if f.signal == CollusionSignal.CLOSED_CLIQUE]
        # The A/B/C agents should NOT register as a clique with those agents
        assert not any(set(f.implicated) == set(agents) for f in cliques)


class TestRoundRobin:
    def test_detects_three_agent_cycle(self):
        det = CollusionDetector()
        # A→B, B→C, C→A repeated
        cycle = [("agent:A", "agent:B"), ("agent:B", "agent:C"), ("agent:C", "agent:A")]
        chain = 0
        for _ in range(3):
            for proposer, approver in cycle:
                det.observe(_mk(f"c-{chain}", proposer, approver))
                chain += 1

        findings = det.scan()
        rr = [f for f in findings if f.signal == CollusionSignal.ROUND_ROBIN]
        assert rr, "expected round-robin finding"
        assert set(rr[0].implicated) == {"agent:A", "agent:B", "agent:C"}

    def test_no_round_robin_when_random(self):
        det = CollusionDetector()
        pairs = [
            ("agent:A", "agent:B"),
            ("agent:C", "agent:D"),
            ("agent:B", "agent:E"),
            ("agent:D", "agent:A"),
            ("agent:E", "agent:C"),
            ("agent:A", "agent:D"),
            ("agent:B", "agent:C"),
            ("agent:E", "agent:A"),
        ]
        for i, (p, a) in enumerate(pairs):
            det.observe(_mk(f"c-{i}", p, a))

        findings = det.scan()
        assert not any(f.signal == CollusionSignal.ROUND_ROBIN for f in findings)


class TestEmptyAndSmall:
    def test_empty_detector_no_findings(self):
        det = CollusionDetector()
        assert det.scan() == []

    def test_single_chain_no_findings(self):
        det = CollusionDetector()
        det.observe(_mk("c-0", "agent:A", "agent:B"))
        assert det.scan() == []

    def test_window_bound(self):
        det = CollusionDetector(window=10)
        for i in range(25):
            det.observe(_mk(f"c-{i}", "agent:A", "agent:B"))
        assert len(det._chains) == 10
