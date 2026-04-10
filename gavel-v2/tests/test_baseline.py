"""Tests for gavel.baseline — per-agent behavioral baselines + drift detection."""

from __future__ import annotations

import pytest

from gavel.baseline import (
    BehavioralBaseline,
    BehavioralBaselineRegistry,
    BehavioralObservation,
    DriftReport,
    _score_drift,
)


def _obs(agent_id: str, **kw) -> BehavioralObservation:
    defaults = dict(
        chain_id=f"chain-{kw.get('i', 0)}",
        action_type="FILE_WRITE",
        tool="edit",
        risk_score=0.2,
        touched_paths=["src/app.py"],
        network=False,
        outcome="APPROVED",
    )
    defaults.update(kw)
    defaults.pop("i", None)
    return BehavioralObservation(agent_id=agent_id, **defaults)


class TestBaselineBasics:
    def test_empty_registry_returns_empty_baseline(self):
        reg = BehavioralBaselineRegistry()
        baseline = reg.current_baseline("agent:nobody")
        assert baseline.is_empty()
        assert baseline.sample_size == 0
        assert baseline.mean_risk == 0.0

    def test_single_observation_updates_baseline(self):
        reg = BehavioralBaselineRegistry()
        baseline = reg.observe(_obs("agent:a", risk_score=0.4))
        assert baseline.sample_size == 1
        assert baseline.mean_risk == 0.4
        assert baseline.max_risk == 0.4
        assert baseline.tool_frequencies == {"edit": 1.0}

    def test_rolling_window_bounds_memory(self):
        reg = BehavioralBaselineRegistry(window=5, min_samples_for_snapshot=2)
        for i in range(10):
            reg.observe(_obs("agent:a", i=i, risk_score=0.1 * i))
        baseline = reg.current_baseline("agent:a")
        # Only the last 5 observations survive
        assert baseline.sample_size == 5

    def test_tool_frequencies_sum_to_one(self):
        reg = BehavioralBaselineRegistry()
        reg.observe(_obs("agent:a", tool="edit"))
        reg.observe(_obs("agent:a", tool="edit"))
        reg.observe(_obs("agent:a", tool="grep"))
        reg.observe(_obs("agent:a", tool="bash"))
        baseline = reg.current_baseline("agent:a")
        total = sum(baseline.tool_frequencies.values())
        assert abs(total - 1.0) < 1e-9
        assert baseline.tool_frequencies["edit"] == 0.5

    def test_outcome_rates(self):
        reg = BehavioralBaselineRegistry()
        reg.observe(_obs("agent:a", outcome="APPROVED"))
        reg.observe(_obs("agent:a", outcome="APPROVED"))
        reg.observe(_obs("agent:a", outcome="DENIED"))
        reg.observe(_obs("agent:a", outcome="ESCALATED"))
        baseline = reg.current_baseline("agent:a")
        assert baseline.approval_rate == 0.5
        assert baseline.denial_rate == 0.25
        assert baseline.escalation_rate == 0.25

    def test_network_rate(self):
        reg = BehavioralBaselineRegistry()
        for _ in range(4):
            reg.observe(_obs("agent:a", network=False))
        reg.observe(_obs("agent:a", network=True))
        assert reg.current_baseline("agent:a").network_rate == 0.2

    def test_top_paths_truncated(self):
        reg = BehavioralBaselineRegistry()
        for i in range(20):
            reg.observe(_obs("agent:a", i=i, touched_paths=[f"path/{i % 3}.py"]))
        baseline = reg.current_baseline("agent:a")
        assert len(baseline.top_paths) <= 5
        # The three most-used paths should all be present
        assert set(baseline.top_paths[:3]) == {"path/0.py", "path/1.py", "path/2.py"}


class TestEnrollmentSnapshot:
    def test_snapshot_frozen_on_min_samples(self):
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=3)
        assert reg.enrollment_snapshot("agent:a") is None
        reg.observe(_obs("agent:a"))
        reg.observe(_obs("agent:a"))
        assert reg.enrollment_snapshot("agent:a") is None
        reg.observe(_obs("agent:a"))
        snap = reg.enrollment_snapshot("agent:a")
        assert snap is not None
        assert snap.sample_size == 3

    def test_snapshot_does_not_update_after_freeze(self):
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=2)
        reg.observe(_obs("agent:a", risk_score=0.1))
        reg.observe(_obs("agent:a", risk_score=0.1))
        snap = reg.enrollment_snapshot("agent:a")
        frozen_risk = snap.mean_risk
        reg.observe(_obs("agent:a", risk_score=0.9))
        reg.observe(_obs("agent:a", risk_score=0.9))
        snap2 = reg.enrollment_snapshot("agent:a")
        assert snap2.mean_risk == frozen_risk  # unchanged

    def test_reset_snapshot_allows_re_freeze(self):
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=2)
        reg.observe(_obs("agent:a", risk_score=0.1))
        reg.observe(_obs("agent:a", risk_score=0.1))
        reg.reset_snapshot("agent:a")
        assert reg.enrollment_snapshot("agent:a") is None
        reg.observe(_obs("agent:a", risk_score=0.9))
        snap = reg.enrollment_snapshot("agent:a")
        assert snap is not None


class TestDriftDetection:
    def test_no_drift_when_baseline_unchanged(self):
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=3)
        for _ in range(5):
            reg.observe(_obs("agent:a", risk_score=0.2))
        # Keep adding identical observations; drift should stay near zero.
        for _ in range(5):
            reg.observe(_obs("agent:a", risk_score=0.2))
        report = reg.drift("agent:a")
        assert report is not None
        assert report.drift_score < 0.1
        assert not report.is_significant

    def test_risk_inflation_detected(self):
        reg = BehavioralBaselineRegistry(window=100, min_samples_for_snapshot=5)
        for _ in range(5):
            reg.observe(_obs("agent:a", risk_score=0.1))
        # Dramatic risk escalation
        for _ in range(20):
            reg.observe(_obs("agent:a", risk_score=0.9))
        report = reg.drift("agent:a")
        assert report.is_significant
        assert report.risk_delta > 0.3
        assert any("risk_delta" in r for r in report.reasons)

    def test_new_tools_flagged(self):
        reg = BehavioralBaselineRegistry(window=100, min_samples_for_snapshot=3)
        for _ in range(3):
            reg.observe(_obs("agent:a", tool="edit"))
        for _ in range(3):
            reg.observe(_obs("agent:a", tool="bash"))
        report = reg.drift("agent:a")
        assert "bash" in report.new_tools

    def test_network_escalation_detected(self):
        reg = BehavioralBaselineRegistry(window=100, min_samples_for_snapshot=5)
        for _ in range(5):
            reg.observe(_obs("agent:a", network=False))
        for _ in range(15):
            reg.observe(_obs("agent:a", network=True))
        report = reg.drift("agent:a")
        assert report.network_delta > 0.3
        assert any("network_delta" in r for r in report.reasons)

    def test_drift_report_none_without_snapshot(self):
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=100)
        reg.observe(_obs("agent:a"))
        assert reg.drift("agent:a") is None

    def test_tool_distribution_shift_bounded(self):
        e = BehavioralBaseline(agent_id="a", sample_size=10, tool_frequencies={"edit": 1.0})
        c = BehavioralBaseline(agent_id="a", sample_size=10, tool_frequencies={"bash": 1.0})
        r = _score_drift(e, c)
        # Disjoint distributions → L1 distance is 2.0
        assert r.tool_distribution_shift == pytest.approx(2.0, abs=1e-4)

    def test_drift_score_bounded_0_1(self):
        # Extreme case: everything flipped
        e = BehavioralBaseline(
            agent_id="a",
            sample_size=10,
            tool_frequencies={"edit": 1.0},
            mean_risk=0.0,
            network_rate=0.0,
            denial_rate=0.0,
            escalation_rate=0.0,
        )
        c = BehavioralBaseline(
            agent_id="a",
            sample_size=10,
            tool_frequencies={"bash": 1.0},
            mean_risk=1.0,
            network_rate=1.0,
            denial_rate=1.0,
            escalation_rate=1.0,
        )
        r = _score_drift(e, c)
        assert 0.0 <= r.drift_score <= 1.0
        assert r.is_significant
