"""Tests for runtime fairness metrics — NIST AI RMF MAP 2.3."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gavel.fairness import (
    DecisionOutcome,
    FairnessBaseline,
    FairnessDriftReport,
    FairnessMetric,
    FairnessMonitor,
    FairnessViolation,
    FairnessViolationSeverity,
    ProtectedAttribute,
)


# ── Helpers ───────────────────────────────────────────────────

def _outcome(
    agent_id: str = "agent-1",
    decision: str = "APPROVED",
    gender: str | None = None,
    race: str | None = None,
    risk_level: str = "LOW",
    chain_id: str = "",
) -> DecisionOutcome:
    attrs: dict[str, str] = {}
    if gender is not None:
        attrs["gender"] = gender
    if race is not None:
        attrs["race"] = race
    return DecisionOutcome(
        agent_id=agent_id,
        chain_id=chain_id,
        decision=decision,
        protected_attributes=attrs,
        risk_level=risk_level,
    )


def _record_balanced(monitor: FairnessMonitor, agent_id: str = "agent-1", n: int = 50) -> None:
    """Record n balanced outcomes: half male approved, half female approved."""
    for i in range(n):
        gender = "male" if i % 2 == 0 else "female"
        monitor.record_outcome(_outcome(agent_id=agent_id, gender=gender, decision="APPROVED"))


def _record_skewed(monitor: FairnessMonitor, agent_id: str = "agent-1", n: int = 50) -> None:
    """Record skewed outcomes: males mostly approved, females mostly denied."""
    for i in range(n):
        if i % 2 == 0:
            monitor.record_outcome(_outcome(agent_id=agent_id, gender="male", decision="APPROVED"))
        else:
            monitor.record_outcome(_outcome(agent_id=agent_id, gender="female", decision="DENIED"))


# ── ProtectedAttribute enum ──────────────────────────────────

class TestProtectedAttribute:
    def test_values(self) -> None:
        assert ProtectedAttribute.RACE.value == "race"
        assert ProtectedAttribute.GENDER.value == "gender"
        assert ProtectedAttribute.SOCIOECONOMIC_STATUS.value == "socioeconomic_status"
        assert len(ProtectedAttribute) == 8


# ── Basic recording and metrics ──────────────────────────────

class TestRecordAndCompute:
    def test_empty_metrics(self) -> None:
        m = FairnessMonitor()
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.is_empty()
        assert metric.sample_size == 0

    def test_single_outcome(self) -> None:
        m = FairnessMonitor()
        m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.sample_size == 1
        assert metric.group_counts == {"male": 1}
        assert metric.group_approval_rates["male"] == 1.0

    def test_balanced_outcomes_parity(self) -> None:
        m = FairnessMonitor()
        _record_balanced(m, n=100)
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.sample_size == 100
        assert metric.demographic_parity_ratio == 1.0
        assert metric.four_fifths_violated is False
        assert metric.disparate_impact_score == 0.0

    def test_skewed_outcomes_flag_violation(self) -> None:
        m = FairnessMonitor()
        _record_skewed(m, n=100)
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.sample_size == 100
        # Males: 100% approved, Females: 0% approved
        assert metric.group_approval_rates["male"] == 1.0
        assert metric.group_approval_rates["female"] == 0.0
        assert metric.demographic_parity_ratio == 0.0
        assert metric.four_fifths_violated is True
        assert metric.disparate_impact_score == 1.0

    def test_moderate_disparity(self) -> None:
        """70% approval for group A, 100% for group B -> ratio = 0.7."""
        m = FairnessMonitor()
        for _ in range(70):
            m.record_outcome(_outcome(gender="female", decision="APPROVED"))
        for _ in range(30):
            m.record_outcome(_outcome(gender="female", decision="DENIED"))
        for _ in range(100):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.demographic_parity_ratio == 0.7
        assert metric.four_fifths_violated is True

    def test_compute_all_metrics(self) -> None:
        m = FairnessMonitor()
        m.record_outcome(_outcome(gender="male", race="white", decision="APPROVED"))
        m.record_outcome(_outcome(gender="female", race="black", decision="APPROVED"))
        metrics = m.compute_all_metrics("agent-1")
        assert len(metrics) == 2
        attrs = {met.attribute for met in metrics}
        assert "gender" in attrs
        assert "race" in attrs

    def test_no_outcomes_returns_empty_list(self) -> None:
        m = FairnessMonitor()
        assert m.compute_all_metrics("ghost") == []


# ── Four-fifths rule ──────────────────────────────────────────

class TestFourFifthsRule:
    def test_exactly_at_boundary(self) -> None:
        """80% / 100% = 0.8 -> not violated."""
        m = FairnessMonitor()
        for _ in range(80):
            m.record_outcome(_outcome(gender="female", decision="APPROVED"))
        for _ in range(20):
            m.record_outcome(_outcome(gender="female", decision="DENIED"))
        for _ in range(100):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.demographic_parity_ratio == 0.8
        assert metric.four_fifths_violated is False

    def test_just_below_boundary(self) -> None:
        """79/100 vs 100/100 -> 0.79 -> violated."""
        m = FairnessMonitor()
        for _ in range(79):
            m.record_outcome(_outcome(gender="female", decision="APPROVED"))
        for _ in range(21):
            m.record_outcome(_outcome(gender="female", decision="DENIED"))
        for _ in range(100):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.demographic_parity_ratio == 0.79
        assert metric.four_fifths_violated is True


# ── Equalized odds ────────────────────────────────────────────

class TestEqualizedOdds:
    def test_same_rate_per_risk_level(self) -> None:
        m = FairnessMonitor()
        for _ in range(50):
            m.record_outcome(_outcome(gender="male", decision="APPROVED", risk_level="LOW"))
            m.record_outcome(_outcome(gender="female", decision="APPROVED", risk_level="LOW"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.equalized_odds_delta == 0.0

    def test_different_rate_per_risk_level(self) -> None:
        m = FairnessMonitor()
        # LOW risk: both approved
        for _ in range(20):
            m.record_outcome(_outcome(gender="male", decision="APPROVED", risk_level="LOW"))
            m.record_outcome(_outcome(gender="female", decision="APPROVED", risk_level="LOW"))
        # HIGH risk: male approved, female denied
        for _ in range(20):
            m.record_outcome(_outcome(gender="male", decision="APPROVED", risk_level="HIGH"))
            m.record_outcome(_outcome(gender="female", decision="DENIED", risk_level="HIGH"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.equalized_odds_delta == 1.0


# ── Drift detection ──────────────────────────────────────────

class TestDriftDetection:
    def test_no_baseline_returns_none(self) -> None:
        m = FairnessMonitor()
        assert m.detect_drift("agent-1") is None

    def test_baseline_frozen_at_threshold(self) -> None:
        m = FairnessMonitor(min_samples_for_snapshot=10)
        for i in range(9):
            m.record_outcome(_outcome(gender="male" if i % 2 == 0 else "female"))
        assert m.enrollment_baseline("agent-1") is None
        m.record_outcome(_outcome(gender="male"))
        bl = m.enrollment_baseline("agent-1")
        assert bl is not None
        assert bl.sample_size == 10

    def test_no_drift_when_stable(self) -> None:
        m = FairnessMonitor(min_samples_for_snapshot=10)
        _record_balanced(m, n=100)
        report = m.detect_drift("agent-1")
        assert report is not None
        assert report.drift_score == 0.0
        assert report.is_significant is False

    def test_drift_after_shift(self) -> None:
        m = FairnessMonitor(min_samples_for_snapshot=10, window=200)
        # Phase 1: balanced (builds baseline)
        _record_balanced(m, n=50)
        # Phase 2: heavily skewed (shifts distribution)
        _record_skewed(m, n=150)
        report = m.detect_drift("agent-1")
        assert report is not None
        assert report.is_significant is True
        assert report.drift_score > 0.0
        assert len(report.reasons) > 0

    def test_reset_baseline(self) -> None:
        m = FairnessMonitor(min_samples_for_snapshot=10)
        _record_balanced(m, n=20)
        assert m.enrollment_baseline("agent-1") is not None
        m.reset_baseline("agent-1")
        assert m.enrollment_baseline("agent-1") is None


# ── Multiple agents ──────────────────────────────────────────

class TestMultipleAgents:
    def test_agents_tracked_independently(self) -> None:
        m = FairnessMonitor()
        _record_balanced(m, agent_id="agent-1", n=50)
        _record_skewed(m, agent_id="agent-2", n=50)

        m1 = m.compute_metrics("agent-1", "gender")
        m2 = m.compute_metrics("agent-2", "gender")
        assert m1.demographic_parity_ratio == 1.0
        assert m2.demographic_parity_ratio == 0.0

    def test_no_cross_contamination(self) -> None:
        m = FairnessMonitor()
        m.record_outcome(_outcome(agent_id="a", gender="male", decision="APPROVED"))
        metric = m.compute_metrics("b", "gender")
        assert metric.is_empty()


# ── Window bounding ──────────────────────────────────────────

class TestWindowBounding:
    def test_window_limits_memory(self) -> None:
        m = FairnessMonitor(window=10)
        for i in range(100):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.sample_size == 10

    def test_old_outcomes_evicted(self) -> None:
        m = FairnessMonitor(window=20)
        # First 20: all denied
        for _ in range(20):
            m.record_outcome(_outcome(gender="male", decision="DENIED"))
        # Next 20: all approved (evicts the denied ones)
        for _ in range(20):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.group_approval_rates["male"] == 1.0


# ── Edge cases ────────────────────────────────────────────────

class TestEdgeCases:
    def test_single_group_no_parity(self) -> None:
        """Only one group: parity ratio is None."""
        m = FairnessMonitor()
        for _ in range(10):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.demographic_parity_ratio is None
        assert metric.four_fifths_violated is False

    def test_all_same_decision(self) -> None:
        """All approved: parity = 1.0."""
        m = FairnessMonitor()
        for _ in range(10):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
            m.record_outcome(_outcome(gender="female", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.demographic_parity_ratio == 1.0

    def test_all_denied(self) -> None:
        """All denied across groups: both rates = 0, parity = 1.0."""
        m = FairnessMonitor()
        for _ in range(10):
            m.record_outcome(_outcome(gender="male", decision="DENIED"))
            m.record_outcome(_outcome(gender="female", decision="DENIED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.demographic_parity_ratio == 1.0
        assert metric.four_fifths_violated is False

    def test_three_groups(self) -> None:
        """Three groups: parity uses worst pair."""
        m = FairnessMonitor()
        for _ in range(100):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        for _ in range(80):
            m.record_outcome(_outcome(gender="female", decision="APPROVED"))
        for _ in range(20):
            m.record_outcome(_outcome(gender="female", decision="DENIED"))
        for _ in range(50):
            m.record_outcome(_outcome(gender="non-binary", decision="APPROVED"))
        for _ in range(50):
            m.record_outcome(_outcome(gender="non-binary", decision="DENIED"))
        metric = m.compute_metrics("agent-1", "gender")
        # male: 1.0, female: 0.8, non-binary: 0.5
        # worst pair: male vs non-binary -> 0.5/1.0 = 0.5
        assert metric.demographic_parity_ratio == 0.5
        assert metric.four_fifths_violated is True

    def test_outcome_without_attribute(self) -> None:
        """Outcomes without the queried attribute are ignored."""
        m = FairnessMonitor()
        m.record_outcome(_outcome(race="white", decision="APPROVED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.is_empty()

    def test_escalated_decision(self) -> None:
        """ESCALATED is not APPROVED."""
        m = FairnessMonitor()
        for _ in range(10):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
            m.record_outcome(_outcome(gender="female", decision="ESCALATED"))
        metric = m.compute_metrics("agent-1", "gender")
        assert metric.group_approval_rates["male"] == 1.0
        assert metric.group_approval_rates["female"] == 0.0


# ── Violations ────────────────────────────────────────────────

class TestViolations:
    def test_no_violations_when_fair(self) -> None:
        m = FairnessMonitor()
        _record_balanced(m, n=50)
        violations = m.flag_violations()
        assert violations == []

    def test_violations_flagged(self) -> None:
        m = FairnessMonitor()
        _record_skewed(m, n=50)
        violations = m.flag_violations()
        assert len(violations) >= 1
        v = violations[0]
        assert v.metric_name == "demographic_parity_ratio"
        assert v.value == 0.0
        assert v.threshold == 0.8
        assert v.severity == FairnessViolationSeverity.HIGH

    def test_equalized_odds_violation(self) -> None:
        m = FairnessMonitor()
        for _ in range(30):
            m.record_outcome(_outcome(gender="male", decision="APPROVED", risk_level="HIGH"))
            m.record_outcome(_outcome(gender="female", decision="DENIED", risk_level="HIGH"))
        violations = m.flag_violations()
        eq_violations = [v for v in violations if v.metric_name == "equalized_odds_delta"]
        assert len(eq_violations) >= 1

    def test_multiple_agents_violations(self) -> None:
        m = FairnessMonitor()
        _record_skewed(m, agent_id="agent-1", n=50)
        _record_skewed(m, agent_id="agent-2", n=50)
        violations = m.flag_violations()
        agents = {v.agent_id for v in violations}
        assert "agent-1" in agents
        assert "agent-2" in agents


# ── Summary ───────────────────────────────────────────────────

class TestSummary:
    def test_fair_posture(self) -> None:
        m = FairnessMonitor()
        _record_balanced(m, n=50)
        s = m.get_summary("agent-1")
        assert s.posture == "FAIR"
        assert s.violation_count == 0

    def test_violation_posture(self) -> None:
        m = FairnessMonitor()
        _record_skewed(m, n=50)
        s = m.get_summary("agent-1")
        assert s.posture == "VIOLATION"
        assert s.violation_count >= 1

    def test_empty_summary(self) -> None:
        m = FairnessMonitor()
        s = m.get_summary("ghost")
        assert s.total_outcomes == 0
        assert s.posture == "UNKNOWN"

    def test_at_risk_posture(self) -> None:
        """Parity below 0.9 but no four-fifths violation -> AT_RISK."""
        m = FairnessMonitor()
        # male: 100% approved, female: 85% approved -> ratio = 0.85
        # 0.85 >= 0.8 so no four-fifths violation, but < 0.9 so AT_RISK
        for _ in range(100):
            m.record_outcome(_outcome(gender="male", decision="APPROVED"))
        for _ in range(85):
            m.record_outcome(_outcome(gender="female", decision="APPROVED"))
        for _ in range(15):
            m.record_outcome(_outcome(gender="female", decision="DENIED"))
        s = m.get_summary("agent-1")
        assert s.posture == "AT_RISK"


# ── DecisionOutcome model ────────────────────────────────────

class TestDecisionOutcome:
    def test_defaults(self) -> None:
        o = DecisionOutcome(agent_id="a")
        assert o.decision == "APPROVED"
        assert o.risk_level == "LOW"
        assert o.protected_attributes == {}
        assert o.timestamp is not None

    def test_custom_attributes(self) -> None:
        o = DecisionOutcome(
            agent_id="a",
            protected_attributes={"gender": "female", "race": "asian"},
        )
        assert o.protected_attributes["gender"] == "female"
