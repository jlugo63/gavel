"""Tests for gavel.performance_metrics — EU AI Act Article 15 performance tracking."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from gavel.performance_metrics import (
    PerformanceTarget,
    PerformanceObservation,
    PerformanceReport,
    PerformanceTracker,
)


def _obs(agent_id: str, metric: str, value: float, **kw) -> PerformanceObservation:
    return PerformanceObservation(agent_id=agent_id, metric_name=metric, observed_value=value, **kw)


class TestTargetSetting:
    def test_set_and_retrieve_target(self):
        tracker = PerformanceTracker()
        target = PerformanceTarget(metric_name="accuracy", target_value=0.95, threshold_type="minimum")
        tracker.set_target("agent:a", target)
        # No observations yet — report returns None
        assert tracker.report("agent:a", "accuracy") is None

    def test_report_without_target_returns_none(self):
        tracker = PerformanceTracker()
        tracker.observe(_obs("agent:a", "accuracy", 0.97))
        assert tracker.report("agent:a", "accuracy") is None


class TestObservationsAndCompliance:
    def test_all_observations_meeting_target(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        for _ in range(10):
            tracker.observe(_obs("agent:a", "accuracy", 0.95))

        rpt = tracker.report("agent:a", "accuracy")
        assert rpt is not None
        assert rpt.sample_size == 10
        assert rpt.compliance_rate == 1.0
        assert rpt.is_compliant is True
        assert rpt.mean_observed == 0.95

    def test_some_observations_below_minimum(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="precision", target_value=0.90, threshold_type="minimum",
        ))
        # 8 good, 2 bad => compliance_rate = 0.8
        for _ in range(8):
            tracker.observe(_obs("agent:a", "precision", 0.92))
        for _ in range(2):
            tracker.observe(_obs("agent:a", "precision", 0.85))

        rpt = tracker.report("agent:a", "precision")
        assert rpt.compliance_rate == 0.8
        assert rpt.is_compliant is False

    def test_maximum_threshold_type(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="latency_p99", target_value=200.0, threshold_type="maximum", unit="ms",
        ))
        for _ in range(9):
            tracker.observe(_obs("agent:a", "latency_p99", 150.0))
        tracker.observe(_obs("agent:a", "latency_p99", 250.0))

        rpt = tracker.report("agent:a", "latency_p99")
        assert rpt.compliance_rate == 0.9
        assert rpt.is_compliant is False
        assert rpt.min_observed == 150.0
        assert rpt.max_observed == 250.0

    def test_exactly_at_threshold_counts_as_compliant(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        tracker.observe(_obs("agent:a", "accuracy", 0.90))
        rpt = tracker.report("agent:a", "accuracy")
        assert rpt.compliance_rate == 1.0

    def test_rolling_window_bounds_memory(self):
        tracker = PerformanceTracker(window=5)
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="f1", target_value=0.80, threshold_type="minimum",
        ))
        for i in range(10):
            tracker.observe(_obs("agent:a", "f1", 0.70 + i * 0.01))

        rpt = tracker.report("agent:a", "f1")
        assert rpt.sample_size == 5


class TestTrendDetection:
    def test_improving_trend_minimum(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        # First half low, second half high
        for _ in range(10):
            tracker.observe(_obs("agent:a", "accuracy", 0.80))
        for _ in range(10):
            tracker.observe(_obs("agent:a", "accuracy", 0.95))

        rpt = tracker.report("agent:a", "accuracy")
        assert rpt.trend == "improving"

    def test_degrading_trend_minimum(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="recall", target_value=0.90, threshold_type="minimum",
        ))
        for _ in range(10):
            tracker.observe(_obs("agent:a", "recall", 0.95))
        for _ in range(10):
            tracker.observe(_obs("agent:a", "recall", 0.80))

        rpt = tracker.report("agent:a", "recall")
        assert rpt.trend == "degrading"

    def test_stable_trend(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        for _ in range(20):
            tracker.observe(_obs("agent:a", "accuracy", 0.92))

        rpt = tracker.report("agent:a", "accuracy")
        assert rpt.trend == "stable"

    def test_improving_trend_maximum(self):
        """For latency (maximum threshold), decreasing values = improving."""
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="latency_p99", target_value=200.0, threshold_type="maximum", unit="ms",
        ))
        for _ in range(10):
            tracker.observe(_obs("agent:a", "latency_p99", 190.0))
        for _ in range(10):
            tracker.observe(_obs("agent:a", "latency_p99", 120.0))

        rpt = tracker.report("agent:a", "latency_p99")
        assert rpt.trend == "improving"

    def test_too_few_samples_returns_stable(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        tracker.observe(_obs("agent:a", "accuracy", 0.95))
        tracker.observe(_obs("agent:a", "accuracy", 0.80))

        rpt = tracker.report("agent:a", "accuracy")
        assert rpt.trend == "stable"


class TestReportAll:
    def test_report_all_returns_all_metrics(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="latency_p99", target_value=200.0, threshold_type="maximum",
        ))
        tracker.observe(_obs("agent:a", "accuracy", 0.95))
        tracker.observe(_obs("agent:a", "latency_p99", 150.0))

        reports = tracker.report_all("agent:a")
        assert len(reports) == 2
        metric_names = {r.metric_name for r in reports}
        assert metric_names == {"accuracy", "latency_p99"}

    def test_report_all_excludes_other_agents(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        tracker.set_target("agent:b", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        tracker.observe(_obs("agent:a", "accuracy", 0.95))
        tracker.observe(_obs("agent:b", "accuracy", 0.95))

        reports = tracker.report_all("agent:a")
        assert len(reports) == 1
        assert reports[0].agent_id == "agent:a"


class TestDegradationAlerts:
    def test_alerts_below_threshold(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.95, threshold_type="minimum",
        ))
        # All below target => compliance_rate = 0
        for _ in range(10):
            tracker.observe(_obs("agent:a", "accuracy", 0.80))

        alerts = tracker.degradation_alerts(threshold=0.90)
        assert len(alerts) == 1
        assert alerts[0].metric_name == "accuracy"

    def test_no_alerts_when_compliant(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.90, threshold_type="minimum",
        ))
        for _ in range(10):
            tracker.observe(_obs("agent:a", "accuracy", 0.95))

        alerts = tracker.degradation_alerts(threshold=0.90)
        assert len(alerts) == 0

    def test_default_threshold(self):
        tracker = PerformanceTracker()
        tracker.set_target("agent:a", PerformanceTarget(
            metric_name="accuracy", target_value=0.95, threshold_type="minimum",
        ))
        # 8/10 compliant = 0.80, below default 0.90
        for _ in range(8):
            tracker.observe(_obs("agent:a", "accuracy", 0.96))
        for _ in range(2):
            tracker.observe(_obs("agent:a", "accuracy", 0.80))

        alerts = tracker.degradation_alerts()
        assert len(alerts) == 1
