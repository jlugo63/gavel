"""
Performance Metrics — EU AI Act Article 15.

Tracks declared accuracy/performance targets vs observed outcomes for
high-risk AI systems.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


# ── Models ────────────────────────────────────────────────────

class PerformanceTarget(BaseModel):
    """A declared performance target for a specific metric."""

    metric_name: str  # e.g. "accuracy", "precision", "recall", "f1", "latency_p99"
    target_value: float
    threshold_type: str  # "minimum" for accuracy, "maximum" for latency
    unit: str = ""  # e.g. "ms", "%", "ratio"


class PerformanceObservation(BaseModel):
    """A single observed metric value for an agent."""

    agent_id: str
    metric_name: str
    observed_value: float
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: dict = Field(default_factory=dict)


class PerformanceReport(BaseModel):
    """Compliance report comparing observations against a declared target."""

    agent_id: str
    metric_name: str
    target: PerformanceTarget
    sample_size: int
    mean_observed: float
    min_observed: float
    max_observed: float
    compliance_rate: float  # fraction of observations meeting target
    is_compliant: bool  # compliance_rate >= 0.95
    trend: str  # "stable", "improving", "degrading"
    reported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Tracker ───────────────────────────────────────────────────

_DEFAULT_WINDOW = 500


class PerformanceTracker:
    """Accumulates metric observations and reports compliance against
    declared targets.

    Memory is bounded: each (agent, metric) pair keeps at most `window`
    recent observations.
    """

    def __init__(self, window: int = _DEFAULT_WINDOW):
        self._window = window
        # (agent_id, metric_name) -> target
        self._targets: dict[tuple[str, str], PerformanceTarget] = {}
        # (agent_id, metric_name) -> deque of observations
        self._observations: dict[tuple[str, str], deque[PerformanceObservation]] = {}

    def set_target(self, agent_id: str, target: PerformanceTarget) -> None:
        """Declare a performance target for an agent metric."""
        self._targets[(agent_id, target.metric_name)] = target

    def observe(self, obs: PerformanceObservation) -> None:
        """Record a single metric observation."""
        key = (obs.agent_id, obs.metric_name)
        buf = self._observations.setdefault(key, deque(maxlen=self._window))
        buf.append(obs)

    def report(self, agent_id: str, metric_name: str) -> Optional[PerformanceReport]:
        """Generate a compliance report for one agent metric.

        Returns None if no target or no observations exist.
        """
        key = (agent_id, metric_name)
        target = self._targets.get(key)
        if target is None:
            return None
        buf = self._observations.get(key)
        if not buf:
            return None

        values = [o.observed_value for o in buf]
        n = len(values)
        mean_val = round(sum(values) / n, 6)
        min_val = min(values)
        max_val = max(values)

        # compliance: how many observations meet the target
        if target.threshold_type == "minimum":
            compliant_count = sum(1 for v in values if v >= target.target_value)
        else:  # "maximum"
            compliant_count = sum(1 for v in values if v <= target.target_value)

        compliance_rate = round(compliant_count / n, 6)

        # trend: compare first-half mean to second-half mean
        trend = _detect_trend(values, target.threshold_type)

        return PerformanceReport(
            agent_id=agent_id,
            metric_name=metric_name,
            target=target,
            sample_size=n,
            mean_observed=mean_val,
            min_observed=min_val,
            max_observed=max_val,
            compliance_rate=compliance_rate,
            is_compliant=compliance_rate >= 0.95,
            trend=trend,
        )

    def report_all(self, agent_id: str) -> list[PerformanceReport]:
        """Generate compliance reports for all metrics of an agent."""
        reports = []
        for (aid, metric), _target in self._targets.items():
            if aid == agent_id:
                rpt = self.report(aid, metric)
                if rpt is not None:
                    reports.append(rpt)
        return reports

    def degradation_alerts(self, threshold: float = 0.90) -> list[PerformanceReport]:
        """Find all metrics across all agents with compliance_rate below threshold."""
        alerts = []
        for (agent_id, metric_name) in self._targets:
            rpt = self.report(agent_id, metric_name)
            if rpt is not None and rpt.compliance_rate < threshold:
                alerts.append(rpt)
        return alerts


# ── Helpers ───────────────────────────────────────────────────

def _detect_trend(values: list[float], threshold_type: str) -> str:
    """Compare first-half mean to second-half mean to detect trend.

    For "minimum" thresholds (e.g. accuracy): increasing is improving.
    For "maximum" thresholds (e.g. latency): decreasing is improving.
    """
    if len(values) < 4:
        return "stable"

    mid = len(values) // 2
    first_half = values[:mid]
    second_half = values[mid:]
    mean_first = sum(first_half) / len(first_half)
    mean_second = sum(second_half) / len(second_half)

    delta = mean_second - mean_first
    relative = abs(delta) / max(abs(mean_first), 1e-9)

    if relative < 0.05:
        return "stable"

    if threshold_type == "minimum":
        return "improving" if delta > 0 else "degrading"
    else:  # "maximum"
        return "improving" if delta < 0 else "degrading"
