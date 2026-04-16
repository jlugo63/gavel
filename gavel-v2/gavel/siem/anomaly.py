"""Anomaly detection — unusual agent behavior patterns across the fleet."""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from gavel.siem.events import GovernanceEvent, GovernanceEventCategory


class AnomalyType(str, Enum):
    UNUSUAL_VOLUME = "unusual_volume"             # Spike in events from one agent/endpoint
    OFF_HOURS_ACTIVITY = "off_hours_activity"     # Activity outside normal working hours
    RAPID_ENROLLMENT = "rapid_enrollment"         # Many agents enrolling in burst
    DENIAL_SPIKE = "denial_spike"                 # Surge in denied actions
    NEW_TOOL_PATTERN = "new_tool_pattern"         # Agent using tools it hasn't used before
    CROSS_MACHINE_SPIKE = "cross_machine_spike"   # Agent suddenly active on many machines


class AnomalyFinding(BaseModel):
    """A detected anomaly in fleet-wide agent behavior."""
    finding_id: str = Field(default_factory=lambda: f"anom-{uuid.uuid4().hex[:8]}")
    anomaly_type: AnomalyType
    severity: str = "medium"
    agent_id: str = ""
    endpoint_id: str = ""
    description: str = ""
    score: float = 0.0               # Anomaly score (higher = more anomalous)
    baseline_value: float = 0.0      # Expected normal value
    observed_value: float = 0.0      # What we actually saw
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: dict[str, Any] = Field(default_factory=dict)


class AnomalyDetector:
    """Detect unusual agent behavior patterns across the fleet."""

    def __init__(self, volume_window_minutes: int = 60, volume_threshold_sigma: float = 2.0):
        self._findings: list[AnomalyFinding] = []
        self._volume_window = timedelta(minutes=volume_window_minutes)
        self._volume_threshold = volume_threshold_sigma
        # Rolling statistics per agent
        self._agent_event_counts: dict[str, list[int]] = defaultdict(list)  # agent_id -> [count per window]

    def _mean_std(self, values: list[int | float]) -> tuple[float, float]:
        """Compute mean and standard deviation without numpy."""
        if not values:
            return 0.0, 0.0
        n = len(values)
        mean = sum(values) / n
        if n < 2:
            return mean, 0.0
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        return mean, math.sqrt(variance)

    def detect_volume_anomaly(self, events: list[GovernanceEvent]) -> list[AnomalyFinding]:
        """Detect unusual event volume per agent."""
        findings = []
        # Count events per agent
        agent_counts: dict[str, int] = defaultdict(int)
        for e in events:
            if e.agent_id:
                agent_counts[e.agent_id] += 1

        for agent_id, count in agent_counts.items():
            self._agent_event_counts[agent_id].append(count)
            history = self._agent_event_counts[agent_id]
            if len(history) < 3:
                continue
            mean, std = self._mean_std(history[:-1])  # Compare against prior windows
            if std > 0 and (count - mean) / std > self._volume_threshold:
                score = (count - mean) / std
                finding = AnomalyFinding(
                    anomaly_type=AnomalyType.UNUSUAL_VOLUME,
                    severity="high" if score > 3.0 else "medium",
                    agent_id=agent_id,
                    description=f"Agent {agent_id} generated {count} events (baseline: {mean:.1f} +/- {std:.1f})",
                    score=round(score, 2),
                    baseline_value=round(mean, 2),
                    observed_value=float(count),
                    evidence={"history": history[-10:]},
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def detect_denial_spike(self, events: list[GovernanceEvent]) -> list[AnomalyFinding]:
        """Detect surge in denied actions per agent."""
        findings = []
        agent_denials: dict[str, int] = defaultdict(int)
        agent_total: dict[str, int] = defaultdict(int)

        for e in events:
            if e.agent_id and e.category == GovernanceEventCategory.DECISION:
                agent_total[e.agent_id] += 1
                if e.event_type in ("chain.denied", "action.denied"):
                    agent_denials[e.agent_id] += 1

        for agent_id, denials in agent_denials.items():
            total = agent_total.get(agent_id, 0)
            if total >= 5 and denials / total > 0.5:
                denial_rate = denials / total
                finding = AnomalyFinding(
                    anomaly_type=AnomalyType.DENIAL_SPIKE,
                    severity="high",
                    agent_id=agent_id,
                    description=f"Agent {agent_id}: {denials}/{total} actions denied ({denial_rate:.0%})",
                    score=round(denial_rate * 10, 2),
                    baseline_value=0.1,
                    observed_value=round(denial_rate, 3),
                    evidence={"denials": denials, "total": total},
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def detect_rapid_enrollment(self, events: list[GovernanceEvent],
                                 threshold: int = 5) -> list[AnomalyFinding]:
        """Detect burst of agent enrollments on a single endpoint."""
        findings = []
        endpoint_enrollments: dict[str, int] = defaultdict(int)

        for e in events:
            if e.category == GovernanceEventCategory.ENROLLMENT:
                endpoint_enrollments[e.endpoint_id] += 1

        for endpoint_id, count in endpoint_enrollments.items():
            if count >= threshold:
                finding = AnomalyFinding(
                    anomaly_type=AnomalyType.RAPID_ENROLLMENT,
                    severity="high",
                    endpoint_id=endpoint_id,
                    description=f"Endpoint {endpoint_id}: {count} agents enrolled in window",
                    score=float(count),
                    baseline_value=1.0,
                    observed_value=float(count),
                    evidence={"enrollment_count": count},
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def analyze(self, events: list[GovernanceEvent]) -> list[AnomalyFinding]:
        """Run all anomaly detectors."""
        results = []
        results.extend(self.detect_volume_anomaly(events))
        results.extend(self.detect_denial_spike(events))
        results.extend(self.detect_rapid_enrollment(events))
        return results

    @property
    def all_findings(self) -> list[AnomalyFinding]:
        return list(self._findings)
