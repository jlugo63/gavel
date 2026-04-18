"""
Anomaly Detection SLA Monitor — ATF B-4.

Provides an explicit <60-second SLA guarantee for anomaly detection
across the agent fleet. The AnomalyMonitor wraps the existing
BehavioralBaselineRegistry drift scoring and adds:

  - Periodic fleet-wide scans (configurable interval, default 30s)
  - Per-scan timing measurement to prove SLA compliance
  - Alert generation for agents with significant drift
  - Bounded alert history
  - SLA compliance tracking (fraction of scans within target)

The scan itself is synchronous — BehavioralBaselineRegistry.drift()
is already sync. The optional async loop just calls scan_all()
periodically.

Design constraints:
  - stdlib + pydantic only
  - No LLM in the loop
  - Bounded memory (alert history capped)
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from gavel.baseline import BehavioralBaselineRegistry

logger = logging.getLogger(__name__)


# ── Models ────────────────────────────────────────────────────

class AnomalyAlert(BaseModel):
    """An alert raised when anomalous agent behavior is detected."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    alert_type: str  # "drift_detected", "evasion_detected"
    drift_score: float
    details: dict = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sla_met: bool = True  # Was this detected within the SLA target?


class AnomalyMonitorConfig(BaseModel):
    """Configuration for the anomaly monitoring loop."""

    scan_interval_seconds: float = 30.0  # How often to scan
    sla_target_seconds: float = 60.0     # The ATF B-4 SLA
    drift_threshold: float = 0.20        # Drift score threshold for alerts
    max_alert_history: int = 1000        # Bounded alert history size


# ── Monitor ───────────────────────────────────────────────────

class AnomalyMonitor:
    """Fleet-wide anomaly detection with SLA tracking.

    Wraps a BehavioralBaselineRegistry and provides periodic scanning
    with timing measurement to guarantee <60s anomaly detection SLA.

    Usage:
        registry = BehavioralBaselineRegistry()
        monitor = AnomalyMonitor(registry)

        # Synchronous scan
        alerts = monitor.scan_all()

        # Or start the async loop
        await monitor.start_async_loop()
        # ... later ...
        monitor.stop()
    """

    def __init__(
        self,
        registry: BehavioralBaselineRegistry,
        config: Optional[AnomalyMonitorConfig] = None,
    ):
        self._registry = registry
        self._config = config or AnomalyMonitorConfig()
        self._alert_history: deque[AnomalyAlert] = deque(
            maxlen=self._config.max_alert_history,
        )
        self._last_scan_at: Optional[datetime] = None
        self._scan_duration_ms: float = 0.0
        self._total_scans: int = 0
        self._sla_met_scans: int = 0
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None

    # ── Properties ────────────────────────────────────────────

    @property
    def last_scan_at(self) -> Optional[datetime]:
        """Timestamp of the most recent completed scan."""
        return self._last_scan_at

    @property
    def scan_duration_ms(self) -> float:
        """Duration of the most recent scan in milliseconds."""
        return self._scan_duration_ms

    @property
    def sla_compliance_rate(self) -> float:
        """Fraction of scans completed within the SLA target (0.0..1.0)."""
        if self._total_scans == 0:
            return 1.0
        return self._sla_met_scans / self._total_scans

    @property
    def alert_history(self) -> list[AnomalyAlert]:
        """Recent alerts (bounded to max_alert_history)."""
        return list(self._alert_history)

    @property
    def total_scans(self) -> int:
        """Total number of scans performed."""
        return self._total_scans

    # ── Scanning ──────────────────────────────────────────────

    def scan_agent(self, agent_id: str) -> Optional[AnomalyAlert]:
        """Scan a single agent for behavioral drift.

        Returns an AnomalyAlert if drift exceeds the threshold, else None.
        """
        drift_report = self._registry.drift(agent_id)
        if drift_report is None:
            return None

        if not drift_report.is_significant:
            return None

        if drift_report.drift_score < self._config.drift_threshold:
            return None

        alert = AnomalyAlert(
            agent_id=agent_id,
            alert_type="drift_detected",
            drift_score=drift_report.drift_score,
            details={
                "reasons": drift_report.reasons,
                "risk_delta": drift_report.risk_delta,
                "network_delta": drift_report.network_delta,
                "new_tools": drift_report.new_tools,
                "new_paths": drift_report.new_paths,
                "enrollment_sample_size": drift_report.enrollment_sample_size,
                "current_sample_size": drift_report.current_sample_size,
            },
        )
        return alert

    def scan_all(self) -> list[AnomalyAlert]:
        """Scan all enrolled agents for behavioral drift.

        Returns a list of alerts for agents with significant drift.
        Tracks scan timing for SLA compliance measurement.
        """
        start = time.monotonic()
        start_utc = datetime.now(timezone.utc)
        alerts: list[AnomalyAlert] = []

        # Get all agent IDs that have enrollment snapshots (only those
        # can produce drift reports).
        agent_ids = list(self._registry._enrollment_snapshots.keys())

        for agent_id in agent_ids:
            alert = self.scan_agent(agent_id)
            if alert is not None:
                alerts.append(alert)

        elapsed_ms = (time.monotonic() - start) * 1000.0
        elapsed_seconds = elapsed_ms / 1000.0
        sla_met = elapsed_seconds < self._config.sla_target_seconds

        self._last_scan_at = start_utc
        self._scan_duration_ms = round(elapsed_ms, 2)
        self._total_scans += 1
        if sla_met:
            self._sla_met_scans += 1
        else:
            logger.warning(
                "Anomaly scan took %.1fms (%.1fs), exceeding SLA target of %.1fs",
                elapsed_ms,
                elapsed_seconds,
                self._config.sla_target_seconds,
            )

        # Tag alerts with SLA status and record in history
        for alert in alerts:
            alert.sla_met = sla_met
            self._alert_history.append(alert)

        return alerts

    # ── Async loop ────────────────────────────────────────────

    async def start_async_loop(self) -> None:
        """Start an async loop that calls scan_all() every scan_interval_seconds."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.current_task() or asyncio.ensure_future(self._loop())
        if asyncio.current_task():
            # We were called directly; start the loop as a new task
            self._task = asyncio.ensure_future(self._loop())

    async def _loop(self) -> None:
        """Internal async loop."""
        while self._running:
            try:
                self.scan_all()
            except Exception:
                logger.exception("Anomaly scan failed")
            await asyncio.sleep(self._config.scan_interval_seconds)

    def stop(self) -> None:
        """Stop the async monitoring loop."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            self._task = None

    # ── Status ────────────────────────────────────────────────

    def status_summary(self) -> dict:
        """Dashboard-ready summary of anomaly monitoring status."""
        return {
            "total_scans": self._total_scans,
            "last_scan_at": self._last_scan_at.isoformat() if self._last_scan_at else None,
            "scan_duration_ms": self._scan_duration_ms,
            "sla_target_seconds": self._config.sla_target_seconds,
            "sla_compliance_rate": round(self.sla_compliance_rate, 4),
            "scan_interval_seconds": self._config.scan_interval_seconds,
            "alert_count": len(self._alert_history),
            "drift_threshold": self._config.drift_threshold,
        }
