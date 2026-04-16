"""Tests for gavel.anomaly_monitor — ATF B-4 anomaly detection SLA guarantee."""

from __future__ import annotations

import pytest

from gavel.baseline import BehavioralBaselineRegistry, BehavioralObservation
from gavel.anomaly_monitor import AnomalyAlert, AnomalyMonitor, AnomalyMonitorConfig


# ── Helpers ───────────────────────────────────────────────────

def _obs(agent_id: str, **kw) -> BehavioralObservation:
    """Create a BehavioralObservation with sane defaults."""
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


def _build_enrolled_registry(
    agent_id: str = "agent:a",
    enrollment_count: int = 15,
    **obs_kw,
) -> BehavioralBaselineRegistry:
    """Build a registry with one agent past the enrollment threshold."""
    reg = BehavioralBaselineRegistry(min_samples_for_snapshot=10)
    for i in range(enrollment_count):
        reg.observe(_obs(agent_id, i=i, **obs_kw))
    return reg


def _induce_drift(
    reg: BehavioralBaselineRegistry,
    agent_id: str = "agent:a",
    count: int = 20,
) -> None:
    """Push observations that heavily differ from enrollment baseline."""
    for i in range(count):
        reg.observe(_obs(
            agent_id,
            i=1000 + i,
            tool="curl",
            risk_score=0.9,
            network=True,
            touched_paths=["/etc/shadow"],
            outcome="DENIED",
        ))


# ── Config validation ────────────────────────────────────────

class TestAnomalyMonitorConfig:
    def test_defaults(self):
        cfg = AnomalyMonitorConfig()
        assert cfg.scan_interval_seconds == 30.0
        assert cfg.sla_target_seconds == 60.0
        assert cfg.drift_threshold == 0.20
        assert cfg.max_alert_history == 1000

    def test_custom_values(self):
        cfg = AnomalyMonitorConfig(
            scan_interval_seconds=10.0,
            sla_target_seconds=30.0,
            drift_threshold=0.15,
            max_alert_history=500,
        )
        assert cfg.scan_interval_seconds == 10.0
        assert cfg.sla_target_seconds == 30.0
        assert cfg.drift_threshold == 0.15
        assert cfg.max_alert_history == 500


# ── Single agent scan ────────────────────────────────────────

class TestScanAgent:
    def test_no_enrollment_returns_none(self):
        """Agent without enrollment snapshot produces no alert."""
        reg = BehavioralBaselineRegistry()
        reg.observe(_obs("agent:a"))  # Only 1 obs, below min_samples
        monitor = AnomalyMonitor(reg)
        assert monitor.scan_agent("agent:a") is None

    def test_no_drift_returns_none(self):
        """Agent with stable behavior produces no alert."""
        reg = _build_enrolled_registry("agent:a")
        monitor = AnomalyMonitor(reg)
        assert monitor.scan_agent("agent:a") is None

    def test_significant_drift_returns_alert(self):
        """Agent with significant drift produces an alert."""
        reg = _build_enrolled_registry("agent:a")
        _induce_drift(reg, "agent:a")
        monitor = AnomalyMonitor(reg)

        alert = monitor.scan_agent("agent:a")
        assert alert is not None
        assert isinstance(alert, AnomalyAlert)
        assert alert.agent_id == "agent:a"
        assert alert.alert_type == "drift_detected"
        assert alert.drift_score > 0.20
        assert alert.sla_met is True
        assert len(alert.alert_id) > 0
        assert alert.details["reasons"]

    def test_unknown_agent_returns_none(self):
        """Scanning a completely unknown agent produces no alert."""
        reg = BehavioralBaselineRegistry()
        monitor = AnomalyMonitor(reg)
        assert monitor.scan_agent("agent:nonexistent") is None

    def test_custom_threshold(self):
        """Alert respects the configured drift threshold."""
        reg = _build_enrolled_registry("agent:a")
        _induce_drift(reg, "agent:a")

        # Very high threshold should suppress alerts
        cfg = AnomalyMonitorConfig(drift_threshold=0.99)
        monitor = AnomalyMonitor(reg, config=cfg)
        assert monitor.scan_agent("agent:a") is None


# ── Fleet scan ────────────────────────────────────────────────

class TestScanAll:
    def test_empty_fleet(self):
        """Scanning an empty registry produces no alerts."""
        reg = BehavioralBaselineRegistry()
        monitor = AnomalyMonitor(reg)
        alerts = monitor.scan_all()
        assert alerts == []

    def test_fleet_no_drift(self):
        """Fleet of healthy agents produces no alerts."""
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=10)
        for aid in ["agent:a", "agent:b", "agent:c"]:
            for i in range(15):
                reg.observe(_obs(aid, i=i))

        monitor = AnomalyMonitor(reg)
        alerts = monitor.scan_all()
        assert alerts == []

    def test_fleet_with_one_drifted(self):
        """Only the drifted agent in a fleet generates an alert."""
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=10)
        for aid in ["agent:a", "agent:b", "agent:c"]:
            for i in range(15):
                reg.observe(_obs(aid, i=i))

        # Drift agent:b only
        _induce_drift(reg, "agent:b")

        monitor = AnomalyMonitor(reg)
        alerts = monitor.scan_all()
        assert len(alerts) == 1
        assert alerts[0].agent_id == "agent:b"

    def test_fleet_with_multiple_drifted(self):
        """Multiple drifted agents all generate alerts."""
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=10)
        for aid in ["agent:a", "agent:b", "agent:c"]:
            for i in range(15):
                reg.observe(_obs(aid, i=i))

        _induce_drift(reg, "agent:a")
        _induce_drift(reg, "agent:c")

        monitor = AnomalyMonitor(reg)
        alerts = monitor.scan_all()
        drifted_ids = {a.agent_id for a in alerts}
        assert drifted_ids == {"agent:a", "agent:c"}


# ── SLA timing tracking ──────────────────────────────────────

class TestSLATracking:
    def test_initial_state(self):
        """Before any scan, properties have clean defaults."""
        reg = BehavioralBaselineRegistry()
        monitor = AnomalyMonitor(reg)
        assert monitor.last_scan_at is None
        assert monitor.scan_duration_ms == 0.0
        assert monitor.sla_compliance_rate == 1.0
        assert monitor.total_scans == 0
        assert monitor.alert_history == []

    def test_scan_records_timing(self):
        """After a scan, timing properties are populated."""
        reg = _build_enrolled_registry("agent:a")
        monitor = AnomalyMonitor(reg)
        monitor.scan_all()

        assert monitor.last_scan_at is not None
        assert monitor.scan_duration_ms >= 0.0
        assert monitor.total_scans == 1
        assert monitor.sla_compliance_rate == 1.0

    def test_multiple_scans_track_cumulative(self):
        """Multiple scans accumulate correctly."""
        reg = _build_enrolled_registry("agent:a")
        monitor = AnomalyMonitor(reg)

        for _ in range(5):
            monitor.scan_all()

        assert monitor.total_scans == 5
        assert monitor.sla_compliance_rate == 1.0

    def test_sla_met_flag_on_alerts(self):
        """Alerts from a scan that completes within SLA have sla_met=True."""
        reg = _build_enrolled_registry("agent:a")
        _induce_drift(reg, "agent:a")
        monitor = AnomalyMonitor(reg)

        alerts = monitor.scan_all()
        assert len(alerts) == 1
        assert alerts[0].sla_met is True

    def test_scan_duration_is_reasonable(self):
        """A scan of a small fleet should complete in well under the SLA."""
        reg = BehavioralBaselineRegistry(min_samples_for_snapshot=10)
        for aid in [f"agent:{i}" for i in range(50)]:
            for j in range(15):
                reg.observe(_obs(aid, i=j))

        monitor = AnomalyMonitor(reg)
        monitor.scan_all()

        # 50 agents should complete in <1 second, not even close to 60s
        assert monitor.scan_duration_ms < 1000.0


# ── Alert history ─────────────────────────────────────────────

class TestAlertHistory:
    def test_alerts_accumulate_in_history(self):
        """Alerts from scan_all are stored in history."""
        reg = _build_enrolled_registry("agent:a")
        _induce_drift(reg, "agent:a")
        monitor = AnomalyMonitor(reg)

        monitor.scan_all()
        assert len(monitor.alert_history) == 1

        monitor.scan_all()
        assert len(monitor.alert_history) == 2

    def test_history_bounded_size(self):
        """Alert history is bounded to max_alert_history."""
        reg = _build_enrolled_registry("agent:a")
        _induce_drift(reg, "agent:a")

        cfg = AnomalyMonitorConfig(max_alert_history=5)
        monitor = AnomalyMonitor(reg, config=cfg)

        for _ in range(10):
            monitor.scan_all()

        assert len(monitor.alert_history) == 5

    def test_history_preserves_most_recent(self):
        """When history overflows, oldest alerts are evicted."""
        reg = _build_enrolled_registry("agent:a")
        _induce_drift(reg, "agent:a")

        cfg = AnomalyMonitorConfig(max_alert_history=3)
        monitor = AnomalyMonitor(reg, config=cfg)

        all_alert_ids = []
        for _ in range(5):
            alerts = monitor.scan_all()
            all_alert_ids.append(alerts[0].alert_id)

        history_ids = [a.alert_id for a in monitor.alert_history]
        # Should have the last 3
        assert history_ids == all_alert_ids[-3:]


# ── Status summary ────────────────────────────────────────────

class TestStatusSummary:
    def test_summary_structure(self):
        """status_summary returns expected keys."""
        reg = _build_enrolled_registry("agent:a")
        monitor = AnomalyMonitor(reg)
        monitor.scan_all()

        summary = monitor.status_summary()
        assert summary["total_scans"] == 1
        assert summary["sla_target_seconds"] == 60.0
        assert summary["sla_compliance_rate"] == 1.0
        assert summary["scan_interval_seconds"] == 30.0
        assert summary["drift_threshold"] == 0.20
        assert "scan_duration_ms" in summary
        assert "last_scan_at" in summary
        assert "alert_count" in summary


# ── AnomalyAlert model ───────────────────────────────────────

class TestAnomalyAlert:
    def test_default_fields(self):
        alert = AnomalyAlert(
            agent_id="agent:x",
            alert_type="drift_detected",
            drift_score=0.45,
        )
        assert alert.agent_id == "agent:x"
        assert alert.alert_type == "drift_detected"
        assert alert.drift_score == 0.45
        assert alert.sla_met is True
        assert len(alert.alert_id) == 36  # UUID format
        assert alert.details == {}
        assert alert.detected_at is not None

    def test_custom_details(self):
        alert = AnomalyAlert(
            agent_id="agent:y",
            alert_type="evasion_detected",
            drift_score=0.80,
            details={"reasons": ["risk_delta=+0.500"]},
            sla_met=False,
        )
        assert alert.sla_met is False
        assert alert.details["reasons"] == ["risk_delta=+0.500"]


# ── Stop method ───────────────────────────────────────────────

class TestStop:
    def test_stop_when_not_running(self):
        """Stopping when not running is a no-op."""
        reg = BehavioralBaselineRegistry()
        monitor = AnomalyMonitor(reg)
        monitor.stop()  # Should not raise
        assert monitor._running is False
