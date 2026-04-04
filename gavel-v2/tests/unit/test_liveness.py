"""Unit tests for LivenessMonitor — SLA tracking, expiry, escalation levels."""

import time

from gavel.liveness import LivenessMonitor, EscalationLevel, EscalationTimeout


class TestSLATracking:
    def test_track_creates_timeout(self, liveness):
        timeout = liveness.track("c-1", sla_seconds=600)
        assert isinstance(timeout, EscalationTimeout)
        assert timeout.chain_id == "c-1"
        assert timeout.sla_seconds == 600

    def test_check_returns_timeout(self, liveness):
        liveness.track("c-1", sla_seconds=600)
        timeout = liveness.check("c-1")
        assert timeout is not None
        assert timeout.chain_id == "c-1"

    def test_check_unknown_returns_none(self, liveness):
        assert liveness.check("c-nonexistent") is None


class TestEscalationLevels:
    def test_new_timeout_is_normal(self, liveness):
        timeout = liveness.track("c-1", sla_seconds=600)
        assert timeout.level == EscalationLevel.NORMAL

    def test_remaining_seconds(self, liveness):
        timeout = liveness.track("c-1", sla_seconds=600)
        assert timeout.remaining_seconds > 590  # Should be close to 600

    def test_elapsed_fraction_starts_near_zero(self, liveness):
        timeout = liveness.track("c-1", sla_seconds=600)
        assert timeout.elapsed_fraction < 0.01

    def test_very_short_sla_expires_quickly(self):
        """Use a 1-second SLA to test expiry."""
        monitor = LivenessMonitor()
        timeout = monitor.track("c-1", sla_seconds=1)
        time.sleep(1.1)
        assert timeout.is_expired is True
        assert timeout.level == EscalationLevel.TIMED_OUT

    def test_deadline_property(self, liveness):
        timeout = liveness.track("c-1", sla_seconds=600)
        assert timeout.deadline > timeout.created_at


class TestResolution:
    def test_resolve_marks_resolved(self, liveness):
        liveness.track("c-1", sla_seconds=600)
        result = liveness.resolve("c-1", "APPROVED")
        assert result is True
        timeout = liveness.check("c-1")
        assert timeout.resolved is True
        assert timeout.resolution == "APPROVED"

    def test_resolve_unknown_returns_false(self, liveness):
        assert liveness.resolve("c-nonexistent", "APPROVED") is False

    def test_double_resolve_returns_false(self, liveness):
        liveness.track("c-1", sla_seconds=600)
        liveness.resolve("c-1", "APPROVED")
        assert liveness.resolve("c-1", "DENIED") is False

    def test_resolved_not_in_expired_list(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=1)
        time.sleep(1.1)
        monitor.resolve("c-1", "APPROVED")
        assert len(monitor.get_expired()) == 0


class TestExpiredChains:
    def test_get_expired_returns_timed_out(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=1)
        time.sleep(1.1)
        expired = monitor.get_expired()
        assert len(expired) == 1
        assert expired[0].chain_id == "c-1"

    def test_non_expired_not_in_list(self, liveness):
        liveness.track("c-1", sla_seconds=600)
        assert len(liveness.get_expired()) == 0


class TestStatusSummary:
    def test_summary_structure(self, liveness):
        liveness.track("c-1", sla_seconds=600)
        liveness.track("c-2", sla_seconds=300)
        summary = liveness.status_summary()
        assert summary["total_tracked"] == 2
        assert summary["active"] == 2
        assert "c-1" in summary["chains"]
        assert "c-2" in summary["chains"]
        assert "level" in summary["chains"]["c-1"]
        assert "remaining_seconds" in summary["chains"]["c-1"]

    def test_resolved_not_in_active(self, liveness):
        liveness.track("c-1", sla_seconds=600)
        liveness.resolve("c-1", "DONE")
        summary = liveness.status_summary()
        assert summary["active"] == 0


class TestEscalationCallbacks:
    def test_callback_fires_on_tick(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=1)
        time.sleep(1.1)
        fired = []
        monitor.on_escalation(lambda cid, level: fired.append((cid, level)))
        monitor.tick()
        assert len(fired) > 0
        assert fired[0][0] == "c-1"
        assert fired[0][1] == EscalationLevel.TIMED_OUT
