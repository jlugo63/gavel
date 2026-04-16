"""Tests for Liveness Monitor — SLA escalation and auto-deny (Article IV.2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from gavel.liveness import (
    EscalationLevel,
    EscalationTimeout,
    LivenessMonitor,
)


# ---------------------------------------------------------------------------
# EscalationLevel enum
# ---------------------------------------------------------------------------

class TestEscalationLevel:
    def test_all_levels_present(self):
        expected = {"NORMAL", "WARNING", "CRITICAL", "TIMED_OUT"}
        assert {l.value for l in EscalationLevel} == expected


# ---------------------------------------------------------------------------
# EscalationTimeout — properties
# ---------------------------------------------------------------------------

class TestEscalationTimeout:
    def test_deadline_calculation(self):
        now = datetime.now(timezone.utc)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=now)
        assert t.deadline == now + timedelta(seconds=600)

    def test_elapsed_seconds(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=30)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert 29.5 < t.elapsed_seconds < 31.0

    def test_remaining_seconds(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=100)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert 499 < t.remaining_seconds < 501

    def test_remaining_seconds_never_negative(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=1000)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert t.remaining_seconds == 0

    def test_elapsed_fraction_capped_at_one(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=1200)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert t.elapsed_fraction == 1.0

    def test_elapsed_fraction_zero_sla(self):
        t = EscalationTimeout(chain_id="c-1", sla_seconds=0)
        assert t.elapsed_fraction == 1.0

    def test_level_normal(self):
        now = datetime.now(timezone.utc)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=now)
        assert t.level == EscalationLevel.NORMAL

    def test_level_warning_at_50_percent(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=310)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert t.level == EscalationLevel.WARNING

    def test_level_critical_at_80_percent(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=490)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert t.level == EscalationLevel.CRITICAL

    def test_level_timed_out_at_100_percent(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=601)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert t.level == EscalationLevel.TIMED_OUT

    def test_is_expired_false_when_active(self):
        now = datetime.now(timezone.utc)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=now)
        assert t.is_expired is False

    def test_is_expired_true_after_sla(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=700)
        t = EscalationTimeout(chain_id="c-1", sla_seconds=600, created_at=past)
        assert t.is_expired is True

    def test_defaults(self):
        t = EscalationTimeout(chain_id="c-1", sla_seconds=60)
        assert t.resolved is False
        assert t.resolution == ""


# ---------------------------------------------------------------------------
# LivenessMonitor — track / check / resolve
# ---------------------------------------------------------------------------

class TestLivenessMonitorBasics:
    def test_track_returns_timeout(self):
        monitor = LivenessMonitor()
        t = monitor.track("c-1", sla_seconds=600)
        assert isinstance(t, EscalationTimeout)
        assert t.chain_id == "c-1"
        assert t.sla_seconds == 600

    def test_check_returns_tracked_timeout(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        result = monitor.check("c-1")
        assert result is not None
        assert result.chain_id == "c-1"

    def test_check_returns_none_for_untracked(self):
        monitor = LivenessMonitor()
        assert monitor.check("c-unknown") is None

    def test_resolve_marks_resolved(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        assert monitor.resolve("c-1", "APPROVED") is True
        t = monitor.check("c-1")
        assert t.resolved is True
        assert t.resolution == "APPROVED"

    def test_resolve_already_resolved_returns_false(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        monitor.resolve("c-1", "APPROVED")
        assert monitor.resolve("c-1", "DENIED") is False

    def test_resolve_unknown_chain_returns_false(self):
        monitor = LivenessMonitor()
        assert monitor.resolve("c-unknown", "DENIED") is False


# ---------------------------------------------------------------------------
# LivenessMonitor — get_expired / get_at_level
# ---------------------------------------------------------------------------

class TestLivenessMonitorQueries:
    def test_get_expired_finds_timed_out_chains(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=700)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past  # simulate time passing
        expired = monitor.get_expired()
        assert len(expired) == 1
        assert expired[0].chain_id == "c-1"

    def test_get_expired_excludes_resolved(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=700)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past
        monitor.resolve("c-1", "DENIED")
        assert monitor.get_expired() == []

    def test_get_expired_excludes_active(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        assert monitor.get_expired() == []

    def test_get_at_level_warning(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=310)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past
        result = monitor.get_at_level(EscalationLevel.WARNING)
        assert len(result) == 1
        assert result[0].chain_id == "c-1"

    def test_get_at_level_excludes_resolved(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=310)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past
        monitor.resolve("c-1", "OK")
        assert monitor.get_at_level(EscalationLevel.WARNING) == []


# ---------------------------------------------------------------------------
# LivenessMonitor — tick / callbacks
# ---------------------------------------------------------------------------

class TestLivenessMonitorTick:
    def test_tick_returns_escalated_chains(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=310)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past
        escalations = monitor.tick()
        assert len(escalations) == 1
        assert escalations[0] == ("c-1", EscalationLevel.WARNING)

    def test_tick_skips_normal_chains(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        assert monitor.tick() == []

    def test_tick_skips_resolved_chains(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=700)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past
        monitor.resolve("c-1", "DENIED")
        assert monitor.tick() == []

    def test_tick_fires_callbacks(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=500)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past

        events = []
        monitor.on_escalation(lambda cid, lvl: events.append((cid, lvl)))
        monitor.tick()
        assert len(events) == 1
        assert events[0] == ("c-1", EscalationLevel.CRITICAL)

    def test_tick_fires_multiple_callbacks(self):
        monitor = LivenessMonitor()
        past = datetime.now(timezone.utc) - timedelta(seconds=700)
        t = monitor.track("c-1", sla_seconds=600)
        t.created_at = past

        events_a, events_b = [], []
        monitor.on_escalation(lambda cid, lvl: events_a.append(cid))
        monitor.on_escalation(lambda cid, lvl: events_b.append(cid))
        monitor.tick()
        assert events_a == ["c-1"]
        assert events_b == ["c-1"]


# ---------------------------------------------------------------------------
# LivenessMonitor — multiple agents
# ---------------------------------------------------------------------------

class TestMultipleAgentsMonitored:
    def test_track_multiple_chains(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        monitor.track("c-2", sla_seconds=300)
        monitor.track("c-3", sla_seconds=900)
        assert monitor.check("c-1") is not None
        assert monitor.check("c-2") is not None
        assert monitor.check("c-3") is not None

    def test_mixed_expiry_states(self):
        monitor = LivenessMonitor()
        now = datetime.now(timezone.utc)

        t1 = monitor.track("c-active", sla_seconds=600)
        t2 = monitor.track("c-expired", sla_seconds=60)
        t2.created_at = now - timedelta(seconds=120)
        t3 = monitor.track("c-resolved", sla_seconds=60)
        t3.created_at = now - timedelta(seconds=120)
        monitor.resolve("c-resolved", "DENIED")

        expired = monitor.get_expired()
        assert len(expired) == 1
        assert expired[0].chain_id == "c-expired"

    def test_replacing_tracked_chain(self):
        """Tracking the same chain_id again replaces the old timeout."""
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=60)
        monitor.track("c-1", sla_seconds=9999)
        t = monitor.check("c-1")
        assert t.sla_seconds == 9999


# ---------------------------------------------------------------------------
# LivenessMonitor — status_summary
# ---------------------------------------------------------------------------

class TestStatusSummary:
    def test_summary_structure(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        summary = monitor.status_summary()
        assert summary["total_tracked"] == 1
        assert summary["active"] == 1
        assert summary["expired"] == 0
        assert "c-1" in summary["chains"]

    def test_summary_excludes_resolved_from_chains(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        monitor.resolve("c-1", "OK")
        summary = monitor.status_summary()
        assert summary["total_tracked"] == 1
        assert summary["active"] == 0
        assert "c-1" not in summary["chains"]

    def test_summary_chain_detail_keys(self):
        monitor = LivenessMonitor()
        monitor.track("c-1", sla_seconds=600)
        detail = monitor.status_summary()["chains"]["c-1"]
        assert "level" in detail
        assert "remaining_seconds" in detail
        assert "elapsed_fraction" in detail

    def test_summary_empty_monitor(self):
        monitor = LivenessMonitor()
        summary = monitor.status_summary()
        assert summary == {
            "total_tracked": 0,
            "active": 0,
            "expired": 0,
            "chains": {},
        }
