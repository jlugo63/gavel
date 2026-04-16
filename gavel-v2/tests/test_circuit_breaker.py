"""Tests for Circuit Breaker — per-agent failure isolation (ATF R-1)."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gavel.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerState,
    CircuitState,
)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _make_cb(**overrides) -> CircuitBreaker:
    """Build a CircuitBreaker with small thresholds for fast tests."""
    config = CircuitBreakerConfig(
        failure_threshold=overrides.pop("failure_threshold", 3),
        recovery_timeout_seconds=overrides.pop("recovery_timeout_seconds", 5),
        half_open_max_requests=overrides.pop("half_open_max_requests", 2),
        success_threshold=overrides.pop("success_threshold", 2),
    )
    return CircuitBreaker(default_config=config)


AGENT = "agent:test"


# -------------------------------------------------------------------
# CLOSED state
# -------------------------------------------------------------------

class TestClosedState:
    def test_starts_closed(self):
        cb = _make_cb()
        assert cb.allow_request(AGENT) is True
        state = cb.get_state(AGENT)
        assert state is not None
        assert state.state == CircuitState.CLOSED

    def test_success_stays_closed(self):
        cb = _make_cb()
        cb.allow_request(AGENT)
        result = cb.record_success(AGENT)
        assert result == CircuitState.CLOSED

    def test_failures_below_threshold_stay_closed(self):
        cb = _make_cb(failure_threshold=3)
        for _ in range(2):
            cb.allow_request(AGENT)
            cb.record_failure(AGENT)
        state = cb.get_state(AGENT)
        assert state.state == CircuitState.CLOSED
        assert state.consecutive_failures == 2

    def test_success_resets_consecutive_failures(self):
        cb = _make_cb(failure_threshold=3)
        cb.allow_request(AGENT)
        cb.record_failure(AGENT)
        cb.record_failure(AGENT)
        cb.record_success(AGENT)
        state = cb.get_state(AGENT)
        assert state.consecutive_failures == 0
        assert state.state == CircuitState.CLOSED


# -------------------------------------------------------------------
# OPEN state (tripping)
# -------------------------------------------------------------------

class TestTripping:
    def test_trips_at_threshold(self):
        cb = _make_cb(failure_threshold=3)
        for _ in range(3):
            cb.allow_request(AGENT)
            cb.record_failure(AGENT)
        state = cb.get_state(AGENT)
        assert state.state == CircuitState.OPEN
        assert state.trip_count == 1

    def test_open_denies_requests(self):
        cb = _make_cb(failure_threshold=3)
        for _ in range(3):
            cb.allow_request(AGENT)
            cb.record_failure(AGENT)
        assert cb.allow_request(AGENT) is False

    def test_trip_count_increments(self):
        cb = _make_cb(failure_threshold=2, recovery_timeout_seconds=1)
        # First trip
        cb.record_failure(AGENT)
        cb.record_failure(AGENT)
        assert cb.get_state(AGENT).trip_count == 1
        # Backdate to allow half-open transition
        state = cb.get_state(AGENT)
        state.last_state_change = datetime.now(timezone.utc) - timedelta(seconds=2)
        cb.allow_request(AGENT)  # transitions to HALF_OPEN
        cb.record_failure(AGENT)
        assert cb.get_state(AGENT).trip_count == 2


# -------------------------------------------------------------------
# HALF_OPEN state (recovery)
# -------------------------------------------------------------------

class TestHalfOpen:
    def _trip(self, cb: CircuitBreaker, agent: str = AGENT) -> None:
        config = cb.get_config(agent)
        for _ in range(config.failure_threshold):
            cb.allow_request(agent)
            cb.record_failure(agent)

    def _force_half_open(self, cb: CircuitBreaker, agent: str = AGENT) -> None:
        """Trip the breaker, then backdate the state change to force HALF_OPEN."""
        self._trip(cb, agent)
        state = cb.get_state(agent)
        config = cb.get_config(agent)
        state.last_state_change = datetime.now(timezone.utc) - timedelta(
            seconds=config.recovery_timeout_seconds + 1
        )

    def test_transitions_to_half_open_after_timeout(self):
        cb = _make_cb(failure_threshold=2, recovery_timeout_seconds=1)
        self._trip(cb)
        self._force_half_open(cb)
        assert cb.allow_request(AGENT) is True
        assert cb.get_state(AGENT).state == CircuitState.HALF_OPEN

    def test_half_open_limits_requests(self):
        cb = _make_cb(failure_threshold=2, half_open_max_requests=2, recovery_timeout_seconds=1)
        self._force_half_open(cb)
        # First request transitions to HALF_OPEN and counts as the first allow
        assert cb.allow_request(AGENT) is True
        # Second allowed (budget incremented on allow)
        assert cb.allow_request(AGENT) is True
        # Third denied — budget exhausted
        assert cb.allow_request(AGENT) is False

    def test_success_threshold_closes(self):
        cb = _make_cb(
            failure_threshold=2,
            success_threshold=2,
            recovery_timeout_seconds=1,
        )
        self._force_half_open(cb)
        cb.allow_request(AGENT)  # -> HALF_OPEN
        cb.record_success(AGENT)
        assert cb.get_state(AGENT).state == CircuitState.HALF_OPEN  # not enough yet
        cb.record_success(AGENT)
        assert cb.get_state(AGENT).state == CircuitState.CLOSED

    def test_failure_in_half_open_reopens(self):
        cb = _make_cb(failure_threshold=2, recovery_timeout_seconds=1)
        self._force_half_open(cb)
        cb.allow_request(AGENT)  # -> HALF_OPEN
        cb.record_failure(AGENT)
        assert cb.get_state(AGENT).state == CircuitState.OPEN

    def test_backdated_half_open(self):
        cb = _make_cb(failure_threshold=2, recovery_timeout_seconds=30)
        self._force_half_open(cb)
        assert cb.allow_request(AGENT) is True
        assert cb.get_state(AGENT).state == CircuitState.HALF_OPEN


# -------------------------------------------------------------------
# Per-agent isolation
# -------------------------------------------------------------------

class TestPerAgentIsolation:
    def test_agents_are_independent(self):
        cb = _make_cb(failure_threshold=2)
        a, b = "agent:a", "agent:b"
        # Trip agent:a
        cb.record_failure(a)
        cb.record_failure(a)
        assert cb.get_state(a).state == CircuitState.OPEN
        # agent:b unaffected
        assert cb.allow_request(b) is True
        assert cb.get_state(b).state == CircuitState.CLOSED

    def test_per_agent_config(self):
        cb = _make_cb(failure_threshold=5)
        cb.configure("agent:fragile", CircuitBreakerConfig(failure_threshold=1))
        cb.record_failure("agent:fragile")
        assert cb.get_state("agent:fragile").state == CircuitState.OPEN
        # Default agent still fine after 1 failure
        cb.record_failure("agent:sturdy")
        assert cb.get_state("agent:sturdy").state == CircuitState.CLOSED


# -------------------------------------------------------------------
# Manual reset
# -------------------------------------------------------------------

class TestReset:
    def test_reset_closes_open_breaker(self):
        cb = _make_cb(failure_threshold=2)
        cb.record_failure(AGENT)
        cb.record_failure(AGENT)
        assert cb.get_state(AGENT).state == CircuitState.OPEN
        cb.reset(AGENT)
        state = cb.get_state(AGENT)
        assert state.state == CircuitState.CLOSED
        assert state.consecutive_failures == 0


# -------------------------------------------------------------------
# Config validation
# -------------------------------------------------------------------

class TestConfigValidation:
    def test_defaults(self):
        config = CircuitBreakerConfig()
        assert config.failure_threshold == 5
        assert config.recovery_timeout_seconds == 60
        assert config.half_open_max_requests == 3
        assert config.success_threshold == 2

    def test_rejects_zero_threshold(self):
        with pytest.raises(Exception):
            CircuitBreakerConfig(failure_threshold=0)


# -------------------------------------------------------------------
# Diagnostics
# -------------------------------------------------------------------

class TestDiagnostics:
    def test_status_summary(self):
        cb = _make_cb(failure_threshold=2)
        cb.record_success(AGENT)
        cb.record_failure(AGENT)
        summary = cb.status_summary()
        assert AGENT in summary
        assert summary[AGENT]["state"] == "CLOSED"
        assert summary[AGENT]["total_failures"] == 1
        assert summary[AGENT]["total_successes"] == 1

    def test_get_state_returns_none_for_unknown(self):
        cb = _make_cb()
        assert cb.get_state("agent:unknown") is None


# -------------------------------------------------------------------
# Counters
# -------------------------------------------------------------------

class TestCounters:
    def test_total_counters_accumulate(self):
        cb = _make_cb(failure_threshold=10)
        for _ in range(3):
            cb.record_success(AGENT)
        for _ in range(2):
            cb.record_failure(AGENT)
        state = cb.get_state(AGENT)
        assert state.total_successes == 3
        assert state.total_failures == 2
