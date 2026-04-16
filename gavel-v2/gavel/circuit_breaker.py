"""
Circuit Breaker — per-agent failure isolation (ATF R-1).

Implements the classic circuit breaker pattern to prevent cascading
failures in governance decisions.  When an agent accumulates too many
consecutive failures, its circuit *trips* to OPEN and all subsequent
requests are immediately denied.  After a cooldown period the circuit
moves to HALF_OPEN, allowing a limited number of probe requests.  If
enough probes succeed the circuit closes; otherwise it re-opens.

Integration with liveness.py: the LivenessMonitor handles SLA deadlines
and escalation timeouts.  The circuit breaker sits *below* that layer,
protecting the system from agents that are consistently failing rather
than merely slow.

Constitutional Article IV.2 — "The system degrades toward safety."
An open circuit breaker is a safety-default: DENY.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CircuitState(str, Enum):
    """Possible states of a circuit breaker."""

    CLOSED = "CLOSED"        # Normal operation — requests flow through
    OPEN = "OPEN"            # Tripped — requests immediately denied
    HALF_OPEN = "HALF_OPEN"  # Recovery probe — limited requests allowed


class CircuitBreakerConfig(BaseModel):
    """Tuning knobs for a single agent's circuit breaker."""

    failure_threshold: int = Field(
        default=5,
        ge=1,
        description="Consecutive failures required to trip the breaker.",
    )
    recovery_timeout_seconds: int = Field(
        default=60,
        ge=1,
        description="Seconds to remain OPEN before transitioning to HALF_OPEN.",
    )
    half_open_max_requests: int = Field(
        default=3,
        ge=1,
        description="Maximum probe requests allowed while HALF_OPEN.",
    )
    success_threshold: int = Field(
        default=2,
        ge=1,
        description="Consecutive successes in HALF_OPEN required to close.",
    )


class CircuitBreakerState(BaseModel):
    """Runtime state of an individual circuit breaker."""

    agent_id: str
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    half_open_requests: int = 0
    last_failure_at: Optional[datetime] = None
    last_state_change: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    total_failures: int = 0
    total_successes: int = 0
    trip_count: int = 0

    def _set_state(self, new_state: CircuitState) -> None:
        self.state = new_state
        self.last_state_change = datetime.now(timezone.utc)


class CircuitBreaker:
    """
    Per-agent circuit breaker registry.

    Usage::

        cb = CircuitBreaker()

        # Check before processing a request
        if not cb.allow_request("agent:foo"):
            # Immediately deny — circuit is open
            ...

        # After processing, record the outcome
        cb.record_success("agent:foo")
        # or
        cb.record_failure("agent:foo")

        # Inspect
        info = cb.get_state("agent:foo")
    """

    def __init__(self, default_config: CircuitBreakerConfig | None = None):
        self._default_config = default_config or CircuitBreakerConfig()
        self._configs: dict[str, CircuitBreakerConfig] = {}
        self._states: dict[str, CircuitBreakerState] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(self, agent_id: str, config: CircuitBreakerConfig) -> None:
        """Set a custom config for *agent_id*."""
        self._configs[agent_id] = config

    def get_config(self, agent_id: str) -> CircuitBreakerConfig:
        """Return the effective config for *agent_id*."""
        return self._configs.get(agent_id, self._default_config)

    # ------------------------------------------------------------------
    # State access
    # ------------------------------------------------------------------

    def _ensure_state(self, agent_id: str) -> CircuitBreakerState:
        if agent_id not in self._states:
            self._states[agent_id] = CircuitBreakerState(agent_id=agent_id)
        return self._states[agent_id]

    def get_state(self, agent_id: str) -> CircuitBreakerState | None:
        """Return the current breaker state, or ``None`` if never seen."""
        return self._states.get(agent_id)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def allow_request(self, agent_id: str) -> bool:
        """Return ``True`` if the agent is allowed to proceed.

        Side-effects:
        * If the breaker is OPEN and the recovery timeout has elapsed,
          it transitions to HALF_OPEN.
        * If the breaker is HALF_OPEN and the probe budget is exhausted,
          returns ``False``.
        """
        state = self._ensure_state(agent_id)
        config = self.get_config(agent_id)

        if state.state == CircuitState.CLOSED:
            return True

        if state.state == CircuitState.OPEN:
            elapsed = (
                datetime.now(timezone.utc) - state.last_state_change
            ).total_seconds()
            if elapsed >= config.recovery_timeout_seconds:
                # Transition to HALF_OPEN
                state._set_state(CircuitState.HALF_OPEN)
                state.half_open_requests = 1  # This request counts
                state.consecutive_successes = 0
                return True
            return False

        # HALF_OPEN
        if state.half_open_requests >= config.half_open_max_requests:
            return False
        state.half_open_requests += 1
        return True

    def record_success(self, agent_id: str) -> CircuitState:
        """Record a successful governance decision and return the new state."""
        state = self._ensure_state(agent_id)
        config = self.get_config(agent_id)

        state.total_successes += 1
        state.consecutive_failures = 0
        state.consecutive_successes += 1

        if state.state == CircuitState.HALF_OPEN:
            if state.consecutive_successes >= config.success_threshold:
                state._set_state(CircuitState.CLOSED)
                state.consecutive_successes = 0

        return state.state

    def record_failure(self, agent_id: str) -> CircuitState:
        """Record a failed governance decision and return the new state."""
        state = self._ensure_state(agent_id)
        config = self.get_config(agent_id)

        state.total_failures += 1
        state.consecutive_failures += 1
        state.consecutive_successes = 0
        state.last_failure_at = datetime.now(timezone.utc)

        if state.state == CircuitState.HALF_OPEN:
            # Any failure while probing re-opens the circuit
            state._set_state(CircuitState.OPEN)
            state.trip_count += 1
            state.consecutive_failures = 0
            return state.state

        if state.state == CircuitState.CLOSED:
            if state.consecutive_failures >= config.failure_threshold:
                state._set_state(CircuitState.OPEN)
                state.trip_count += 1
                state.consecutive_failures = 0

        return state.state

    def reset(self, agent_id: str) -> None:
        """Manually reset a breaker to CLOSED (e.g., after admin intervention)."""
        state = self._ensure_state(agent_id)
        state._set_state(CircuitState.CLOSED)
        state.consecutive_failures = 0
        state.consecutive_successes = 0
        state.half_open_requests = 0

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def status_summary(self) -> dict[str, dict]:
        """Dashboard-friendly snapshot of all tracked breakers."""
        return {
            agent_id: {
                "state": s.state.value,
                "consecutive_failures": s.consecutive_failures,
                "total_failures": s.total_failures,
                "total_successes": s.total_successes,
                "trip_count": s.trip_count,
                "last_failure_at": (
                    s.last_failure_at.isoformat() if s.last_failure_at else None
                ),
            }
            for agent_id, s in self._states.items()
        }
