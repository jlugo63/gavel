"""
Liveness Monitor — escalation timeouts and auto-deny.

Microsoft's Agent SRE has SLOs and circuit breakers for reliability.
But it doesn't have governance liveness: "if nobody approves within
10 minutes, auto-deny and escalate."

The liveness monitor enforces Constitutional Article IV.2:
"The system degrades toward safety. On any ambiguity, error, or
timeout, the default is DENY."
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable


class EscalationLevel(str, Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"     # 50% of SLA elapsed
    CRITICAL = "CRITICAL"   # 80% of SLA elapsed
    TIMED_OUT = "TIMED_OUT" # SLA breached, auto-deny


@dataclass
class EscalationTimeout:
    """Tracks the SLA deadline for a governance chain."""

    chain_id: str
    sla_seconds: int
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    resolution: str = ""

    @property
    def deadline(self) -> datetime:
        return self.created_at + timedelta(seconds=self.sla_seconds)

    @property
    def elapsed_seconds(self) -> float:
        now = datetime.now(timezone.utc)
        return (now - self.created_at).total_seconds()

    @property
    def remaining_seconds(self) -> float:
        return max(0, self.sla_seconds - self.elapsed_seconds)

    @property
    def elapsed_fraction(self) -> float:
        if self.sla_seconds <= 0:
            return 1.0
        return min(1.0, self.elapsed_seconds / self.sla_seconds)

    @property
    def level(self) -> EscalationLevel:
        frac = self.elapsed_fraction
        if frac >= 1.0:
            return EscalationLevel.TIMED_OUT
        elif frac >= 0.8:
            return EscalationLevel.CRITICAL
        elif frac >= 0.5:
            return EscalationLevel.WARNING
        return EscalationLevel.NORMAL

    @property
    def is_expired(self) -> bool:
        return self.elapsed_fraction >= 1.0


class LivenessMonitor:
    """
    Monitors governance chains for SLA compliance and triggers
    auto-deny on timeout.

    Usage:
        monitor = LivenessMonitor()
        timeout = monitor.track("c-8a3f", sla_seconds=600)

        # Later...
        status = monitor.check("c-8a3f")
        if status.is_expired:
            # Auto-deny the chain
            ...

        # When resolved
        monitor.resolve("c-8a3f", "APPROVED")
    """

    def __init__(self):
        self._timeouts: dict[str, EscalationTimeout] = {}
        self._callbacks: list[Callable[[str, EscalationLevel], Any]] = []

    def track(self, chain_id: str, sla_seconds: int) -> EscalationTimeout:
        """Start tracking an SLA deadline for a chain."""
        timeout = EscalationTimeout(
            chain_id=chain_id,
            sla_seconds=sla_seconds,
        )
        self._timeouts[chain_id] = timeout
        return timeout

    def check(self, chain_id: str) -> EscalationTimeout | None:
        """Check the current status of a chain's SLA."""
        return self._timeouts.get(chain_id)

    def resolve(self, chain_id: str, resolution: str) -> bool:
        """Mark a chain's SLA as resolved."""
        timeout = self._timeouts.get(chain_id)
        if timeout and not timeout.resolved:
            timeout.resolved = True
            timeout.resolution = resolution
            return True
        return False

    def get_expired(self) -> list[EscalationTimeout]:
        """Return all chains that have breached their SLA."""
        return [
            t for t in self._timeouts.values()
            if t.is_expired and not t.resolved
        ]

    def get_at_level(self, level: EscalationLevel) -> list[EscalationTimeout]:
        """Return all chains at a given escalation level."""
        return [
            t for t in self._timeouts.values()
            if t.level == level and not t.resolved
        ]

    def on_escalation(self, callback: Callable[[str, EscalationLevel], Any]):
        """Register a callback for escalation events."""
        self._callbacks.append(callback)

    def tick(self) -> list[tuple[str, EscalationLevel]]:
        """
        Check all active timeouts and return any that have changed level.
        Call this periodically (e.g., every second).
        """
        escalations = []
        for chain_id, timeout in self._timeouts.items():
            if timeout.resolved:
                continue
            level = timeout.level
            if level in (EscalationLevel.WARNING, EscalationLevel.CRITICAL, EscalationLevel.TIMED_OUT):
                escalations.append((chain_id, level))
                for cb in self._callbacks:
                    cb(chain_id, level)
        return escalations

    def status_summary(self) -> dict[str, Any]:
        """Dashboard summary of all tracked chains."""
        active = [t for t in self._timeouts.values() if not t.resolved]
        return {
            "total_tracked": len(self._timeouts),
            "active": len(active),
            "expired": len(self.get_expired()),
            "chains": {
                t.chain_id: {
                    "level": t.level.value,
                    "remaining_seconds": round(t.remaining_seconds, 1),
                    "elapsed_fraction": round(t.elapsed_fraction, 3),
                }
                for t in active
            },
        }
