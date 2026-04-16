"""
Org-wide governance chain — tamper-evident audit trail across all endpoints.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


# ── Org-Wide Governance Chain ────────────────────────────────

class OrgChainEvent(BaseModel):
    """A single event in the org-wide governance chain."""
    event_id: str = Field(default_factory=lambda: f"oce-{uuid.uuid4().hex[:8]}")
    endpoint_id: str
    agent_id: str
    event_type: str               # "enrollment", "decision", "violation", "heartbeat", "policy_update"
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    prev_hash: str = ""
    event_hash: str = ""

    def compute_hash(self) -> str:
        content = f"{self.event_id}|{self.endpoint_id}|{self.agent_id}|{self.event_type}|{self.timestamp.isoformat()}|{self.prev_hash}"
        self.event_hash = hashlib.sha256(content.encode()).hexdigest()
        return self.event_hash


class OrgGovernanceChain:
    """Unified, tamper-evident audit trail across all endpoints."""

    def __init__(self):
        self._events: list[OrgChainEvent] = []
        self._head_hash: str = "genesis"

    def append(self, endpoint_id: str, agent_id: str, event_type: str,
               payload: dict[str, Any] | None = None) -> OrgChainEvent:
        event = OrgChainEvent(
            endpoint_id=endpoint_id,
            agent_id=agent_id,
            event_type=event_type,
            payload=payload or {},
            prev_hash=self._head_hash,
        )
        event.compute_hash()
        self._head_hash = event.event_hash
        self._events.append(event)
        return event

    def verify_integrity(self) -> tuple[bool, str]:
        """Walk the chain and verify hash linkage."""
        prev = "genesis"
        for i, event in enumerate(self._events):
            if event.prev_hash != prev:
                return False, f"Event {i} ({event.event_id}): prev_hash mismatch"
            expected = hashlib.sha256(
                f"{event.event_id}|{event.endpoint_id}|{event.agent_id}|{event.event_type}|{event.timestamp.isoformat()}|{event.prev_hash}".encode()
            ).hexdigest()
            if event.event_hash != expected:
                return False, f"Event {i} ({event.event_id}): hash mismatch"
            prev = event.event_hash
        return True, "ok"

    def events_by_endpoint(self, endpoint_id: str) -> list[OrgChainEvent]:
        return [e for e in self._events if e.endpoint_id == endpoint_id]

    def events_by_agent(self, agent_id: str) -> list[OrgChainEvent]:
        return [e for e in self._events if e.agent_id == agent_id]

    def events_by_type(self, event_type: str) -> list[OrgChainEvent]:
        return [e for e in self._events if e.event_type == event_type]

    @property
    def length(self) -> int:
        return len(self._events)

    @property
    def head_hash(self) -> str:
        return self._head_hash

    def events_in_window(self, start: datetime, end: datetime) -> list[OrgChainEvent]:
        return [e for e in self._events if start <= e.timestamp <= end]
