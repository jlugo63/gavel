"""Governance event stream — real-time feed of all governance events org-wide."""

from __future__ import annotations

import uuid
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class GovernanceEventCategory(str, Enum):
    ENROLLMENT = "enrollment"
    DECISION = "decision"
    VIOLATION = "violation"
    HEARTBEAT = "heartbeat"
    POLICY = "policy"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    FLEET = "fleet"


class GovernanceEvent(BaseModel):
    """A single governance event in the org-wide stream."""
    event_id: str = Field(default_factory=lambda: f"ge-{uuid.uuid4().hex[:8]}")
    category: GovernanceEventCategory
    event_type: str                    # e.g. "agent.enrolled", "chain.denied"
    endpoint_id: str = ""
    agent_id: str = ""
    org_id: str = ""
    team_id: str = ""
    severity: str = "info"             # info, warning, high, critical
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GovernanceEventStream:
    """Real-time feed of all enrollments, decisions, violations org-wide."""

    def __init__(self, max_events: int = 10000):
        self._events: deque[GovernanceEvent] = deque(maxlen=max_events)
        self._subscribers: list[str] = []  # subscriber IDs for push notifications

    def emit(self, category: GovernanceEventCategory, event_type: str,
             endpoint_id: str = "", agent_id: str = "", org_id: str = "",
             team_id: str = "", severity: str = "info", summary: str = "",
             **details) -> GovernanceEvent:
        event = GovernanceEvent(
            category=category,
            event_type=event_type,
            endpoint_id=endpoint_id,
            agent_id=agent_id,
            org_id=org_id,
            team_id=team_id,
            severity=severity,
            summary=summary,
            details=details,
        )
        self._events.append(event)
        return event

    def recent(self, count: int = 100) -> list[GovernanceEvent]:
        items = list(self._events)
        return items[-count:]

    def by_category(self, category: GovernanceEventCategory) -> list[GovernanceEvent]:
        return [e for e in self._events if e.category == category]

    def by_endpoint(self, endpoint_id: str) -> list[GovernanceEvent]:
        return [e for e in self._events if e.endpoint_id == endpoint_id]

    def by_agent(self, agent_id: str) -> list[GovernanceEvent]:
        return [e for e in self._events if e.agent_id == agent_id]

    def by_severity(self, severity: str) -> list[GovernanceEvent]:
        return [e for e in self._events if e.severity == severity]

    def in_window(self, start: datetime, end: datetime) -> list[GovernanceEvent]:
        return [e for e in self._events if start <= e.timestamp <= end]

    def subscribe(self, subscriber_id: str) -> None:
        if subscriber_id not in self._subscribers:
            self._subscribers.append(subscriber_id)

    def unsubscribe(self, subscriber_id: str) -> None:
        if subscriber_id in self._subscribers:
            self._subscribers.remove(subscriber_id)

    @property
    def total(self) -> int:
        return len(self._events)

    @property
    def subscribers(self) -> list[str]:
        return list(self._subscribers)
