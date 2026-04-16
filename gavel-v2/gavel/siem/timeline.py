"""Incident timeline — reconstruct what happened across multiple machines."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from gavel.siem.events import GovernanceEvent


class TimelineEntry(BaseModel):
    """A single entry in a cross-machine incident timeline."""
    entry_id: str = Field(default_factory=lambda: f"tle-{uuid.uuid4().hex[:8]}")
    timestamp: datetime
    endpoint_id: str = ""
    agent_id: str = ""
    event_type: str = ""
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"


class IncidentTimeline(BaseModel):
    """Reconstructed timeline of what happened across multiple machines."""
    timeline_id: str = Field(default_factory=lambda: f"tl-{uuid.uuid4().hex[:8]}")
    title: str = ""
    entries: list[TimelineEntry] = Field(default_factory=list)
    endpoints_involved: list[str] = Field(default_factory=list)
    agents_involved: list[str] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TimelineReconstructor:
    """Reconstruct exactly what happened across multiple machines."""

    def __init__(self):
        self._timelines: list[IncidentTimeline] = []

    def reconstruct(self, events: list[GovernanceEvent],
                    title: str = "") -> IncidentTimeline:
        """Build a timeline from governance events, sorted chronologically."""
        entries = []
        endpoints = set()
        agents = set()

        for event in sorted(events, key=lambda e: e.timestamp):
            entry = TimelineEntry(
                timestamp=event.timestamp,
                endpoint_id=event.endpoint_id,
                agent_id=event.agent_id,
                event_type=event.event_type,
                summary=event.summary,
                details=event.details,
                severity=event.severity,
            )
            entries.append(entry)
            if event.endpoint_id:
                endpoints.add(event.endpoint_id)
            if event.agent_id:
                agents.add(event.agent_id)

        timeline = IncidentTimeline(
            title=title,
            entries=entries,
            endpoints_involved=sorted(endpoints),
            agents_involved=sorted(agents),
            start_time=entries[0].timestamp if entries else None,
            end_time=entries[-1].timestamp if entries else None,
        )
        self._timelines.append(timeline)
        return timeline

    def get(self, timeline_id: str) -> Optional[IncidentTimeline]:
        for tl in self._timelines:
            if tl.timeline_id == timeline_id:
                return tl
        return None

    @property
    def all_timelines(self) -> list[IncidentTimeline]:
        return list(self._timelines)
