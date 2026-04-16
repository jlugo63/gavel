"""SIEM forwarding — forward governance events to Splunk, Sentinel, Elastic."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from gavel.siem.events import GovernanceEvent


class SIEMFormat(str, Enum):
    CEF = "cef"                  # Common Event Format (ArcSight, QRadar)
    JSON = "json"                # JSON (Splunk HEC, Elastic)
    SYSLOG = "syslog"            # RFC 5424 Syslog (generic)


class SIEMDestination(BaseModel):
    """A configured SIEM destination for event forwarding."""
    destination_id: str = Field(default_factory=lambda: f"siem-{uuid.uuid4().hex[:8]}")
    name: str
    format: SIEMFormat
    endpoint_url: str = ""           # e.g. https://splunk.corp:8088/services/collector
    api_key: str = ""                # Redacted in output
    enabled: bool = True
    event_filter: list[str] = Field(default_factory=list)  # Empty = all events
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SIEMForwarder:
    """Forward governance events to Splunk, Sentinel, Elastic."""

    SEVERITY_MAP = {"info": 1, "warning": 5, "high": 8, "critical": 10}

    def __init__(self):
        self._destinations: dict[str, SIEMDestination] = {}
        self._forwarded: list[dict[str, Any]] = []  # Log of forwarded events

    def add_destination(self, name: str, format: SIEMFormat,
                        endpoint_url: str = "", api_key: str = "",
                        event_filter: list[str] | None = None) -> SIEMDestination:
        dest = SIEMDestination(
            name=name,
            format=format,
            endpoint_url=endpoint_url,
            api_key=api_key,
            event_filter=event_filter or [],
        )
        self._destinations[dest.destination_id] = dest
        return dest

    def remove_destination(self, destination_id: str) -> bool:
        return self._destinations.pop(destination_id, None) is not None

    def format_cef(self, event: GovernanceEvent) -> str:
        """Format as CEF (Common Event Format)."""
        severity = self.SEVERITY_MAP.get(event.severity, 1)
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        extensions = f"src={event.endpoint_id} duser={event.agent_id} msg={event.summary}"
        return f"CEF:0|Gavel|GovernanceHub|1.0|{event.event_type}|{event.summary or event.event_type}|{severity}|{extensions}"

    def format_json(self, event: GovernanceEvent) -> dict[str, Any]:
        """Format as JSON for Splunk HEC / Elastic."""
        return {
            "timestamp": event.timestamp.isoformat(),
            "source": "gavel-hub",
            "sourcetype": "gavel:governance",
            "event": {
                "event_id": event.event_id,
                "category": event.category.value,
                "event_type": event.event_type,
                "endpoint_id": event.endpoint_id,
                "agent_id": event.agent_id,
                "org_id": event.org_id,
                "severity": event.severity,
                "summary": event.summary,
                "details": event.details,
            },
        }

    def format_syslog(self, event: GovernanceEvent) -> str:
        """Format as RFC 5424 syslog."""
        pri = 14 if event.severity == "info" else (12 if event.severity == "warning" else 10)
        ts = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return f"<{pri}>1 {ts} gavel-hub gavel - {event.event_id} - {event.event_type}: {event.summary}"

    def forward(self, event: GovernanceEvent) -> list[dict[str, Any]]:
        """Forward an event to all matching destinations. Returns formatted payloads."""
        results = []
        for dest in self._destinations.values():
            if not dest.enabled:
                continue
            if dest.event_filter and event.event_type not in dest.event_filter:
                continue

            if dest.format == SIEMFormat.CEF:
                payload = {"destination_id": dest.destination_id, "format": "cef",
                           "data": self.format_cef(event)}
            elif dest.format == SIEMFormat.JSON:
                payload = {"destination_id": dest.destination_id, "format": "json",
                           "data": self.format_json(event)}
            else:
                payload = {"destination_id": dest.destination_id, "format": "syslog",
                           "data": self.format_syslog(event)}

            results.append(payload)
            self._forwarded.append(payload)
        return results

    def forward_batch(self, events: list[GovernanceEvent]) -> int:
        """Forward multiple events. Returns count of forwarded payloads."""
        count = 0
        for event in events:
            count += len(self.forward(event))
        return count

    @property
    def destinations(self) -> list[SIEMDestination]:
        return list(self._destinations.values())

    @property
    def forwarded_count(self) -> int:
        return len(self._forwarded)

    @property
    def forwarded_log(self) -> list[dict[str, Any]]:
        return list(self._forwarded)
