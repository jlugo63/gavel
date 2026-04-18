"""Unregistered agent monitoring — new AI tool detection + immediate notification."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class UnregisteredAgentAlert(BaseModel):
    """Alert for a new AI tool detected on a machine that isn't enrolled in Gavel."""
    alert_id: str = Field(default_factory=lambda: f"ura-{uuid.uuid4().hex[:8]}")
    endpoint_id: str
    hostname: str = ""
    tool_name: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    resolved: bool = False


class UnregisteredAgentMonitor:
    """New AI tool installed on a machine -> immediate notification."""

    def __init__(self):
        self._known_tools: dict[str, set[str]] = defaultdict(set)  # endpoint_id -> {tool_names}
        self._alerts: list[UnregisteredAgentAlert] = []

    def set_baseline(self, endpoint_id: str, tools: list[str]) -> None:
        self._known_tools[endpoint_id] = set(tools)

    def scan(self, endpoint_id: str, current_tools: list[str],
             hostname: str = "") -> list[UnregisteredAgentAlert]:
        known = self._known_tools.get(endpoint_id, set())
        new_tools = set(current_tools) - known
        alerts = []
        for tool in new_tools:
            alert = UnregisteredAgentAlert(
                endpoint_id=endpoint_id,
                hostname=hostname,
                tool_name=tool,
            )
            alerts.append(alert)
            self._alerts.append(alert)
        self._known_tools[endpoint_id] = set(current_tools)
        return alerts

    def acknowledge(self, alert_id: str) -> bool:
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    @property
    def unacknowledged(self) -> list[UnregisteredAgentAlert]:
        return [a for a in self._alerts if not a.acknowledged]

    @property
    def all_alerts(self) -> list[UnregisteredAgentAlert]:
        return list(self._alerts)
