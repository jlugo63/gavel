"""
Alert console and fleet dashboard for the Gavel Hub.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Alert Console ────────────────────────────────────────────

class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class AlertCategory(str, Enum):
    VIOLATION = "violation"
    UNREGISTERED_AGENT = "unregistered_agent"
    HEARTBEAT_MISSED = "heartbeat_missed"
    TAMPER_DETECTED = "tamper_detected"
    POLICY_DRIFT = "policy_drift"
    CORRELATION = "correlation"
    ANOMALY = "anomaly"
    COMPLIANCE = "compliance"


class GavelAlert(BaseModel):
    """A governance alert surfaced to operators."""
    alert_id: str = Field(default_factory=lambda: f"alert-{uuid.uuid4().hex[:8]}")
    category: AlertCategory
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.OPEN
    title: str
    description: str = ""
    endpoint_id: str = ""
    agent_id: str = ""
    source_event_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolved_by: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertConsole:
    """Real-time alert management for the Gavel Hub."""

    def __init__(self):
        self._alerts: dict[str, GavelAlert] = {}

    def create_alert(self, category: AlertCategory, severity: AlertSeverity,
                     title: str, description: str = "", endpoint_id: str = "",
                     agent_id: str = "", source_event_id: str = "",
                     **metadata) -> GavelAlert:
        alert = GavelAlert(
            category=category,
            severity=severity,
            title=title,
            description=description,
            endpoint_id=endpoint_id,
            agent_id=agent_id,
            source_event_id=source_event_id,
            metadata=metadata,
        )
        self._alerts[alert.alert_id] = alert
        return alert

    def acknowledge(self, alert_id: str) -> bool:
        alert = self._alerts.get(alert_id)
        if not alert or alert.status != AlertStatus.OPEN:
            return False
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = datetime.now(timezone.utc)
        return True

    def resolve(self, alert_id: str, resolved_by: str = "") -> bool:
        alert = self._alerts.get(alert_id)
        if not alert or alert.status in (AlertStatus.RESOLVED, AlertStatus.DISMISSED):
            return False
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolved_by = resolved_by
        return True

    def dismiss(self, alert_id: str) -> bool:
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.status = AlertStatus.DISMISSED
        return True

    def get(self, alert_id: str) -> Optional[GavelAlert]:
        return self._alerts.get(alert_id)

    def open_alerts(self) -> list[GavelAlert]:
        return [a for a in self._alerts.values() if a.status == AlertStatus.OPEN]

    def alerts_by_severity(self, severity: AlertSeverity) -> list[GavelAlert]:
        return [a for a in self._alerts.values() if a.severity == severity]

    def alerts_by_category(self, category: AlertCategory) -> list[GavelAlert]:
        return [a for a in self._alerts.values() if a.category == category]

    def alerts_by_endpoint(self, endpoint_id: str) -> list[GavelAlert]:
        return [a for a in self._alerts.values() if a.endpoint_id == endpoint_id]

    def critical_count(self) -> int:
        return len([a for a in self._alerts.values()
                    if a.severity == AlertSeverity.CRITICAL and a.status == AlertStatus.OPEN])

    @property
    def total(self) -> int:
        return len(self._alerts)


# ── Fleet Dashboard Data ─────────────────────────────────────

class FleetDashboard(BaseModel):
    """Snapshot of fleet-wide status for the dashboard."""
    total_endpoints: int = 0
    online_endpoints: int = 0
    offline_endpoints: int = 0
    degraded_endpoints: int = 0
    total_agents: int = 0
    active_agents: int = 0
    suspended_agents: int = 0
    revoked_agents: int = 0
    open_alerts: int = 0
    critical_alerts: int = 0
    chain_length: int = 0
    policy_versions: int = 0
    correlation_findings: int = 0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
