"""
SIEM Integration & EDR-Style Monitoring — governance event stream, anomaly
detection, compliance scoring, incident timeline, and SIEM forwarding.

This module provides the monitoring and alerting layer for network-wide
agent governance:

  1. GovernanceEventStream — real-time feed of all governance events org-wide
  2. AnomalyDetector — unusual agent behavior patterns across the fleet
  3. ComplianceScorer — per-machine and org-wide ATF/EU AI Act compliance %
  4. IncidentTimeline — reconstruct what happened across multiple machines
  5. SIEMForwarder — forward governance events to Splunk, Sentinel, Elastic
  6. UnregisteredAgentMonitor — new AI tool detection + immediate notification

Design:
  - Deterministic anomaly scoring (z-score-like but without numpy)
  - SIEM output in CEF (Common Event Format) and JSON/Syslog
  - All state is in-memory + serializable via Pydantic
"""

from __future__ import annotations

from gavel.siem.events import (
    GovernanceEventCategory,
    GovernanceEvent,
    GovernanceEventStream,
)
from gavel.siem.anomaly import (
    AnomalyType,
    AnomalyFinding,
    AnomalyDetector,
)
from gavel.siem.monitor import (
    UnregisteredAgentAlert,
    UnregisteredAgentMonitor,
)
from gavel.siem.scoring import (
    ComplianceFramework,
    ComplianceCheckResult,
    MachineComplianceScore,
    OrgComplianceScore,
    ComplianceScorer,
)
from gavel.siem.timeline import (
    TimelineEntry,
    IncidentTimeline,
    TimelineReconstructor,
)
from gavel.siem.forwarder import (
    SIEMFormat,
    SIEMDestination,
    SIEMForwarder,
)

__all__ = [
    # Events
    "GovernanceEventCategory",
    "GovernanceEvent",
    "GovernanceEventStream",
    # Anomaly detection
    "AnomalyType",
    "AnomalyFinding",
    "AnomalyDetector",
    # Unregistered agent monitoring
    "UnregisteredAgentAlert",
    "UnregisteredAgentMonitor",
    # Compliance scoring
    "ComplianceFramework",
    "ComplianceCheckResult",
    "MachineComplianceScore",
    "OrgComplianceScore",
    "ComplianceScorer",
    # Incident timeline
    "TimelineEntry",
    "IncidentTimeline",
    "TimelineReconstructor",
    # SIEM forwarding
    "SIEMFormat",
    "SIEMDestination",
    "SIEMForwarder",
]
