"""
Gavel Hub — Central governance server for network-wide agent management.

Like CrowdStrike Falcon or FortiClient EMS, but for AI agent governance.
The Hub is the single pane of glass for an entire organization's AI agent
fleet. Every endpoint agent reports here; every policy is distributed from
here; every governance event is correlated here.

This module provides:

  1. EndpointRecord — registered machine with status, OS, capabilities
  2. HubEnrollmentRegistry — centralized view of all agents across all machines
  3. OrgGovernanceChain — unified, tamper-evident audit trail across endpoints
  4. PolicyDistribution — push constitution updates to all endpoints
  5. CrossMachineCorrelator — detect agents coordinating across machines
  6. AlertConsole — real-time alert management for violations and anomalies
  7. GavelHub — orchestrator tying all subsystems together
"""

from gavel.hub.registry import (
    EndpointOS,
    EndpointRecord,
    EndpointStatus,
    FleetAgentRecord,
    HubEnrollmentRegistry,
)
from gavel.hub.governance import (
    OrgChainEvent,
    OrgGovernanceChain,
)
from gavel.hub.policy import (
    PolicyDistributionRecord,
    PolicyDistributor,
    PolicyVersion,
)
from gavel.hub.correlation import (
    CorrelationFinding,
    CorrelationSignal,
    CrossMachineCorrelator,
)
from gavel.hub.alerts import (
    AlertCategory,
    AlertConsole,
    AlertSeverity,
    AlertStatus,
    FleetDashboard,
    GavelAlert,
)
from gavel.hub.hub import GavelHub

__all__ = [
    # Registry
    "EndpointOS",
    "EndpointRecord",
    "EndpointStatus",
    "FleetAgentRecord",
    "HubEnrollmentRegistry",
    # Governance chain
    "OrgChainEvent",
    "OrgGovernanceChain",
    # Policy distribution
    "PolicyDistributionRecord",
    "PolicyDistributor",
    "PolicyVersion",
    # Correlation
    "CorrelationFinding",
    "CorrelationSignal",
    "CrossMachineCorrelator",
    # Alerts
    "AlertCategory",
    "AlertConsole",
    "AlertSeverity",
    "AlertStatus",
    "FleetDashboard",
    "GavelAlert",
    # Orchestrator
    "GavelHub",
]
