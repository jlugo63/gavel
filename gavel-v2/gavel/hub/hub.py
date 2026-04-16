"""
GavelHub — Central governance server orchestrator.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from gavel.hub.registry import (
    EndpointOS,
    EndpointRecord,
    EndpointStatus,
    FleetAgentRecord,
    HubEnrollmentRegistry,
)
from gavel.hub.governance import OrgGovernanceChain
from gavel.hub.policy import PolicyDistributor, PolicyVersion
from gavel.hub.correlation import CrossMachineCorrelator
from gavel.hub.alerts import (
    AlertCategory,
    AlertConsole,
    AlertSeverity,
    FleetDashboard,
)


# ── Gavel Hub Orchestrator ───────────────────────────────────

class GavelHub:
    """Central governance server — orchestrates all Hub subsystems."""

    def __init__(self):
        self.endpoints: dict[str, EndpointRecord] = {}
        self.enrollment = HubEnrollmentRegistry()
        self.chain = OrgGovernanceChain()
        self.policy = PolicyDistributor()
        self.correlator = CrossMachineCorrelator()
        self.alerts = AlertConsole()

    # ── Endpoint management ──────────────────────────────────

    def register_endpoint(self, hostname: str, os: EndpointOS,
                          os_version: str = "", ip_address: str = "",
                          org_id: str = "", team_id: str = "",
                          agent_version: str = "", agent_hash: str = "",
                          **metadata) -> EndpointRecord:
        ep = EndpointRecord(
            hostname=hostname,
            os=os,
            os_version=os_version,
            ip_address=ip_address,
            org_id=org_id,
            team_id=team_id,
            agent_version=agent_version,
            agent_hash=agent_hash,
            metadata=metadata,
        )
        self.endpoints[ep.endpoint_id] = ep
        self.chain.append(ep.endpoint_id, "", "endpoint_enrolled",
                          {"hostname": hostname, "os": os.value})
        return ep

    def heartbeat(self, endpoint_id: str, active_agent_ids: list[str] | None = None,
                  installed_ai_tools: list[str] | None = None,
                  agent_hash: str = "") -> bool:
        ep = self.endpoints.get(endpoint_id)
        if not ep:
            return False
        ep.last_heartbeat = datetime.now(timezone.utc)
        ep.status = EndpointStatus.ONLINE
        if active_agent_ids is not None:
            # Check for new unregistered agents
            for aid in active_agent_ids:
                if not self.enrollment.get(aid):
                    self.alerts.create_alert(
                        category=AlertCategory.UNREGISTERED_AGENT,
                        severity=AlertSeverity.HIGH,
                        title=f"Unregistered agent detected: {aid}",
                        description=f"Agent {aid} found running on {ep.hostname} ({endpoint_id}) but not enrolled in Gavel",
                        endpoint_id=endpoint_id,
                        agent_id=aid,
                    )
            ep.active_agent_ids = active_agent_ids
        if installed_ai_tools is not None:
            # Detect newly installed AI tools
            new_tools = set(installed_ai_tools) - set(ep.installed_ai_tools)
            if new_tools:
                self.alerts.create_alert(
                    category=AlertCategory.UNREGISTERED_AGENT,
                    severity=AlertSeverity.WARNING,
                    title=f"New AI tool(s) installed on {ep.hostname}",
                    description=f"Detected: {', '.join(new_tools)}",
                    endpoint_id=endpoint_id,
                )
            ep.installed_ai_tools = installed_ai_tools
        if agent_hash and ep.agent_hash and agent_hash != ep.agent_hash:
            self.alerts.create_alert(
                category=AlertCategory.TAMPER_DETECTED,
                severity=AlertSeverity.CRITICAL,
                title=f"Endpoint agent tamper detected on {ep.hostname}",
                description=f"Agent hash changed from {ep.agent_hash[:16]}... to {agent_hash[:16]}...",
                endpoint_id=endpoint_id,
            )
        if agent_hash:
            ep.agent_hash = agent_hash
        return True

    def check_stale_endpoints(self, timeout_minutes: int = 5) -> list[str]:
        """Mark endpoints as offline if heartbeat is stale. Returns affected endpoint_ids."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)
        stale = []
        for ep in self.endpoints.values():
            if ep.status == EndpointStatus.ONLINE and ep.last_heartbeat < cutoff:
                ep.status = EndpointStatus.OFFLINE
                stale.append(ep.endpoint_id)
                self.alerts.create_alert(
                    category=AlertCategory.HEARTBEAT_MISSED,
                    severity=AlertSeverity.WARNING,
                    title=f"Endpoint offline: {ep.hostname}",
                    description=f"No heartbeat since {ep.last_heartbeat.isoformat()}",
                    endpoint_id=ep.endpoint_id,
                )
        return stale

    def decommission_endpoint(self, endpoint_id: str) -> bool:
        ep = self.endpoints.get(endpoint_id)
        if not ep:
            return False
        ep.status = EndpointStatus.DECOMMISSIONED
        # Revoke all agents on this endpoint
        for aid in ep.active_agent_ids:
            self.enrollment.revoke_agent(aid)
        self.chain.append(endpoint_id, "", "endpoint_decommissioned", {})
        return True

    # ── Agent management (fleet-wide) ────────────────────────

    def register_agent(self, agent_id: str, endpoint_id: str,
                       display_name: str = "", owner: str = "",
                       org_id: str = "", team_id: str = "") -> Optional[FleetAgentRecord]:
        if endpoint_id not in self.endpoints:
            return None
        record = self.enrollment.register(
            agent_id, endpoint_id, display_name, owner, org_id, team_id
        )
        self.chain.append(endpoint_id, agent_id, "agent_enrolled",
                          {"display_name": display_name, "owner": owner})
        return record

    def kill_agent_fleet_wide(self, agent_id: str) -> list[str]:
        """Revoke a specific agent's token across all machines from the Hub."""
        affected = self.enrollment.revoke_agent_fleet_wide(agent_id)
        for eid in affected:
            self.chain.append(eid, agent_id, "agent_killed_fleet_wide", {})
        if affected:
            self.alerts.create_alert(
                category=AlertCategory.VIOLATION,
                severity=AlertSeverity.HIGH,
                title=f"Agent {agent_id} killed fleet-wide",
                description=f"Revoked across {len(affected)} endpoint(s)",
                agent_id=agent_id,
            )
        return affected

    # ── Dashboard ────────────────────────────────────────────

    def dashboard(self) -> FleetDashboard:
        agents = self.enrollment.all_agents()
        return FleetDashboard(
            total_endpoints=len(self.endpoints),
            online_endpoints=len([e for e in self.endpoints.values() if e.status == EndpointStatus.ONLINE]),
            offline_endpoints=len([e for e in self.endpoints.values() if e.status == EndpointStatus.OFFLINE]),
            degraded_endpoints=len([e for e in self.endpoints.values() if e.status == EndpointStatus.DEGRADED]),
            total_agents=len(agents),
            active_agents=len([a for a in agents if a.status == "active"]),
            suspended_agents=len([a for a in agents if a.status == "suspended"]),
            revoked_agents=len([a for a in agents if a.status == "revoked"]),
            open_alerts=len(self.alerts.open_alerts()),
            critical_alerts=self.alerts.critical_count(),
            chain_length=self.chain.length,
            policy_versions=len(self.policy._versions),
            correlation_findings=len(self.correlator.all_findings),
        )

    # ── Policy push ──────────────────────────────────────────

    def push_policy(self, policy_name: str, content: dict[str, Any],
                    created_by: str = "", target_scope: str = "all") -> PolicyVersion:
        pv = self.policy.publish(policy_name, content, created_by, target_scope)
        # Distribute to all matching endpoints
        if target_scope == "all":
            target_endpoints = list(self.endpoints.keys())
        else:
            target_endpoints = [
                eid for eid, ep in self.endpoints.items()
                if ep.org_id == target_scope or ep.team_id == target_scope or eid == target_scope
            ]
        self.policy.distribute(pv.version_id, target_endpoints)
        self.chain.append("hub", "", "policy_distributed",
                          {"policy_name": policy_name, "version": pv.version_number,
                           "targets": len(target_endpoints)})
        return pv
