"""
Fleet Management — machine inventory, group policies, deployment, auto-update.

This module manages the operational fleet of endpoints running Gavel agents:

  1. MachineInventory — OS, installed AI tools, active agents, compliance per endpoint
  2. GroupPolicy — apply different constitutions per team/department/machine group
  3. RemoteAgentKill — revoke a specific agent's token across all machines
  4. DeploymentPackage — MSI/DEB/RPM installer metadata, Docker image refs
  5. AutoUpdater — endpoint agents self-update from Hub (signed packages)
  6. LiveAgentMap — which agents are running on which machines right now
  7. FleetManager — orchestrator for fleet operations
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from gavel.compliance import ComplianceStatus


# ── Machine Inventory ────────────────────────────────────────


class MachineInventoryRecord(BaseModel):
    """Full inventory of a single endpoint machine."""
    endpoint_id: str
    hostname: str
    os: str
    os_version: str = ""
    ip_address: str = ""
    org_id: str = ""
    team_id: str = ""
    installed_ai_tools: list[str] = Field(default_factory=list)
    active_agents: list[str] = Field(default_factory=list)
    agent_version: str = ""
    compliance_status: ComplianceStatus = ComplianceStatus.UNKNOWN
    compliance_score: float = 0.0
    last_scan: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class MachineInventory:
    """Inventory of all machines in the fleet."""

    def __init__(self):
        self._machines: dict[str, MachineInventoryRecord] = {}

    def upsert(self, endpoint_id: str, hostname: str, os: str, os_version: str = "",
               ip_address: str = "", org_id: str = "", team_id: str = "",
               installed_ai_tools: list[str] | None = None,
               active_agents: list[str] | None = None,
               agent_version: str = "", compliance_score: float = 0.0) -> MachineInventoryRecord:
        compliance_status = ComplianceStatus.UNKNOWN
        if compliance_score >= 0.9:
            compliance_status = ComplianceStatus.COMPLIANT
        elif compliance_score >= 0.5:
            compliance_status = ComplianceStatus.PARTIAL
        elif compliance_score > 0.0:
            compliance_status = ComplianceStatus.NON_COMPLIANT

        record = MachineInventoryRecord(
            endpoint_id=endpoint_id,
            hostname=hostname,
            os=os,
            os_version=os_version,
            ip_address=ip_address,
            org_id=org_id,
            team_id=team_id,
            installed_ai_tools=installed_ai_tools or [],
            active_agents=active_agents or [],
            agent_version=agent_version,
            compliance_status=compliance_status,
            compliance_score=compliance_score,
        )
        self._machines[endpoint_id] = record
        return record

    def get(self, endpoint_id: str) -> Optional[MachineInventoryRecord]:
        return self._machines.get(endpoint_id)

    def all_machines(self) -> list[MachineInventoryRecord]:
        return list(self._machines.values())

    def by_org(self, org_id: str) -> list[MachineInventoryRecord]:
        return [m for m in self._machines.values() if m.org_id == org_id]

    def by_team(self, team_id: str) -> list[MachineInventoryRecord]:
        return [m for m in self._machines.values() if m.team_id == team_id]

    def by_compliance(self, status: ComplianceStatus) -> list[MachineInventoryRecord]:
        return [m for m in self._machines.values() if m.compliance_status == status]

    def non_compliant(self) -> list[MachineInventoryRecord]:
        return [m for m in self._machines.values()
                if m.compliance_status == ComplianceStatus.NON_COMPLIANT]

    @property
    def total(self) -> int:
        return len(self._machines)

    def org_compliance_score(self, org_id: str) -> float:
        machines = self.by_org(org_id)
        if not machines:
            return 0.0
        return sum(m.compliance_score for m in machines) / len(machines)

    def fleet_compliance_score(self) -> float:
        if not self._machines:
            return 0.0
        return sum(m.compliance_score for m in self._machines.values()) / len(self._machines)

    def remove(self, endpoint_id: str) -> bool:
        return self._machines.pop(endpoint_id, None) is not None


# ── Group Policies ───────────────────────────────────────────

class PolicyScope(str, Enum):
    GLOBAL = "global"
    ORG = "org"
    TEAM = "team"
    MACHINE_GROUP = "machine_group"
    ENDPOINT = "endpoint"


class GroupPolicy(BaseModel):
    """A constitution/policy applied to a group of endpoints."""
    policy_id: str = Field(default_factory=lambda: f"gp-{uuid.uuid4().hex[:8]}")
    name: str
    scope: PolicyScope
    scope_id: str = ""
    constitution: dict[str, Any] = Field(default_factory=dict)
    priority: int = 0
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    description: str = ""


class MachineGroup(BaseModel):
    """A custom grouping of machines for policy assignment."""
    group_id: str = Field(default_factory=lambda: f"mg-{uuid.uuid4().hex[:8]}")
    name: str
    description: str = ""
    endpoint_ids: list[str] = Field(default_factory=list)
    org_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GroupPolicyManager:
    """Apply different constitutions per team/department/machine group."""

    def __init__(self):
        self._policies: dict[str, GroupPolicy] = {}
        self._groups: dict[str, MachineGroup] = {}

    def create_policy(self, name: str, scope: PolicyScope, scope_id: str = "",
                      constitution: dict[str, Any] | None = None,
                      priority: int = 0, created_by: str = "",
                      description: str = "") -> GroupPolicy:
        policy = GroupPolicy(
            name=name,
            scope=scope,
            scope_id=scope_id,
            constitution=constitution or {},
            priority=priority,
            created_by=created_by,
            description=description,
        )
        self._policies[policy.policy_id] = policy
        return policy

    def update_policy(self, policy_id: str, constitution: dict[str, Any] | None = None,
                      enabled: bool | None = None) -> Optional[GroupPolicy]:
        policy = self._policies.get(policy_id)
        if not policy:
            return None
        if constitution is not None:
            policy.constitution = constitution
        if enabled is not None:
            policy.enabled = enabled
        policy.updated_at = datetime.now(timezone.utc)
        return policy

    def get_policy(self, policy_id: str) -> Optional[GroupPolicy]:
        return self._policies.get(policy_id)

    def delete_policy(self, policy_id: str) -> bool:
        return self._policies.pop(policy_id, None) is not None

    def create_group(self, name: str, endpoint_ids: list[str] | None = None,
                     org_id: str = "", description: str = "") -> MachineGroup:
        group = MachineGroup(
            name=name,
            endpoint_ids=endpoint_ids or [],
            org_id=org_id,
            description=description,
        )
        self._groups[group.group_id] = group
        return group

    def add_to_group(self, group_id: str, endpoint_id: str) -> bool:
        group = self._groups.get(group_id)
        if not group:
            return False
        if endpoint_id not in group.endpoint_ids:
            group.endpoint_ids.append(endpoint_id)
        return True

    def remove_from_group(self, group_id: str, endpoint_id: str) -> bool:
        group = self._groups.get(group_id)
        if not group:
            return False
        if endpoint_id in group.endpoint_ids:
            group.endpoint_ids.remove(endpoint_id)
            return True
        return False

    def resolve_policies(self, endpoint_id: str, org_id: str = "",
                         team_id: str = "") -> list[GroupPolicy]:
        """Resolve which policies apply to a specific endpoint, sorted by priority."""
        applicable = []
        for policy in self._policies.values():
            if not policy.enabled:
                continue
            if policy.scope == PolicyScope.GLOBAL:
                applicable.append(policy)
            elif policy.scope == PolicyScope.ORG and policy.scope_id == org_id:
                applicable.append(policy)
            elif policy.scope == PolicyScope.TEAM and policy.scope_id == team_id:
                applicable.append(policy)
            elif policy.scope == PolicyScope.ENDPOINT and policy.scope_id == endpoint_id:
                applicable.append(policy)
            elif policy.scope == PolicyScope.MACHINE_GROUP:
                group = self._groups.get(policy.scope_id)
                if group and endpoint_id in group.endpoint_ids:
                    applicable.append(policy)
        return sorted(applicable, key=lambda p: p.priority)

    def effective_constitution(self, endpoint_id: str, org_id: str = "",
                               team_id: str = "") -> dict[str, Any]:
        """Merge all applicable policies into one effective constitution."""
        policies = self.resolve_policies(endpoint_id, org_id, team_id)
        merged: dict[str, Any] = {}
        for policy in policies:
            merged.update(policy.constitution)
        return merged

    @property
    def policy_count(self) -> int:
        return len(self._policies)

    @property
    def group_count(self) -> int:
        return len(self._groups)


# ── Remote Agent Kill ────────────────────────────────────────

class KillOrder(BaseModel):
    """An order to revoke a specific agent's token across all machines."""
    kill_id: str = Field(default_factory=lambda: f"kill-{uuid.uuid4().hex[:8]}")
    agent_id: str
    reason: str = ""
    issued_by: str = ""
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    affected_endpoints: list[str] = Field(default_factory=list)
    status: str = "issued"


class KillOrderRegistry:
    """Track all kill orders issued from the Hub."""

    def __init__(self):
        self._orders: list[KillOrder] = []

    def issue(self, agent_id: str, affected_endpoints: list[str],
              reason: str = "", issued_by: str = "") -> KillOrder:
        order = KillOrder(
            agent_id=agent_id,
            reason=reason,
            issued_by=issued_by,
            affected_endpoints=affected_endpoints,
        )
        self._orders.append(order)
        return order

    def complete(self, kill_id: str) -> bool:
        for order in self._orders:
            if order.kill_id == kill_id:
                order.status = "completed"
                return True
        return False

    def orders_for_agent(self, agent_id: str) -> list[KillOrder]:
        return [o for o in self._orders if o.agent_id == agent_id]

    @property
    def all_orders(self) -> list[KillOrder]:
        return list(self._orders)


# ── Deployment Packages ──────────────────────────────────────

class PackageFormat(str, Enum):
    MSI = "msi"
    DEB = "deb"
    RPM = "rpm"
    PKG = "pkg"
    DOCKER = "docker"
    TAR_GZ = "tar.gz"


class DeploymentPackage(BaseModel):
    """Metadata for an endpoint agent installer package."""
    package_id: str = Field(default_factory=lambda: f"pkg-{uuid.uuid4().hex[:8]}")
    version: str
    format: PackageFormat
    filename: str = ""
    download_url: str = ""
    package_hash: str = ""
    signing_key_id: str = ""
    signature: str = ""
    size_bytes: int = 0
    min_os_version: str = ""
    release_notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_current: bool = True


class DeploymentManager:
    """Manages installer packages for GPO/MDM push and Docker images."""

    def __init__(self):
        self._packages: list[DeploymentPackage] = []

    def register_package(self, version: str, format: PackageFormat,
                         filename: str = "", download_url: str = "",
                         package_hash: str = "", signing_key_id: str = "",
                         signature: str = "", size_bytes: int = 0,
                         min_os_version: str = "",
                         release_notes: str = "") -> DeploymentPackage:
        for pkg in self._packages:
            if pkg.format == format:
                pkg.is_current = False
        package = DeploymentPackage(
            version=version,
            format=format,
            filename=filename,
            download_url=download_url,
            package_hash=package_hash,
            signing_key_id=signing_key_id,
            signature=signature,
            size_bytes=size_bytes,
            min_os_version=min_os_version,
            release_notes=release_notes,
        )
        self._packages.append(package)
        return package

    def current_package(self, format: PackageFormat) -> Optional[DeploymentPackage]:
        for pkg in reversed(self._packages):
            if pkg.format == format and pkg.is_current:
                return pkg
        return None

    def all_packages(self) -> list[DeploymentPackage]:
        return list(self._packages)

    def packages_for_version(self, version: str) -> list[DeploymentPackage]:
        return [p for p in self._packages if p.version == version]

    def verify_package(self, package_id: str, content_hash: str) -> bool:
        for pkg in self._packages:
            if pkg.package_id == package_id:
                return pkg.package_hash == content_hash
        return False


# ── Auto-Update ──────────────────────────────────────────────

class UpdateStatus(str, Enum):
    AVAILABLE = "available"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    INSTALLING = "installing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class UpdateRecord(BaseModel):
    """Record of an endpoint agent update attempt."""
    update_id: str = Field(default_factory=lambda: f"upd-{uuid.uuid4().hex[:8]}")
    endpoint_id: str
    from_version: str
    to_version: str
    package_id: str = ""
    status: UpdateStatus = UpdateStatus.AVAILABLE
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: str = ""


class AutoUpdater:
    """Manages self-update lifecycle for endpoint agents."""

    def __init__(self):
        self._updates: list[UpdateRecord] = []
        self._endpoint_versions: dict[str, str] = {}

    def register_endpoint_version(self, endpoint_id: str, version: str) -> None:
        self._endpoint_versions[endpoint_id] = version

    def check_update(self, endpoint_id: str, target_version: str) -> Optional[UpdateRecord]:
        current = self._endpoint_versions.get(endpoint_id, "")
        if not current or current == target_version:
            return None
        record = UpdateRecord(
            endpoint_id=endpoint_id,
            from_version=current,
            to_version=target_version,
        )
        self._updates.append(record)
        return record

    def start_update(self, update_id: str) -> bool:
        for rec in self._updates:
            if rec.update_id == update_id:
                rec.status = UpdateStatus.DOWNLOADING
                rec.started_at = datetime.now(timezone.utc)
                return True
        return False

    def complete_update(self, update_id: str) -> bool:
        for rec in self._updates:
            if rec.update_id == update_id:
                rec.status = UpdateStatus.COMPLETED
                rec.completed_at = datetime.now(timezone.utc)
                self._endpoint_versions[rec.endpoint_id] = rec.to_version
                return True
        return False

    def fail_update(self, update_id: str, error: str = "") -> bool:
        for rec in self._updates:
            if rec.update_id == update_id:
                rec.status = UpdateStatus.FAILED
                rec.error = error
                rec.completed_at = datetime.now(timezone.utc)
                return True
        return False

    def pending_updates(self) -> list[UpdateRecord]:
        return [r for r in self._updates
                if r.status in (UpdateStatus.AVAILABLE, UpdateStatus.DOWNLOADING)]

    def endpoints_needing_update(self, target_version: str) -> list[str]:
        return [eid for eid, ver in self._endpoint_versions.items()
                if ver != target_version]

    @property
    def update_history(self) -> list[UpdateRecord]:
        return list(self._updates)


# ── Live Agent Map ───────────────────────────────────────────

class AgentLocation(BaseModel):
    """Where an agent is running right now."""
    agent_id: str
    endpoint_id: str
    hostname: str = ""
    status: str = "active"
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LiveAgentMap:
    """Which agents are running on which machines right now."""

    def __init__(self):
        self._map: dict[str, AgentLocation] = {}

    def update(self, agent_id: str, endpoint_id: str,
               hostname: str = "", status: str = "active") -> AgentLocation:
        loc = AgentLocation(
            agent_id=agent_id,
            endpoint_id=endpoint_id,
            hostname=hostname,
            status=status,
        )
        self._map[agent_id] = loc
        return loc

    def remove(self, agent_id: str) -> bool:
        return self._map.pop(agent_id, None) is not None

    def get(self, agent_id: str) -> Optional[AgentLocation]:
        return self._map.get(agent_id)

    def agents_on(self, endpoint_id: str) -> list[AgentLocation]:
        return [loc for loc in self._map.values() if loc.endpoint_id == endpoint_id]

    def all_locations(self) -> list[AgentLocation]:
        return list(self._map.values())

    def active_agents(self) -> list[AgentLocation]:
        return [loc for loc in self._map.values() if loc.status == "active"]

    def endpoints_with_agents(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for loc in self._map.values():
            result.setdefault(loc.endpoint_id, []).append(loc.agent_id)
        return result

    @property
    def total_agents(self) -> int:
        return len(self._map)


# ── Fleet Manager ────────────────────────────────────────────

class FleetManager:
    """Orchestrator for fleet operations."""

    def __init__(self):
        self.inventory = MachineInventory()
        self.policies = GroupPolicyManager()
        self.kills = KillOrderRegistry()
        self.deployment = DeploymentManager()
        self.updater = AutoUpdater()
        self.agent_map = LiveAgentMap()

    def sync_endpoint(self, endpoint_id: str, hostname: str, os: str,
                      os_version: str = "", ip_address: str = "",
                      org_id: str = "", team_id: str = "",
                      installed_ai_tools: list[str] | None = None,
                      active_agents: list[str] | None = None,
                      agent_version: str = "",
                      compliance_score: float = 0.0) -> MachineInventoryRecord:
        """Update inventory and agent map from a heartbeat."""
        record = self.inventory.upsert(
            endpoint_id=endpoint_id, hostname=hostname, os=os,
            os_version=os_version, ip_address=ip_address,
            org_id=org_id, team_id=team_id,
            installed_ai_tools=installed_ai_tools,
            active_agents=active_agents,
            agent_version=agent_version,
            compliance_score=compliance_score,
        )
        for aid in (active_agents or []):
            self.agent_map.update(aid, endpoint_id, hostname)
        if agent_version:
            self.updater.register_endpoint_version(endpoint_id, agent_version)
        return record

    def kill_agent(self, agent_id: str, reason: str = "",
                   issued_by: str = "") -> KillOrder:
        """Issue a kill order for an agent across all endpoints."""
        loc = self.agent_map.get(agent_id)
        affected = [loc.endpoint_id] if loc else []
        order = self.kills.issue(agent_id, affected, reason, issued_by)
        self.agent_map.remove(agent_id)
        return order

    def fleet_summary(self) -> dict[str, Any]:
        return {
            "total_machines": self.inventory.total,
            "compliance_score": self.inventory.fleet_compliance_score(),
            "non_compliant": len(self.inventory.non_compliant()),
            "total_agents_tracked": self.agent_map.total_agents,
            "active_policies": self.policies.policy_count,
            "machine_groups": self.policies.group_count,
            "pending_updates": len(self.updater.pending_updates()),
            "kill_orders": len(self.kills.all_orders),
            "deployment_packages": len(self.deployment.all_packages()),
        }
