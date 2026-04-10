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

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Endpoint Status ──────────────────────────────────────────

class EndpointStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"       # Hub unreachable, running on local cache
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"


class EndpointOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CONTAINER = "container"     # Docker / K8s pod


# ── Endpoint Record ──────────────────────────────────────────

class EndpointRecord(BaseModel):
    """A registered machine/container in the Gavel fleet."""
    endpoint_id: str = Field(default_factory=lambda: f"ep-{uuid.uuid4().hex[:8]}")
    hostname: str
    os: EndpointOS
    os_version: str = ""
    ip_address: str = ""
    org_id: str = ""
    team_id: str = ""
    status: EndpointStatus = EndpointStatus.ONLINE
    agent_version: str = ""          # Gavel endpoint agent version
    enrolled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    installed_ai_tools: list[str] = Field(default_factory=list)  # e.g. ["openai-cli", "copilot", "claude-code"]
    active_agent_ids: list[str] = Field(default_factory=list)    # governed agent DIDs currently running
    metadata: dict[str, Any] = Field(default_factory=dict)
    agent_hash: str = ""             # Self-integrity hash of the endpoint agent binary


# ── Hub Enrollment Registry ──────────────────────────────────

class FleetAgentRecord(BaseModel):
    """An agent as seen from the Hub — includes which endpoint it's on."""
    agent_id: str
    endpoint_id: str
    display_name: str = ""
    owner: str = ""
    status: str = "active"           # active, suspended, revoked
    enrolled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    token_hash: str = ""
    org_id: str = ""
    team_id: str = ""


class HubEnrollmentRegistry:
    """Centralized enrollment registry — every agent on every machine reports here."""

    def __init__(self):
        self._agents: dict[str, FleetAgentRecord] = {}          # agent_id -> record
        self._endpoint_agents: dict[str, set[str]] = defaultdict(set)  # endpoint_id -> {agent_id}

    def register(self, agent_id: str, endpoint_id: str, display_name: str = "",
                 owner: str = "", org_id: str = "", team_id: str = "") -> FleetAgentRecord:
        record = FleetAgentRecord(
            agent_id=agent_id,
            endpoint_id=endpoint_id,
            display_name=display_name,
            owner=owner,
            org_id=org_id,
            team_id=team_id,
        )
        self._agents[agent_id] = record
        self._endpoint_agents[endpoint_id].add(agent_id)
        return record

    def get(self, agent_id: str) -> Optional[FleetAgentRecord]:
        return self._agents.get(agent_id)

    def agents_on_endpoint(self, endpoint_id: str) -> list[FleetAgentRecord]:
        return [self._agents[aid] for aid in self._endpoint_agents.get(endpoint_id, set()) if aid in self._agents]

    def all_agents(self) -> list[FleetAgentRecord]:
        return list(self._agents.values())

    def suspend_agent(self, agent_id: str) -> bool:
        rec = self._agents.get(agent_id)
        if not rec:
            return False
        rec.status = "suspended"
        return True

    def revoke_agent(self, agent_id: str) -> bool:
        """Revoke across all endpoints."""
        rec = self._agents.get(agent_id)
        if not rec:
            return False
        rec.status = "revoked"
        return True

    def revoke_agent_fleet_wide(self, agent_id: str) -> list[str]:
        """Revoke a specific agent's token across ALL machines. Returns affected endpoint_ids."""
        affected = []
        for eid, agents in self._endpoint_agents.items():
            if agent_id in agents:
                affected.append(eid)
        self.revoke_agent(agent_id)
        return affected

    def update_last_seen(self, agent_id: str) -> None:
        rec = self._agents.get(agent_id)
        if rec:
            rec.last_seen = datetime.now(timezone.utc)

    @property
    def agent_count(self) -> int:
        return len(self._agents)

    def agents_by_org(self, org_id: str) -> list[FleetAgentRecord]:
        return [a for a in self._agents.values() if a.org_id == org_id]

    def agents_by_status(self, status: str) -> list[FleetAgentRecord]:
        return [a for a in self._agents.values() if a.status == status]


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


# ── Policy Distribution ──────────────────────────────────────

class PolicyVersion(BaseModel):
    """A versioned constitution/policy document distributed to endpoints."""
    version_id: str = Field(default_factory=lambda: f"pv-{uuid.uuid4().hex[:8]}")
    version_number: int
    policy_name: str
    content_hash: str = ""           # SHA-256 of the policy content
    content: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    target_scope: str = "all"        # "all", org_id, team_id, or endpoint_id


class PolicyDistributionRecord(BaseModel):
    """Tracks which endpoints have received which policy version."""
    endpoint_id: str
    version_id: str
    distributed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None


class PolicyDistributor:
    """Push constitution updates to all endpoints simultaneously."""

    def __init__(self):
        self._versions: list[PolicyVersion] = []
        self._distributions: list[PolicyDistributionRecord] = []
        self._endpoint_versions: dict[str, str] = {}  # endpoint_id -> latest version_id

    def publish(self, policy_name: str, content: dict[str, Any],
                created_by: str = "", target_scope: str = "all") -> PolicyVersion:
        version_number = len([v for v in self._versions if v.policy_name == policy_name]) + 1
        content_hash = hashlib.sha256(
            str(sorted(content.items())).encode()
        ).hexdigest()
        pv = PolicyVersion(
            version_number=version_number,
            policy_name=policy_name,
            content_hash=content_hash,
            content=content,
            created_by=created_by,
            target_scope=target_scope,
        )
        self._versions.append(pv)
        return pv

    def distribute(self, version_id: str, endpoint_ids: list[str]) -> list[PolicyDistributionRecord]:
        records = []
        for eid in endpoint_ids:
            rec = PolicyDistributionRecord(endpoint_id=eid, version_id=version_id)
            self._distributions.append(rec)
            self._endpoint_versions[eid] = version_id
            records.append(rec)
        return records

    def acknowledge(self, endpoint_id: str, version_id: str) -> bool:
        for rec in self._distributions:
            if rec.endpoint_id == endpoint_id and rec.version_id == version_id:
                rec.acknowledged = True
                rec.acknowledged_at = datetime.now(timezone.utc)
                return True
        return False

    def pending_endpoints(self, version_id: str) -> list[str]:
        """Endpoints that haven't acknowledged a specific version."""
        return [r.endpoint_id for r in self._distributions
                if r.version_id == version_id and not r.acknowledged]

    def latest_version(self, policy_name: str) -> Optional[PolicyVersion]:
        versions = [v for v in self._versions if v.policy_name == policy_name]
        return versions[-1] if versions else None

    def endpoint_version(self, endpoint_id: str) -> Optional[str]:
        return self._endpoint_versions.get(endpoint_id)


# ── Cross-Machine Correlation ────────────────────────────────

class CorrelationSignal(str, Enum):
    COORDINATED_TIMING = "coordinated_timing"       # Agents on different machines acting in sync
    SHARED_TARGET = "shared_target"                  # Agents on different machines targeting same resource
    DATA_EXFIL_PATTERN = "data_exfil_pattern"        # One agent reads, another on different machine sends
    SYNCHRONIZED_ENROLLMENT = "synchronized_enrollment"  # Agents enrolling in lockstep


class CorrelationFinding(BaseModel):
    """A detected cross-machine correlation pattern."""
    finding_id: str = Field(default_factory=lambda: f"corr-{uuid.uuid4().hex[:8]}")
    signal: CorrelationSignal
    agents: list[str]                # Agent IDs involved
    endpoints: list[str]             # Endpoint IDs involved
    evidence: dict[str, Any] = Field(default_factory=dict)
    severity: str = "medium"         # low, medium, high, critical
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""


class CrossMachineCorrelator:
    """Detect if agents on different machines are coordinating."""

    def __init__(self, timing_window_seconds: int = 30, shared_target_threshold: int = 3):
        self._findings: list[CorrelationFinding] = []
        self._timing_window = timedelta(seconds=timing_window_seconds)
        self._shared_target_threshold = shared_target_threshold

    def analyze_timing(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Detect agents on different endpoints acting within a tight time window."""
        findings = []
        # Group events by time buckets
        by_bucket: dict[str, list[OrgChainEvent]] = defaultdict(list)
        for e in events:
            bucket = e.timestamp.strftime("%Y-%m-%dT%H:%M")  # 1-minute buckets
            by_bucket[bucket].append(e)

        for bucket, bucket_events in by_bucket.items():
            # Find events from different endpoints in same bucket
            endpoint_agents: dict[str, set[str]] = defaultdict(set)
            for e in bucket_events:
                endpoint_agents[e.endpoint_id].add(e.agent_id)

            if len(endpoint_agents) >= 2:
                all_agents = []
                all_endpoints = list(endpoint_agents.keys())
                for agents in endpoint_agents.values():
                    all_agents.extend(agents)

                if len(set(all_agents)) >= 2:
                    finding = CorrelationFinding(
                        signal=CorrelationSignal.COORDINATED_TIMING,
                        agents=list(set(all_agents)),
                        endpoints=all_endpoints,
                        evidence={"time_bucket": bucket, "event_count": len(bucket_events)},
                        severity="medium",
                        description=f"Agents on {len(all_endpoints)} endpoints acted within same minute window",
                    )
                    findings.append(finding)
                    self._findings.append(finding)
        return findings

    def analyze_shared_targets(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Detect agents on different machines targeting the same resource."""
        findings = []
        # Group by target resource (from payload)
        target_accesses: dict[str, list[OrgChainEvent]] = defaultdict(list)
        for e in events:
            target = e.payload.get("target", "")
            if target:
                target_accesses[target].append(e)

        for target, access_events in target_accesses.items():
            endpoints = set(e.endpoint_id for e in access_events)
            if len(endpoints) >= 2 and len(access_events) >= self._shared_target_threshold:
                agents = list(set(e.agent_id for e in access_events))
                finding = CorrelationFinding(
                    signal=CorrelationSignal.SHARED_TARGET,
                    agents=agents,
                    endpoints=list(endpoints),
                    evidence={"target": target, "access_count": len(access_events)},
                    severity="high",
                    description=f"Agents on {len(endpoints)} endpoints accessed '{target}' {len(access_events)} times",
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def analyze_data_exfil(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Detect read-on-A, send-on-B patterns suggesting data exfiltration."""
        findings = []
        reads: dict[str, list[OrgChainEvent]] = defaultdict(list)  # target -> events
        sends: list[OrgChainEvent] = []

        for e in events:
            action = e.payload.get("action", "")
            if action in ("read", "file_read", "db_query"):
                target = e.payload.get("target", "")
                if target:
                    reads[target].append(e)
            elif action in ("send", "network_send", "api_call", "upload"):
                sends.append(e)

        for send_event in sends:
            send_target = send_event.payload.get("target", "")
            for read_target, read_events in reads.items():
                for read_event in read_events:
                    if (read_event.endpoint_id != send_event.endpoint_id and
                            read_event.timestamp < send_event.timestamp):
                        finding = CorrelationFinding(
                            signal=CorrelationSignal.DATA_EXFIL_PATTERN,
                            agents=[read_event.agent_id, send_event.agent_id],
                            endpoints=[read_event.endpoint_id, send_event.endpoint_id],
                            evidence={
                                "read_target": read_target,
                                "send_target": send_target,
                                "read_time": read_event.timestamp.isoformat(),
                                "send_time": send_event.timestamp.isoformat(),
                            },
                            severity="critical",
                            description=f"Agent {read_event.agent_id} read '{read_target}' on {read_event.endpoint_id}, then {send_event.agent_id} sent data from {send_event.endpoint_id}",
                        )
                        findings.append(finding)
                        self._findings.append(finding)
        return findings

    def correlate(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Run all correlation analyses."""
        results = []
        results.extend(self.analyze_timing(events))
        results.extend(self.analyze_shared_targets(events))
        results.extend(self.analyze_data_exfil(events))
        return results

    @property
    def all_findings(self) -> list[CorrelationFinding]:
        return list(self._findings)


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
