"""
Gavel Endpoint Agent — per-machine governance daemon.

Like the CrowdStrike Falcon sensor or FortiClient agent, but for AI agent
governance. Each workstation/server runs a lightweight Gavel endpoint agent
that:

  1. Enforces governance locally (adapter hooks, network proxy, process watchdog)
  2. Sends heartbeats to the Hub with machine status and active agents
  3. Caches policies locally so enforcement continues if Hub is unreachable
  4. Auto-enrolls with the Hub on first heartbeat
  5. Accepts remote commands from the Hub (revoke, kill, update policy)
  6. Monitors its own integrity via self-hash verification

Design constraints:
  - Deterministic logic, no ML/LLM
  - All state is serializable via Pydantic
  - Graceful degradation: if Hub is unreachable, degrade toward safety
"""

from __future__ import annotations

import hashlib
import platform
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Agent Connection State ───────────────────────────────────

class HubConnectionState(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    RECONNECTING = "reconnecting"


class EndpointAgentStatus(str, Enum):
    RUNNING = "running"
    DEGRADED = "degraded"          # Hub unreachable, running on local cache
    STOPPED = "stopped"
    TAMPERED = "tampered"          # Integrity check failed


# ── Remote Command Types ─────────────────────────────────────

class RemoteCommandType(str, Enum):
    REVOKE_TOKEN = "revoke_token"
    KILL_AGENT = "kill_agent"
    UPDATE_POLICY = "update_policy"
    FORCE_RE_REGISTER = "force_re_register"
    COLLECT_INVENTORY = "collect_inventory"
    SELF_UPDATE = "self_update"


class RemoteCommandStatus(str, Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class RemoteCommand(BaseModel):
    """A command sent from the Hub to be executed on this endpoint."""
    command_id: str = Field(default_factory=lambda: f"cmd-{uuid.uuid4().hex[:8]}")
    command_type: RemoteCommandType
    target_agent_id: str = ""         # Empty = applies to endpoint itself
    payload: dict[str, Any] = Field(default_factory=dict)
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: RemoteCommandStatus = RemoteCommandStatus.PENDING
    result: dict[str, Any] = Field(default_factory=dict)
    completed_at: Optional[datetime] = None


# ── Local Policy Cache ───────────────────────────────────────

class CachedPolicy(BaseModel):
    """A locally cached copy of a policy from the Hub."""
    version_id: str
    policy_name: str
    content_hash: str
    content: dict[str, Any] = Field(default_factory=dict)
    cached_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "hub"              # "hub" or "fallback"


class PolicyCache:
    """Local cache for policies — continues enforcing if Hub is unreachable."""

    def __init__(self):
        self._policies: dict[str, CachedPolicy] = {}  # policy_name -> latest cached
        self._history: list[CachedPolicy] = []

    def store(self, version_id: str, policy_name: str, content: dict[str, Any],
              content_hash: str = "") -> CachedPolicy:
        if not content_hash:
            content_hash = hashlib.sha256(str(sorted(content.items())).encode()).hexdigest()
        cached = CachedPolicy(
            version_id=version_id,
            policy_name=policy_name,
            content_hash=content_hash,
            content=content,
        )
        self._policies[policy_name] = cached
        self._history.append(cached)
        return cached

    def get(self, policy_name: str) -> Optional[CachedPolicy]:
        return self._policies.get(policy_name)

    def is_current(self, policy_name: str, expected_hash: str) -> bool:
        cached = self._policies.get(policy_name)
        return cached is not None and cached.content_hash == expected_hash

    def all_policies(self) -> list[CachedPolicy]:
        return list(self._policies.values())

    @property
    def count(self) -> int:
        return len(self._policies)


# ── Heartbeat ────────────────────────────────────────────────

class HeartbeatPayload(BaseModel):
    """Data sent to the Hub on each heartbeat."""
    endpoint_id: str
    hostname: str
    os: str
    os_version: str
    status: EndpointAgentStatus
    agent_version: str
    agent_hash: str                        # Self-integrity hash
    active_agent_ids: list[str] = Field(default_factory=list)
    installed_ai_tools: list[str] = Field(default_factory=list)
    policy_versions: dict[str, str] = Field(default_factory=dict)  # policy_name -> version_id
    uptime_seconds: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HeartbeatResponse(BaseModel):
    """Response from the Hub after a heartbeat."""
    acknowledged: bool = True
    pending_commands: list[RemoteCommand] = Field(default_factory=list)
    policy_updates: list[dict[str, Any]] = Field(default_factory=list)  # New policies to cache
    next_heartbeat_seconds: int = 60       # Hub can adjust heartbeat interval


# ── Local Enforcement ────────────────────────────────────────

class EnforcementAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    LOG_ONLY = "log_only"


class EnforcementRecord(BaseModel):
    """Record of a local enforcement decision."""
    record_id: str = Field(default_factory=lambda: f"enf-{uuid.uuid4().hex[:8]}")
    agent_id: str
    action_requested: str
    decision: EnforcementAction
    reason: str = ""
    policy_version: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LocalEnforcer:
    """Local enforcement engine — adapter hooks, process watchdog."""

    def __init__(self):
        self._records: list[EnforcementRecord] = []
        self._blocked_agents: set[str] = set()
        self._active_agents: dict[str, dict[str, Any]] = {}  # agent_id -> info

    def register_local_agent(self, agent_id: str, info: dict[str, Any] | None = None) -> None:
        self._active_agents[agent_id] = info or {}

    def block_agent(self, agent_id: str) -> None:
        self._blocked_agents.add(agent_id)

    def unblock_agent(self, agent_id: str) -> None:
        self._blocked_agents.discard(agent_id)

    def is_blocked(self, agent_id: str) -> bool:
        return agent_id in self._blocked_agents

    def enforce(self, agent_id: str, action_requested: str,
                policy_version: str = "") -> EnforcementRecord:
        if agent_id in self._blocked_agents:
            record = EnforcementRecord(
                agent_id=agent_id,
                action_requested=action_requested,
                decision=EnforcementAction.DENY,
                reason="Agent is blocked",
                policy_version=policy_version,
            )
        elif agent_id not in self._active_agents:
            record = EnforcementRecord(
                agent_id=agent_id,
                action_requested=action_requested,
                decision=EnforcementAction.DENY,
                reason="Agent not registered locally",
                policy_version=policy_version,
            )
        else:
            record = EnforcementRecord(
                agent_id=agent_id,
                action_requested=action_requested,
                decision=EnforcementAction.ALLOW,
                reason="Agent registered and not blocked",
                policy_version=policy_version,
            )
        self._records.append(record)
        return record

    def kill_agent(self, agent_id: str) -> bool:
        """Remove agent from active set and block it."""
        if agent_id in self._active_agents:
            del self._active_agents[agent_id]
        self._blocked_agents.add(agent_id)
        return True

    @property
    def active_agent_ids(self) -> list[str]:
        return list(self._active_agents.keys())

    @property
    def enforcement_log(self) -> list[EnforcementRecord]:
        return list(self._records)


# ── Tamper Protection ────────────────────────────────────────

class IntegrityStatus(str, Enum):
    VERIFIED = "verified"
    TAMPERED = "tampered"
    UNKNOWN = "unknown"


class IntegrityCheck(BaseModel):
    """Result of a self-integrity check."""
    check_id: str = Field(default_factory=lambda: f"ichk-{uuid.uuid4().hex[:8]}")
    expected_hash: str
    actual_hash: str
    status: IntegrityStatus
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: str = ""


class TamperProtection:
    """Monitors endpoint agent's own integrity via self-hash verification."""

    def __init__(self, reference_hash: str = ""):
        self._reference_hash = reference_hash
        self._checks: list[IntegrityCheck] = []

    def set_reference_hash(self, hash_value: str) -> None:
        self._reference_hash = hash_value

    def compute_hash(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def verify(self, current_content: bytes) -> IntegrityCheck:
        actual = self.compute_hash(current_content)
        if not self._reference_hash:
            status = IntegrityStatus.UNKNOWN
            details = "No reference hash set"
        elif actual == self._reference_hash:
            status = IntegrityStatus.VERIFIED
            details = "Integrity verified"
        else:
            status = IntegrityStatus.TAMPERED
            details = f"Hash mismatch: expected {self._reference_hash[:16]}..., got {actual[:16]}..."

        check = IntegrityCheck(
            expected_hash=self._reference_hash,
            actual_hash=actual,
            status=status,
            details=details,
        )
        self._checks.append(check)
        return check

    @property
    def last_check(self) -> Optional[IntegrityCheck]:
        return self._checks[-1] if self._checks else None

    @property
    def is_tampered(self) -> bool:
        return self.last_check is not None and self.last_check.status == IntegrityStatus.TAMPERED

    @property
    def check_history(self) -> list[IntegrityCheck]:
        return list(self._checks)


# ── Gavel Endpoint Agent ────────────────────────────────────

class GavelEndpointAgent:
    """Lightweight per-machine governance daemon."""

    def __init__(self, hostname: str = "", agent_version: str = "1.0.0",
                 hub_url: str = "", org_id: str = "", team_id: str = ""):
        self.endpoint_id: str = f"ep-{uuid.uuid4().hex[:8]}"
        self.hostname = hostname or platform.node()
        self.os_name = platform.system().lower()
        self.os_version = platform.version()
        self.agent_version = agent_version
        self.hub_url = hub_url
        self.org_id = org_id
        self.team_id = team_id
        self.status = EndpointAgentStatus.RUNNING
        self.hub_connection = HubConnectionState.DISCONNECTED
        self.started_at = datetime.now(timezone.utc)
        self._enrolled_with_hub = False

        # Subsystems
        self.enforcer = LocalEnforcer()
        self.policy_cache = PolicyCache()
        self.tamper = TamperProtection()
        self._command_log: list[RemoteCommand] = []
        self._heartbeat_count = 0
        self._last_heartbeat: Optional[datetime] = None

    # ── Auto-enrollment ──────────────────────────────────────

    def build_enrollment_payload(self) -> dict[str, Any]:
        """Build the payload for auto-enrollment with the Hub."""
        return {
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "os": self.os_name,
            "os_version": self.os_version,
            "agent_version": self.agent_version,
            "org_id": self.org_id,
            "team_id": self.team_id,
            "agent_hash": self.tamper._reference_hash,
        }

    def mark_enrolled(self) -> None:
        self._enrolled_with_hub = True
        self.hub_connection = HubConnectionState.CONNECTED

    @property
    def is_enrolled(self) -> bool:
        return self._enrolled_with_hub

    # ── Heartbeat ────────────────────────────────────────────

    def build_heartbeat(self) -> HeartbeatPayload:
        uptime = int((datetime.now(timezone.utc) - self.started_at).total_seconds())
        policy_versions = {
            p.policy_name: p.version_id for p in self.policy_cache.all_policies()
        }
        return HeartbeatPayload(
            endpoint_id=self.endpoint_id,
            hostname=self.hostname,
            os=self.os_name,
            os_version=self.os_version,
            status=self.status,
            agent_version=self.agent_version,
            agent_hash=self.tamper._reference_hash,
            active_agent_ids=self.enforcer.active_agent_ids,
            installed_ai_tools=[],  # Would be populated by OS scanner
            policy_versions=policy_versions,
            uptime_seconds=uptime,
        )

    def process_heartbeat_response(self, response: HeartbeatResponse) -> list[RemoteCommand]:
        """Process response from the Hub. Returns executed commands."""
        self._heartbeat_count += 1
        self._last_heartbeat = datetime.now(timezone.utc)
        self.hub_connection = HubConnectionState.CONNECTED

        # Apply policy updates
        for update in response.policy_updates:
            self.policy_cache.store(
                version_id=update.get("version_id", ""),
                policy_name=update.get("policy_name", ""),
                content=update.get("content", {}),
                content_hash=update.get("content_hash", ""),
            )

        # Execute pending commands
        executed = []
        for cmd in response.pending_commands:
            self.execute_command(cmd)
            executed.append(cmd)
        return executed

    # ── Remote Commands ──────────────────────────────────────

    def execute_command(self, command: RemoteCommand) -> RemoteCommand:
        """Execute a remote command from the Hub."""
        command.status = RemoteCommandStatus.EXECUTING

        if command.command_type == RemoteCommandType.REVOKE_TOKEN:
            agent_id = command.target_agent_id
            if agent_id:
                self.enforcer.block_agent(agent_id)
                command.result = {"revoked": True, "agent_id": agent_id}
                command.status = RemoteCommandStatus.COMPLETED
            else:
                command.result = {"error": "No target_agent_id specified"}
                command.status = RemoteCommandStatus.FAILED

        elif command.command_type == RemoteCommandType.KILL_AGENT:
            agent_id = command.target_agent_id
            if agent_id:
                self.enforcer.kill_agent(agent_id)
                command.result = {"killed": True, "agent_id": agent_id}
                command.status = RemoteCommandStatus.COMPLETED
            else:
                command.result = {"error": "No target_agent_id specified"}
                command.status = RemoteCommandStatus.FAILED

        elif command.command_type == RemoteCommandType.UPDATE_POLICY:
            policy_data = command.payload
            self.policy_cache.store(
                version_id=policy_data.get("version_id", ""),
                policy_name=policy_data.get("policy_name", ""),
                content=policy_data.get("content", {}),
                content_hash=policy_data.get("content_hash", ""),
            )
            command.result = {"updated": True}
            command.status = RemoteCommandStatus.COMPLETED

        elif command.command_type == RemoteCommandType.FORCE_RE_REGISTER:
            self._enrolled_with_hub = False
            self.hub_connection = HubConnectionState.DISCONNECTED
            command.result = {"re_register": True}
            command.status = RemoteCommandStatus.COMPLETED

        elif command.command_type == RemoteCommandType.COLLECT_INVENTORY:
            command.result = {
                "hostname": self.hostname,
                "os": self.os_name,
                "os_version": self.os_version,
                "agent_version": self.agent_version,
                "active_agents": self.enforcer.active_agent_ids,
                "cached_policies": self.policy_cache.count,
            }
            command.status = RemoteCommandStatus.COMPLETED

        elif command.command_type == RemoteCommandType.SELF_UPDATE:
            # In production, this would download + verify + replace the binary
            new_version = command.payload.get("target_version", "")
            new_hash = command.payload.get("package_hash", "")
            if new_version:
                command.result = {"updated_to": new_version, "hash": new_hash}
                command.status = RemoteCommandStatus.COMPLETED
            else:
                command.result = {"error": "No target_version specified"}
                command.status = RemoteCommandStatus.FAILED

        command.completed_at = datetime.now(timezone.utc)
        self._command_log.append(command)
        return command

    # ── Degraded mode ────────────────────────────────────────

    def enter_degraded_mode(self) -> None:
        """Hub unreachable — degrade toward safety."""
        self.status = EndpointAgentStatus.DEGRADED
        self.hub_connection = HubConnectionState.DISCONNECTED

    def exit_degraded_mode(self) -> None:
        """Hub reconnected."""
        self.status = EndpointAgentStatus.RUNNING
        self.hub_connection = HubConnectionState.CONNECTED

    @property
    def is_degraded(self) -> bool:
        return self.status == EndpointAgentStatus.DEGRADED

    # ── Machine Inventory ────────────────────────────────────

    def collect_inventory(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "os": self.os_name,
            "os_version": self.os_version,
            "agent_version": self.agent_version,
            "status": self.status.value,
            "enrolled": self._enrolled_with_hub,
            "hub_connection": self.hub_connection.value,
            "active_agents": self.enforcer.active_agent_ids,
            "cached_policies": [p.policy_name for p in self.policy_cache.all_policies()],
            "heartbeat_count": self._heartbeat_count,
            "integrity_status": self.tamper.last_check.status.value if self.tamper.last_check else "unchecked",
            "uptime_seconds": int((datetime.now(timezone.utc) - self.started_at).total_seconds()),
        }

    @property
    def heartbeat_count(self) -> int:
        return self._heartbeat_count

    @property
    def command_log(self) -> list[RemoteCommand]:
        return list(self._command_log)
