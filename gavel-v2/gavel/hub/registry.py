"""
Endpoint and fleet agent registration models for the Gavel Hub.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
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
