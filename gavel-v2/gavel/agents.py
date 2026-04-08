"""
Agent Registry — registration, heartbeat, kill switch, and autonomy promotion.

Every agent that participates in Gavel governance must register here.
Registration creates an AGT identity (Ed25519 DID) and starts the agent
at the lowest autonomy tier (SUPERVISED / Intern). Agents earn autonomy
through a track record of successful governed actions.

ATF Maturity Model:
  Intern (SUPERVISED)       → 10 successful chains, trust ≥ 400
  Junior (SEMI_AUTONOMOUS)  → 50 successful chains, trust ≥ 700
  Senior (AUTONOMOUS)       → 200 successful chains, trust ≥ 900, human-endorsed
  Principal (CRITICAL)      → reserved for multi-sig governance
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field
from gavel.agt_compat import AgentMeshClient

from gavel.events import EventBus, DashboardEvent
from gavel.tiers import AutonomyTier


class AgentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    IDLE = "IDLE"
    SUSPENDED = "SUSPENDED"
    DEAD = "DEAD"


class AgentRecord(BaseModel):
    """A registered governed agent."""

    agent_id: str
    display_name: str
    agent_type: str  # "llm", "tool", "human", "claude-code"
    did: str = ""
    trust_score: int = 500
    autonomy_tier: int = 0  # AutonomyTier value
    capabilities: list[str] = Field(default_factory=list)
    status: AgentStatus = AgentStatus.ACTIVE
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    heartbeat_interval_s: int = 30
    chains_proposed: int = 0
    chains_completed: int = 0
    violations: int = 0
    successful_actions: int = 0
    session_id: str = ""
    current_activity: str = "Idle"


class AgentRegistry:
    """Manages the roster of governed agents."""

    def __init__(self, event_bus: EventBus):
        self._agents: dict[str, AgentRecord] = {}
        self._mesh_clients: dict[str, AgentMeshClient] = {}
        self._bus = event_bus

    async def register(
        self,
        agent_id: str,
        display_name: str,
        agent_type: str,
        capabilities: list[str] | None = None,
    ) -> AgentRecord:
        """Register a new agent. Creates AGT identity and starts at SUPERVISED."""
        client = AgentMeshClient(agent_id=agent_id)
        self._mesh_clients[agent_id] = client

        record = AgentRecord(
            agent_id=agent_id,
            display_name=display_name,
            agent_type=agent_type,
            did=str(client.identity.did),
            trust_score=client.trust_score.total_score,
            autonomy_tier=AutonomyTier.SUPERVISED,
            capabilities=capabilities or [],
        )
        self._agents[agent_id] = record

        await self._bus.publish(DashboardEvent(
            event_type="agent_registered",
            agent_id=agent_id,
            payload={
                "display_name": display_name,
                "did": record.did,
                "trust_score": record.trust_score,
                "agent_type": agent_type,
            },
        ))
        return record

    async def heartbeat(self, agent_id: str, payload: dict[str, Any] | None = None) -> AgentRecord | None:
        """Update agent heartbeat. Returns None if agent not found."""
        record = self._agents.get(agent_id)
        if not record:
            return None

        record.last_heartbeat = datetime.now(timezone.utc)
        if record.status == AgentStatus.IDLE:
            record.status = AgentStatus.ACTIVE
        if payload and "activity" in payload:
            record.current_activity = payload["activity"]

        await self._bus.publish(DashboardEvent(
            event_type="agent_heartbeat",
            agent_id=agent_id,
            payload=payload or {},
        ))
        return record

    async def kill(self, agent_id: str, reason: str = "Manual kill switch") -> AgentRecord | None:
        """Kill switch — suspend agent and drop to SUPERVISED tier."""
        record = self._agents.get(agent_id)
        if not record:
            return None

        record.status = AgentStatus.SUSPENDED
        record.autonomy_tier = AutonomyTier.SUPERVISED
        record.violations += 1

        await self._bus.publish(DashboardEvent(
            event_type="agent_killed",
            agent_id=agent_id,
            payload={"reason": reason, "previous_tier": record.autonomy_tier},
        ))
        return record

    async def revive(self, agent_id: str) -> AgentRecord | None:
        """Reactivate a suspended agent (stays at SUPERVISED tier)."""
        record = self._agents.get(agent_id)
        if not record:
            return None
        record.status = AgentStatus.ACTIVE
        record.last_heartbeat = datetime.now(timezone.utc)
        await self._bus.publish(DashboardEvent(
            event_type="agent_status_change",
            agent_id=agent_id,
            payload={"new_status": "ACTIVE"},
        ))
        return record

    async def record_chain_completion(self, agent_id: str, success: bool) -> None:
        """Record a governance chain outcome for promotion tracking."""
        record = self._agents.get(agent_id)
        if not record:
            return

        if success:
            record.chains_completed += 1
            # Update trust score from AGT
            client = self._mesh_clients.get(agent_id)
            if client:
                record.trust_score = client.trust_score.total_score
        else:
            record.violations += 1
            # Immediate demotion on violation
            if record.autonomy_tier > AutonomyTier.SUPERVISED:
                record.autonomy_tier = max(0, record.autonomy_tier - 1)
                await self._bus.publish(DashboardEvent(
                    event_type="agent_demoted",
                    agent_id=agent_id,
                    payload={
                        "new_tier": record.autonomy_tier,
                        "reason": "Governance violation — automatic demotion",
                    },
                ))

        # Check for promotion
        new_tier = self.promote_check(agent_id)
        if new_tier is not None and new_tier > record.autonomy_tier:
            record.autonomy_tier = new_tier
            await self._bus.publish(DashboardEvent(
                event_type="agent_promoted",
                agent_id=agent_id,
                payload={
                    "new_tier": new_tier,
                    "tier_name": AutonomyTier(new_tier).name,
                    "chains_completed": record.chains_completed,
                    "trust_score": record.trust_score,
                },
            ))

    def promote_check(self, agent_id: str) -> int | None:
        """Evaluate whether agent qualifies for promotion. Returns new tier or None."""
        record = self._agents.get(agent_id)
        if not record:
            return None

        c = record.chains_completed
        t = record.trust_score
        v = record.violations

        # Principal: 200 chains, trust ≥ 900 (human endorsement checked separately)
        if c >= 200 and t >= 900 and v == 0:
            return AutonomyTier.CRITICAL
        # Senior: 50 chains, trust ≥ 700
        if c >= 50 and t >= 700:
            return AutonomyTier.AUTONOMOUS
        # Junior: 10 chains, trust ≥ 400, no recent violations
        if c >= 10 and t >= 400 and v == 0:
            return AutonomyTier.SEMI_AUTONOMOUS
        # Stay at current tier
        return record.autonomy_tier

    def update_trust_from_outcome(
        self, agent_id: str, tool_name: str, success: bool
    ) -> Optional[dict]:
        """Update agent trust based on a single tool-call outcome.

        Returns a summary dict or None if agent not found.
        """
        record = self._agents.get(agent_id)
        if not record:
            return None

        old_tier = record.autonomy_tier

        if success:
            record.successful_actions += 1
            record.trust_score = min(1000, record.trust_score + 1)
        else:
            record.violations += 1
            record.trust_score = max(0, record.trust_score - 25)

        # Re-evaluate promotion
        new_tier = self.promote_check(agent_id)
        promoted = False
        if new_tier is not None and new_tier > old_tier:
            record.autonomy_tier = new_tier
            promoted = True

        return {
            "trust_score": record.trust_score,
            "autonomy_tier": record.autonomy_tier,
            "promoted": promoted,
        }

    def get(self, agent_id: str) -> AgentRecord | None:
        return self._agents.get(agent_id)

    def get_all(self) -> list[AgentRecord]:
        return list(self._agents.values())

    def mark_dead(self, agent_id: str) -> None:
        """Mark agent as dead (missed heartbeats). Synchronous for supervisor use."""
        record = self._agents.get(agent_id)
        if record and record.status != AgentStatus.SUSPENDED:
            record.status = AgentStatus.DEAD
