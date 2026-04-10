"""Tests for Agent Registry — registration, heartbeat, kill switch, promotion."""

from __future__ import annotations

import pytest

from gavel.agents import AgentRecord, AgentRegistry, AgentStatus
from gavel.tiers import AutonomyTier


class TestAgentRegistration:
    @pytest.mark.asyncio
    async def test_register_agent(self, agent_registry):
        record = await agent_registry.register(
            agent_id="agent:monitor",
            display_name="Monitor Agent",
            agent_type="llm",
            capabilities=["Read", "Grep"],
        )
        assert record.agent_id == "agent:monitor"
        assert record.display_name == "Monitor Agent"
        assert record.status == AgentStatus.ACTIVE
        assert record.autonomy_tier == AutonomyTier.SUPERVISED
        assert record.trust_score == 500
        assert record.did.startswith("did:mesh:")
        assert record.capabilities == ["Read", "Grep"]

    @pytest.mark.asyncio
    async def test_register_creates_did(self, agent_registry):
        record = await agent_registry.register("agent:a", "Agent A", "llm")
        assert record.did != ""
        assert "did:" in record.did

    @pytest.mark.asyncio
    async def test_get_agent(self, agent_registry):
        await agent_registry.register("agent:a", "A", "llm")
        record = agent_registry.get("agent:a")
        assert record is not None
        assert record.agent_id == "agent:a"

    @pytest.mark.asyncio
    async def test_get_unknown_returns_none(self, agent_registry):
        assert agent_registry.get("agent:ghost") is None

    @pytest.mark.asyncio
    async def test_get_all(self, agent_registry):
        await agent_registry.register("agent:a", "A", "llm")
        await agent_registry.register("agent:b", "B", "tool")
        all_agents = agent_registry.get_all()
        assert len(all_agents) == 2


class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_heartbeat_updates_timestamp(self, agent_registry):
        record = await agent_registry.register("agent:a", "A", "llm")
        original_hb = record.last_heartbeat

        updated = await agent_registry.heartbeat("agent:a", {"activity": "gate: Read"})
        assert updated is not None
        assert updated.last_heartbeat >= original_hb
        assert updated.current_activity == "gate: Read"

    @pytest.mark.asyncio
    async def test_heartbeat_revives_idle(self, agent_registry):
        record = await agent_registry.register("agent:a", "A", "llm")
        record.status = AgentStatus.IDLE

        updated = await agent_registry.heartbeat("agent:a")
        assert updated.status == AgentStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_heartbeat_unknown_agent(self, agent_registry):
        result = await agent_registry.heartbeat("agent:ghost")
        assert result is None


class TestKillSwitch:
    @pytest.mark.asyncio
    async def test_kill_suspends_agent(self, agent_registry):
        await agent_registry.register("agent:rogue", "Rogue", "llm")
        record = await agent_registry.kill("agent:rogue", reason="Anomalous behavior")
        assert record.status == AgentStatus.SUSPENDED
        assert record.autonomy_tier == AutonomyTier.SUPERVISED
        assert record.violations >= 1

    @pytest.mark.asyncio
    async def test_kill_unknown_agent(self, agent_registry):
        result = await agent_registry.kill("agent:ghost")
        assert result is None

    @pytest.mark.asyncio
    async def test_revive_after_kill(self, agent_registry):
        await agent_registry.register("agent:a", "A", "llm")
        await agent_registry.kill("agent:a")

        record = await agent_registry.revive("agent:a")
        assert record.status == AgentStatus.ACTIVE
        # Stays at SUPERVISED after revive
        assert record.autonomy_tier == AutonomyTier.SUPERVISED

    @pytest.mark.asyncio
    async def test_revive_unknown_agent(self, agent_registry):
        result = await agent_registry.revive("agent:ghost")
        assert result is None

    @pytest.mark.asyncio
    async def test_mark_dead(self, agent_registry):
        await agent_registry.register("agent:a", "A", "llm")
        agent_registry.mark_dead("agent:a")
        record = agent_registry.get("agent:a")
        assert record.status == AgentStatus.DEAD

    @pytest.mark.asyncio
    async def test_mark_dead_skips_suspended(self, agent_registry):
        """Suspended agents should not be overwritten to DEAD."""
        await agent_registry.register("agent:a", "A", "llm")
        await agent_registry.kill("agent:a")
        agent_registry.mark_dead("agent:a")
        record = agent_registry.get("agent:a")
        assert record.status == AgentStatus.SUSPENDED  # not DEAD


class TestPromotionTrack:
    def test_promote_check_intern_to_junior(self, agent_registry):
        """10 chains + trust >= 400 + 0 violations = Junior."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            chains_completed=10, trust_score=400, violations=0,
            autonomy_tier=AutonomyTier.SUPERVISED,
        )
        agent_registry._agents["agent:a"] = record
        new_tier = agent_registry.promote_check("agent:a")
        assert new_tier == AutonomyTier.SEMI_AUTONOMOUS

    def test_promote_check_junior_to_senior(self, agent_registry):
        """50 chains + trust >= 700 = Senior."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            chains_completed=50, trust_score=700, violations=0,
            autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
        )
        agent_registry._agents["agent:a"] = record
        new_tier = agent_registry.promote_check("agent:a")
        assert new_tier == AutonomyTier.AUTONOMOUS

    def test_promote_check_senior_to_principal(self, agent_registry):
        """200 chains + trust >= 900 + 0 violations = Principal."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            chains_completed=200, trust_score=900, violations=0,
            autonomy_tier=AutonomyTier.AUTONOMOUS,
        )
        agent_registry._agents["agent:a"] = record
        new_tier = agent_registry.promote_check("agent:a")
        assert new_tier == AutonomyTier.CRITICAL

    def test_violations_block_junior_promotion(self, agent_registry):
        """Violations prevent Junior promotion even with enough chains/trust."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            chains_completed=15, trust_score=500, violations=1,
            autonomy_tier=AutonomyTier.SUPERVISED,
        )
        agent_registry._agents["agent:a"] = record
        new_tier = agent_registry.promote_check("agent:a")
        assert new_tier == AutonomyTier.SUPERVISED  # stays at intern

    def test_violations_block_principal_promotion(self, agent_registry):
        """Any violation blocks Principal tier."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            chains_completed=200, trust_score=950, violations=1,
            autonomy_tier=AutonomyTier.AUTONOMOUS,
        )
        agent_registry._agents["agent:a"] = record
        new_tier = agent_registry.promote_check("agent:a")
        # Should get Senior (50+ chains, 700+ trust) but not Principal
        assert new_tier == AutonomyTier.AUTONOMOUS

    def test_insufficient_trust_no_promotion(self, agent_registry):
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            chains_completed=100, trust_score=300, violations=0,
            autonomy_tier=AutonomyTier.SUPERVISED,
        )
        agent_registry._agents["agent:a"] = record
        new_tier = agent_registry.promote_check("agent:a")
        assert new_tier == AutonomyTier.SUPERVISED

    @pytest.mark.asyncio
    async def test_chain_completion_success_increments(self, agent_registry):
        await agent_registry.register("agent:a", "A", "llm")
        await agent_registry.record_chain_completion("agent:a", success=True)
        record = agent_registry.get("agent:a")
        assert record.chains_completed == 1

    @pytest.mark.asyncio
    async def test_chain_completion_failure_increments_violations(self, agent_registry):
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            autonomy_tier=AutonomyTier.AUTONOMOUS,
            chains_completed=50, trust_score=700,
        )
        agent_registry._agents["agent:a"] = record

        await agent_registry.record_chain_completion("agent:a", success=False)
        record = agent_registry.get("agent:a")
        assert record.violations == 1

    @pytest.mark.asyncio
    async def test_chain_completion_failure_demotes_when_unqualified(self, agent_registry):
        """Demotion sticks when the agent no longer qualifies for re-promotion."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
            chains_completed=10, trust_score=400, violations=0,
        )
        agent_registry._agents["agent:a"] = record

        await agent_registry.record_chain_completion("agent:a", success=False)
        record = agent_registry.get("agent:a")
        assert record.violations == 1
        # Violations > 0 blocks re-promotion to SEMI_AUTONOMOUS
        assert record.autonomy_tier == AutonomyTier.SUPERVISED


class TestTrustUpdate:
    @pytest.mark.asyncio
    async def test_success_increases_trust(self, agent_registry):
        await agent_registry.register("agent:a", "A", "llm")
        result = agent_registry.update_trust_from_outcome("agent:a", "Read", success=True)
        assert result["trust_score"] == 501

    @pytest.mark.asyncio
    async def test_failure_decreases_trust(self, agent_registry):
        await agent_registry.register("agent:a", "A", "llm")
        result = agent_registry.update_trust_from_outcome("agent:a", "Bash", success=False)
        assert result["trust_score"] == 475  # 500 - 25

    @pytest.mark.asyncio
    async def test_trust_capped_at_1000(self, agent_registry):
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            trust_score=1000,
        )
        agent_registry._agents["agent:a"] = record
        result = agent_registry.update_trust_from_outcome("agent:a", "Read", success=True)
        assert result["trust_score"] == 1000

    @pytest.mark.asyncio
    async def test_trust_floored_at_0(self, agent_registry):
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            trust_score=10,
        )
        agent_registry._agents["agent:a"] = record
        result = agent_registry.update_trust_from_outcome("agent:a", "Bash", success=False)
        assert result["trust_score"] == 0

    def test_update_unknown_agent(self, agent_registry):
        result = agent_registry.update_trust_from_outcome("agent:ghost", "Read", True)
        assert result is None
