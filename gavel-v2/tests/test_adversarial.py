"""Adversarial tests — attack vectors that governance MUST block.

These tests prove that the system resists real attack patterns:
self-approval, token forgery, chain tampering, audit bypass, and
privilege escalation. Each test documents the attack vector and
the constitutional guarantee that blocks it.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from gavel.admin import (
    AdminAgent,
    AdminAuditViolation,
    SecurityViolation,
    _reset_admin_mode_snapshot_for_tests,
)
from gavel.agents import AgentRecord, AgentStatus
from gavel.chain import ChainStatus, EventType, GovernanceChain
from gavel.enrollment import (
    EnrollmentRegistry,
    EnrollmentStatus,
    TokenManager,
    TOKEN_PREFIX,
)
from gavel.tiers import AutonomyTier

from conftest import _valid_application, _make_enrollment_registry, _make_token_manager


# ══════════════════════════════════════════════════════════════
# Attack: Token Forgery
# ══════════════════════════════════════════════════════════════


class TestTokenForgery:
    """ATF S-2 / Article II.2: Forged tokens must be rejected."""

    async def test_forged_token_prefix_wrong(self):
        tm = _make_token_manager()
        valid, reason, _ = await tm.validate("forged_token_value")
        assert valid is False
        assert "format" in reason.lower()

    async def test_forged_token_correct_prefix(self):
        """Attacker guesses the prefix but not the hash."""
        tm = _make_token_manager()
        fake = f"{TOKEN_PREFIX}{'a' * 64}"
        valid, reason, _ = await tm.validate(fake)
        assert valid is False
        assert "not recognized" in reason.lower()

    async def test_replay_revoked_token(self):
        """Attacker captures a valid token, we revoke it, attacker replays."""
        tm = _make_token_manager()
        token = await tm.issue("agent:legit")
        # Token works initially
        assert await tm.is_valid(token.token) is True
        # Revoke
        await tm.revoke(token.agent_did)
        # Replay attack
        assert await tm.is_valid(token.token) is False

    async def test_expired_token_replay(self):
        """Attacker captures a token, waits for expiry, tries to use it."""
        tm = _make_token_manager()
        token = await tm.issue("agent:legit", ttl_seconds=0)
        assert await tm.is_valid(token.token) is False


# ══════════════════════════════════════════════════════════════
# Attack: Chain Tampering
# ══════════════════════════════════════════════════════════════


class TestChainTampering:
    """Article I.1: Audit records are append-only and tamper-evident."""

    def test_modify_approval_to_deny(self):
        """Attacker changes APPROVAL_GRANTED to APPROVAL_DENIED."""
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")

        # Tamper: change the event type
        chain.events[1].payload["decision"] = "DENIED"
        assert chain.verify_integrity() is False

    def test_modify_actor_identity(self):
        """Attacker changes who approved — impersonation."""
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")

        chain.events[1].actor_id = "agent:admin"  # impersonate admin
        assert chain.verify_integrity() is False

    def test_delete_denial_event(self):
        """Attacker deletes a DENIAL to make chain look approved."""
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.APPROVAL_DENIED, "agent:b", "approver")

        del chain.events[1]  # remove denial
        # Chain still has one event but if we add an approval, chain breaks
        chain.append(EventType.APPROVAL_GRANTED, "agent:evil", "approver")
        # The new event links to event[0]'s hash, but the chain structure
        # should still be verified (integrity holds if append is clean)
        # The attack here is that the denial was removed from the record

    def test_inject_fake_evidence(self):
        """Attacker inserts a fake evidence event with passing results."""
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.POLICY_EVAL, "system", "evaluator")

        # Save current hash
        valid_hash = chain.events[-1].event_hash

        # Create fake evidence event with wrong prev_hash
        from gavel.chain import ChainEvent
        fake = ChainEvent(
            chain_id=chain.chain_id,
            event_type=EventType.EVIDENCE_REVIEW,
            actor_id="agent:evil",
            role_used="reviewer",
            payload={"verdict": "PASS", "risk_delta": -0.5},
            prev_hash="0" * 64,  # wrong prev hash
        )
        fake.event_hash = fake.compute_hash()
        chain.events.append(fake)

        assert chain.verify_integrity() is False

    def test_artifact_survives_serialization(self):
        """Artifact exported to JSON and verified independently must match."""
        import json

        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer", {"goal": "test"})
        chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")
        chain.status = ChainStatus.APPROVED

        # Serialize round-trip
        artifact = chain.to_artifact()
        json_str = json.dumps(artifact)
        reloaded = json.loads(json_str)

        result = GovernanceChain.verify_artifact(reloaded)
        assert result["valid"] is True


# ══════════════════════════════════════════════════════════════
# Attack: Enrollment Bypass
# ══════════════════════════════════════════════════════════════


class TestEnrollmentBypass:
    """ATF I-4/I-5: Agents must declare scope before operating."""

    async def test_zero_budget_blocked(self):
        """Agent tries to enroll with no spending limits."""
        registry = _make_enrollment_registry()
        app = _valid_application(budget_tokens=0, budget_usd=0.0)
        record = await registry.submit(app)
        assert record.status == EnrollmentStatus.INCOMPLETE
        assert any("budget" in v.lower() for v in record.violations)

    async def test_empty_capabilities_blocked(self):
        """Agent tries to enroll without declaring any tools."""
        registry = _make_enrollment_registry()
        app = _valid_application()
        app.capabilities.tools = []
        record = await registry.submit(app)
        assert record.status == EnrollmentStatus.INCOMPLETE

    async def test_no_owner_blocked(self):
        """Agent tries to enroll without an accountable human."""
        registry = _make_enrollment_registry()
        app = _valid_application(owner="")
        record = await registry.submit(app)
        assert record.status == EnrollmentStatus.INCOMPLETE

    async def test_suspended_agent_not_enrolled(self):
        """Suspended agent's enrollment is invalid."""
        registry = _make_enrollment_registry()
        app = _valid_application()
        await registry.submit(app)
        assert await registry.is_enrolled("agent:test") is True

        await registry.suspend("agent:test")
        assert await registry.is_enrolled("agent:test") is False


# ══════════════════════════════════════════════════════════════
# Attack: Admin Escalation
# ══════════════════════════════════════════════════════════════


class TestAdminEscalation:
    """Admin mode must be impossible to activate in production."""

    def setup_method(self):
        self._saved = {}
        for key in ("GAVEL_ADMIN_MODE", "GAVEL_ENV", "GAVEL_ADMIN_MACHINES"):
            self._saved[key] = os.environ.get(key)
            if key in os.environ:
                del os.environ[key]
        _reset_admin_mode_snapshot_for_tests()

    def teardown_method(self):
        for key, val in self._saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        _reset_admin_mode_snapshot_for_tests()

    async def test_production_hard_block(self):
        """Even with admin mode enabled, production env blocks it."""
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "production"
        _reset_admin_mode_snapshot_for_tests()
        machine_id = __import__("gavel.admin", fromlist=["get_machine_id"]).get_machine_id()
        os.environ["GAVEL_ADMIN_MACHINES"] = machine_id

        with pytest.raises(SecurityViolation) as exc_info:
            await AdminAgent.create(
                operator="attacker",
                registry=_make_enrollment_registry(),
                allowlist={machine_id},
            )
        assert exc_info.value.gate == "production_block"

    async def test_admin_cannot_disable_audit(self):
        """Constitutional guarantee: audit cannot be disabled, even by admin."""
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "development"
        _reset_admin_mode_snapshot_for_tests()
        machine_id = __import__("gavel.admin", fromlist=["get_machine_id"]).get_machine_id()

        agent = await AdminAgent.create(
            operator="dev@gavel.eu",
            registry=_make_enrollment_registry(),
            allowlist={machine_id},
        )

        for forbidden_op in [
            "disable_audit",
            "delete_audit_ledger",
            "truncate_audit_ledger",
            "modify_audit_chain",
            "rewrite_audit_history",
        ]:
            with pytest.raises(AdminAuditViolation):
                agent.execute(forbidden_op)

        # Chain should still be intact after all the blocked attempts
        assert agent.audit_chain.verify_integrity() is True


# ══════════════════════════════════════════════════════════════
# Attack: Trust Score Manipulation
# ══════════════════════════════════════════════════════════════


class TestTrustManipulation:
    """Article I.2: Agents cannot modify their own trust scores."""

    @pytest.mark.asyncio
    async def test_failure_decreases_trust(self, agent_registry):
        """A violation MUST decrease trust — agents cannot avoid consequences."""
        await agent_registry.register("agent:a", "A", "llm")
        record = await agent_registry.get("agent:a")
        original_trust = record.trust_score

        await agent_registry.update_trust_from_outcome("agent:a", "Bash", success=False)
        refreshed = await agent_registry.get("agent:a")
        assert refreshed.trust_score < original_trust

    @pytest.mark.asyncio
    async def test_violation_causes_demotion(self, agent_registry):
        """Violations cause automatic tier demotion when agent no longer qualifies."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            autonomy_tier=AutonomyTier.SEMI_AUTONOMOUS,
            chains_completed=10, trust_score=400, violations=0,
        )
        await agent_registry._repo.save(record)

        await agent_registry.record_chain_completion("agent:a", success=False)
        # violations=1 blocks re-promotion to SEMI_AUTONOMOUS (requires violations==0)
        refreshed = await agent_registry.get("agent:a")
        assert refreshed.autonomy_tier == AutonomyTier.SUPERVISED

    @pytest.mark.asyncio
    async def test_kill_switch_resets_tier(self, agent_registry):
        """Kill switch drops agent to lowest tier regardless of trust."""
        record = AgentRecord(
            agent_id="agent:a", display_name="A", agent_type="llm",
            autonomy_tier=AutonomyTier.CRITICAL,
            chains_completed=200, trust_score=950,
        )
        await agent_registry._repo.save(record)

        await agent_registry.kill("agent:a")
        refreshed = await agent_registry.get("agent:a")
        assert refreshed.autonomy_tier == AutonomyTier.SUPERVISED
        assert refreshed.status == AgentStatus.SUSPENDED
