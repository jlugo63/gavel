"""Tests for Gavel Enrollment Gate — ATF pre-flight validation, registry, tokens."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    EnrollmentRegistry,
    EnrollmentStatus,
    EnrollmentValidator,
    FallbackBehavior,
    GovernanceToken,
    PurposeDeclaration,
    ResourceAllowlist,
    TokenManager,
    TOKEN_PREFIX,
)

from conftest import _valid_application


# ══════════════════════════════════════════════════════════════
# ATF I-4: Purpose Declaration
# ══════════════════════════════════════════════════════════════


class TestPurposeDeclaration:
    def test_valid_purpose(self):
        p = PurposeDeclaration(
            summary="Monitor production infrastructure",
            operational_scope="infrastructure",
        )
        ok, msg = p.is_valid()
        assert ok is True
        assert msg == ""

    def test_summary_too_short(self):
        p = PurposeDeclaration(summary="Hi", operational_scope="test")
        ok, msg = p.is_valid()
        assert ok is False
        assert "too short" in msg

    def test_empty_summary(self):
        p = PurposeDeclaration(summary="", operational_scope="test")
        ok, msg = p.is_valid()
        assert ok is False

    def test_missing_operational_scope(self):
        p = PurposeDeclaration(
            summary="A valid purpose statement here",
            operational_scope="",
        )
        ok, msg = p.is_valid()
        assert ok is False
        assert "scope" in msg.lower()

    def test_invalid_risk_tier(self):
        p = PurposeDeclaration(
            summary="Valid purpose statement",
            operational_scope="test",
            risk_tier="mega-critical",
        )
        ok, msg = p.is_valid()
        assert ok is False
        assert "risk tier" in msg.lower()

    @pytest.mark.parametrize("tier", ["low", "standard", "high", "critical"])
    def test_all_valid_risk_tiers(self, tier):
        p = PurposeDeclaration(
            summary="Valid purpose statement",
            operational_scope="test",
            risk_tier=tier,
        )
        ok, _ = p.is_valid()
        assert ok is True


# ══════════════════════════════════════════════════════════════
# ATF I-5: Capability Manifest
# ══════════════════════════════════════════════════════════════


class TestCapabilityManifest:
    def test_valid_manifest(self):
        m = CapabilityManifest(tools=["Read", "Write"])
        ok, msg = m.is_valid()
        assert ok is True

    def test_empty_tools(self):
        m = CapabilityManifest(tools=[])
        ok, msg = m.is_valid()
        assert ok is False
        assert "at least one tool" in msg

    def test_default_tools_empty(self):
        m = CapabilityManifest()
        ok, msg = m.is_valid()
        assert ok is False


# ══════════════════════════════════════════════════════════════
# ATF S-1: Resource Allowlist
# ══════════════════════════════════════════════════════════════


class TestResourceAllowlist:
    def test_valid_with_paths(self):
        r = ResourceAllowlist(allowed_paths=["/tmp"])
        ok, _ = r.is_valid()
        assert ok is True

    def test_valid_with_hosts(self):
        r = ResourceAllowlist(allowed_hosts=["api.openai.com"])
        ok, _ = r.is_valid()
        assert ok is True

    def test_empty_paths_and_hosts(self):
        r = ResourceAllowlist()
        ok, msg = r.is_valid()
        assert ok is False
        assert "at least one" in msg


# ══════════════════════════════════════════════════════════════
# ATF S-2: Action Boundaries
# ══════════════════════════════════════════════════════════════


class TestActionBoundaries:
    def test_valid_boundaries(self):
        b = ActionBoundaries(allowed_actions=["read", "write"])
        ok, _ = b.is_valid()
        assert ok is True

    def test_no_actions(self):
        b = ActionBoundaries(allowed_actions=[])
        ok, msg = b.is_valid()
        assert ok is False
        assert "at least one" in msg


# ══════════════════════════════════════════════════════════════
# Fallback Behavior
# ══════════════════════════════════════════════════════════════


class TestFallbackBehavior:
    def test_valid_defaults(self):
        f = FallbackBehavior()
        ok, _ = f.is_valid()
        assert ok is True

    def test_invalid_action(self):
        f = FallbackBehavior(on_gateway_unreachable="explode")
        ok, msg = f.is_valid()
        assert ok is False
        assert "explode" in msg


# ══════════════════════════════════════════════════════════════
# Enrollment Validator — cross-checks
# ══════════════════════════════════════════════════════════════


class TestEnrollmentValidator:
    def setup_method(self):
        self.validator = EnrollmentValidator()

    def test_valid_application_passes(self, valid_app):
        passed, violations = self.validator.validate(valid_app)
        assert passed is True
        assert violations == []

    def test_no_budget_rejected(self):
        app = _valid_application(budget_tokens=0, budget_usd=0.0)
        passed, violations = self.validator.validate(app)
        assert passed is False
        assert any("budget" in v.lower() for v in violations)

    def test_token_budget_alone_sufficient(self):
        app = _valid_application(budget_tokens=1000, budget_usd=0.0)
        passed, _ = self.validator.validate(app)
        assert passed is True

    def test_usd_budget_alone_sufficient(self):
        app = _valid_application(budget_tokens=0, budget_usd=1.0)
        passed, _ = self.validator.validate(app)
        assert passed is True

    def test_no_owner_rejected(self):
        app = _valid_application(owner="")
        passed, violations = self.validator.validate(app)
        assert passed is False
        assert any("owner" in v.lower() for v in violations)

    def test_short_owner_rejected(self):
        app = _valid_application(owner="X")
        passed, violations = self.validator.validate(app)
        assert passed is False

    def test_execution_access_without_execute_action(self):
        """execution_access=true requires 'execute' in allowed_actions."""
        app = _valid_application()
        app.capabilities.execution_access = True
        app.boundaries.allowed_actions = ["read", "write"]  # no "execute"
        passed, violations = self.validator.validate(app)
        assert passed is False
        assert any("execution_access" in v for v in violations)

    def test_network_access_without_hosts(self):
        """network_access=true requires at least one allowed_hosts."""
        app = _valid_application()
        app.capabilities.network_access = True
        app.resources.allowed_hosts = []
        passed, violations = self.validator.validate(app)
        assert passed is False
        assert any("network_access" in v for v in violations)

    def test_subagent_spawning_with_low_risk(self):
        """can_spawn_subagents=true is incompatible with low risk tier."""
        app = _valid_application()
        app.capabilities.can_spawn_subagents = True
        app.purpose.risk_tier = "low"
        passed, violations = self.validator.validate(app)
        assert passed is False
        assert any("subagent" in v.lower() for v in violations)

    def test_subagent_spawning_with_standard_risk_ok(self):
        app = _valid_application()
        app.capabilities.can_spawn_subagents = True
        app.purpose.risk_tier = "standard"
        passed, _ = self.validator.validate(app)
        assert passed is True

    def test_multiple_violations_all_reported(self):
        """All violations should be collected, not just the first."""
        app = _valid_application(
            owner="",
            budget_tokens=0,
            budget_usd=0.0,
        )
        app.capabilities.tools = []  # I-5 violation
        app.resources.allowed_paths = []  # S-1 violation
        app.resources.allowed_hosts = []
        app.boundaries.allowed_actions = []  # S-2 violation

        passed, violations = self.validator.validate(app)
        assert passed is False
        assert len(violations) >= 5  # At least I-5, S-1, S-2, owner, budget


# ══════════════════════════════════════════════════════════════
# Enrollment Registry
# ══════════════════════════════════════════════════════════════


class TestEnrollmentRegistry:
    def test_submit_valid_enrolls(self, enrollment_registry, valid_app):
        record = enrollment_registry.submit(valid_app)
        assert record.status == EnrollmentStatus.ENROLLED
        assert record.enrolled_at is not None
        assert record.violations == []

    def test_submit_invalid_is_incomplete(self, enrollment_registry):
        app = _valid_application(budget_tokens=0, budget_usd=0.0)
        record = enrollment_registry.submit(app)
        assert record.status == EnrollmentStatus.INCOMPLETE
        assert record.enrolled_at is None
        assert len(record.violations) > 0

    def test_is_enrolled(self, enrollment_registry, valid_app):
        enrollment_registry.submit(valid_app)
        assert enrollment_registry.is_enrolled("agent:test") is True

    def test_not_enrolled_unknown_agent(self, enrollment_registry):
        assert enrollment_registry.is_enrolled("agent:unknown") is False

    def test_not_enrolled_incomplete(self, enrollment_registry):
        app = _valid_application(budget_tokens=0, budget_usd=0.0)
        enrollment_registry.submit(app)
        assert enrollment_registry.is_enrolled("agent:test") is False

    def test_get_record(self, enrollment_registry, valid_app):
        enrollment_registry.submit(valid_app)
        record = enrollment_registry.get("agent:test")
        assert record is not None
        assert record.agent_id == "agent:test"

    def test_get_unknown_returns_none(self, enrollment_registry):
        assert enrollment_registry.get("agent:ghost") is None

    def test_get_all(self, enrollment_registry):
        for i in range(3):
            app = _valid_application(agent_id=f"agent:test-{i}")
            enrollment_registry.submit(app)
        assert len(enrollment_registry.get_all()) == 3

    def test_reject(self, enrollment_registry, valid_app):
        enrollment_registry.submit(valid_app)
        record = enrollment_registry.reject(
            "agent:test", reason="Failed security review", reviewed_by="admin@gavel.eu"
        )
        assert record.status == EnrollmentStatus.REJECTED
        assert record.rejection_reason == "Failed security review"
        assert record.reviewed_by == "admin@gavel.eu"

    def test_reject_unknown_returns_none(self, enrollment_registry):
        assert enrollment_registry.reject("agent:ghost", "reason", "admin") is None

    def test_approve_manual(self, enrollment_registry):
        """Manual approval overrides INCOMPLETE status."""
        app = _valid_application(budget_tokens=0, budget_usd=0.0)
        enrollment_registry.submit(app)
        assert enrollment_registry.is_enrolled("agent:test") is False

        record = enrollment_registry.approve_manual("agent:test", reviewed_by="admin@gavel.eu")
        assert record.status == EnrollmentStatus.ENROLLED
        assert record.enrolled_at is not None
        assert record.reviewed_by == "admin@gavel.eu"

    def test_suspend(self, enrollment_registry, valid_app):
        enrollment_registry.submit(valid_app)
        record = enrollment_registry.suspend("agent:test")
        assert record.status == EnrollmentStatus.SUSPENDED
        assert enrollment_registry.is_enrolled("agent:test") is False

    def test_suspend_unknown_returns_none(self, enrollment_registry):
        assert enrollment_registry.suspend("agent:ghost") is None

    def test_overwrite_existing_enrollment(self, enrollment_registry, valid_app):
        """Re-submitting overwrites the previous record."""
        enrollment_registry.submit(valid_app)
        assert enrollment_registry.is_enrolled("agent:test") is True

        bad_app = _valid_application(budget_tokens=0, budget_usd=0.0)
        enrollment_registry.submit(bad_app)
        assert enrollment_registry.is_enrolled("agent:test") is False


# ══════════════════════════════════════════════════════════════
# Governance Token — generation and format
# ══════════════════════════════════════════════════════════════


class TestGovernanceToken:
    def test_issue_token(self, token_manager):
        token = token_manager.issue("agent:test")
        assert token.token.startswith(TOKEN_PREFIX)
        assert token.agent_id == "agent:test"
        assert token.agent_did.startswith("did:gavel:agent:")
        assert token.revoked is False

    def test_token_has_expiry(self, token_manager):
        token = token_manager.issue("agent:test", ttl_seconds=3600)
        assert token.expires_at > token.issued_at
        delta = (token.expires_at - token.issued_at).total_seconds()
        assert 3599 <= delta <= 3601

    def test_token_uniqueness(self, token_manager):
        """Two tokens for the same agent should be different."""
        t1 = token_manager.issue("agent:test")
        t2 = token_manager.issue("agent:test")
        assert t1.token != t2.token
        assert t1.agent_did != t2.agent_did  # different DID each time

    def test_token_with_scope(self, token_manager):
        scope = {"tools": ["Read", "Write"], "allowed_actions": ["read"]}
        token = token_manager.issue("agent:test", scope=scope)
        assert token.scope == scope

    def test_token_binding(self, token_manager):
        """Token is bound to agent_id + machine_id + pid."""
        t1 = token_manager.issue("agent:a", machine_id="machine-1", pid=100)
        t2 = token_manager.issue("agent:a", machine_id="machine-2", pid=100)
        assert t1.token != t2.token  # different machine = different token


# ══════════════════════════════════════════════════════════════
# Token Validation — 5-point check
# ══════════════════════════════════════════════════════════════


class TestTokenValidation:
    def test_valid_token(self, token_manager):
        token = token_manager.issue("agent:test")
        valid, reason, record = token_manager.validate(token.token)
        assert valid is True
        assert reason == "valid"
        assert record is not None

    def test_invalid_format(self, token_manager):
        valid, reason, record = token_manager.validate("bad_token_string")
        assert valid is False
        assert "format" in reason.lower()
        assert record is None

    def test_unknown_token(self, token_manager):
        valid, reason, record = token_manager.validate(f"{TOKEN_PREFIX}{'a' * 64}")
        assert valid is False
        assert "not recognized" in reason.lower()

    def test_revoked_token(self, token_manager):
        token = token_manager.issue("agent:test")
        token_manager.revoke(token.agent_did)
        valid, reason, record = token_manager.validate(token.token)
        assert valid is False
        assert "revoked" in reason.lower()
        assert record is not None
        assert record.revoked is True

    def test_expired_token(self, token_manager):
        token = token_manager.issue("agent:test", ttl_seconds=0)
        # Token with 0 TTL expires immediately
        valid, reason, record = token_manager.validate(token.token)
        assert valid is False
        assert "expired" in reason.lower()

    def test_scope_check_pass(self, token_manager):
        scope = {"tools": ["Read"], "deploy": True}
        token = token_manager.issue("agent:test", scope=scope)
        valid, reason, _ = token_manager.validate(token.token, required_scope="tools")
        assert valid is True

    def test_scope_check_fail(self, token_manager):
        scope = {"tools": ["Read"]}
        token = token_manager.issue("agent:test", scope=scope)
        valid, reason, _ = token_manager.validate(token.token, required_scope="deploy")
        assert valid is False
        assert "scope" in reason.lower()

    def test_scope_check_skipped_when_no_scope(self, token_manager):
        """If token has no scope dict, scope check is skipped (passes)."""
        token = token_manager.issue("agent:test", scope=None)
        valid, _, _ = token_manager.validate(token.token, required_scope="anything")
        assert valid is True

    def test_is_valid_shorthand(self, token_manager):
        token = token_manager.issue("agent:test")
        assert token_manager.is_valid(token.token) is True
        token_manager.revoke(token.agent_did)
        assert token_manager.is_valid(token.token) is False


# ══════════════════════════════════════════════════════════════
# Token Revocation
# ══════════════════════════════════════════════════════════════


class TestTokenRevocation:
    def test_revoke_by_did(self, token_manager):
        token = token_manager.issue("agent:test")
        revoked = token_manager.revoke(token.agent_did)
        assert revoked is not None
        assert revoked.revoked is True

    def test_revoke_unknown_did(self, token_manager):
        result = token_manager.revoke("did:gavel:agent:nonexistent")
        assert result is None

    def test_revoke_is_immediate(self, token_manager):
        """Revocation takes effect immediately for subsequent validations."""
        token = token_manager.issue("agent:test")
        assert token_manager.is_valid(token.token) is True
        token_manager.revoke(token.agent_did)
        assert token_manager.is_valid(token.token) is False

    def test_get_by_did(self, token_manager):
        token = token_manager.issue("agent:test")
        found = token_manager.get_by_did(token.agent_did)
        assert found is not None
        assert found.token == token.token

    def test_get_by_did_unknown(self, token_manager):
        assert token_manager.get_by_did("did:gavel:agent:nope") is None
