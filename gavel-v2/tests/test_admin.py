"""Tests for Admin Agent — triple gate, audit guarantee, forbidden operations."""

from __future__ import annotations

import os

import pytest

from gavel.admin import (
    AdminAgent,
    AdminAuditViolation,
    AdminGateResult,
    AdminToken,
    SecurityViolation,
    get_machine_id,
    is_admin_safe,
    validate_admin_gates,
    validate_environment_for_production,
)
from gavel.chain import EventType, GovernanceChain
from gavel.enrollment import EnrollmentRegistry, EnrollmentStatus


# ══════════════════════════════════════════════════════════════
# Machine ID
# ══════════════════════════════════════════════════════════════


class TestMachineId:
    def test_machine_id_deterministic(self):
        """Same machine produces same ID."""
        id1 = get_machine_id()
        id2 = get_machine_id()
        assert id1 == id2

    def test_machine_id_is_sha256(self):
        mid = get_machine_id()
        assert len(mid) == 64  # SHA-256 hex length
        assert all(c in "0123456789abcdef" for c in mid)


# ══════════════════════════════════════════════════════════════
# Admin Token
# ══════════════════════════════════════════════════════════════


class TestAdminToken:
    def test_generate_token(self):
        token = AdminToken.generate("dev@gavel.eu", "machine123")
        assert token.token.startswith("gvl_admin_")
        assert token.operator == "dev@gavel.eu"
        assert token.machine_id == "machine123"
        assert token.capabilities == ["*"]
        assert token.revoked is False
        assert token.expires_at is None  # dev-only, no expiry

    def test_token_uniqueness(self):
        t1 = AdminToken.generate("dev@gavel.eu", "machine123")
        t2 = AdminToken.generate("dev@gavel.eu", "machine123")
        assert t1.token != t2.token


# ══════════════════════════════════════════════════════════════
# Triple Gate Validation
# ══════════════════════════════════════════════════════════════


class TestAdminGates:
    def setup_method(self):
        """Save and clear admin-related env vars."""
        self._saved = {}
        for key in ("GAVEL_ADMIN_MODE", "GAVEL_ENV", "GAVEL_ADMIN_MACHINES"):
            self._saved[key] = os.environ.get(key)
            if key in os.environ:
                del os.environ[key]

    def teardown_method(self):
        """Restore env vars."""
        for key, val in self._saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val

    def test_gate1_admin_mode_not_set(self):
        result = validate_admin_gates()
        assert result.passed is False
        assert result.failure_gate == "env_flag"

    def test_gate1_admin_mode_false(self):
        os.environ["GAVEL_ADMIN_MODE"] = "false"
        result = validate_admin_gates()
        assert result.passed is False
        assert result.failure_gate == "env_flag"

    def test_gate2_production_blocked(self):
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "production"
        result = validate_admin_gates()
        assert result.passed is False
        assert result.failure_gate == "production_block"
        assert result.env_flag_ok is True  # gate 1 passed

    def test_gate3_no_allowlist(self):
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "development"
        result = validate_admin_gates(allowlist=set())
        assert result.passed is False
        assert result.failure_gate == "machine_allowlist"
        assert result.env_flag_ok is True
        assert result.production_block_ok is True

    def test_gate3_machine_not_in_allowlist(self):
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "development"
        result = validate_admin_gates(allowlist={"wrong_machine_id"})
        assert result.passed is False
        assert result.failure_gate == "machine_allowlist"

    def test_all_gates_pass(self):
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "development"
        machine_id = get_machine_id()
        result = validate_admin_gates(allowlist={machine_id})
        assert result.passed is True
        assert result.env_flag_ok is True
        assert result.production_block_ok is True
        assert result.machine_allowlist_ok is True

    def test_gate_reads_from_env_var(self):
        """GAVEL_ADMIN_MACHINES env var is read when allowlist param is None."""
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "development"
        machine_id = get_machine_id()
        os.environ["GAVEL_ADMIN_MACHINES"] = machine_id
        result = validate_admin_gates(allowlist=None)
        assert result.passed is True


# ══════════════════════════════════════════════════════════════
# AdminAgent — construction and lifecycle
# ══════════════════════════════════════════════════════════════


class TestAdminAgent:
    def setup_method(self):
        self._saved = {}
        for key in ("GAVEL_ADMIN_MODE", "GAVEL_ENV", "GAVEL_ADMIN_MACHINES"):
            self._saved[key] = os.environ.get(key)
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "development"

    def teardown_method(self):
        for key, val in self._saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val

    def _make_agent(self, operator="dev@gavel.eu"):
        registry = EnrollmentRegistry()
        machine_id = get_machine_id()
        return AdminAgent(
            operator=operator,
            registry=registry,
            allowlist={machine_id},
        )

    def test_construction_succeeds(self):
        agent = self._make_agent()
        assert agent.is_active is True
        assert agent.operator == "dev@gavel.eu"
        assert agent.token.token.startswith("gvl_admin_")

    def test_construction_fails_without_admin_mode(self):
        os.environ["GAVEL_ADMIN_MODE"] = "false"
        with pytest.raises(SecurityViolation) as exc_info:
            self._make_agent()
        assert exc_info.value.gate == "env_flag"

    def test_construction_fails_in_production(self):
        os.environ["GAVEL_ENV"] = "production"
        with pytest.raises(SecurityViolation) as exc_info:
            self._make_agent()
        assert exc_info.value.gate == "production_block"

    def test_construction_fails_wrong_machine(self):
        with pytest.raises(SecurityViolation) as exc_info:
            registry = EnrollmentRegistry()
            AdminAgent(
                operator="dev@gavel.eu",
                registry=registry,
                allowlist={"wrong_machine_hash"},
            )
        assert exc_info.value.gate == "machine_allowlist"

    def test_blocked_attempt_logged_to_chain(self):
        """Even a failed activation attempt is logged."""
        os.environ["GAVEL_ADMIN_MODE"] = "false"
        chain = GovernanceChain()
        registry = EnrollmentRegistry()
        with pytest.raises(SecurityViolation):
            AdminAgent(
                operator="attacker",
                registry=registry,
                allowlist=set(),
                audit_chain=chain,
            )
        # The chain should have a denial event
        assert len(chain.events) == 1
        assert chain.events[0].event_type == EventType.AUTO_DENIED
        assert "ADMIN_BLOCKED" in str(chain.events[0].payload)


# ══════════════════════════════════════════════════════════════
# AdminAgent — execute with audit guarantee
# ══════════════════════════════════════════════════════════════


class TestAdminExecution:
    def setup_method(self):
        self._saved = {}
        for key in ("GAVEL_ADMIN_MODE", "GAVEL_ENV"):
            self._saved[key] = os.environ.get(key)
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        os.environ["GAVEL_ENV"] = "development"
        self.machine_id = get_machine_id()

    def teardown_method(self):
        for key, val in self._saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val

    def _make_agent(self):
        return AdminAgent(
            operator="dev@gavel.eu",
            registry=EnrollmentRegistry(),
            allowlist={self.machine_id},
        )

    def test_execute_returns_receipt(self):
        agent = self._make_agent()
        result = agent.execute("deploy_model", {"model": "v2.3"})
        assert result["status"] == "executed"
        assert result["action"] == "deploy_model"
        assert result["governance_bypassed"] is True
        assert result["audit_recorded"] is True
        assert "event_hash" in result

    def test_execute_increments_counter(self):
        agent = self._make_agent()
        assert agent.action_count == 0
        agent.execute("action_1")
        agent.execute("action_2")
        assert agent.action_count == 2

    def test_execute_creates_chain_event(self):
        agent = self._make_agent()
        agent.execute("test_action", {"key": "val"})
        # Chain should have: registration event + execution event
        events = agent.audit_chain.events
        assert len(events) >= 2
        exec_event = events[-1]
        assert exec_event.payload["action"] == "test_action"
        assert exec_event.payload["audit_recorded"] is True

    def test_audit_chain_integrity_after_execution(self):
        agent = self._make_agent()
        for i in range(5):
            agent.execute(f"action_{i}")
        assert agent.audit_chain.verify_integrity() is True

    def test_forbidden_operation_blocked(self):
        """Admin cannot disable audit logging."""
        agent = self._make_agent()
        with pytest.raises(AdminAuditViolation) as exc_info:
            agent.execute("disable_audit")
        assert exc_info.value.operation == "disable_audit"

    @pytest.mark.parametrize("op", [
        "disable_audit",
        "delete_audit_ledger",
        "truncate_audit_ledger",
        "clear_audit_ledger",
        "pause_audit",
        "stop_audit",
        "modify_audit_chain",
        "rewrite_audit_history",
    ])
    def test_all_forbidden_operations(self, op):
        agent = self._make_agent()
        with pytest.raises(AdminAuditViolation):
            agent.execute(op)

    def test_forbidden_op_still_logged(self):
        """Even a blocked forbidden operation gets a chain event."""
        agent = self._make_agent()
        events_before = len(agent.audit_chain.events)
        with pytest.raises(AdminAuditViolation):
            agent.execute("delete_audit_ledger")
        events_after = len(agent.audit_chain.events)
        assert events_after > events_before

    def test_execute_after_end_session_raises(self):
        agent = self._make_agent()
        agent.end_session()
        assert agent.is_active is False
        with pytest.raises(RuntimeError, match="not active"):
            agent.execute("anything")

    def test_end_session_revokes_token(self):
        agent = self._make_agent()
        agent.end_session()
        assert agent._token.revoked is True

    def test_end_session_idempotent(self):
        agent = self._make_agent()
        agent.end_session()
        agent.end_session()  # should not raise


# ══════════════════════════════════════════════════════════════
# Production Safety
# ══════════════════════════════════════════════════════════════


class TestProductionSafety:
    def setup_method(self):
        self._saved = {}
        for key in ("GAVEL_ADMIN_MODE", "GAVEL_ENV", "GAVEL_ADMIN_MACHINES"):
            self._saved[key] = os.environ.get(key)
            if key in os.environ:
                del os.environ[key]

    def teardown_method(self):
        for key, val in self._saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val

    def test_is_admin_safe_default(self):
        """No env vars = safe."""
        assert is_admin_safe() is True

    def test_is_admin_safe_production(self):
        os.environ["GAVEL_ENV"] = "production"
        os.environ["GAVEL_ADMIN_MODE"] = "true"  # even with this
        assert is_admin_safe() is True  # production always blocks

    def test_is_admin_safe_dev_with_admin(self):
        os.environ["GAVEL_ENV"] = "development"
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        assert is_admin_safe() is False  # admin active in non-prod

    def test_validate_production_clean(self):
        os.environ["GAVEL_ENV"] = "production"
        is_safe, warnings = validate_environment_for_production()
        assert is_safe is True
        assert warnings == []

    def test_validate_production_with_admin_mode(self):
        os.environ["GAVEL_ENV"] = "production"
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        is_safe, warnings = validate_environment_for_production()
        assert is_safe is False
        assert any("GAVEL_ADMIN_MODE" in w for w in warnings)

    def test_validate_production_with_machine_list(self):
        os.environ["GAVEL_ENV"] = "production"
        os.environ["GAVEL_ADMIN_MACHINES"] = "abc123"
        is_safe, warnings = validate_environment_for_production()
        assert is_safe is False
        assert any("GAVEL_ADMIN_MACHINES" in w for w in warnings)
