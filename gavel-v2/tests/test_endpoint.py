import hashlib
import pytest

from gavel.endpoint import (
    CachedPolicy,
    EndpointAgentStatus,
    EnforcementAction,
    GavelEndpointAgent,
    HeartbeatPayload,
    HeartbeatResponse,
    HubConnectionState,
    IntegrityStatus,
    LocalEnforcer,
    PolicyCache,
    RemoteCommand,
    RemoteCommandStatus,
    RemoteCommandType,
    TamperProtection,
)


# ── PolicyCache ─────────────────────────────────────────────


class TestPolicyCache:
    def test_store_and_get(self):
        cache = PolicyCache()
        cached = cache.store("v1", "access_control", {"max_tier": 3})
        assert cached.version_id == "v1"
        assert cached.policy_name == "access_control"
        assert cached.content == {"max_tier": 3}
        retrieved = cache.get("access_control")
        assert retrieved is not None
        assert retrieved.version_id == "v1"

    def test_store_auto_generates_hash(self):
        cache = PolicyCache()
        cached = cache.store("v1", "pol", {"key": "val"})
        assert len(cached.content_hash) == 64

    def test_store_with_explicit_hash(self):
        cache = PolicyCache()
        cached = cache.store("v1", "pol", {}, content_hash="abc123")
        assert cached.content_hash == "abc123"

    def test_get_missing_returns_none(self):
        cache = PolicyCache()
        assert cache.get("nonexistent") is None

    def test_is_current_true(self):
        cache = PolicyCache()
        cache.store("v1", "pol", {"a": 1}, content_hash="hash1")
        assert cache.is_current("pol", "hash1") is True

    def test_is_current_false_wrong_hash(self):
        cache = PolicyCache()
        cache.store("v1", "pol", {"a": 1}, content_hash="hash1")
        assert cache.is_current("pol", "hash2") is False

    def test_is_current_false_missing_policy(self):
        cache = PolicyCache()
        assert cache.is_current("missing", "hash1") is False

    def test_all_policies(self):
        cache = PolicyCache()
        cache.store("v1", "pol_a", {})
        cache.store("v2", "pol_b", {})
        policies = cache.all_policies()
        assert len(policies) == 2
        names = {p.policy_name for p in policies}
        assert names == {"pol_a", "pol_b"}

    def test_store_overwrites_same_name(self):
        cache = PolicyCache()
        cache.store("v1", "pol", {"old": True})
        cache.store("v2", "pol", {"new": True})
        assert cache.count == 1
        assert cache.get("pol").version_id == "v2"

    def test_history_preserves_all_versions(self):
        cache = PolicyCache()
        cache.store("v1", "pol", {"a": 1})
        cache.store("v2", "pol", {"a": 2})
        assert len(cache._history) == 2


# ── LocalEnforcer ───────────────────────────────────────────


class TestLocalEnforcer:
    def test_register_and_enforce_allow(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("agent-1")
        record = enforcer.enforce("agent-1", "read_data")
        assert record.decision == EnforcementAction.ALLOW
        assert record.agent_id == "agent-1"

    def test_enforce_unregistered_denied(self):
        enforcer = LocalEnforcer()
        record = enforcer.enforce("unknown-agent", "write_data")
        assert record.decision == EnforcementAction.DENY
        assert "not registered" in record.reason.lower()

    def test_block_and_enforce_denied(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("agent-1")
        enforcer.block_agent("agent-1")
        record = enforcer.enforce("agent-1", "read_data")
        assert record.decision == EnforcementAction.DENY
        assert "blocked" in record.reason.lower()

    def test_unblock_restores_allow(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("agent-1")
        enforcer.block_agent("agent-1")
        enforcer.unblock_agent("agent-1")
        record = enforcer.enforce("agent-1", "read_data")
        assert record.decision == EnforcementAction.ALLOW

    def test_kill_agent_removes_and_blocks(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("agent-1")
        result = enforcer.kill_agent("agent-1")
        assert result is True
        assert "agent-1" not in enforcer.active_agent_ids
        assert enforcer.is_blocked("agent-1")

    def test_enforcement_log_accumulates(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("a1")
        enforcer.enforce("a1", "act1")
        enforcer.enforce("a1", "act2")
        assert len(enforcer.enforcement_log) == 2

    def test_enforce_records_policy_version(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("a1")
        record = enforcer.enforce("a1", "run", policy_version="v3")
        assert record.policy_version == "v3"

    def test_active_agent_ids_tracks_registered(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("a1")
        enforcer.register_local_agent("a2")
        assert set(enforcer.active_agent_ids) == {"a1", "a2"}

    def test_block_takes_precedence_over_registered(self):
        enforcer = LocalEnforcer()
        enforcer.register_local_agent("a1")
        enforcer.block_agent("a1")
        assert enforcer.is_blocked("a1")
        record = enforcer.enforce("a1", "anything")
        assert record.decision == EnforcementAction.DENY


# ── TamperProtection ────────────────────────────────────────


class TestTamperProtection:
    def test_verify_no_reference_hash(self):
        tp = TamperProtection()
        check = tp.verify(b"content")
        assert check.status == IntegrityStatus.UNKNOWN

    def test_verify_matching_hash(self):
        content = b"my agent binary"
        ref = hashlib.sha256(content).hexdigest()
        tp = TamperProtection(reference_hash=ref)
        check = tp.verify(content)
        assert check.status == IntegrityStatus.VERIFIED

    def test_verify_tampered(self):
        tp = TamperProtection(reference_hash="deadbeef" * 8)
        check = tp.verify(b"tampered content")
        assert check.status == IntegrityStatus.TAMPERED
        assert "mismatch" in check.details.lower()

    def test_set_reference_hash(self):
        tp = TamperProtection()
        tp.set_reference_hash("abc")
        check = tp.verify(b"x")
        assert check.expected_hash == "abc"
        assert check.status == IntegrityStatus.TAMPERED

    def test_is_tampered_false_before_any_check(self):
        tp = TamperProtection(reference_hash="wrong" * 13)
        assert tp.is_tampered is False

    def test_is_tampered_true_after_failed_check(self):
        tp = TamperProtection(reference_hash="wrong" * 13)
        tp.verify(b"data")
        assert tp.is_tampered is True

    def test_check_history(self):
        tp = TamperProtection()
        tp.verify(b"a")
        tp.verify(b"b")
        assert len(tp.check_history) == 2

    def test_last_check_none_initially(self):
        tp = TamperProtection()
        assert tp.last_check is None


# ── HeartbeatPayload ────────────────────────────────────────


class TestHeartbeatPayload:
    def test_construction(self):
        hb = HeartbeatPayload(
            endpoint_id="ep-001",
            hostname="workstation-1",
            os="linux",
            os_version="6.1",
            status=EndpointAgentStatus.RUNNING,
            agent_version="1.0.0",
            agent_hash="abc123",
            active_agent_ids=["a1", "a2"],
            uptime_seconds=120,
        )
        assert hb.endpoint_id == "ep-001"
        assert hb.active_agent_ids == ["a1", "a2"]
        assert hb.uptime_seconds == 120
        assert hb.timestamp is not None

    def test_defaults(self):
        hb = HeartbeatPayload(
            endpoint_id="ep-002",
            hostname="h",
            os="win",
            os_version="11",
            status=EndpointAgentStatus.RUNNING,
            agent_version="1.0.0",
            agent_hash="",
        )
        assert hb.active_agent_ids == []
        assert hb.installed_ai_tools == []
        assert hb.policy_versions == {}
        assert hb.uptime_seconds == 0


# ── GavelEndpointAgent ──────────────────────────────────────


class TestGavelEndpointAgent:
    def test_initial_state(self):
        agent = GavelEndpointAgent(hostname="test-host")
        assert agent.endpoint_id.startswith("ep-")
        assert agent.status == EndpointAgentStatus.RUNNING
        assert agent.hub_connection == HubConnectionState.DISCONNECTED
        assert agent.is_enrolled is False
        assert agent.heartbeat_count == 0

    def test_build_enrollment_payload(self):
        agent = GavelEndpointAgent(hostname="test-host", org_id="org-1", team_id="team-1")
        payload = agent.build_enrollment_payload()
        assert payload["hostname"] == "test-host"
        assert payload["org_id"] == "org-1"
        assert payload["team_id"] == "team-1"
        assert payload["endpoint_id"] == agent.endpoint_id

    def test_mark_enrolled(self):
        agent = GavelEndpointAgent()
        assert agent.is_enrolled is False
        agent.mark_enrolled()
        assert agent.is_enrolled is True
        assert agent.hub_connection == HubConnectionState.CONNECTED

    def test_build_heartbeat(self):
        agent = GavelEndpointAgent(hostname="hb-host", agent_version="2.0.0")
        agent.enforcer.register_local_agent("a1")
        agent.policy_cache.store("v1", "pol1", {})
        hb = agent.build_heartbeat()
        assert hb.hostname == "hb-host"
        assert hb.agent_version == "2.0.0"
        assert "a1" in hb.active_agent_ids
        assert "pol1" in hb.policy_versions
        assert hb.policy_versions["pol1"] == "v1"
        assert hb.uptime_seconds >= 0

    def test_process_heartbeat_response_with_policy_updates(self):
        agent = GavelEndpointAgent()
        response = HeartbeatResponse(
            policy_updates=[
                {"version_id": "v5", "policy_name": "new_pol", "content": {"rule": 1}},
            ],
        )
        agent.process_heartbeat_response(response)
        assert agent.policy_cache.get("new_pol") is not None
        assert agent.heartbeat_count == 1
        assert agent.hub_connection == HubConnectionState.CONNECTED

    def test_process_heartbeat_response_with_commands(self):
        agent = GavelEndpointAgent()
        agent.enforcer.register_local_agent("victim")
        cmd = RemoteCommand(
            command_type=RemoteCommandType.KILL_AGENT,
            target_agent_id="victim",
        )
        response = HeartbeatResponse(pending_commands=[cmd])
        executed = agent.process_heartbeat_response(response)
        assert len(executed) == 1
        assert executed[0].status == RemoteCommandStatus.COMPLETED
        assert agent.enforcer.is_blocked("victim")

    def test_execute_revoke_token(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(command_type=RemoteCommandType.REVOKE_TOKEN, target_agent_id="a1")
        result = agent.execute_command(cmd)
        assert result.status == RemoteCommandStatus.COMPLETED
        assert result.result["revoked"] is True
        assert agent.enforcer.is_blocked("a1")

    def test_execute_revoke_token_no_target(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(command_type=RemoteCommandType.REVOKE_TOKEN)
        result = agent.execute_command(cmd)
        assert result.status == RemoteCommandStatus.FAILED

    def test_execute_kill_agent(self):
        agent = GavelEndpointAgent()
        agent.enforcer.register_local_agent("target")
        cmd = RemoteCommand(command_type=RemoteCommandType.KILL_AGENT, target_agent_id="target")
        result = agent.execute_command(cmd)
        assert result.status == RemoteCommandStatus.COMPLETED
        assert result.result["killed"] is True
        assert "target" not in agent.enforcer.active_agent_ids

    def test_execute_kill_agent_no_target(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(command_type=RemoteCommandType.KILL_AGENT)
        result = agent.execute_command(cmd)
        assert result.status == RemoteCommandStatus.FAILED

    def test_execute_update_policy(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(
            command_type=RemoteCommandType.UPDATE_POLICY,
            payload={"version_id": "v3", "policy_name": "firewall", "content": {"block": True}},
        )
        agent.execute_command(cmd)
        assert agent.policy_cache.get("firewall") is not None
        assert agent.policy_cache.get("firewall").version_id == "v3"

    def test_execute_force_re_register(self):
        agent = GavelEndpointAgent()
        agent.mark_enrolled()
        cmd = RemoteCommand(command_type=RemoteCommandType.FORCE_RE_REGISTER)
        agent.execute_command(cmd)
        assert agent.is_enrolled is False
        assert agent.hub_connection == HubConnectionState.DISCONNECTED

    def test_execute_collect_inventory(self):
        agent = GavelEndpointAgent(hostname="inv-host")
        cmd = RemoteCommand(command_type=RemoteCommandType.COLLECT_INVENTORY)
        result = agent.execute_command(cmd)
        assert result.result["hostname"] == "inv-host"
        assert result.status == RemoteCommandStatus.COMPLETED

    def test_execute_self_update(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(
            command_type=RemoteCommandType.SELF_UPDATE,
            payload={"target_version": "2.0.0", "package_hash": "newhash"},
        )
        result = agent.execute_command(cmd)
        assert result.status == RemoteCommandStatus.COMPLETED
        assert result.result["updated_to"] == "2.0.0"

    def test_execute_self_update_no_version(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(command_type=RemoteCommandType.SELF_UPDATE, payload={})
        result = agent.execute_command(cmd)
        assert result.status == RemoteCommandStatus.FAILED

    def test_enter_exit_degraded_mode(self):
        agent = GavelEndpointAgent()
        assert agent.is_degraded is False
        agent.enter_degraded_mode()
        assert agent.is_degraded is True
        assert agent.status == EndpointAgentStatus.DEGRADED
        assert agent.hub_connection == HubConnectionState.DISCONNECTED
        agent.exit_degraded_mode()
        assert agent.is_degraded is False
        assert agent.status == EndpointAgentStatus.RUNNING
        assert agent.hub_connection == HubConnectionState.CONNECTED

    def test_collect_inventory(self):
        agent = GavelEndpointAgent(hostname="inv-host", agent_version="1.2.3")
        agent.enforcer.register_local_agent("a1")
        agent.policy_cache.store("v1", "pol1", {})
        inv = agent.collect_inventory()
        assert inv["hostname"] == "inv-host"
        assert inv["agent_version"] == "1.2.3"
        assert "a1" in inv["active_agents"]
        assert "pol1" in inv["cached_policies"]
        assert inv["integrity_status"] == "unchecked"
        assert inv["enrolled"] is False

    def test_collect_inventory_with_integrity_check(self):
        agent = GavelEndpointAgent()
        content = b"binary"
        ref = hashlib.sha256(content).hexdigest()
        agent.tamper.set_reference_hash(ref)
        agent.tamper.verify(content)
        inv = agent.collect_inventory()
        assert inv["integrity_status"] == "verified"

    def test_command_log(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(command_type=RemoteCommandType.COLLECT_INVENTORY)
        agent.execute_command(cmd)
        assert len(agent.command_log) == 1
        assert agent.command_log[0].completed_at is not None

    def test_commands_set_completed_at(self):
        agent = GavelEndpointAgent()
        cmd = RemoteCommand(command_type=RemoteCommandType.COLLECT_INVENTORY)
        agent.execute_command(cmd)
        assert cmd.completed_at is not None
