import pytest
from datetime import datetime, timedelta, timezone

from gavel.hub import (
    AlertCategory,
    AlertConsole,
    AlertSeverity,
    AlertStatus,
    CorrelationSignal,
    CrossMachineCorrelator,
    EndpointOS,
    EndpointRecord,
    EndpointStatus,
    FleetDashboard,
    GavelAlert,
    GavelHub,
    HubEnrollmentRegistry,
    OrgChainEvent,
    OrgGovernanceChain,
    PolicyDistributor,
)


# ── EndpointRecord ──────────────────────────────────────────


class TestEndpointRecord:
    def test_defaults(self):
        ep = EndpointRecord(hostname="dev-01", os=EndpointOS.LINUX)
        assert ep.hostname == "dev-01"
        assert ep.os == EndpointOS.LINUX
        assert ep.endpoint_id.startswith("ep-")
        assert ep.status == EndpointStatus.ONLINE
        assert ep.installed_ai_tools == []
        assert ep.active_agent_ids == []
        assert ep.os_version == ""
        assert ep.ip_address == ""
        assert ep.agent_hash == ""

    def test_custom_fields(self):
        ep = EndpointRecord(
            hostname="prod-db",
            os=EndpointOS.WINDOWS,
            os_version="11",
            ip_address="10.0.0.5",
            org_id="acme",
            team_id="infra",
            agent_version="2.1.0",
            installed_ai_tools=["copilot"],
        )
        assert ep.org_id == "acme"
        assert ep.team_id == "infra"
        assert ep.installed_ai_tools == ["copilot"]
        assert ep.agent_version == "2.1.0"


# ── HubEnrollmentRegistry ──────────────────────────────────


class TestHubEnrollmentRegistry:
    def test_register_and_get(self):
        reg = HubEnrollmentRegistry()
        rec = reg.register("agent-1", "ep-1", display_name="Test Agent", owner="alice")
        assert rec.agent_id == "agent-1"
        assert rec.endpoint_id == "ep-1"
        assert rec.status == "active"
        assert reg.get("agent-1") is rec

    def test_get_missing(self):
        reg = HubEnrollmentRegistry()
        assert reg.get("nonexistent") is None

    def test_suspend(self):
        reg = HubEnrollmentRegistry()
        reg.register("a1", "ep-1")
        assert reg.suspend_agent("a1") is True
        assert reg.get("a1").status == "suspended"

    def test_suspend_missing(self):
        reg = HubEnrollmentRegistry()
        assert reg.suspend_agent("no-such") is False

    def test_revoke(self):
        reg = HubEnrollmentRegistry()
        reg.register("a1", "ep-1")
        assert reg.revoke_agent("a1") is True
        assert reg.get("a1").status == "revoked"

    def test_revoke_missing(self):
        reg = HubEnrollmentRegistry()
        assert reg.revoke_agent("ghost") is False

    def test_revoke_fleet_wide(self):
        reg = HubEnrollmentRegistry()
        reg.register("a1", "ep-1")
        reg._endpoint_agents["ep-2"].add("a1")
        affected = reg.revoke_agent_fleet_wide("a1")
        assert "ep-1" in affected
        assert "ep-2" in affected
        assert reg.get("a1").status == "revoked"

    def test_agents_on_endpoint(self):
        reg = HubEnrollmentRegistry()
        reg.register("a1", "ep-1")
        reg.register("a2", "ep-1")
        reg.register("a3", "ep-2")
        agents = reg.agents_on_endpoint("ep-1")
        assert len(agents) == 2
        assert {a.agent_id for a in agents} == {"a1", "a2"}

    def test_agents_on_endpoint_empty(self):
        reg = HubEnrollmentRegistry()
        assert reg.agents_on_endpoint("ep-none") == []

    def test_agents_by_org(self):
        reg = HubEnrollmentRegistry()
        reg.register("a1", "ep-1", org_id="acme")
        reg.register("a2", "ep-1", org_id="acme")
        reg.register("a3", "ep-2", org_id="globex")
        assert len(reg.agents_by_org("acme")) == 2
        assert len(reg.agents_by_org("globex")) == 1
        assert len(reg.agents_by_org("nobody")) == 0

    def test_agents_by_status(self):
        reg = HubEnrollmentRegistry()
        reg.register("a1", "ep-1")
        reg.register("a2", "ep-1")
        reg.suspend_agent("a2")
        assert len(reg.agents_by_status("active")) == 1
        assert len(reg.agents_by_status("suspended")) == 1
        assert len(reg.agents_by_status("revoked")) == 0

    def test_agent_count(self):
        reg = HubEnrollmentRegistry()
        assert reg.agent_count == 0
        reg.register("a1", "ep-1")
        reg.register("a2", "ep-1")
        assert reg.agent_count == 2


# ── OrgGovernanceChain ──────────────────────────────────────


class TestOrgGovernanceChain:
    def test_append_and_length(self):
        chain = OrgGovernanceChain()
        ev = chain.append("ep-1", "a1", "enrollment", {"name": "test"})
        assert chain.length == 1
        assert ev.event_type == "enrollment"
        assert ev.prev_hash == "genesis"
        assert ev.event_hash != ""

    def test_hash_chain_linkage(self):
        chain = OrgGovernanceChain()
        e1 = chain.append("ep-1", "a1", "enrollment")
        e2 = chain.append("ep-1", "a1", "decision")
        assert e2.prev_hash == e1.event_hash
        assert chain.head_hash == e2.event_hash

    def test_verify_integrity_valid(self):
        chain = OrgGovernanceChain()
        for i in range(5):
            chain.append(f"ep-{i}", f"a{i}", "heartbeat")
        valid, msg = chain.verify_integrity()
        assert valid is True
        assert msg == "ok"

    def test_verify_integrity_empty_chain(self):
        chain = OrgGovernanceChain()
        valid, msg = chain.verify_integrity()
        assert valid is True

    def test_verify_integrity_tampered_hash(self):
        chain = OrgGovernanceChain()
        chain.append("ep-1", "a1", "enrollment")
        chain.append("ep-1", "a1", "decision")
        chain._events[0].event_hash = "tampered"
        valid, msg = chain.verify_integrity()
        assert valid is False
        assert "hash mismatch" in msg

    def test_verify_integrity_tampered_prev_hash(self):
        chain = OrgGovernanceChain()
        chain.append("ep-1", "a1", "enrollment")
        chain.append("ep-1", "a1", "decision")
        chain._events[1].prev_hash = "wrong"
        valid, msg = chain.verify_integrity()
        assert valid is False
        assert "prev_hash mismatch" in msg

    def test_verify_integrity_tampered_event_type(self):
        chain = OrgGovernanceChain()
        chain.append("ep-1", "a1", "decision")
        chain.append("ep-1", "a1", "heartbeat")
        chain._events[0].event_type = "violation"
        valid, msg = chain.verify_integrity()
        assert valid is False

    def test_events_by_endpoint(self):
        chain = OrgGovernanceChain()
        chain.append("ep-1", "a1", "enrollment")
        chain.append("ep-2", "a2", "enrollment")
        chain.append("ep-1", "a1", "decision")
        assert len(chain.events_by_endpoint("ep-1")) == 2
        assert len(chain.events_by_endpoint("ep-2")) == 1

    def test_events_by_agent(self):
        chain = OrgGovernanceChain()
        chain.append("ep-1", "a1", "enrollment")
        chain.append("ep-1", "a2", "enrollment")
        chain.append("ep-1", "a1", "decision")
        assert len(chain.events_by_agent("a1")) == 2
        assert len(chain.events_by_agent("a2")) == 1

    def test_events_by_type(self):
        chain = OrgGovernanceChain()
        chain.append("ep-1", "a1", "enrollment")
        chain.append("ep-1", "a1", "violation")
        chain.append("ep-1", "a1", "violation")
        assert len(chain.events_by_type("violation")) == 2
        assert len(chain.events_by_type("enrollment")) == 1

    def test_events_in_window(self):
        chain = OrgGovernanceChain()
        now = datetime.now(timezone.utc)
        e1 = chain.append("ep-1", "a1", "enrollment")
        e1.timestamp = now - timedelta(hours=2)
        e2 = chain.append("ep-1", "a1", "decision")
        e2.timestamp = now - timedelta(minutes=30)
        e3 = chain.append("ep-1", "a1", "violation")
        e3.timestamp = now
        start = now - timedelta(hours=1)
        end = now + timedelta(seconds=1)
        window = chain.events_in_window(start, end)
        assert len(window) == 2

    def test_events_in_window_empty(self):
        chain = OrgGovernanceChain()
        now = datetime.now(timezone.utc)
        e1 = chain.append("ep-1", "a1", "enrollment")
        e1.timestamp = now - timedelta(days=10)
        window = chain.events_in_window(now - timedelta(hours=1), now)
        assert len(window) == 0


# ── PolicyDistributor ───────────────────────────────────────


class TestPolicyDistributor:
    def test_publish(self):
        pd = PolicyDistributor()
        pv = pd.publish("constitution", {"rule_1": "no harm"}, created_by="admin")
        assert pv.policy_name == "constitution"
        assert pv.version_number == 1
        assert pv.content_hash != ""
        assert pv.created_by == "admin"

    def test_publish_increments_version(self):
        pd = PolicyDistributor()
        pd.publish("constitution", {"v": 1})
        pv2 = pd.publish("constitution", {"v": 2})
        assert pv2.version_number == 2

    def test_publish_different_policies_independent_versions(self):
        pd = PolicyDistributor()
        pd.publish("constitution", {"v": 1})
        pv_other = pd.publish("other-policy", {"x": 1})
        assert pv_other.version_number == 1

    def test_distribute_and_pending(self):
        pd = PolicyDistributor()
        pv = pd.publish("constitution", {"v": 1})
        records = pd.distribute(pv.version_id, ["ep-1", "ep-2", "ep-3"])
        assert len(records) == 3
        pending = pd.pending_endpoints(pv.version_id)
        assert set(pending) == {"ep-1", "ep-2", "ep-3"}

    def test_acknowledge(self):
        pd = PolicyDistributor()
        pv = pd.publish("constitution", {"v": 1})
        pd.distribute(pv.version_id, ["ep-1", "ep-2"])
        assert pd.acknowledge("ep-1", pv.version_id) is True
        pending = pd.pending_endpoints(pv.version_id)
        assert pending == ["ep-2"]

    def test_acknowledge_unknown(self):
        pd = PolicyDistributor()
        assert pd.acknowledge("ep-999", "pv-fake") is False

    def test_latest_version(self):
        pd = PolicyDistributor()
        pd.publish("constitution", {"v": 1})
        pv2 = pd.publish("constitution", {"v": 2})
        latest = pd.latest_version("constitution")
        assert latest.version_id == pv2.version_id
        assert latest.version_number == 2

    def test_latest_version_nonexistent(self):
        pd = PolicyDistributor()
        assert pd.latest_version("nonexistent") is None

    def test_endpoint_version(self):
        pd = PolicyDistributor()
        pv = pd.publish("constitution", {"v": 1})
        pd.distribute(pv.version_id, ["ep-1"])
        assert pd.endpoint_version("ep-1") == pv.version_id
        assert pd.endpoint_version("ep-unknown") is None


# ── CrossMachineCorrelator ──────────────────────────────────


class TestCrossMachineCorrelator:
    def _make_event(self, endpoint_id, agent_id, event_type="decision",
                    payload=None, timestamp=None):
        return OrgChainEvent(
            endpoint_id=endpoint_id,
            agent_id=agent_id,
            event_type=event_type,
            payload=payload or {},
            timestamp=timestamp or datetime.now(timezone.utc),
        )

    def test_analyze_timing_coordinated(self):
        corr = CrossMachineCorrelator()
        now = datetime.now(timezone.utc)
        events = [
            self._make_event("ep-1", "a1", timestamp=now),
            self._make_event("ep-2", "a2", timestamp=now),
        ]
        findings = corr.analyze_timing(events)
        assert len(findings) >= 1
        assert findings[0].signal == CorrelationSignal.COORDINATED_TIMING
        assert len(findings[0].endpoints) == 2

    def test_analyze_timing_single_endpoint_no_finding(self):
        corr = CrossMachineCorrelator()
        now = datetime.now(timezone.utc)
        events = [
            self._make_event("ep-1", "a1", timestamp=now),
            self._make_event("ep-1", "a2", timestamp=now),
        ]
        findings = corr.analyze_timing(events)
        assert len(findings) == 0

    def test_analyze_shared_targets(self):
        corr = CrossMachineCorrelator(shared_target_threshold=2)
        events = [
            self._make_event("ep-1", "a1", payload={"target": "/etc/passwd"}),
            self._make_event("ep-2", "a2", payload={"target": "/etc/passwd"}),
        ]
        findings = corr.analyze_shared_targets(events)
        assert len(findings) == 1
        assert findings[0].signal == CorrelationSignal.SHARED_TARGET
        assert findings[0].severity == "high"

    def test_analyze_shared_targets_below_threshold(self):
        corr = CrossMachineCorrelator(shared_target_threshold=5)
        events = [
            self._make_event("ep-1", "a1", payload={"target": "/etc/passwd"}),
            self._make_event("ep-2", "a2", payload={"target": "/etc/passwd"}),
        ]
        findings = corr.analyze_shared_targets(events)
        assert len(findings) == 0

    def test_analyze_data_exfil(self):
        corr = CrossMachineCorrelator()
        now = datetime.now(timezone.utc)
        events = [
            self._make_event("ep-1", "a1",
                             payload={"action": "file_read", "target": "secrets.db"},
                             timestamp=now - timedelta(seconds=10)),
            self._make_event("ep-2", "a2",
                             payload={"action": "network_send", "target": "evil.com"},
                             timestamp=now),
        ]
        findings = corr.analyze_data_exfil(events)
        assert len(findings) == 1
        assert findings[0].signal == CorrelationSignal.DATA_EXFIL_PATTERN
        assert findings[0].severity == "critical"

    def test_analyze_data_exfil_same_endpoint_ignored(self):
        corr = CrossMachineCorrelator()
        now = datetime.now(timezone.utc)
        events = [
            self._make_event("ep-1", "a1",
                             payload={"action": "read", "target": "data.csv"},
                             timestamp=now - timedelta(seconds=10)),
            self._make_event("ep-1", "a2",
                             payload={"action": "send", "target": "out.com"},
                             timestamp=now),
        ]
        findings = corr.analyze_data_exfil(events)
        assert len(findings) == 0

    def test_correlate_runs_all(self):
        corr = CrossMachineCorrelator(shared_target_threshold=2)
        now = datetime.now(timezone.utc)
        events = [
            self._make_event("ep-1", "a1", timestamp=now,
                             payload={"target": "/data", "action": "file_read"}),
            self._make_event("ep-2", "a2", timestamp=now,
                             payload={"target": "/data", "action": "network_send"}),
        ]
        findings = corr.correlate(events)
        signals = {f.signal for f in findings}
        assert CorrelationSignal.COORDINATED_TIMING in signals
        assert len(corr.all_findings) == len(findings)


# ── AlertConsole ────────────────────────────────────────────


class TestAlertConsole:
    def test_create_alert(self):
        console = AlertConsole()
        alert = console.create_alert(
            category=AlertCategory.VIOLATION,
            severity=AlertSeverity.HIGH,
            title="Bad agent",
            endpoint_id="ep-1",
            agent_id="a1",
        )
        assert alert.status == AlertStatus.OPEN
        assert alert.alert_id.startswith("alert-")
        assert console.total == 1

    def test_get(self):
        console = AlertConsole()
        alert = console.create_alert(AlertCategory.ANOMALY, AlertSeverity.INFO, "X")
        assert console.get(alert.alert_id) is alert
        assert console.get("nonexistent") is None

    def test_acknowledge(self):
        console = AlertConsole()
        alert = console.create_alert(AlertCategory.ANOMALY, AlertSeverity.WARNING, "Test")
        assert console.acknowledge(alert.alert_id) is True
        assert console.get(alert.alert_id).status == AlertStatus.ACKNOWLEDGED
        assert console.get(alert.alert_id).acknowledged_at is not None

    def test_acknowledge_non_open_fails(self):
        console = AlertConsole()
        alert = console.create_alert(AlertCategory.ANOMALY, AlertSeverity.WARNING, "Test")
        console.acknowledge(alert.alert_id)
        assert console.acknowledge(alert.alert_id) is False

    def test_acknowledge_nonexistent_fails(self):
        console = AlertConsole()
        assert console.acknowledge("no-such") is False

    def test_resolve(self):
        console = AlertConsole()
        alert = console.create_alert(AlertCategory.VIOLATION, AlertSeverity.CRITICAL, "Breach")
        assert console.resolve(alert.alert_id, resolved_by="admin") is True
        resolved = console.get(alert.alert_id)
        assert resolved.status == AlertStatus.RESOLVED
        assert resolved.resolved_by == "admin"
        assert resolved.resolved_at is not None

    def test_resolve_already_resolved_fails(self):
        console = AlertConsole()
        alert = console.create_alert(AlertCategory.VIOLATION, AlertSeverity.HIGH, "X")
        console.resolve(alert.alert_id)
        assert console.resolve(alert.alert_id) is False

    def test_resolve_dismissed_fails(self):
        console = AlertConsole()
        alert = console.create_alert(AlertCategory.ANOMALY, AlertSeverity.INFO, "X")
        console.dismiss(alert.alert_id)
        assert console.resolve(alert.alert_id) is False

    def test_dismiss(self):
        console = AlertConsole()
        alert = console.create_alert(AlertCategory.ANOMALY, AlertSeverity.INFO, "Low")
        assert console.dismiss(alert.alert_id) is True
        assert console.get(alert.alert_id).status == AlertStatus.DISMISSED

    def test_dismiss_nonexistent(self):
        console = AlertConsole()
        assert console.dismiss("no-such") is False

    def test_open_alerts(self):
        console = AlertConsole()
        console.create_alert(AlertCategory.VIOLATION, AlertSeverity.HIGH, "A")
        a2 = console.create_alert(AlertCategory.ANOMALY, AlertSeverity.WARNING, "B")
        console.resolve(a2.alert_id)
        assert len(console.open_alerts()) == 1

    def test_filter_by_severity(self):
        console = AlertConsole()
        console.create_alert(AlertCategory.VIOLATION, AlertSeverity.HIGH, "A")
        console.create_alert(AlertCategory.VIOLATION, AlertSeverity.CRITICAL, "B")
        console.create_alert(AlertCategory.ANOMALY, AlertSeverity.HIGH, "C")
        assert len(console.alerts_by_severity(AlertSeverity.HIGH)) == 2
        assert len(console.alerts_by_severity(AlertSeverity.CRITICAL)) == 1

    def test_filter_by_category(self):
        console = AlertConsole()
        console.create_alert(AlertCategory.VIOLATION, AlertSeverity.HIGH, "A")
        console.create_alert(AlertCategory.TAMPER_DETECTED, AlertSeverity.CRITICAL, "B")
        assert len(console.alerts_by_category(AlertCategory.VIOLATION)) == 1
        assert len(console.alerts_by_category(AlertCategory.TAMPER_DETECTED)) == 1

    def test_filter_by_endpoint(self):
        console = AlertConsole()
        console.create_alert(AlertCategory.ANOMALY, AlertSeverity.HIGH, "A", endpoint_id="ep-1")
        console.create_alert(AlertCategory.ANOMALY, AlertSeverity.HIGH, "B", endpoint_id="ep-2")
        console.create_alert(AlertCategory.ANOMALY, AlertSeverity.HIGH, "C", endpoint_id="ep-1")
        assert len(console.alerts_by_endpoint("ep-1")) == 2
        assert len(console.alerts_by_endpoint("ep-3")) == 0

    def test_critical_count(self):
        console = AlertConsole()
        a1 = console.create_alert(AlertCategory.VIOLATION, AlertSeverity.CRITICAL, "A")
        console.create_alert(AlertCategory.VIOLATION, AlertSeverity.CRITICAL, "B")
        console.create_alert(AlertCategory.VIOLATION, AlertSeverity.HIGH, "C")
        assert console.critical_count() == 2
        console.resolve(a1.alert_id)
        assert console.critical_count() == 1


# ── GavelHub ────────────────────────────────────────────────


class TestGavelHub:
    def test_register_endpoint(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX, org_id="acme")
        assert ep.endpoint_id in hub.endpoints
        assert hub.chain.length == 1
        events = hub.chain.events_by_type("endpoint_enrolled")
        assert len(events) == 1

    def test_heartbeat_updates_status(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        ep.status = EndpointStatus.DEGRADED
        assert hub.heartbeat(ep.endpoint_id) is True
        assert hub.endpoints[ep.endpoint_id].status == EndpointStatus.ONLINE

    def test_heartbeat_unknown_endpoint(self):
        hub = GavelHub()
        assert hub.heartbeat("ep-nonexistent") is False

    def test_heartbeat_unregistered_agent_alert(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        hub.heartbeat(ep.endpoint_id, active_agent_ids=["rogue-agent"])
        alerts = hub.alerts.alerts_by_category(AlertCategory.UNREGISTERED_AGENT)
        assert len(alerts) == 1
        assert "rogue-agent" in alerts[0].title

    def test_heartbeat_registered_agent_no_alert(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        hub.register_agent("a1", ep.endpoint_id)
        hub.heartbeat(ep.endpoint_id, active_agent_ids=["a1"])
        alerts = hub.alerts.alerts_by_category(AlertCategory.UNREGISTERED_AGENT)
        assert len(alerts) == 0

    def test_heartbeat_tamper_detection(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX, agent_hash="abc123")
        hub.heartbeat(ep.endpoint_id, agent_hash="different_hash")
        tamper_alerts = hub.alerts.alerts_by_category(AlertCategory.TAMPER_DETECTED)
        assert len(tamper_alerts) == 1
        assert tamper_alerts[0].severity == AlertSeverity.CRITICAL

    def test_heartbeat_no_tamper_when_hash_matches(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX, agent_hash="abc123")
        hub.heartbeat(ep.endpoint_id, agent_hash="abc123")
        tamper_alerts = hub.alerts.alerts_by_category(AlertCategory.TAMPER_DETECTED)
        assert len(tamper_alerts) == 0

    def test_heartbeat_new_tool_detection(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        ep.installed_ai_tools = ["copilot"]
        hub.heartbeat(ep.endpoint_id, installed_ai_tools=["copilot", "claude-code"])
        alerts = hub.alerts.alerts_by_category(AlertCategory.UNREGISTERED_AGENT)
        assert any("New AI tool" in a.title for a in alerts)

    def test_check_stale_endpoints(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        ep.last_heartbeat = datetime.now(timezone.utc) - timedelta(minutes=10)
        stale = hub.check_stale_endpoints(timeout_minutes=5)
        assert ep.endpoint_id in stale
        assert hub.endpoints[ep.endpoint_id].status == EndpointStatus.OFFLINE
        hb_alerts = hub.alerts.alerts_by_category(AlertCategory.HEARTBEAT_MISSED)
        assert len(hb_alerts) == 1

    def test_check_stale_endpoints_fresh_not_affected(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        stale = hub.check_stale_endpoints(timeout_minutes=5)
        assert len(stale) == 0
        assert hub.endpoints[ep.endpoint_id].status == EndpointStatus.ONLINE

    def test_decommission_endpoint(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        hub.register_agent("a1", ep.endpoint_id)
        ep.active_agent_ids = ["a1"]
        assert hub.decommission_endpoint(ep.endpoint_id) is True
        assert hub.endpoints[ep.endpoint_id].status == EndpointStatus.DECOMMISSIONED
        assert hub.enrollment.get("a1").status == "revoked"

    def test_decommission_nonexistent(self):
        hub = GavelHub()
        assert hub.decommission_endpoint("ep-fake") is False

    def test_register_agent(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        rec = hub.register_agent("a1", ep.endpoint_id, display_name="Agent One")
        assert rec is not None
        assert rec.agent_id == "a1"
        assert hub.chain.length == 2

    def test_register_agent_unknown_endpoint(self):
        hub = GavelHub()
        assert hub.register_agent("a1", "ep-nonexistent") is None

    def test_kill_agent_fleet_wide(self):
        hub = GavelHub()
        ep = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        hub.register_agent("a1", ep.endpoint_id)
        affected = hub.kill_agent_fleet_wide("a1")
        assert ep.endpoint_id in affected
        assert hub.enrollment.get("a1").status == "revoked"
        violation_alerts = hub.alerts.alerts_by_category(AlertCategory.VIOLATION)
        assert len(violation_alerts) == 1

    def test_kill_agent_fleet_wide_no_agent(self):
        hub = GavelHub()
        affected = hub.kill_agent_fleet_wide("ghost")
        assert affected == []

    def test_dashboard(self):
        hub = GavelHub()
        ep1 = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        ep2 = hub.register_endpoint("dev-02", EndpointOS.WINDOWS)
        hub.register_agent("a1", ep1.endpoint_id)
        hub.register_agent("a2", ep1.endpoint_id)
        hub.enrollment.suspend_agent("a2")
        ep2.status = EndpointStatus.OFFLINE
        dash = hub.dashboard()
        assert dash.total_endpoints == 2
        assert dash.online_endpoints == 1
        assert dash.offline_endpoints == 1
        assert dash.total_agents == 2
        assert dash.active_agents == 1
        assert dash.suspended_agents == 1
        assert dash.chain_length >= 3

    def test_push_policy_all(self):
        hub = GavelHub()
        ep1 = hub.register_endpoint("dev-01", EndpointOS.LINUX)
        ep2 = hub.register_endpoint("dev-02", EndpointOS.WINDOWS)
        pv = hub.push_policy("constitution", {"rule": "no harm"}, created_by="admin")
        assert pv.version_number == 1
        pending = hub.policy.pending_endpoints(pv.version_id)
        assert set(pending) == {ep1.endpoint_id, ep2.endpoint_id}

    def test_push_policy_scoped(self):
        hub = GavelHub()
        ep1 = hub.register_endpoint("dev-01", EndpointOS.LINUX, org_id="acme")
        hub.register_endpoint("dev-02", EndpointOS.WINDOWS, org_id="globex")
        pv = hub.push_policy("constitution", {"rule": "no harm"}, target_scope="acme")
        pending = hub.policy.pending_endpoints(pv.version_id)
        assert len(pending) == 1
        assert pending[0] == ep1.endpoint_id

    def test_push_policy_creates_chain_event(self):
        hub = GavelHub()
        hub.register_endpoint("dev-01", EndpointOS.LINUX)
        hub.push_policy("constitution", {"rule": "no harm"})
        events = hub.chain.events_by_type("policy_distributed")
        assert len(events) == 1
        assert events[0].payload["policy_name"] == "constitution"
