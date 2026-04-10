import pytest

from gavel.fleet import (
    AutoUpdater,
    ComplianceStatus,
    DeploymentManager,
    FleetManager,
    GroupPolicyManager,
    KillOrderRegistry,
    LiveAgentMap,
    MachineInventory,
    PackageFormat,
    PolicyScope,
    UpdateStatus,
)


# ── MachineInventory ────────────────────────────────────────


class TestMachineInventory:
    def test_upsert_and_get(self):
        inv = MachineInventory()
        rec = inv.upsert("ep-1", "host1", "windows", os_version="11")
        assert rec.endpoint_id == "ep-1"
        assert rec.hostname == "host1"
        assert inv.get("ep-1") is rec

    def test_upsert_overwrites(self):
        inv = MachineInventory()
        inv.upsert("ep-1", "host1", "windows")
        inv.upsert("ep-1", "host1-updated", "linux")
        assert inv.total == 1
        assert inv.get("ep-1").hostname == "host1-updated"

    def test_compliance_thresholds(self):
        inv = MachineInventory()
        assert inv.upsert("a", "h", "w", compliance_score=0.95).compliance_status == ComplianceStatus.COMPLIANT
        assert inv.upsert("b", "h", "w", compliance_score=0.6).compliance_status == ComplianceStatus.PARTIAL
        assert inv.upsert("c", "h", "w", compliance_score=0.3).compliance_status == ComplianceStatus.NON_COMPLIANT
        assert inv.upsert("d", "h", "w", compliance_score=0.0).compliance_status == ComplianceStatus.UNKNOWN

    def test_by_org(self):
        inv = MachineInventory()
        inv.upsert("ep-1", "h1", "w", org_id="org-a")
        inv.upsert("ep-2", "h2", "w", org_id="org-b")
        inv.upsert("ep-3", "h3", "w", org_id="org-a")
        assert len(inv.by_org("org-a")) == 2

    def test_by_team(self):
        inv = MachineInventory()
        inv.upsert("ep-1", "h1", "w", team_id="t1")
        inv.upsert("ep-2", "h2", "w", team_id="t2")
        assert len(inv.by_team("t1")) == 1

    def test_by_compliance(self):
        inv = MachineInventory()
        inv.upsert("ep-1", "h1", "w", compliance_score=0.95)
        inv.upsert("ep-2", "h2", "w", compliance_score=0.3)
        assert len(inv.by_compliance(ComplianceStatus.COMPLIANT)) == 1

    def test_non_compliant(self):
        inv = MachineInventory()
        inv.upsert("ep-1", "h1", "w", compliance_score=0.95)
        inv.upsert("ep-2", "h2", "w", compliance_score=0.3)
        inv.upsert("ep-3", "h3", "w", compliance_score=0.1)
        assert len(inv.non_compliant()) == 2

    def test_org_compliance_score(self):
        inv = MachineInventory()
        inv.upsert("ep-1", "h1", "w", org_id="org-a", compliance_score=0.8)
        inv.upsert("ep-2", "h2", "w", org_id="org-a", compliance_score=0.4)
        assert inv.org_compliance_score("org-a") == pytest.approx(0.6)
        assert inv.org_compliance_score("org-none") == 0.0

    def test_fleet_compliance_score(self):
        inv = MachineInventory()
        assert inv.fleet_compliance_score() == 0.0
        inv.upsert("ep-1", "h1", "w", compliance_score=1.0)
        inv.upsert("ep-2", "h2", "w", compliance_score=0.5)
        assert inv.fleet_compliance_score() == pytest.approx(0.75)

    def test_remove(self):
        inv = MachineInventory()
        inv.upsert("ep-1", "h1", "w")
        assert inv.remove("ep-1") is True
        assert inv.remove("ep-1") is False
        assert inv.get("ep-1") is None


# ── GroupPolicyManager ──────────────────────────────────────


class TestGroupPolicyManager:
    def test_create_policy(self):
        mgr = GroupPolicyManager()
        p = mgr.create_policy("Global baseline", PolicyScope.GLOBAL, constitution={"audit": True})
        assert p.name == "Global baseline"
        assert p.scope == PolicyScope.GLOBAL
        assert mgr.policy_count == 1

    def test_update_policy(self):
        mgr = GroupPolicyManager()
        p = mgr.create_policy("test", PolicyScope.GLOBAL)
        updated = mgr.update_policy(p.policy_id, constitution={"new": True}, enabled=False)
        assert updated.constitution == {"new": True}
        assert updated.enabled is False

    def test_update_policy_not_found(self):
        mgr = GroupPolicyManager()
        assert mgr.update_policy("nope") is None

    def test_delete_policy(self):
        mgr = GroupPolicyManager()
        p = mgr.create_policy("test", PolicyScope.GLOBAL)
        assert mgr.delete_policy(p.policy_id) is True
        assert mgr.delete_policy(p.policy_id) is False
        assert mgr.policy_count == 0

    def test_create_group_and_membership(self):
        mgr = GroupPolicyManager()
        g = mgr.create_group("servers", endpoint_ids=["ep-1"])
        assert mgr.group_count == 1
        assert mgr.add_to_group(g.group_id, "ep-2") is True
        assert "ep-2" in mgr._groups[g.group_id].endpoint_ids
        assert mgr.remove_from_group(g.group_id, "ep-2") is True
        assert mgr.remove_from_group(g.group_id, "ep-2") is False

    def test_add_to_group_nonexistent(self):
        mgr = GroupPolicyManager()
        assert mgr.add_to_group("nope", "ep-1") is False

    def test_remove_from_group_nonexistent(self):
        mgr = GroupPolicyManager()
        assert mgr.remove_from_group("nope", "ep-1") is False

    def test_resolve_policies_all_scopes(self):
        mgr = GroupPolicyManager()
        mgr.create_policy("global", PolicyScope.GLOBAL, priority=0)
        mgr.create_policy("org", PolicyScope.ORG, scope_id="org-a", priority=1)
        mgr.create_policy("team", PolicyScope.TEAM, scope_id="team-x", priority=2)
        mgr.create_policy("endpoint", PolicyScope.ENDPOINT, scope_id="ep-1", priority=3)
        g = mgr.create_group("grp", endpoint_ids=["ep-1"])
        mgr.create_policy("group", PolicyScope.MACHINE_GROUP, scope_id=g.group_id, priority=4)

        resolved = mgr.resolve_policies("ep-1", org_id="org-a", team_id="team-x")
        assert len(resolved) == 5
        assert [p.priority for p in resolved] == [0, 1, 2, 3, 4]

    def test_resolve_policies_skips_disabled(self):
        mgr = GroupPolicyManager()
        p = mgr.create_policy("disabled", PolicyScope.GLOBAL)
        mgr.update_policy(p.policy_id, enabled=False)
        assert mgr.resolve_policies("ep-1") == []

    def test_effective_constitution_merges(self):
        mgr = GroupPolicyManager()
        mgr.create_policy("base", PolicyScope.GLOBAL, constitution={"audit": True, "log": False}, priority=0)
        mgr.create_policy("override", PolicyScope.ORG, scope_id="org-a", constitution={"log": True}, priority=1)
        merged = mgr.effective_constitution("ep-1", org_id="org-a")
        assert merged == {"audit": True, "log": True}


# ── KillOrderRegistry ──────────────────────────────────────


class TestKillOrderRegistry:
    def test_issue_and_complete(self):
        reg = KillOrderRegistry()
        order = reg.issue("agent-1", ["ep-1", "ep-2"], reason="compromised")
        assert order.agent_id == "agent-1"
        assert order.status == "issued"
        assert reg.complete(order.kill_id) is True
        assert order.status == "completed"

    def test_complete_nonexistent(self):
        reg = KillOrderRegistry()
        assert reg.complete("nope") is False

    def test_orders_for_agent(self):
        reg = KillOrderRegistry()
        reg.issue("agent-1", ["ep-1"])
        reg.issue("agent-2", ["ep-2"])
        reg.issue("agent-1", ["ep-3"])
        assert len(reg.orders_for_agent("agent-1")) == 2
        assert len(reg.orders_for_agent("agent-2")) == 1


# ── DeploymentManager ──────────────────────────────────────


class TestDeploymentManager:
    def test_register_marks_old_not_current(self):
        dm = DeploymentManager()
        p1 = dm.register_package("1.0", PackageFormat.MSI)
        p2 = dm.register_package("2.0", PackageFormat.MSI)
        assert p1.is_current is False
        assert p2.is_current is True

    def test_current_package(self):
        dm = DeploymentManager()
        dm.register_package("1.0", PackageFormat.DEB)
        dm.register_package("2.0", PackageFormat.DEB)
        current = dm.current_package(PackageFormat.DEB)
        assert current.version == "2.0"
        assert dm.current_package(PackageFormat.RPM) is None

    def test_packages_for_version(self):
        dm = DeploymentManager()
        dm.register_package("1.0", PackageFormat.MSI)
        dm.register_package("1.0", PackageFormat.DEB)
        dm.register_package("2.0", PackageFormat.MSI)
        assert len(dm.packages_for_version("1.0")) == 2

    def test_verify_package(self):
        dm = DeploymentManager()
        pkg = dm.register_package("1.0", PackageFormat.MSI, package_hash="abc123")
        assert dm.verify_package(pkg.package_id, "abc123") is True
        assert dm.verify_package(pkg.package_id, "wrong") is False
        assert dm.verify_package("no-such-id", "abc123") is False


# ── AutoUpdater ─────────────────────────────────────────────


class TestAutoUpdater:
    def test_register_and_check_update(self):
        au = AutoUpdater()
        au.register_endpoint_version("ep-1", "1.0")
        rec = au.check_update("ep-1", "2.0")
        assert rec is not None
        assert rec.from_version == "1.0"
        assert rec.to_version == "2.0"

    def test_check_update_already_current(self):
        au = AutoUpdater()
        au.register_endpoint_version("ep-1", "2.0")
        assert au.check_update("ep-1", "2.0") is None

    def test_check_update_unknown_endpoint(self):
        au = AutoUpdater()
        assert au.check_update("ep-unknown", "2.0") is None

    def test_start_update(self):
        au = AutoUpdater()
        au.register_endpoint_version("ep-1", "1.0")
        rec = au.check_update("ep-1", "2.0")
        assert au.start_update(rec.update_id) is True
        assert rec.status == UpdateStatus.DOWNLOADING
        assert rec.started_at is not None

    def test_complete_update(self):
        au = AutoUpdater()
        au.register_endpoint_version("ep-1", "1.0")
        rec = au.check_update("ep-1", "2.0")
        assert au.complete_update(rec.update_id) is True
        assert rec.status == UpdateStatus.COMPLETED
        assert au._endpoint_versions["ep-1"] == "2.0"

    def test_fail_update(self):
        au = AutoUpdater()
        au.register_endpoint_version("ep-1", "1.0")
        rec = au.check_update("ep-1", "2.0")
        assert au.fail_update(rec.update_id, error="disk full") is True
        assert rec.status == UpdateStatus.FAILED
        assert rec.error == "disk full"

    def test_fail_update_nonexistent(self):
        au = AutoUpdater()
        assert au.fail_update("nope") is False

    def test_endpoints_needing_update(self):
        au = AutoUpdater()
        au.register_endpoint_version("ep-1", "1.0")
        au.register_endpoint_version("ep-2", "2.0")
        au.register_endpoint_version("ep-3", "1.5")
        needing = au.endpoints_needing_update("2.0")
        assert sorted(needing) == ["ep-1", "ep-3"]


# ── LiveAgentMap ────────────────────────────────────────────


class TestLiveAgentMap:
    def test_update_and_get(self):
        lam = LiveAgentMap()
        loc = lam.update("a-1", "ep-1", hostname="host1")
        assert loc.agent_id == "a-1"
        assert lam.get("a-1") is loc

    def test_remove(self):
        lam = LiveAgentMap()
        lam.update("a-1", "ep-1")
        assert lam.remove("a-1") is True
        assert lam.remove("a-1") is False
        assert lam.get("a-1") is None

    def test_agents_on(self):
        lam = LiveAgentMap()
        lam.update("a-1", "ep-1")
        lam.update("a-2", "ep-1")
        lam.update("a-3", "ep-2")
        assert len(lam.agents_on("ep-1")) == 2

    def test_active_agents(self):
        lam = LiveAgentMap()
        lam.update("a-1", "ep-1", status="active")
        lam.update("a-2", "ep-1", status="stopped")
        assert len(lam.active_agents()) == 1

    def test_endpoints_with_agents(self):
        lam = LiveAgentMap()
        lam.update("a-1", "ep-1")
        lam.update("a-2", "ep-1")
        lam.update("a-3", "ep-2")
        mapping = lam.endpoints_with_agents()
        assert set(mapping.keys()) == {"ep-1", "ep-2"}
        assert sorted(mapping["ep-1"]) == ["a-1", "a-2"]


# ── FleetManager ────────────────────────────────────────────


class TestFleetManager:
    def test_sync_endpoint(self):
        fm = FleetManager()
        rec = fm.sync_endpoint(
            "ep-1", "host1", "windows",
            active_agents=["a-1", "a-2"],
            agent_version="1.0",
            compliance_score=0.95,
        )
        assert rec.endpoint_id == "ep-1"
        assert fm.agent_map.get("a-1") is not None
        assert fm.agent_map.get("a-2") is not None
        assert fm.updater._endpoint_versions["ep-1"] == "1.0"

    def test_kill_agent(self):
        fm = FleetManager()
        fm.sync_endpoint("ep-1", "host1", "w", active_agents=["a-1"])
        order = fm.kill_agent("a-1", reason="rogue", issued_by="admin")
        assert order.agent_id == "a-1"
        assert "ep-1" in order.affected_endpoints
        assert fm.agent_map.get("a-1") is None

    def test_kill_agent_not_tracked(self):
        fm = FleetManager()
        order = fm.kill_agent("ghost")
        assert order.affected_endpoints == []

    def test_fleet_summary(self):
        fm = FleetManager()
        fm.sync_endpoint("ep-1", "h1", "w", compliance_score=0.95, active_agents=["a-1"])
        fm.sync_endpoint("ep-2", "h2", "w", compliance_score=0.3)
        fm.policies.create_policy("base", PolicyScope.GLOBAL)
        summary = fm.fleet_summary()
        assert summary["total_machines"] == 2
        assert summary["total_agents_tracked"] == 1
        assert summary["active_policies"] == 1
        assert summary["non_compliant"] == 1
