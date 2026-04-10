"""Tests for gavel.tenants — multi-tenant isolation."""

from __future__ import annotations

import pytest

from gavel.tenants import (
    Organization,
    OrgStatus,
    Team,
    TenantAgentQuota,
    TenantContext,
    TenantIsolationEnforcer,
    TenantRegistry,
)


@pytest.fixture
def registry():
    return TenantRegistry()


@pytest.fixture
def populated_registry(registry):
    org = registry.create_org("Acme Corp", billing_owner="cfo@acme.com")
    team = registry.create_team(org.org_id, "Engineering", owner="eng-lead@acme.com")
    return registry, org, team


class TestTenantRegistry:
    def test_create_org(self, registry):
        org = registry.create_org("Acme", billing_owner="cfo@acme.com")
        assert org.name == "Acme"
        assert org.status == OrgStatus.ACTIVE
        assert org.org_id.startswith("org-")

    def test_create_team_under_org(self, populated_registry):
        registry, org, team = populated_registry
        assert team.org_id == org.org_id
        assert team.name == "Engineering"
        assert team.team_id.startswith("team-")

    def test_create_team_fails_for_unknown_org(self, registry):
        with pytest.raises(ValueError, match="not found"):
            registry.create_team("org-nonexistent", "Team", owner="x")

    def test_create_team_fails_for_suspended_org(self, registry):
        org = registry.create_org("Suspended Inc", billing_owner="x")
        registry.suspend_org(org.org_id)
        with pytest.raises(ValueError, match="suspended"):
            registry.create_team(org.org_id, "Team", owner="x")

    def test_list_teams_scoped_to_org(self, registry):
        org1 = registry.create_org("Org1", billing_owner="a")
        org2 = registry.create_org("Org2", billing_owner="b")
        registry.create_team(org1.org_id, "Team1A", owner="x")
        registry.create_team(org1.org_id, "Team1B", owner="x")
        registry.create_team(org2.org_id, "Team2A", owner="x")
        assert len(registry.list_teams(org1.org_id)) == 2
        assert len(registry.list_teams(org2.org_id)) == 1

    def test_delete_team(self, populated_registry):
        registry, org, team = populated_registry
        assert registry.delete_team(team.team_id)
        assert len(registry.list_teams(org.org_id)) == 0

    def test_team_limit_enforced(self, registry):
        org = registry.create_org("Small", billing_owner="x", max_teams=2)
        registry.create_team(org.org_id, "T1", owner="x")
        registry.create_team(org.org_id, "T2", owner="x")
        with pytest.raises(ValueError, match="team limit"):
            registry.create_team(org.org_id, "T3", owner="x")

    def test_list_orgs(self, registry):
        registry.create_org("A", billing_owner="x")
        registry.create_org("B", billing_owner="y")
        assert len(registry.list_orgs()) == 2

    def test_suspend_org(self, registry):
        org = registry.create_org("X", billing_owner="x")
        registry.suspend_org(org.org_id)
        assert registry.get_org(org.org_id).status == OrgStatus.SUSPENDED


class TestTenantIsolation:
    def test_store_and_retrieve_within_tenant(self, populated_registry):
        registry, org, team = populated_registry
        enforcer = TenantIsolationEnforcer(registry)
        ctx = TenantContext(org_id=org.org_id, team_id=team.team_id, operator_id="op:1")
        enforcer.store("rec-1", org.org_id, team.team_id, {"key": "val"})
        record = enforcer.get("rec-1", ctx)
        assert record is not None
        assert record["key"] == "val"

    def test_cross_tenant_read_returns_none(self, registry):
        org1 = registry.create_org("Org1", billing_owner="a")
        org2 = registry.create_org("Org2", billing_owner="b")
        t1 = registry.create_team(org1.org_id, "T1", owner="x")
        t2 = registry.create_team(org2.org_id, "T2", owner="y")
        enforcer = TenantIsolationEnforcer(registry)
        enforcer.store("rec-1", org1.org_id, t1.team_id, {"secret": "data"})
        ctx2 = TenantContext(org_id=org2.org_id, team_id=t2.team_id, operator_id="op:2")
        assert enforcer.get("rec-1", ctx2) is None

    def test_platform_admin_reads_across_tenants(self, populated_registry):
        registry, org, team = populated_registry
        enforcer = TenantIsolationEnforcer(registry)
        enforcer.store("rec-1", org.org_id, team.team_id, {"data": "x"})
        admin_ctx = TenantContext(org_id="other", team_id="other", operator_id="admin", is_platform_admin=True)
        assert enforcer.get("rec-1", admin_ctx) is not None

    def test_list_records_scoped(self, registry):
        org1 = registry.create_org("O1", billing_owner="a")
        org2 = registry.create_org("O2", billing_owner="b")
        t1 = registry.create_team(org1.org_id, "T1", owner="x")
        t2 = registry.create_team(org2.org_id, "T2", owner="y")
        enforcer = TenantIsolationEnforcer(registry)
        enforcer.store("r1", org1.org_id, t1.team_id, {})
        enforcer.store("r2", org1.org_id, t1.team_id, {})
        enforcer.store("r3", org2.org_id, t2.team_id, {})
        ctx1 = TenantContext(org_id=org1.org_id, team_id=t1.team_id, operator_id="op")
        assert enforcer.count(ctx1) == 2
        ctx2 = TenantContext(org_id=org2.org_id, team_id=t2.team_id, operator_id="op")
        assert enforcer.count(ctx2) == 1

    def test_store_rejects_invalid_org(self, populated_registry):
        registry, org, team = populated_registry
        enforcer = TenantIsolationEnforcer(registry)
        with pytest.raises(ValueError, match="not found"):
            enforcer.store("r", "bogus", team.team_id, {})

    def test_store_rejects_cross_org_team(self, registry):
        org1 = registry.create_org("O1", billing_owner="a")
        org2 = registry.create_org("O2", billing_owner="b")
        t2 = registry.create_team(org2.org_id, "T2", owner="y")
        enforcer = TenantIsolationEnforcer(registry)
        with pytest.raises(ValueError, match="does not belong"):
            enforcer.store("r", org1.org_id, t2.team_id, {})

    def test_delete_enforces_tenant_scope(self, registry):
        org1 = registry.create_org("O1", billing_owner="a")
        org2 = registry.create_org("O2", billing_owner="b")
        t1 = registry.create_team(org1.org_id, "T1", owner="x")
        t2 = registry.create_team(org2.org_id, "T2", owner="y")
        enforcer = TenantIsolationEnforcer(registry)
        enforcer.store("r1", org1.org_id, t1.team_id, {})
        ctx2 = TenantContext(org_id=org2.org_id, team_id=t2.team_id, operator_id="op")
        assert not enforcer.delete("r1", ctx2)


class TestAgentQuota:
    def test_can_enroll_within_limits(self, populated_registry):
        registry, org, team = populated_registry
        quota = TenantAgentQuota(registry)
        ok, msg = quota.can_enroll(org.org_id, team.team_id)
        assert ok

    def test_org_limit_enforced(self, registry):
        org = registry.create_org("Small", billing_owner="x", max_agents=2)
        team = registry.create_team(org.org_id, "T", owner="x")
        quota = TenantAgentQuota(registry)
        quota.record_enrollment(org.org_id, team.team_id)
        quota.record_enrollment(org.org_id, team.team_id)
        ok, msg = quota.can_enroll(org.org_id, team.team_id)
        assert not ok
        assert "agent limit" in msg

    def test_team_limit_enforced(self, registry):
        org = registry.create_org("Big", billing_owner="x", max_agents=100)
        team = registry.create_team(org.org_id, "Tiny", owner="x", max_agents=1)
        quota = TenantAgentQuota(registry)
        quota.record_enrollment(org.org_id, team.team_id)
        ok, msg = quota.can_enroll(org.org_id, team.team_id)
        assert not ok
        assert "Team" in msg

    def test_disenrollment_frees_quota(self, registry):
        org = registry.create_org("X", billing_owner="x", max_agents=1)
        team = registry.create_team(org.org_id, "T", owner="x")
        quota = TenantAgentQuota(registry)
        quota.record_enrollment(org.org_id, team.team_id)
        ok, _ = quota.can_enroll(org.org_id, team.team_id)
        assert not ok
        quota.record_disenrollment(org.org_id, team.team_id)
        ok, _ = quota.can_enroll(org.org_id, team.team_id)
        assert ok

    def test_usage_reporting(self, populated_registry):
        registry, org, team = populated_registry
        quota = TenantAgentQuota(registry)
        quota.record_enrollment(org.org_id, team.team_id)
        usage = quota.org_usage(org.org_id)
        assert usage["enrolled"] == 1
        assert usage["limit"] == org.max_agents
