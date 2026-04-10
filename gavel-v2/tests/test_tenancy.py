"""Tests for gavel.tenancy — multi-tenant isolation."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from gavel.tenancy import (
    PartitionedStore,
    Tenant,
    TenantContext,
    TenantIsolationError,
    TenantRegistry,
    TenantStatus,
    UnknownTenantError,
    require_same_tenant,
    with_tenant_scope,
)


class Item(BaseModel):
    value: str
    tenant_id: str | None = None


def _fresh_registry() -> TenantRegistry:
    r = TenantRegistry()
    r.register(Tenant(
        tenant_id="acme",
        display_name="Acme Corp",
        owner_contact="ops@acme.test",
    ))
    r.register(Tenant(
        tenant_id="globex",
        display_name="Globex Inc",
        owner_contact="ops@globex.test",
    ))
    return r


class TestContext:
    def test_single_tenant_scope(self):
        ctx = TenantContext.single("op:a", "acme")
        assert ctx.can_see("acme")
        assert not ctx.can_see("globex")

    def test_cross_tenant_sees_everything(self):
        ctx = TenantContext.cross_tenant("op:root", ["acme", "globex"])
        assert ctx.can_see("acme")
        assert ctx.can_see("globex")
        assert ctx.can_see("anything")  # wildcard


class TestRegistry:
    def test_register_and_get(self):
        r = _fresh_registry()
        assert r.get("acme").display_name == "Acme Corp"

    def test_duplicate_registration_rejected(self):
        r = _fresh_registry()
        with pytest.raises(ValueError):
            r.register(Tenant(
                tenant_id="acme",
                display_name="x",
                owner_contact="x@x",
            ))

    def test_unknown_tenant_raises(self):
        r = _fresh_registry()
        with pytest.raises(UnknownTenantError):
            r.get("missing")

    def test_set_status(self):
        r = _fresh_registry()
        r.set_status("acme", TenantStatus.SUSPENDED)
        assert r.get("acme").status == TenantStatus.SUSPENDED


class TestPartitionedStore:
    def test_put_and_list_same_tenant(self):
        r = _fresh_registry()
        store = PartitionedStore[Item](r, "events")
        ctx = TenantContext.single("op:a", "acme")
        store.put(ctx, "acme", Item(value="hello"))
        items = store.list_for(ctx, "acme")
        assert len(items) == 1
        assert items[0].value == "hello"

    def test_cannot_write_outside_scope(self):
        r = _fresh_registry()
        store = PartitionedStore[Item](r, "events")
        ctx = TenantContext.single("op:a", "acme")
        with pytest.raises(TenantIsolationError):
            store.put(ctx, "globex", Item(value="leak"))

    def test_cannot_read_outside_scope(self):
        r = _fresh_registry()
        store = PartitionedStore[Item](r, "events")
        admin = TenantContext.cross_tenant("op:root", ["acme", "globex"])
        store.put(admin, "globex", Item(value="secret"))
        alice = TenantContext.single("op:a", "acme")
        with pytest.raises(TenantIsolationError):
            store.list_for(alice, "globex")

    def test_suspended_tenant_rejects_writes(self):
        r = _fresh_registry()
        r.set_status("acme", TenantStatus.SUSPENDED)
        store = PartitionedStore[Item](r, "events")
        ctx = TenantContext.single("op:a", "acme")
        with pytest.raises(TenantIsolationError):
            store.put(ctx, "acme", Item(value="x"))

    def test_list_all_requires_cross_tenant_admin(self):
        r = _fresh_registry()
        store = PartitionedStore[Item](r, "events")
        alice = TenantContext.single("op:a", "acme")
        with pytest.raises(TenantIsolationError):
            store.list_all(alice)

    def test_list_all_records_audit(self):
        r = _fresh_registry()
        store = PartitionedStore[Item](r, "events")
        admin = TenantContext.cross_tenant("op:root", ["acme", "globex"])
        store.put(admin, "acme", Item(value="a"))
        store.put(admin, "globex", Item(value="g"))
        all_items = store.list_all(admin)
        assert set(all_items.keys()) == {"acme", "globex"}
        audits = r.audits()
        assert len(audits) == 1
        assert audits[0].cross_tenant
        assert audits[0].operator_id == "op:root"

    def test_tenant_isolation_between_two_tenants(self):
        r = _fresh_registry()
        store = PartitionedStore[Item](r, "events")
        ctx_a = TenantContext.single("op:a", "acme")
        ctx_g = TenantContext.single("op:g", "globex")
        store.put(ctx_a, "acme", Item(value="acme-1"))
        store.put(ctx_g, "globex", Item(value="globex-1"))
        assert [i.value for i in store.list_for(ctx_a, "acme")] == ["acme-1"]
        assert [i.value for i in store.list_for(ctx_g, "globex")] == ["globex-1"]


class TestWithTenantScope:
    def test_filters_out_of_scope_items(self):
        items = [
            Item(value="a", tenant_id="acme"),
            Item(value="g", tenant_id="globex"),
            Item(value="sys", tenant_id=None),
        ]
        ctx = TenantContext.single("op:a", "acme")
        filtered = with_tenant_scope(ctx, items, key=lambda i: i.tenant_id)
        values = {i.value for i in filtered}
        assert values == {"a", "sys"}  # system items (None) pass through

    def test_cross_tenant_admin_sees_all(self):
        items = [
            Item(value="a", tenant_id="acme"),
            Item(value="g", tenant_id="globex"),
        ]
        ctx = TenantContext.cross_tenant("op:root", ["acme", "globex"])
        filtered = with_tenant_scope(ctx, items, key=lambda i: i.tenant_id)
        assert len(filtered) == 2


class TestRequireSameTenant:
    def test_allows_in_scope(self):
        ctx = TenantContext.single("op:a", "acme")
        require_same_tenant(ctx, "acme", "approve")  # no raise

    def test_raises_out_of_scope(self):
        ctx = TenantContext.single("op:a", "acme")
        with pytest.raises(TenantIsolationError):
            require_same_tenant(ctx, "globex", "approve")
