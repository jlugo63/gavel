"""
V6 — Multi-Tenant Isolation Pen-Test (Wave 2).

Goal: prove an operator scoped to tenant A cannot read, write, or
enumerate tenant B's governance data via any exposed primitive. Also
prove that cross-tenant admin access (legitimate, e.g. a platform SRE)
is always audited.

Attack surface (5 vectors):
  V1  Direct read           — TenantA op calls PartitionedStore.list_for(B)
  V2  Direct write          — TenantA op calls PartitionedStore.put(B, item)
  V3  Cross-tenant list     — TenantA op (no cross_tenant_admin) calls list_all()
  V4  Scope filter bypass   — with_tenant_scope() refuses to pass B items
                               through a TenantA-scoped query
  V5  Suspended tenant      — operator (even their own) cannot write to a
                               SUSPENDED tenant — prevents zombie writes

Plus:
  C1  Same-tenant control   — all listed operations succeed inside scope
  C2  Cross-tenant admin    — list_all() works and leaves an audit trail
"""

from __future__ import annotations

import pytest

from gavel.tenancy import (
    PartitionedStore,
    Tenant,
    TenantContext,
    TenantIsolationError,
    TenantRegistry,
    TenantStatus,
    with_tenant_scope,
)


# ── Scenario setup ─────────────────────────────────────────────


@pytest.fixture
def two_tenants() -> tuple[TenantRegistry, PartitionedStore]:
    """Registry with acme + widgets active tenants + a shared store."""
    reg = TenantRegistry()
    reg.register(Tenant(
        tenant_id="acme",
        display_name="Acme Corp",
        owner_contact="sec@acme.example",
    ))
    reg.register(Tenant(
        tenant_id="widgets",
        display_name="Widgets Ltd",
        owner_contact="sec@widgets.example",
    ))
    store = PartitionedStore[dict](reg, name="enrollment-records")
    return reg, store


@pytest.fixture
def seeded_store(two_tenants) -> tuple[TenantRegistry, PartitionedStore]:
    """Store pre-populated with a record in each tenant, written by its own admin."""
    reg, store = two_tenants
    acme_ctx = TenantContext.single("op:acme-admin", "acme")
    widgets_ctx = TenantContext.single("op:widgets-admin", "widgets")
    store.put(acme_ctx, "acme", {"agent_id": "agent:acme-1", "secret": "acme-only"})
    store.put(widgets_ctx, "widgets", {"agent_id": "agent:widgets-1", "secret": "widgets-only"})
    return reg, store


# ── V1: direct read ──────────────────────────────────────────


class TestDirectReadRefused:
    def test_acme_op_cannot_read_widgets(self, seeded_store) -> None:
        _, store = seeded_store
        acme_ctx = TenantContext.single("op:acme-snoop", "acme")
        with pytest.raises(TenantIsolationError) as exc_info:
            store.list_for(acme_ctx, "widgets")
        msg = str(exc_info.value)
        assert "op:acme-snoop" in msg
        assert "widgets" in msg

    def test_acme_op_reads_own_tenant_cleanly(self, seeded_store) -> None:
        _, store = seeded_store
        acme_ctx = TenantContext.single("op:acme-admin", "acme")
        items = store.list_for(acme_ctx, "acme")
        assert len(items) == 1
        assert items[0]["agent_id"] == "agent:acme-1"
        # Critical: the returned records contain zero widgets data.
        assert all("widgets" not in str(i) for i in items)


# ── V2: direct write ─────────────────────────────────────────


class TestDirectWriteRefused:
    def test_acme_op_cannot_write_widgets(self, two_tenants) -> None:
        _, store = two_tenants
        acme_ctx = TenantContext.single("op:acme-snoop", "acme")
        with pytest.raises(TenantIsolationError):
            store.put(acme_ctx, "widgets", {"agent_id": "agent:injected"})
        # And after the failed write, widgets must still be empty.
        widgets_admin = TenantContext.single("op:widgets-admin", "widgets")
        assert store.list_for(widgets_admin, "widgets") == []


# ── V3: cross-tenant list without permission ─────────────────


class TestCrossTenantListRefused:
    def test_non_admin_cannot_list_all(self, seeded_store) -> None:
        _, store = seeded_store
        acme_ctx = TenantContext.single("op:acme-admin", "acme")
        # Even though this operator has 'admin' in their name, their
        # TenantContext has cross_tenant_admin=False.
        with pytest.raises(TenantIsolationError):
            store.list_all(acme_ctx)


# ── V4: scope filter on existing iterables ──────────────────


class TestScopeFilterBypass:
    def test_with_tenant_scope_filters_out_other_tenant_items(self) -> None:
        """Existing flat iterables (like the chain event log) get their
        cross-tenant safety from with_tenant_scope(). This test models
        a mixed list of records from both tenants and asserts that the
        scope filter returns only the caller's share."""
        records = [
            {"id": 1, "tenant_id": "acme", "payload": "acme-data"},
            {"id": 2, "tenant_id": "widgets", "payload": "widgets-secret"},
            {"id": 3, "tenant_id": "acme", "payload": "more-acme-data"},
            {"id": 4, "tenant_id": "widgets", "payload": "widgets-secret-2"},
            {"id": 5, "tenant_id": None, "payload": "genesis"},  # system record
        ]
        acme_ctx = TenantContext.single("op:acme-reader", "acme")
        filtered = with_tenant_scope(acme_ctx, records, key=lambda r: r["tenant_id"])

        # Exactly 3 results: 2 acme records + 1 system record (tenant_id=None).
        assert len(filtered) == 3
        ids = {r["id"] for r in filtered}
        assert ids == {1, 3, 5}

        # Critically, no widgets payload anywhere in the filtered output.
        combined = " ".join(r["payload"] for r in filtered)
        assert "widgets-secret" not in combined
        assert "widgets-secret-2" not in combined


# ── V5: suspended tenant ─────────────────────────────────────


class TestSuspendedTenantBlocked:
    """A suspended tenant refuses writes even from its own admin — this
    prevents in-flight or delayed requests from continuing to modify the
    suspended tenant's state."""

    def test_write_to_suspended_tenant_rejected(self, two_tenants) -> None:
        reg, store = two_tenants
        reg.set_status("acme", TenantStatus.SUSPENDED)

        acme_ctx = TenantContext.single("op:acme-admin", "acme")
        with pytest.raises(TenantIsolationError) as exc_info:
            store.put(acme_ctx, "acme", {"agent_id": "agent:zombie"})
        assert "suspended" in str(exc_info.value)


# ── C2: legitimate cross-tenant admin is audited ────────────


class TestCrossTenantAdminAudited:
    """The only way to see across tenants is via cross_tenant_admin=True,
    and every such access must leave an audit record."""

    def test_admin_list_all_creates_audit_record(self, seeded_store) -> None:
        reg, store = seeded_store
        admin_ctx = TenantContext.cross_tenant(
            "op:platform-sre", ["acme", "widgets"],
        )
        # Before the call: no audit records.
        assert reg.audits() == []

        result = store.list_all(admin_ctx)

        # The admin got both tenants' data.
        assert set(result.keys()) == {"acme", "widgets"}
        assert len(result["acme"]) == 1
        assert len(result["widgets"]) == 1

        # And an audit record was created.
        audits = reg.audits()
        assert len(audits) == 1
        audit = audits[0]
        assert audit.operator_id == "op:platform-sre"
        assert audit.cross_tenant is True
        assert "enrollment-records" in audit.action
        assert set(audit.tenant_ids) == {"acme", "widgets"}
