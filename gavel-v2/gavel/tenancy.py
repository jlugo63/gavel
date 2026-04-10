"""
Multi-tenant isolation — Phase 8.

Gavel is a single-process control plane. When a deployer uses it for
multiple teams / orgs at once ("tenants"), governance data from tenant
A must not leak into queries, exports, or enforcement decisions for
tenant B. This module defines:

  - Tenant — a unit of isolation (org, team, business unit).
  - TenantContext — which tenant a request is acting within, plus
    the allowed set (for admins that span multiple tenants).
  - TenantRegistry — enrollment of tenants, lookup, listing.
  - PartitionedStore — a generic per-tenant keyed collection that
    refuses cross-tenant reads.
  - `with_tenant_scope(ctx, items, key)` — filter helper for existing
    collections (enrollment ledger, chain events, incidents).

Isolation model:

  - Every governable object (EnrollmentRecord, ChainEvent, Incident,
    ComplianceMatrix) gains an implicit `tenant_id` when created
    under a TenantContext.
  - Reads require a TenantContext. An operator can only see records
    whose tenant_id is in `ctx.allowed_tenants`.
  - Admin operators may be granted a wildcard TenantContext
    (`TenantContext.cross_tenant(...)`) which allows them to
    enumerate across all tenants — but every such access is flagged
    in the returned `TenantAccessAudit` record for later review.

Design notes:

  - No global state. The registry is an instance the caller owns.
  - Purely in-memory; persistence is the deployer's problem.
  - This module does *not* speak to the database or the chain
    directly — it provides the isolation primitives that other
    modules layer on top.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Generic, Iterable, Optional, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


# ── Tenant model ───────────────────────────────────────────────

class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class Tenant(BaseModel):
    tenant_id: str                          # Short stable slug (e.g. "acme")
    display_name: str
    owner_contact: str
    status: TenantStatus = TenantStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""


class TenantContext(BaseModel):
    """Carries the tenant scope of a single operator request."""

    operator_id: str
    primary_tenant: str
    allowed_tenants: list[str] = Field(default_factory=list)
    cross_tenant_admin: bool = False

    @classmethod
    def single(cls, operator_id: str, tenant_id: str) -> "TenantContext":
        return cls(
            operator_id=operator_id,
            primary_tenant=tenant_id,
            allowed_tenants=[tenant_id],
        )

    @classmethod
    def cross_tenant(cls, operator_id: str, tenants: list[str]) -> "TenantContext":
        return cls(
            operator_id=operator_id,
            primary_tenant=tenants[0] if tenants else "",
            allowed_tenants=list(tenants),
            cross_tenant_admin=True,
        )

    def can_see(self, tenant_id: str) -> bool:
        return self.cross_tenant_admin or tenant_id in self.allowed_tenants


class TenantAccessAudit(BaseModel):
    """Record that a cross-tenant read or write happened."""

    operator_id: str
    action: str
    tenant_ids: list[str]
    cross_tenant: bool
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Exceptions ─────────────────────────────────────────────────

class TenantIsolationError(RuntimeError):
    """Raised when a request tries to access a tenant outside its scope."""


class UnknownTenantError(KeyError):
    """Raised when a tenant_id is not registered."""


# ── Registry ───────────────────────────────────────────────────

class TenantRegistry:
    def __init__(self) -> None:
        self._tenants: dict[str, Tenant] = {}
        self._audits: list[TenantAccessAudit] = []

    def register(self, tenant: Tenant) -> None:
        if tenant.tenant_id in self._tenants:
            raise ValueError(f"tenant already registered: {tenant.tenant_id}")
        self._tenants[tenant.tenant_id] = tenant

    def get(self, tenant_id: str) -> Tenant:
        if tenant_id not in self._tenants:
            raise UnknownTenantError(tenant_id)
        return self._tenants[tenant_id]

    def all(self) -> list[Tenant]:
        return list(self._tenants.values())

    def set_status(self, tenant_id: str, status: TenantStatus) -> None:
        t = self.get(tenant_id)
        self._tenants[tenant_id] = t.model_copy(update={"status": status})

    # Auditing

    def record_access(self, audit: TenantAccessAudit) -> None:
        self._audits.append(audit)

    def audits(self) -> list[TenantAccessAudit]:
        return list(self._audits)


# ── Partitioned store ──────────────────────────────────────────

class PartitionedStore(Generic[T]):
    """Per-tenant append/list collection with isolation enforcement.

    Items are kept in a dict keyed by tenant_id. All reads go through
    `list_for(ctx)`, which refuses to return items from tenants the
    context cannot see. Cross-tenant admins may pass their wildcard
    context to see everything — but that access is audited.
    """

    def __init__(self, registry: TenantRegistry, name: str) -> None:
        self._registry = registry
        self._name = name
        self._items: dict[str, list[T]] = defaultdict(list)

    @property
    def name(self) -> str:
        return self._name

    def put(self, ctx: TenantContext, tenant_id: str, item: T) -> None:
        if not ctx.can_see(tenant_id):
            raise TenantIsolationError(
                f"{ctx.operator_id} may not write into tenant {tenant_id}"
            )
        # Validate that the tenant exists and is active.
        tenant = self._registry.get(tenant_id)
        if tenant.status != TenantStatus.ACTIVE:
            raise TenantIsolationError(
                f"tenant {tenant_id} is {tenant.status.value}; writes rejected"
            )
        self._items[tenant_id].append(item)

    def list_for(self, ctx: TenantContext, tenant_id: str) -> list[T]:
        if not ctx.can_see(tenant_id):
            raise TenantIsolationError(
                f"{ctx.operator_id} may not read tenant {tenant_id}"
            )
        return list(self._items.get(tenant_id, []))

    def list_all(self, ctx: TenantContext) -> dict[str, list[T]]:
        """Cross-tenant listing. Requires cross_tenant_admin."""
        if not ctx.cross_tenant_admin:
            raise TenantIsolationError(
                f"{ctx.operator_id} is not a cross-tenant admin"
            )
        self._registry.record_access(TenantAccessAudit(
            operator_id=ctx.operator_id,
            action=f"list_all:{self._name}",
            tenant_ids=sorted(self._items.keys()),
            cross_tenant=True,
        ))
        return {t: list(items) for t, items in self._items.items()}

    def count(self, tenant_id: str) -> int:
        """Unscoped count, for metrics only — does not leak contents."""
        return len(self._items.get(tenant_id, []))


# ── Helpers ────────────────────────────────────────────────────

def with_tenant_scope(
    ctx: TenantContext,
    items: Iterable[T],
    key: Callable[[T], Optional[str]],
) -> list[T]:
    """Filter an existing iterable down to what ctx may see.

    `key` extracts the tenant_id from each item. Items whose key is
    None are treated as tenant-less system records and pass through
    unconditionally (useful for genesis events, constitution entries).
    """
    out: list[T] = []
    for item in items:
        tid = key(item)
        if tid is None or ctx.can_see(tid):
            out.append(item)
    return out


def require_same_tenant(ctx: TenantContext, tenant_id: str, action: str) -> None:
    """Guard helper: raise if ctx may not act inside tenant_id."""
    if not ctx.can_see(tenant_id):
        raise TenantIsolationError(
            f"{ctx.operator_id} attempted {action} on tenant {tenant_id} "
            f"outside scope {ctx.allowed_tenants}"
        )
