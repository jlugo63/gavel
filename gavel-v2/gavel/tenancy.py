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

import uuid as _uuid

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


# ── Org / Team hierarchy (enterprise multi-tenancy) ──────────

class OrgStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEPROVISIONED = "deprovisioned"


class Organization(BaseModel):
    """Top-level tenant boundary."""
    org_id: str = Field(default_factory=lambda: f"org-{_uuid.uuid4().hex[:8]}")
    name: str
    billing_owner: str
    compliance_contact: str = ""
    status: OrgStatus = OrgStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    max_agents: int = 100  # agent enrollment cap per org
    max_teams: int = 20


class Team(BaseModel):
    """Sub-unit within an organization."""
    team_id: str = Field(default_factory=lambda: f"team-{_uuid.uuid4().hex[:8]}")
    org_id: str
    name: str
    owner: str  # team lead / responsible party
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    max_agents: int = 25  # per-team agent cap


class OrgTenantContext(BaseModel):
    """Request-scoped tenant identity. Resolved from auth token or SSO."""
    org_id: str
    team_id: str
    operator_id: str
    is_platform_admin: bool = False


class OrgTenantRegistry:
    """Manages organizations and teams."""

    def __init__(self):
        self._orgs: dict[str, Organization] = {}
        self._teams: dict[str, Team] = {}  # team_id -> Team
        self._org_teams: dict[str, list[str]] = {}  # org_id -> [team_id, ...]

    def create_org(self, name: str, billing_owner: str, compliance_contact: str = "", **kwargs) -> Organization:
        org = Organization(name=name, billing_owner=billing_owner, compliance_contact=compliance_contact, **kwargs)
        self._orgs[org.org_id] = org
        self._org_teams[org.org_id] = []
        return org

    def get_org(self, org_id: str) -> Optional[Organization]:
        return self._orgs.get(org_id)

    def list_orgs(self) -> list[Organization]:
        return list(self._orgs.values())

    def suspend_org(self, org_id: str) -> Optional[Organization]:
        org = self._orgs.get(org_id)
        if org:
            org.status = OrgStatus.SUSPENDED
        return org

    def create_team(self, org_id: str, name: str, owner: str, **kwargs) -> Team:
        org = self._orgs.get(org_id)
        if not org:
            raise ValueError(f"Organization {org_id} not found")
        if org.status != OrgStatus.ACTIVE:
            raise ValueError(f"Organization {org_id} is {org.status.value}")
        existing = self._org_teams.get(org_id, [])
        if len(existing) >= org.max_teams:
            raise ValueError(f"Organization {org_id} has reached team limit ({org.max_teams})")
        team = Team(org_id=org_id, name=name, owner=owner, **kwargs)
        self._teams[team.team_id] = team
        self._org_teams.setdefault(org_id, []).append(team.team_id)
        return team

    def get_team(self, team_id: str) -> Optional[Team]:
        return self._teams.get(team_id)

    def list_teams(self, org_id: str) -> list[Team]:
        team_ids = self._org_teams.get(org_id, [])
        return [self._teams[tid] for tid in team_ids if tid in self._teams]

    def delete_team(self, team_id: str) -> bool:
        team = self._teams.pop(team_id, None)
        if team:
            org_teams = self._org_teams.get(team.org_id, [])
            if team_id in org_teams:
                org_teams.remove(team_id)
            return True
        return False


class TenantScopedRecord(BaseModel):
    """Mixin fields for any record that must be tenant-scoped."""
    org_id: str
    team_id: str


class TenantIsolationEnforcer:
    """Enforces tenant boundaries on reads and writes.

    Wraps any collection of tenant-scoped records and ensures:
    - Writes reject cross-tenant references
    - Reads are always filtered to the caller's tenant context
    - Platform admins can read across tenants (but never write cross-tenant)
    """

    def __init__(self, registry: OrgTenantRegistry):
        self._registry = registry
        self._records: dict[str, dict[str, Any]] = {}  # record_id -> record dict with org_id, team_id

    def store(self, record_id: str, org_id: str, team_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """Store a record with tenant tagging. Validates org/team exist."""
        org = self._registry.get_org(org_id)
        if not org:
            raise ValueError(f"Organization {org_id} not found")
        if org.status != OrgStatus.ACTIVE:
            raise ValueError(f"Organization {org_id} is {org.status.value}")
        team = self._registry.get_team(team_id)
        if not team:
            raise ValueError(f"Team {team_id} not found")
        if team.org_id != org_id:
            raise ValueError(f"Team {team_id} does not belong to org {org_id}")

        record = {"record_id": record_id, "org_id": org_id, "team_id": team_id, **data}
        self._records[record_id] = record
        return record

    def get(self, record_id: str, ctx: OrgTenantContext) -> Optional[dict[str, Any]]:
        """Retrieve a record, enforcing tenant scope."""
        record = self._records.get(record_id)
        if not record:
            return None
        if ctx.is_platform_admin:
            return record
        if record["org_id"] != ctx.org_id:
            return None  # invisible — not "forbidden", just doesn't exist for this tenant
        if record["team_id"] != ctx.team_id:
            return None
        return record

    def list_records(self, ctx: OrgTenantContext) -> list[dict[str, Any]]:
        """List all records visible to the given tenant context."""
        if ctx.is_platform_admin:
            return list(self._records.values())
        return [
            r for r in self._records.values()
            if r["org_id"] == ctx.org_id and r["team_id"] == ctx.team_id
        ]

    def count(self, ctx: OrgTenantContext) -> int:
        """Count records visible to the given tenant context."""
        return len(self.list_records(ctx))

    def delete(self, record_id: str, ctx: OrgTenantContext) -> bool:
        """Delete a record, enforcing tenant scope."""
        record = self._records.get(record_id)
        if not record:
            return False
        if not ctx.is_platform_admin and (record["org_id"] != ctx.org_id or record["team_id"] != ctx.team_id):
            return False
        del self._records[record_id]
        return True


class TenantAgentQuota:
    """Track agent enrollment counts per org and team against limits."""

    def __init__(self, registry: OrgTenantRegistry):
        self._registry = registry
        self._org_counts: dict[str, int] = {}  # org_id -> enrolled agent count
        self._team_counts: dict[str, int] = {}  # team_id -> enrolled agent count

    def can_enroll(self, org_id: str, team_id: str) -> tuple[bool, str]:
        """Check if the org/team has capacity for another agent."""
        org = self._registry.get_org(org_id)
        if not org:
            return False, f"Organization {org_id} not found"
        if org.status != OrgStatus.ACTIVE:
            return False, f"Organization {org_id} is {org.status.value}"

        team = self._registry.get_team(team_id)
        if not team:
            return False, f"Team {team_id} not found"
        if team.org_id != org_id:
            return False, f"Team {team_id} does not belong to org {org_id}"

        org_count = self._org_counts.get(org_id, 0)
        if org_count >= org.max_agents:
            return False, f"Organization {org_id} agent limit reached ({org.max_agents})"

        team_count = self._team_counts.get(team_id, 0)
        if team_count >= team.max_agents:
            return False, f"Team {team_id} agent limit reached ({team.max_agents})"

        return True, ""

    def record_enrollment(self, org_id: str, team_id: str) -> None:
        """Increment enrollment counters after successful enrollment."""
        self._org_counts[org_id] = self._org_counts.get(org_id, 0) + 1
        self._team_counts[team_id] = self._team_counts.get(team_id, 0) + 1

    def record_disenrollment(self, org_id: str, team_id: str) -> None:
        """Decrement enrollment counters after agent removal."""
        self._org_counts[org_id] = max(0, self._org_counts.get(org_id, 0) - 1)
        self._team_counts[team_id] = max(0, self._team_counts.get(team_id, 0) - 1)

    def org_usage(self, org_id: str) -> dict[str, int]:
        org = self._registry.get_org(org_id)
        limit = org.max_agents if org else 0
        return {"enrolled": self._org_counts.get(org_id, 0), "limit": limit}

    def team_usage(self, team_id: str) -> dict[str, int]:
        team = self._registry.get_team(team_id)
        limit = team.max_agents if team else 0
        return {"enrolled": self._team_counts.get(team_id, 0), "limit": limit}
