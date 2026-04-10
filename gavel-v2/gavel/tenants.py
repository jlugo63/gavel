"""
Multi-tenant isolation — per-team, per-org agent enrollment.

Enterprise deployments need hard boundaries between organizational units.
A team in Org A must never see agents, chains, or incidents from Org B.
This module provides:

  1. Organization — top-level tenant boundary with billing/compliance owner
  2. Team — sub-unit within an org (engineering, security, ops, etc.)
  3. TenantContext — request-scoped tenant identity resolved from auth
  4. TenantIsolationEnforcer — wraps registries to enforce scoping
  5. TenantRegistry — manages orgs and teams

Isolation guarantees:
  - Every enrollment, chain, incident, and token is tagged with (org_id, team_id)
  - Queries are always scoped — no global reads except for platform admins
  - Cross-tenant references are rejected at write time
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Tenant models ─────────────────────────────────────────────

class OrgStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEPROVISIONED = "deprovisioned"


class Organization(BaseModel):
    """Top-level tenant boundary."""
    org_id: str = Field(default_factory=lambda: f"org-{uuid.uuid4().hex[:8]}")
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
    team_id: str = Field(default_factory=lambda: f"team-{uuid.uuid4().hex[:8]}")
    org_id: str
    name: str
    owner: str  # team lead / responsible party
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    max_agents: int = 25  # per-team agent cap


class TenantContext(BaseModel):
    """Request-scoped tenant identity. Resolved from auth token or SSO."""
    org_id: str
    team_id: str
    operator_id: str
    is_platform_admin: bool = False


# ── Tenant Registry ───────────────────────────────────────────

class TenantRegistry:
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


# ── Tenant-scoped data store ──────────────────────────────────

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

    def __init__(self, registry: TenantRegistry):
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

    def get(self, record_id: str, ctx: TenantContext) -> Optional[dict[str, Any]]:
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

    def list_records(self, ctx: TenantContext) -> list[dict[str, Any]]:
        """List all records visible to the given tenant context."""
        if ctx.is_platform_admin:
            return list(self._records.values())
        return [
            r for r in self._records.values()
            if r["org_id"] == ctx.org_id and r["team_id"] == ctx.team_id
        ]

    def count(self, ctx: TenantContext) -> int:
        """Count records visible to the given tenant context."""
        return len(self.list_records(ctx))

    def delete(self, record_id: str, ctx: TenantContext) -> bool:
        """Delete a record, enforcing tenant scope."""
        record = self._records.get(record_id)
        if not record:
            return False
        if not ctx.is_platform_admin and (record["org_id"] != ctx.org_id or record["team_id"] != ctx.team_id):
            return False
        del self._records[record_id]
        return True


# ── Tenant-scoped enrollment helpers ──────────────────────────

class TenantAgentQuota:
    """Track agent enrollment counts per org and team against limits."""

    def __init__(self, registry: TenantRegistry):
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
