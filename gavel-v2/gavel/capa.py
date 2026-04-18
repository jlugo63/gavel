"""
Corrective and Preventive Action (CAPA) — ISO 42001 Clause 10.

Tracks nonconformities through root cause analysis, corrective action,
and verification.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Status ────────────────────────────────────────────────────

class CAPAStatus(str, Enum):
    """Lifecycle status of a corrective action."""
    OPEN = "open"
    ROOT_CAUSE_IDENTIFIED = "root_cause_identified"
    ACTION_PLANNED = "action_planned"
    ACTION_TAKEN = "action_taken"
    VERIFIED = "verified"
    CLOSED = "closed"


# ── Models ────────────────────────────────────────────────────

class NonConformity(BaseModel):
    """A recorded nonconformity (deviation from requirement or expectation)."""

    nc_id: str = Field(default_factory=lambda: f"nc-{uuid.uuid4().hex[:8]}")
    title: str
    description: str
    source: str  # "audit", "incident", "drift_detection", "customer_complaint"
    severity: str  # "critical", "major", "minor"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detected_by: str
    related_requirements: list[str] = Field(default_factory=list)  # e.g. ["ATF B-4", "EU AI Act Art. 9"]


class CorrectiveAction(BaseModel):
    """A corrective / preventive action linked to a nonconformity."""

    action_id: str = Field(default_factory=lambda: f"ca-{uuid.uuid4().hex[:8]}")
    nc_id: str  # links to NonConformity
    description: str
    assigned_to: str
    due_date: datetime
    root_cause: str
    preventive_measures: list[str] = Field(default_factory=list)
    status: CAPAStatus = CAPAStatus.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None


# ── Registry ──────────────────────────────────────────────────

class CAPARegistry:
    """Track nonconformities and corrective actions per ISO 42001 Clause 10."""

    def __init__(self):
        self._nonconformities: dict[str, NonConformity] = {}
        self._actions: dict[str, CorrectiveAction] = {}

    # ---- nonconformities ----

    def file_nonconformity(self, nc: NonConformity) -> str:
        """Register a nonconformity. Returns nc_id."""
        self._nonconformities[nc.nc_id] = nc
        return nc.nc_id

    def get_nonconformity(self, nc_id: str) -> Optional[NonConformity]:
        """Look up a nonconformity by ID."""
        return self._nonconformities.get(nc_id)

    def get_open(self) -> list[NonConformity]:
        """Return all nonconformities that have no CLOSED action."""
        closed_ncs: set[str] = set()
        for action in self._actions.values():
            if action.status == CAPAStatus.CLOSED:
                closed_ncs.add(action.nc_id)
        return [nc for nc in self._nonconformities.values() if nc.nc_id not in closed_ncs]

    # ---- corrective actions ----

    def create_action(self, action: CorrectiveAction) -> str:
        """Create a corrective action plan. Returns action_id."""
        self._actions[action.action_id] = action
        return action.action_id

    def update_status(self, action_id: str, status: CAPAStatus, **kwargs) -> None:
        """Transition a corrective action to a new status.

        Accepted kwargs:
        - completed_at: datetime (auto-set on ACTION_TAKEN if not provided)
        - verified_at: datetime (auto-set on VERIFIED if not provided)
        - verified_by: str
        """
        action = self._actions.get(action_id)
        if action is None:
            raise KeyError(f"Unknown action_id: {action_id}")

        action.status = status

        if status == CAPAStatus.ACTION_TAKEN and action.completed_at is None:
            action.completed_at = kwargs.get("completed_at", datetime.now(timezone.utc))

        if status == CAPAStatus.VERIFIED:
            if action.verified_at is None:
                action.verified_at = kwargs.get("verified_at", datetime.now(timezone.utc))
            if "verified_by" in kwargs:
                action.verified_by = kwargs["verified_by"]

        if status == CAPAStatus.CLOSED:
            if action.completed_at is None:
                action.completed_at = kwargs.get("completed_at", datetime.now(timezone.utc))

    def get_actions(self, nc_id: str) -> list[CorrectiveAction]:
        """Return all corrective actions linked to a nonconformity."""
        return [a for a in self._actions.values() if a.nc_id == nc_id]

    def get_overdue(self, now: Optional[datetime] = None) -> list[CorrectiveAction]:
        """Return actions past their due date that are not yet closed."""
        now = now or datetime.now(timezone.utc)
        return [
            a for a in self._actions.values()
            if a.due_date < now and a.status not in (CAPAStatus.VERIFIED, CAPAStatus.CLOSED)
        ]

    def summary(self) -> dict:
        """Stats: total, open, closed, overdue, by severity."""
        all_ncs = list(self._nonconformities.values())
        open_ncs = self.get_open()
        overdue = self.get_overdue()

        by_severity: dict[str, int] = {}
        for nc in all_ncs:
            by_severity[nc.severity] = by_severity.get(nc.severity, 0) + 1

        closed_ncs: set[str] = set()
        for action in self._actions.values():
            if action.status == CAPAStatus.CLOSED:
                closed_ncs.add(action.nc_id)

        return {
            "total": len(all_ncs),
            "open": len(open_ncs),
            "closed": len(closed_ncs),
            "overdue_actions": len(overdue),
            "by_severity": by_severity,
        }
