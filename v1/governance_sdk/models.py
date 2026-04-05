"""
Governance SDK — Data Models
"""

from __future__ import annotations

from pydantic import BaseModel


class ProposalResult(BaseModel):
    """Result of a POST /propose call."""
    decision: str           # APPROVED | ESCALATED | DENIED
    intent_event_id: str
    policy_event_id: str
    risk_score: float | None = None
    violations: list[dict] = []
    raw: dict               # full response body


class ApprovalResult(BaseModel):
    """Result of a POST /approve call."""
    success: bool
    event_id: str | None = None
    raw: dict               # full response body
