"""
Enrollment data models — Pydantic models and enums for the enrollment gate.

Extracted from ``gavel.enrollment`` so that data definitions live separately
from business logic (``EnrollmentValidator``, ``EnrollmentRegistry``,
``TokenManager``).  All symbols are re-exported by ``gavel.enrollment`` for
backwards compatibility.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enrollment Status ──────────────────────────────────────────

class EnrollmentStatus(str, Enum):
    PENDING = "PENDING"              # Submitted, awaiting validation
    INCOMPLETE = "INCOMPLETE"        # Failed validation — missing fields
    ENROLLED = "ENROLLED"            # Passed all checks — agent may operate
    REJECTED = "REJECTED"            # Denied by policy or human review
    SUSPENDED = "SUSPENDED"          # Previously enrolled, now suspended


class HighRiskCategory(str, Enum):
    """EU AI Act Annex III high-risk AI system categories."""
    NONE = "none"
    BIOMETRICS = "biometrics"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    EDUCATION = "education"
    EMPLOYMENT = "employment"
    ESSENTIAL_SERVICES = "essential_services"
    LAW_ENFORCEMENT = "law_enforcement"
    MIGRATION = "migration"
    JUSTICE = "justice"
    PROHIBITED = "prohibited"  # Article 5 — must be rejected


# ── ATF Requirement Models ─────────────────────────────────────

class PurposeDeclaration(BaseModel):
    """ATF I-4: Documented intended use and operational scope."""
    summary: str                         # One-line purpose statement
    operational_scope: str               # What domain does this agent operate in?
    expected_lifetime: str = "session"   # "session", "persistent", "ephemeral"
    risk_tier: str = "standard"          # "low", "standard", "high", "critical"

    def is_valid(self) -> tuple[bool, str]:
        if not self.summary or len(self.summary) < 10:
            return False, "Purpose summary too short (min 10 chars)"
        if not self.operational_scope:
            return False, "Operational scope is required"
        if self.risk_tier not in ("low", "standard", "high", "critical"):
            return False, f"Invalid risk tier: {self.risk_tier}"
        return True, ""


class CapabilityManifest(BaseModel):
    """ATF I-5: Machine-readable list of claimed agent capabilities."""
    tools: list[str] = Field(default_factory=list)        # Tools the agent will use
    max_concurrent_chains: int = 1                         # Max governance chains at once
    can_spawn_subagents: bool = False                      # Does it create child agents?
    network_access: bool = False                           # Needs internet?
    file_system_access: bool = True                        # Needs local files?
    execution_access: bool = False                         # Can run shell commands?

    def is_valid(self) -> tuple[bool, str]:
        if not self.tools:
            return False, "Capability manifest must declare at least one tool"
        return True, ""


class ResourceAllowlist(BaseModel):
    """ATF S-1: Explicit enumeration of permitted resources."""
    allowed_paths: list[str] = Field(default_factory=list)  # File paths/patterns
    allowed_hosts: list[str] = Field(default_factory=list)  # Network hosts
    allowed_env_vars: list[str] = Field(default_factory=list)  # Env vars to read
    max_file_size_mb: float = 10.0                          # Max single file size

    def is_valid(self) -> tuple[bool, str]:
        # At least one resource scope must be declared
        if not self.allowed_paths and not self.allowed_hosts:
            return False, "Must declare at least one allowed path or host"
        return True, ""


class ActionBoundaries(BaseModel):
    """ATF S-2: Explicit enumeration of permitted actions."""
    allowed_actions: list[str] = Field(default_factory=list)  # e.g. ["read", "write", "execute"]
    blocked_patterns: list[str] = Field(default_factory=list)  # Explicit deny patterns
    max_actions_per_minute: int = 60                           # Rate limit
    max_risk_threshold: float = 0.7                            # Auto-deny above this risk

    def is_valid(self) -> tuple[bool, str]:
        if not self.allowed_actions:
            return False, "Must declare at least one allowed action type"
        return True, ""


class FallbackBehavior(BaseModel):
    """What happens when governance fails or the agent loses connectivity."""
    on_gateway_unreachable: str = "stop"     # "stop", "degrade", "continue"
    on_budget_exceeded: str = "stop"         # "stop", "alert", "continue"
    on_sla_timeout: str = "deny"             # "deny", "escalate", "auto-approve"
    graceful_shutdown: bool = True            # Can it clean up on kill?

    def is_valid(self) -> tuple[bool, str]:
        valid_actions = {"stop", "degrade", "continue", "deny", "escalate", "alert", "auto-approve"}
        for field_name in ("on_gateway_unreachable", "on_budget_exceeded", "on_sla_timeout"):
            val = getattr(self, field_name)
            if val not in valid_actions:
                return False, f"Invalid fallback action for {field_name}: {val}"
        return True, ""


# ── Enrollment Application ─────────────────────────────────────

class EnrollmentApplication(BaseModel):
    """Everything an agent must declare before it can operate."""

    # Identity
    agent_id: str
    display_name: str
    agent_type: str = "llm"

    # Accountability
    owner: str                                    # Human accountable for this agent
    owner_contact: str = ""                       # Email, Slack, etc.
    budget_tokens: int = 0                        # Max API tokens — MUST be > 0
    budget_usd: float = 0.0                       # Max USD spend — MUST be > 0

    # ATF Requirements
    purpose: PurposeDeclaration
    capabilities: CapabilityManifest
    resources: ResourceAllowlist
    boundaries: ActionBoundaries
    fallback: FallbackBehavior = Field(default_factory=FallbackBehavior)

    # EU AI Act compliance
    high_risk_category: HighRiskCategory = HighRiskCategory.NONE
    interaction_type: str = "system_only"  # "human_facing", "system_only", "mixed"
    synthetic_content: bool = False  # whether agent generates synthetic content


class EnrollmentRecord(BaseModel):
    """Stored enrollment state for an agent."""

    agent_id: str
    status: EnrollmentStatus = EnrollmentStatus.PENDING
    application: EnrollmentApplication
    enrolled_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    rejection_reason: Optional[str] = None
    violations: list[str] = Field(default_factory=list)  # Validation failures


# ── Governance Token ──────────────────────────────────────────

TOKEN_PREFIX = "gvl_tok_"
DEFAULT_TOKEN_TTL_SECONDS = 3600  # 1 hour


class GovernanceToken(BaseModel):
    """A governance token issued upon successful enrollment.

    Tokens are SHA-256 based, bound to agent_id + machine_id + pid,
    short-lived (default 1 hour), and carry the agent's DID.
    """
    token: str = Field(..., description="Governance token (gvl_tok_ prefix)")
    agent_did: str = Field(..., description="DID of the agent this token was issued to")
    agent_id: str
    issued_at: datetime
    expires_at: datetime
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS
    revoked: bool = False
    scope: Optional[dict[str, Any]] = None
