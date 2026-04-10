"""
Gavel Enrollment Gate — pre-flight checks before agents enter governance.

Gavel governs what agents DO. This module governs whether they should be
RUNNING at all. Before an agent can propose actions or pass through the
gate, it must complete enrollment by declaring:

  ATF I-4  Purpose Declaration    — Why does this agent exist?
  ATF I-5  Capability Manifest    — What can it do? (machine-readable)
  ATF S-1  Resource Allowlist     — What resources will it touch?
  ATF S-2  Action Boundaries      — What actions is it allowed to take?

Plus Gavel-specific requirements:
  - Accountable owner (human who is responsible)
  - Operational budget (token/cost limit)
  - Fallback behavior (what happens when governance fails)

Agents that skip enrollment or fail validation are set to PENDING_ENROLLMENT
and blocked at the gate. This is constitutional — no agent operates without
declaring its scope.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

log = logging.getLogger("gavel.enrollment")


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


# ── EU AI Act Risk Classification ─────────────────────────────

# Keywords that trigger high-risk classification
_RISK_CATEGORY_KEYWORDS: dict[HighRiskCategory, list[str]] = {
    HighRiskCategory.BIOMETRICS: ["biometric", "facial recognition", "fingerprint", "emotion recognition", "voice identification"],
    HighRiskCategory.CRITICAL_INFRASTRUCTURE: ["power grid", "water supply", "traffic control", "energy management", "digital infrastructure", "telecom"],
    HighRiskCategory.EDUCATION: ["student assessment", "exam scoring", "admission", "learning evaluation", "academic grading"],
    HighRiskCategory.EMPLOYMENT: ["recruitment", "cv screening", "hiring", "performance evaluation", "task allocation", "termination decision", "promotion decision"],
    HighRiskCategory.ESSENTIAL_SERVICES: ["credit scoring", "insurance risk", "social benefit", "healthcare triage", "emergency dispatch", "loan assessment"],
    HighRiskCategory.LAW_ENFORCEMENT: ["crime prediction", "risk assessment law", "evidence reliability", "polygraph", "profiling"],
    HighRiskCategory.MIGRATION: ["visa processing", "asylum", "border control", "immigration risk", "document authenticity"],
    HighRiskCategory.JUSTICE: ["sentencing", "court analysis", "dispute resolution", "judicial", "parole decision"],
}

_PROHIBITED_KEYWORDS: list[str] = [
    "social scoring", "social credit",
    "subliminal manipulation", "subliminal technique",
    "exploit vulnerability", "exploit disabled", "exploit elderly", "exploit minor",
    "real-time biometric identification", "mass surveillance",
    "predictive policing individual",
    "emotion recognition workplace", "emotion recognition education",
]


def classify_risk_category(purpose: PurposeDeclaration, capabilities: CapabilityManifest) -> HighRiskCategory:
    """Auto-classify agent into EU AI Act Annex III risk category."""
    text = f"{purpose.summary} {purpose.operational_scope}".lower()

    # Check prohibited first
    for keyword in _PROHIBITED_KEYWORDS:
        if keyword in text:
            return HighRiskCategory.PROHIBITED

    # Check high-risk categories
    for category, keywords in _RISK_CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text:
                return category

    return HighRiskCategory.NONE


def detect_prohibited_practices(app: "EnrollmentApplication") -> list[str]:
    """Detect EU AI Act Article 5 prohibited practices in an enrollment application."""
    violations = []
    text = f"{app.purpose.summary} {app.purpose.operational_scope} {app.display_name}".lower()

    if any(k in text for k in ["social scoring", "social credit"]):
        violations.append("Art. 5(1)(c): Social scoring by public authorities or on their behalf")

    if any(k in text for k in ["subliminal manipulation", "subliminal technique"]):
        violations.append("Art. 5(1)(a): Subliminal techniques to materially distort behavior")

    if any(k in text for k in ["exploit vulnerability", "exploit disabled", "exploit elderly", "exploit minor"]):
        violations.append("Art. 5(1)(b): Exploiting vulnerabilities of specific groups (age, disability)")

    if any(k in text for k in ["real-time biometric identification", "mass surveillance"]):
        violations.append("Art. 5(1)(d): Real-time remote biometric identification in public spaces")

    if "predictive policing individual" in text:
        violations.append("Art. 5(1)(d): Individual predictive policing based solely on profiling")

    if any(k in text for k in ["emotion recognition workplace", "emotion recognition education"]):
        violations.append("Art. 5(1)(f): Emotion recognition in workplace or education institutions")

    # Check capabilities for biometric indicators
    tools_text = " ".join(app.capabilities.tools).lower()
    if any(k in tools_text for k in ["facial_recognition", "biometric_scan", "emotion_detect"]):
        if "biometric" not in app.purpose.operational_scope.lower():
            violations.append("Art. 5: Biometric capabilities declared without biometric purpose declaration")

    return violations


# ── Enrollment Validator ───────────────────────────────────────

class EnrollmentValidator:
    """Validates enrollment applications against ATF requirements."""

    def validate(self, app: EnrollmentApplication) -> tuple[bool, list[str]]:
        """Validate an enrollment application. Returns (passed, list of violations)."""
        violations = []

        # ATF I-4: Purpose Declaration
        ok, msg = app.purpose.is_valid()
        if not ok:
            violations.append(f"I-4 Purpose Declaration: {msg}")

        # ATF I-5: Capability Manifest
        ok, msg = app.capabilities.is_valid()
        if not ok:
            violations.append(f"I-5 Capability Manifest: {msg}")

        # ATF S-1: Resource Allowlist
        ok, msg = app.resources.is_valid()
        if not ok:
            violations.append(f"S-1 Resource Allowlist: {msg}")

        # ATF S-2: Action Boundaries
        ok, msg = app.boundaries.is_valid()
        if not ok:
            violations.append(f"S-2 Action Boundaries: {msg}")

        # Fallback behavior
        ok, msg = app.fallback.is_valid()
        if not ok:
            violations.append(f"Fallback Behavior: {msg}")

        # Accountability
        if not app.owner or len(app.owner) < 2:
            violations.append("Accountability: owner is required")

        # Budget — agents don't run for free. Declare your limits.
        if app.budget_tokens <= 0 and app.budget_usd <= 0:
            violations.append("Budget: must declare budget_tokens > 0 or budget_usd > 0 — no open-ended spending")

        # Capability/boundary cross-checks
        if app.capabilities.execution_access and "execute" not in app.boundaries.allowed_actions:
            violations.append("Cross-check: execution_access=true but 'execute' not in allowed_actions")

        if app.capabilities.network_access and not app.resources.allowed_hosts:
            violations.append("Cross-check: network_access=true but no allowed_hosts declared")

        if app.capabilities.can_spawn_subagents and app.purpose.risk_tier == "low":
            violations.append("Cross-check: subagent spawning incompatible with 'low' risk tier")

        # EU AI Act: Risk category classification
        detected_category = classify_risk_category(app.purpose, app.capabilities)
        if detected_category == HighRiskCategory.PROHIBITED:
            violations.append("EU AI Act Art. 5: Application describes a prohibited AI practice")

        if app.high_risk_category == HighRiskCategory.NONE and detected_category != HighRiskCategory.NONE:
            violations.append(f"EU AI Act Art. 6: Agent auto-classified as high-risk ({detected_category.value}) but declared as none")

        # EU AI Act: Prohibited practice detection
        prohibited = detect_prohibited_practices(app)
        violations.extend(prohibited)

        # EU AI Act: High-risk agents need stricter requirements
        if app.high_risk_category != HighRiskCategory.NONE or detected_category != HighRiskCategory.NONE:
            if app.purpose.risk_tier not in ("high", "critical"):
                violations.append("EU AI Act: High-risk category agents must declare risk_tier as 'high' or 'critical'")
            if not app.owner_contact:
                violations.append("EU AI Act Art. 26: High-risk system deployers must provide contact information")

        passed = len(violations) == 0
        return passed, violations


# ── Enrollment Registry ────────────────────────────────────────

class EnrollmentRegistry:
    """Stores and manages enrollment records."""

    def __init__(self):
        self._records: dict[str, EnrollmentRecord] = {}
        self._validator = EnrollmentValidator()

    def submit(self, application: EnrollmentApplication) -> EnrollmentRecord:
        """Submit an enrollment application. Validates and returns the record."""
        passed, violations = self._validator.validate(application)

        record = EnrollmentRecord(
            agent_id=application.agent_id,
            status=EnrollmentStatus.ENROLLED if passed else EnrollmentStatus.INCOMPLETE,
            application=application,
            enrolled_at=datetime.now(timezone.utc) if passed else None,
            violations=violations,
        )

        self._records[application.agent_id] = record

        if passed:
            log.info("Agent %s enrolled successfully (owner: %s)", application.agent_id, application.owner)
        else:
            log.warning(
                "Agent %s enrollment INCOMPLETE — %d violations: %s",
                application.agent_id, len(violations), "; ".join(violations),
            )

        return record

    def is_enrolled(self, agent_id: str) -> bool:
        """Check if an agent has completed enrollment."""
        record = self._records.get(agent_id)
        return record is not None and record.status == EnrollmentStatus.ENROLLED

    def get(self, agent_id: str) -> Optional[EnrollmentRecord]:
        return self._records.get(agent_id)

    def get_all(self) -> list[EnrollmentRecord]:
        return list(self._records.values())

    def reject(self, agent_id: str, reason: str, reviewed_by: str) -> Optional[EnrollmentRecord]:
        """Reject an enrollment application."""
        record = self._records.get(agent_id)
        if not record:
            return None
        record.status = EnrollmentStatus.REJECTED
        record.rejection_reason = reason
        record.reviewed_by = reviewed_by
        return record

    def approve_manual(self, agent_id: str, reviewed_by: str) -> Optional[EnrollmentRecord]:
        """Manually approve an incomplete enrollment (override)."""
        record = self._records.get(agent_id)
        if not record:
            return None
        record.status = EnrollmentStatus.ENROLLED
        record.enrolled_at = datetime.now(timezone.utc)
        record.reviewed_by = reviewed_by
        log.info("Agent %s manually enrolled by %s", agent_id, reviewed_by)
        return record

    def suspend(self, agent_id: str) -> Optional[EnrollmentRecord]:
        """Suspend an enrolled agent's enrollment."""
        record = self._records.get(agent_id)
        if not record:
            return None
        record.status = EnrollmentStatus.SUSPENDED
        return record


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


def _generate_did(agent_id: str) -> str:
    """Generate a Gavel decentralized identifier for an agent.

    Format: did:gavel:agent:<short_hash>
    """
    hash_input = f"{agent_id}:{secrets.token_hex(8)}"
    short_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    return f"did:gavel:agent:{short_hash}"


def _generate_governance_token(agent_id: str, machine_id: str, pid: int) -> str:
    """Generate a governance token bound to agent_id + machine_id + pid.

    The token is SHA-256 based, non-transferable (bound to the specific
    agent instance), and prefixed with gvl_tok_.
    """
    binding = f"{agent_id}|{machine_id}|{pid}|{secrets.token_hex(16)}"
    token_hash = hashlib.sha256(binding.encode("utf-8")).hexdigest()
    return f"{TOKEN_PREFIX}{token_hash}"


class TokenManager:
    """Manages governance token lifecycle: issue, validate, revoke.

    Thread-safe in-memory store for governance tokens. In production
    this would be backed by a database or distributed cache.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, GovernanceToken] = {}   # token string -> GovernanceToken
        self._by_did: dict[str, GovernanceToken] = {}    # agent_did -> GovernanceToken
        self._lock = threading.Lock()

    def issue(
        self,
        agent_id: str,
        machine_id: str = "local",
        pid: int = 0,
        ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
        scope: Optional[dict[str, Any]] = None,
    ) -> GovernanceToken:
        """Issue a new governance token for an enrolled agent.

        Args:
            agent_id: The enrolled agent's ID.
            machine_id: Host machine identifier for binding.
            pid: OS process ID for binding.
            ttl_seconds: Token lifetime in seconds (default 3600 = 1 hour).
            scope: Optional scope dict describing what the token permits.

        Returns:
            A GovernanceToken with a unique gvl_tok_ prefixed SHA-256 token.
        """
        agent_did = _generate_did(agent_id)
        token_str = _generate_governance_token(agent_id, machine_id, pid)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        gov_token = GovernanceToken(
            token=token_str,
            agent_did=agent_did,
            agent_id=agent_id,
            issued_at=now,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
            revoked=False,
            scope=scope,
        )

        with self._lock:
            self._tokens[token_str] = gov_token
            self._by_did[agent_did] = gov_token

        log.info("Governance token issued for agent %s (DID: %s, TTL: %ds)", agent_id, agent_did, ttl_seconds)
        return gov_token

    def validate(self, token: str, required_scope: Optional[str] = None) -> tuple[bool, str, Optional[GovernanceToken]]:
        """Validate a governance token.

        Checks:
        1. Token format (gvl_tok_ prefix)
        2. Token exists in store
        3. Token has not been revoked
        4. Token has not expired
        5. If required_scope is provided, token scope must include it

        Args:
            token: The token string to validate.
            required_scope: Optional scope key that must be present in the token's scope.

        Returns:
            Tuple of (valid: bool, reason: str, token_record: GovernanceToken | None).
        """
        if not token.startswith(TOKEN_PREFIX):
            return False, "Invalid token format: missing gvl_tok_ prefix", None

        with self._lock:
            gov_token = self._tokens.get(token)

        if gov_token is None:
            return False, "Token not recognized", None

        if gov_token.revoked:
            return False, "Token has been revoked", gov_token

        if datetime.now(timezone.utc) >= gov_token.expires_at:
            return False, "Token has expired", gov_token

        if required_scope and gov_token.scope:
            if required_scope not in gov_token.scope:
                return False, f"Token scope does not include '{required_scope}'", gov_token

        return True, "valid", gov_token

    def revoke(self, agent_did: str) -> Optional[GovernanceToken]:
        """Revoke a governance token by agent DID, immediately invalidating it.

        Args:
            agent_did: The DID of the agent whose token should be revoked.

        Returns:
            The revoked GovernanceToken, or None if no token found for that DID.
        """
        with self._lock:
            gov_token = self._by_did.get(agent_did)
            if gov_token is None:
                return None
            gov_token.revoked = True

        log.info("Governance token revoked for DID: %s", agent_did)
        return gov_token

    def is_valid(self, token: str) -> bool:
        """Quick boolean check: is this token currently valid?

        Returns True only if the token exists, is not revoked, and has not expired.
        """
        valid, _, _ = self.validate(token)
        return valid

    def get_by_did(self, agent_did: str) -> Optional[GovernanceToken]:
        """Look up a token by agent DID."""
        with self._lock:
            return self._by_did.get(agent_did)
