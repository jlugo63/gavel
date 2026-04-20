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
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, TYPE_CHECKING

# ── Re-export all data models from gavel.models.enrollment ────
# This keeps every existing ``from gavel.enrollment import X`` working.
from gavel.models.enrollment import (  # noqa: F401 — re-exports
    ActionBoundaries,
    CapabilityManifest,
    DEFAULT_TOKEN_TTL_SECONDS,
    EnrollmentApplication,
    EnrollmentRecord,
    EnrollmentStatus,
    FallbackBehavior,
    GovernanceToken,
    HighRiskCategory,
    PurposeDeclaration,
    ResourceAllowlist,
    TOKEN_PREFIX,
)

if TYPE_CHECKING:
    from gavel.db.repositories import (
        EnrollmentRepository,
        GovernanceTokenRepository,
    )

log = logging.getLogger("gavel.enrollment")


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

import re as _re

# ── Article 5 Prohibited Practice Detection ──────────────────
#
# Each Article 5 prohibition is captured by a set of regex patterns that
# look for co-occurring semantic components, not single bigram keywords.
# This catches naturally-phrased descriptions (e.g. from LLM-generated
# enrollment applications) that paraphrase the prohibition without using
# the Act's exact wording.
#
# Patterns are compiled once at module load for performance.

_PROHIBITED_PATTERNS: list[tuple[str, list["_re.Pattern[str]"]]] = []

def _compile_prohibited() -> list[tuple[str, list["_re.Pattern[str]"]]]:
    """Build and compile Article 5 pattern families."""
    specs: list[tuple[str, list[str]]] = [
        # Art. 5(1)(a) — Subliminal manipulation
        ("Art. 5(1)(a): Subliminal techniques to materially distort behavior", [
            r"subliminal",                                           # any mention
            r"imperceptib\w*.*\b(influenc|manipulat|nudg|persuad|cue|modify)",
            r"\b(influenc|manipulat)\w*.*\bwithout\b.*\b(notic|aware|conscious|perceiv)",
        ]),
        # Art. 5(1)(b) — Exploitation of vulnerabilities
        ("Art. 5(1)(b): Exploiting vulnerabilities of specific groups (age, disability)", [
            r"exploit\w*\s+(vulnerab|disab|elder|minor|child|infirm)",
            r"(target|manipulat)\w*.*\b(vulnerab|disab|elderly|minor|child)\b",
        ]),
        # Art. 5(1)(c) — Social scoring
        ("Art. 5(1)(c): Social scoring by public authorities or on their behalf", [
            r"social\s+(scor|credit)",                               # exact phrase
            r"(rank|scor|rat[ei]|classif|assess)\w*.*\bcitizen\w*.*\b(behavio|conduct|social)",
            r"citizen\w*.*\b(rank|scor|eligib)\w*.*\b(benefit|service|allocat|housing|municipal)",
            r"(social\s+behavio|public\s+record).*\b(rank|scor|allocat|eligib)",
        ]),
        # Art. 5(1)(d) — Real-time remote biometric identification
        ("Art. 5(1)(d): Real-time remote biometric identification in public spaces", [
            r"real.?time.*biometric.*identif",                       # exact phrase
            r"mass\s+surveillance",
            r"(facial\s+recogni|face\s+match)\w*.*\b(public|cctv|crowd|surveillance|watchlist)",
            r"real.?time.*identif\w*.*\b(face|biometric|individual)",
            r"(cctv|surveillance|live\b.*\bvideo).*\b(identif|recogni|match)\w*.*\b(face|individual|watchlist)",
        ]),
        # Art. 5(1)(d) — Individual predictive policing
        ("Art. 5(1)(d): Individual predictive policing based solely on profiling", [
            r"predictive\s+policing.*individual",
            r"predict\w*.*\bcrim\w*.*\b(individual|profil|person)",
        ]),
        # Art. 5(1)(f) — Emotion recognition in workplace / education
        ("Art. 5(1)(f): Emotion recognition in workplace or education institutions", [
            r"emotion\s+recognition\s+(workplace|education)",        # exact phrase
            r"(emotion|sentiment|facial\s+express|vocal\s+ton)\w*.*\b(employ|workplace|hr\b|meeting|staff|corporate|office)",
            r"(employ|workplace|hr\b|staff|corporate).*\b(emotion|sentiment|facial\s+express)",
            r"(emotion|sentiment)\w*.*\b(student|classroom|school|university|education)",
        ]),
    ]
    return [
        (citation, [_re.compile(p, _re.IGNORECASE | _re.DOTALL) for p in patterns])
        for citation, patterns in specs
    ]

_PROHIBITED_PATTERNS = _compile_prohibited()

# Keyword list for classify_risk_category fast-path.
_PROHIBITED_KEYWORDS: list[str] = [
    "social scoring", "social credit",
    "subliminal manipulation", "subliminal technique", "subliminal",
    "exploit vulnerability", "exploit disabled", "exploit elderly", "exploit minor",
    "real-time biometric identification", "mass surveillance",
    "predictive policing individual",
    "emotion recognition workplace", "emotion recognition education",
]


def classify_risk_category(purpose: PurposeDeclaration, capabilities: CapabilityManifest) -> HighRiskCategory:
    """Auto-classify agent into EU AI Act Annex III risk category."""
    text = f"{purpose.summary} {purpose.operational_scope}".lower()

    for keyword in _PROHIBITED_KEYWORDS:
        if keyword in text:
            return HighRiskCategory.PROHIBITED

    # Regex pass catches paraphrased descriptions that keyword matching misses
    for _citation, patterns in _PROHIBITED_PATTERNS:
        if any(p.search(text) for p in patterns):
            return HighRiskCategory.PROHIBITED

    for category, keywords in _RISK_CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text:
                return category

    return HighRiskCategory.NONE


def detect_prohibited_practices(app: "EnrollmentApplication") -> list[str]:
    """Detect EU AI Act Article 5 prohibited practices in an enrollment application.

    Uses two detection layers:
      1. Fast keyword substring check (catches exact phrasing).
      2. Regex pattern families (catches LLM-generated paraphrases).
    """
    violations = []
    text = f"{app.purpose.summary} {app.purpose.operational_scope} {app.display_name}".lower()

    # Layer 1: keyword checks (fast, covers exact Act wording)
    if any(k in text for k in ["social scoring", "social credit"]):
        violations.append("Art. 5(1)(c): Social scoring by public authorities or on their behalf")

    if any(k in text for k in ["subliminal manipulation", "subliminal technique", "subliminal"]):
        violations.append("Art. 5(1)(a): Subliminal techniques to materially distort behavior")

    if any(k in text for k in ["exploit vulnerability", "exploit disabled", "exploit elderly", "exploit minor"]):
        violations.append("Art. 5(1)(b): Exploiting vulnerabilities of specific groups (age, disability)")

    if any(k in text for k in ["real-time biometric identification", "mass surveillance"]):
        violations.append("Art. 5(1)(d): Real-time remote biometric identification in public spaces")

    if "predictive policing individual" in text:
        violations.append("Art. 5(1)(d): Individual predictive policing based solely on profiling")

    if any(k in text for k in ["emotion recognition workplace", "emotion recognition education"]):
        violations.append("Art. 5(1)(f): Emotion recognition in workplace or education institutions")

    # Layer 2: regex pattern families (catches paraphrases)
    for citation, patterns in _PROHIBITED_PATTERNS:
        if citation not in violations and any(p.search(text) for p in patterns):
            violations.append(citation)

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
    """Stores and manages enrollment records.

    Storage is backed by :class:`gavel.db.repositories.EnrollmentRepository`.
    Validation logic stays in :class:`EnrollmentValidator`.
    """

    def __init__(self, repo: "EnrollmentRepository"):
        self._repo = repo
        self._validator = EnrollmentValidator()

    async def submit(self, application: EnrollmentApplication) -> EnrollmentRecord:
        """Submit an enrollment application. Validates and returns the record."""
        passed, violations = self._validator.validate(application)

        if passed:
            status = EnrollmentStatus.ENROLLED
        elif any("Art. 5" in v or "prohibited" in v.lower() for v in violations):
            status = EnrollmentStatus.REJECTED
        else:
            status = EnrollmentStatus.INCOMPLETE

        record = EnrollmentRecord(
            agent_id=application.agent_id,
            status=status,
            application=application,
            enrolled_at=datetime.now(timezone.utc) if passed else None,
            violations=violations,
        )

        await self._repo.save(record)

        if passed:
            log.info("Agent %s enrolled successfully (owner: %s)", application.agent_id, application.owner)
        elif status == EnrollmentStatus.REJECTED:
            log.warning(
                "Agent %s enrollment REJECTED — prohibited practice: %s",
                application.agent_id, "; ".join(violations),
            )
        else:
            log.warning(
                "Agent %s enrollment INCOMPLETE — %d violations: %s",
                application.agent_id, len(violations), "; ".join(violations),
            )

        return record

    async def is_enrolled(self, agent_id: str) -> bool:
        """Check if an agent has completed enrollment."""
        record = await self._repo.get(agent_id)
        return record is not None and record.status == EnrollmentStatus.ENROLLED

    async def get(self, agent_id: str) -> Optional[EnrollmentRecord]:
        return await self._repo.get(agent_id)

    async def get_all(self) -> list[EnrollmentRecord]:
        return await self._repo.list_all()

    async def reject(self, agent_id: str, reason: str, reviewed_by: str) -> Optional[EnrollmentRecord]:
        """Reject an enrollment application."""
        record = await self._repo.get(agent_id)
        if not record:
            return None
        record.status = EnrollmentStatus.REJECTED
        record.rejection_reason = reason
        record.reviewed_by = reviewed_by
        await self._repo.save(record)
        return record

    async def approve_manual(self, agent_id: str, reviewed_by: str) -> Optional[EnrollmentRecord]:
        """Manually approve an incomplete enrollment (override)."""
        record = await self._repo.get(agent_id)
        if not record:
            return None
        record.status = EnrollmentStatus.ENROLLED
        record.enrolled_at = datetime.now(timezone.utc)
        record.reviewed_by = reviewed_by
        await self._repo.save(record)
        log.info("Agent %s manually enrolled by %s", agent_id, reviewed_by)
        return record

    async def suspend(self, agent_id: str) -> Optional[EnrollmentRecord]:
        """Suspend an enrolled agent's enrollment."""
        record = await self._repo.get(agent_id)
        if not record:
            return None
        record.status = EnrollmentStatus.SUSPENDED
        await self._repo.save(record)
        return record


# ── Governance Token helpers ─────────────────────────────────

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

    Storage is backed by :class:`gavel.db.repositories.GovernanceTokenRepository`.
    """

    def __init__(self, repo: "GovernanceTokenRepository") -> None:
        self._repo = repo

    async def issue(
        self,
        agent_id: str,
        machine_id: str = "local",
        pid: int = 0,
        ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
        scope: Optional[dict[str, Any]] = None,
    ) -> GovernanceToken:
        """Issue a new governance token for an enrolled agent."""
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

        await self._repo.save(gov_token)

        log.info("Governance token issued for agent %s (DID: %s, TTL: %ds)", agent_id, agent_did, ttl_seconds)
        return gov_token

    async def validate(
        self, token: str, required_scope: Optional[str] = None
    ) -> tuple[bool, str, Optional[GovernanceToken]]:
        """Validate a governance token.

        Returns ``(valid, reason, token_record)``. The 3-tuple shape is
        locked — ``reason`` is always a human-readable string.
        """
        if not token.startswith(TOKEN_PREFIX):
            return False, "Invalid token format: missing gvl_tok_ prefix", None

        gov_token = await self._repo.get(token)

        if gov_token is None:
            return False, "Token not recognized", None

        if gov_token.revoked:
            return False, "Token has been revoked", gov_token

        expires = gov_token.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) >= expires:
            return False, "Token has expired", gov_token

        if required_scope and gov_token.scope:
            if required_scope not in gov_token.scope:
                return False, f"Token scope does not include '{required_scope}'", gov_token

        return True, "valid", gov_token

    async def revoke(self, agent_did: str) -> Optional[GovernanceToken]:
        """Revoke every governance token issued to ``agent_did``.

        Flips ``revoked=True`` on each row so subsequent validations
        can report ``revoked`` rather than ``not recognized``. Returns
        the revoked token record (first one) for callers that expect
        ``Optional[GovernanceToken]``.
        """
        tokens = await self._repo.get_by_agent(agent_did)
        if not tokens:
            return None

        await self._repo.mark_revoked(agent_did)
        gov_token = tokens[0]
        gov_token.revoked = True

        log.info("Governance token revoked for DID: %s", agent_did)
        return gov_token

    async def is_valid(self, token: str) -> bool:
        """Quick boolean check: is this token currently valid?"""
        valid, _, _ = await self.validate(token)
        return valid

    async def get_by_did(self, agent_did: str) -> Optional[GovernanceToken]:
        """Look up a token by agent DID.

        The repo returns a list (multiple tokens per DID are possible in
        theory, but all call sites assume a single active token per DID).
        Returns the first token or ``None``.
        """
        tokens = await self._repo.get_by_agent(agent_did)
        if not tokens:
            return None
        return tokens[0]

    async def cleanup_expired(self) -> int:
        """Remove expired and revoked tokens.

        Runs two repo deletes so either condition alone is sufficient for
        a row to be swept. ``mark_revoked`` leaves the row in place so
        ``validate`` can report a ``revoked`` reason; this method garbage-
        collects those rows once the caller no longer needs that signal.
        """
        now = datetime.now(timezone.utc)
        expired = await self._repo.delete_expired(now)
        revoked = await self._repo.delete_revoked()
        total = expired + revoked
        if total:
            log.info(
                "Token cleanup: removed %d expired + %d revoked tokens",
                expired,
                revoked,
            )
        return total
