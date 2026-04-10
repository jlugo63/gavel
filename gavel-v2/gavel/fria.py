"""
Fundamental Rights Impact Assessment (FRIA) — EU AI Act Article 27.

Before a deployer first uses a high-risk AI system, Article 27(1) of
Regulation (EU) 2024/1689 requires a FRIA documenting six mandatory
elements (a)-(f). This module implements a Pydantic schema for those
elements, a validator that flags missing or shallow sections, and a
gate function that refuses enrollment of applicable agents until a
FRIA is attached.

Scope (Article 27(1)):
  - Bodies governed by public law
  - Private entities providing public services
  - Any deployer of Annex III point 5(b) or 5(c) systems
    (credit scoring; life/health insurance risk & pricing)
  - Excludes: critical infrastructure (Annex III point 2)

This module does not itself talk to market surveillance authorities
(Art. 27(3) notification is operational, not code). It emits a
FriaNotificationPacket ready to be posted to whatever transport the
deployer uses.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from gavel.enrollment import EnrollmentApplication, HighRiskCategory


# ── FRIA schema ────────────────────────────────────────────────

class FriaStatus(str, Enum):
    DRAFT = "draft"
    COMPLETE = "complete"
    NOTIFIED = "notified"          # reported to market surveillance authority
    REJECTED = "rejected"          # validation failed


class DeployerContext(BaseModel):
    """Who is deploying the system and in what capacity."""

    deployer_name: str
    deployer_type: str  # "public_body" | "public_service_provider" | "private_annex_iii_5"
    jurisdiction: str = "EU"
    contact_email: str = ""
    dpo_contact: str = ""  # Data Protection Officer, if any


class FriaAssessment(BaseModel):
    """Article 27(1)(a)-(f) — mandatory FRIA contents."""

    # Reference metadata
    fria_id: str = Field(default_factory=lambda: f"fria-{datetime.now(timezone.utc).timestamp():.0f}")
    agent_id: str
    deployer: DeployerContext
    status: FriaStatus = FriaStatus.DRAFT
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Art. 27(1)(a) — Processes in which the system will be used
    process_description: str = ""

    # Art. 27(1)(b) — Period and frequency of use
    usage_period: str = ""
    usage_frequency: str = ""

    # Art. 27(1)(c) — Affected categories of natural persons / groups
    affected_categories: list[str] = Field(default_factory=list)

    # Art. 27(1)(d) — Specific risks of harm
    risks_of_harm: list[str] = Field(default_factory=list)

    # Art. 27(1)(e) — Human oversight implementation
    human_oversight_measures: str = ""

    # Art. 27(1)(f) — Mitigation measures + complaint mechanisms
    mitigation_measures: list[str] = Field(default_factory=list)
    complaint_mechanism: str = ""

    # DPIA reuse per Art. 27(4)
    linked_dpia_reference: Optional[str] = None

    def mark_updated(self) -> None:
        self.updated_at = datetime.now(timezone.utc)


class FriaValidationResult(BaseModel):
    """Result of validating a FriaAssessment against Art. 27(1)."""

    passed: bool
    missing_sections: list[str] = Field(default_factory=list)
    shallow_sections: list[str] = Field(default_factory=list)
    article_references: list[str] = Field(default_factory=list)


class FriaNotificationPacket(BaseModel):
    """Art. 27(3) notification packet for the market surveillance authority."""

    fria_id: str
    deployer_name: str
    jurisdiction: str
    agent_id: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: dict[str, str] = Field(default_factory=dict)
    full_assessment: dict = Field(default_factory=dict)


# ── Gate ───────────────────────────────────────────────────────

# Annex III items triggering FRIA for *any* deployer (Art. 27(1)).
# Item numbering maps to Gavel's high-risk categories.
_FRIA_ALWAYS_REQUIRED: set[HighRiskCategory] = {
    HighRiskCategory.ESSENTIAL_SERVICES,  # 5(b)+5(c): credit scoring, insurance
}

# Annex III item 2 — critical infrastructure — is explicitly excluded
# from FRIA by Art. 27(1).
_FRIA_EXCLUDED: set[HighRiskCategory] = {
    HighRiskCategory.CRITICAL_INFRASTRUCTURE,
}


def fria_required(app: EnrollmentApplication) -> bool:
    """Decide whether an enrollment application requires a FRIA.

    A FRIA is mandated when:
      - the declared or auto-classified category is in the "always"
        set (credit scoring / insurance — Annex III 5(b)(c)), OR
      - the agent is any high-risk Annex III system AND the deployer
        is a public body or public-service provider.

    We don't know the deployer type from the enrollment application
    alone — Gavel's contract is that any agent flagged as high-risk
    and public-facing must attach a FRIA before enrollment completes.
    The ESSENTIAL_SERVICES case is mandatory regardless of deployer.
    """
    if app.high_risk_category in _FRIA_EXCLUDED:
        return False
    if app.high_risk_category in _FRIA_ALWAYS_REQUIRED:
        return True
    # Public-facing high-risk categories: require FRIA.
    if app.high_risk_category != HighRiskCategory.NONE and app.interaction_type in (
        "human_facing",
        "mixed",
    ):
        return True
    return False


# ── Validator ──────────────────────────────────────────────────

_MIN_PROSE_CHARS = 40


def _prose_is_shallow(text: str) -> bool:
    return len(text.strip()) < _MIN_PROSE_CHARS


def validate_fria(assessment: FriaAssessment) -> FriaValidationResult:
    """Check that every Art. 27(1) section is populated with substantive content."""
    missing: list[str] = []
    shallow: list[str] = []
    refs: list[str] = []

    # (a) Process description
    if not assessment.process_description.strip():
        missing.append("Art. 27(1)(a): process description")
    elif _prose_is_shallow(assessment.process_description):
        shallow.append("Art. 27(1)(a): process description too shallow")
    refs.append("Art. 27(1)(a)")

    # (b) Usage period + frequency
    if not assessment.usage_period.strip():
        missing.append("Art. 27(1)(b): usage period")
    if not assessment.usage_frequency.strip():
        missing.append("Art. 27(1)(b): usage frequency")
    refs.append("Art. 27(1)(b)")

    # (c) Affected categories
    if not assessment.affected_categories:
        missing.append("Art. 27(1)(c): affected categories of natural persons")
    refs.append("Art. 27(1)(c)")

    # (d) Risks of harm
    if not assessment.risks_of_harm:
        missing.append("Art. 27(1)(d): specific risks of harm")
    elif len(assessment.risks_of_harm) < 2:
        shallow.append("Art. 27(1)(d): only one risk declared — document all foreseeable harms")
    refs.append("Art. 27(1)(d)")

    # (e) Human oversight
    if not assessment.human_oversight_measures.strip():
        missing.append("Art. 27(1)(e): human oversight measures")
    elif _prose_is_shallow(assessment.human_oversight_measures):
        shallow.append("Art. 27(1)(e): human oversight description too shallow")
    refs.append("Art. 27(1)(e)")

    # (f) Mitigations + complaint mechanism
    if not assessment.mitigation_measures:
        missing.append("Art. 27(1)(f): mitigation measures")
    if not assessment.complaint_mechanism.strip():
        missing.append("Art. 27(1)(f): complaint mechanism")
    refs.append("Art. 27(1)(f)")

    # Deployer metadata
    if not assessment.deployer.deployer_name.strip():
        missing.append("Deployer identity")

    passed = not missing and not shallow
    return FriaValidationResult(
        passed=passed,
        missing_sections=missing,
        shallow_sections=shallow,
        article_references=refs,
    )


# ── Registry ───────────────────────────────────────────────────

class FriaRegistry:
    """Store for FRIAs, keyed by agent_id."""

    def __init__(self):
        self._by_agent: dict[str, FriaAssessment] = {}

    def attach(self, assessment: FriaAssessment) -> FriaValidationResult:
        """Attach (or replace) a FRIA for an agent. Returns validation result."""
        result = validate_fria(assessment)
        if result.passed:
            assessment.status = FriaStatus.COMPLETE
        else:
            assessment.status = FriaStatus.REJECTED
        assessment.mark_updated()
        self._by_agent[assessment.agent_id] = assessment
        return result

    def get(self, agent_id: str) -> Optional[FriaAssessment]:
        return self._by_agent.get(agent_id)

    def has_valid(self, agent_id: str) -> bool:
        fria = self._by_agent.get(agent_id)
        return fria is not None and fria.status == FriaStatus.COMPLETE

    def notify_authority(self, agent_id: str) -> Optional[FriaNotificationPacket]:
        """Produce an Art. 27(3) notification packet for dispatch."""
        fria = self._by_agent.get(agent_id)
        if fria is None or fria.status != FriaStatus.COMPLETE:
            return None

        packet = FriaNotificationPacket(
            fria_id=fria.fria_id,
            deployer_name=fria.deployer.deployer_name,
            jurisdiction=fria.deployer.jurisdiction,
            agent_id=agent_id,
            summary={
                "process": fria.process_description[:200],
                "usage_period": fria.usage_period,
                "usage_frequency": fria.usage_frequency,
                "affected_count": str(len(fria.affected_categories)),
                "risk_count": str(len(fria.risks_of_harm)),
                "oversight": fria.human_oversight_measures[:200],
            },
            full_assessment=fria.model_dump(mode="json"),
        )
        fria.status = FriaStatus.NOTIFIED
        fria.mark_updated()
        return packet
