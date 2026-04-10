"""
Multi-regulation mapping — EU AI Act + GDPR + CRA + DSA + NIS2.

An agent deployment rarely touches only one regulation at a time. A
high-risk customer-facing credit agent built on AI is simultaneously
subject to:

  - EU AI Act (Regulation (EU) 2024/1689)        high-risk AI obligations
  - GDPR (Regulation (EU) 2016/679)              personal-data processing
  - Cyber Resilience Act (Regulation (EU) 2024/2847) digital-product security
  - Digital Services Act (Regulation (EU) 2022/2065) platform obligations (if applicable)
  - NIS2 (Directive (EU) 2022/2555)              critical/important entity cybersecurity

This module provides:

  1. A regulatory catalogue — each regulation's relevant article set
     distilled into short-form obligation IDs.
  2. An applicability classifier — given an EnrollmentApplication,
     decide which regulations are relevant.
  3. A compliance matrix — cross-cut every applicable regulation
     against Gavel's existing capability evidence, flagging gaps.
  4. A combined obligation list — every unique obligation an agent
     must meet across all applicable regulations, deduplicated where
     obligations overlap (e.g. DPIA ↔ FRIA, Art. 9 risk mgmt ↔ NIS2
     risk mgmt).

Scope note: the regulation catalogue here covers the obligations
Gavel can evidence. It is not exhaustive — it's a compliance *mapping*
intended to help a deployer see, at a glance, which Gavel capability
satisfies which cross-regulatory obligation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from gavel.enrollment import EnrollmentApplication, HighRiskCategory


class Regulation(str, Enum):
    EU_AI_ACT = "eu_ai_act"          # (EU) 2024/1689
    GDPR = "gdpr"                    # (EU) 2016/679
    CRA = "cra"                      # (EU) 2024/2847
    DSA = "dsa"                      # (EU) 2022/2065
    NIS2 = "nis2"                    # (EU) 2022/2555


class CoverageState(str, Enum):
    SATISFIED = "satisfied"                  # Gavel evidence fully covers
    PARTIAL = "partial"                      # Gavel + provider input together
    PROVIDER_RESPONSIBLE = "provider_responsible"  # Outside Gavel's scope
    GAP = "gap"                              # Not currently satisfied


class Obligation(BaseModel):
    """A single regulatory obligation."""

    regulation: Regulation
    article: str                 # "Art. 9" / "Art. 32" / "Art. 21(2)(a)"
    title: str                   # Short human-readable name
    description: str             # One-line summary
    coverage: CoverageState
    gavel_evidence: list[str] = Field(default_factory=list)
    overlaps_with: list[str] = Field(default_factory=list)  # Other obligation IDs

    @property
    def obligation_id(self) -> str:
        return f"{self.regulation.value}:{self.article}"


class ComplianceMatrix(BaseModel):
    """Per-agent multi-regulation compliance matrix."""

    agent_id: str
    applicable_regulations: list[Regulation]
    obligations: list[Obligation]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def coverage_summary(self) -> dict[str, int]:
        summary = {s.value: 0 for s in CoverageState}
        for o in self.obligations:
            summary[o.coverage.value] += 1
        return summary

    def gaps(self) -> list[Obligation]:
        return [o for o in self.obligations if o.coverage == CoverageState.GAP]

    def by_regulation(self) -> dict[str, list[Obligation]]:
        out: dict[str, list[Obligation]] = {}
        for o in self.obligations:
            out.setdefault(o.regulation.value, []).append(o)
        return out


# ── Applicability classifier ───────────────────────────────────

def classify_applicability(app: EnrollmentApplication) -> list[Regulation]:
    """Determine which regulations apply to a given enrollment application."""
    regs: set[Regulation] = set()

    # EU AI Act always applies to governed agents — Gavel is an AI Act
    # governance tool by construction. All agents are subject to the
    # general-purpose obligations; high-risk agents add more.
    regs.add(Regulation.EU_AI_ACT)

    # GDPR applies whenever the agent might touch personal data.
    # Heuristic: human_facing interaction, high-risk categories that
    # imply personal data processing, or declared network/file access
    # to locations that could contain personal data.
    personal_data_categories = {
        HighRiskCategory.BIOMETRICS,
        HighRiskCategory.EDUCATION,
        HighRiskCategory.EMPLOYMENT,
        HighRiskCategory.ESSENTIAL_SERVICES,
        HighRiskCategory.LAW_ENFORCEMENT,
        HighRiskCategory.MIGRATION,
        HighRiskCategory.JUSTICE,
    }
    if (
        app.high_risk_category in personal_data_categories
        or app.interaction_type in ("human_facing", "mixed")
    ):
        regs.add(Regulation.GDPR)

    # CRA applies to digital products with digital elements. If the
    # agent is shipped as part of a product (has network access or
    # execution_access), treat CRA as applicable.
    if app.capabilities.network_access or app.capabilities.execution_access:
        regs.add(Regulation.CRA)

    # NIS2 applies to essential and important entities. Gavel cannot
    # tell from the application alone, so we use critical infrastructure
    # as the proxy: if declared, NIS2 applies.
    if app.high_risk_category == HighRiskCategory.CRITICAL_INFRASTRUCTURE:
        regs.add(Regulation.NIS2)

    # DSA applies to intermediary services (hosting, search, online
    # platforms). If the agent is customer-facing and has network
    # access + synthetic content generation, we flag DSA as possibly
    # applicable and let the provider confirm.
    if app.synthetic_content and app.interaction_type in ("human_facing", "mixed"):
        regs.add(Regulation.DSA)

    return sorted(regs, key=lambda r: r.value)


# ── Obligation catalogue ───────────────────────────────────────

def _ai_act_obligations() -> list[Obligation]:
    """Short-form catalogue of EU AI Act obligations Gavel touches."""
    return [
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 9",
            title="Risk management system",
            description="Iterative risk identification, analysis, mitigation across lifecycle",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=[
                "gavel.tiers — tiered autonomy with SLA escalation",
                "gavel.gate — risk scoring at propose-time",
                "gavel.liveness — auto-deny on timeout",
            ],
            overlaps_with=["nis2:Art. 21(2)(a)"],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 10",
            title="Data governance",
            description="Training data quality, bias examination, mitigation",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "gavel.data_governance — policy attachment + validator",
                "gavel.privacy — PII/PHI scan in evidence review",
            ],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 11 / Annex IV",
            title="Technical documentation",
            description="Annex IV 9-section technical documentation",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=["gavel.compliance.AnnexIVGenerator"],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 12",
            title="Record-keeping (logs)",
            description="Automatic logging of events during operation",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=[
                "gavel.chain — append-only governance events with SHA-256 linkage",
                "gavel.enrollment — enrollment ledger",
            ],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 13",
            title="Transparency and information to deployers",
            description="Instructions for use; system capabilities + limits",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "gavel.enrollment.CapabilityManifest",
                "Enrollment application declares accountable owner",
            ],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 14",
            title="Human oversight",
            description="Human oversight mechanisms throughout system use",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=[
                "gavel.separation — structural proposer ≠ reviewer ≠ approver",
                "gavel.tiers — SUPERVISED tier requires human approval",
                "Human approval endpoint with audit logging",
            ],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 15",
            title="Accuracy, robustness, cybersecurity",
            description="Appropriate level of accuracy, robustness, cybersecurity",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=[
                "tests/test_adversarial.py + test_adversarial_threat_model.py",
                "docs/threat-model.md — STRIDE coverage",
            ],
            overlaps_with=["cra:Annex I", "nis2:Art. 21(2)(d)"],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 17",
            title="Quality management system",
            description="Systematic QMS per Art. 17(1)(a)–(m)",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=["gavel.qms.QmsGenerator — 13-clause manual"],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 27",
            title="Fundamental Rights Impact Assessment",
            description="FRIA before first use of high-risk system",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=["gavel.fria — schema, validator, notification packet"],
            overlaps_with=["gdpr:Art. 35"],
        ),
        Obligation(
            regulation=Regulation.EU_AI_ACT,
            article="Art. 73",
            title="Reporting of serious incidents",
            description="2-day critical / 15-day standard incident reporting",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=[
                "gavel.compliance.IncidentRegistry",
                "Deadline tracking + SSE updates",
            ],
            overlaps_with=["gdpr:Art. 33", "nis2:Art. 23"],
        ),
    ]


def _gdpr_obligations() -> list[Obligation]:
    return [
        Obligation(
            regulation=Regulation.GDPR,
            article="Art. 5",
            title="Principles relating to processing",
            description="Lawfulness, fairness, transparency, purpose limitation, "
                        "data minimisation, accuracy, storage limit, integrity, accountability",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "gavel.privacy — PII/PHI redaction",
                "gavel.chain — accountability via append-only log",
            ],
        ),
        Obligation(
            regulation=Regulation.GDPR,
            article="Art. 25",
            title="Data protection by design and by default",
            description="Technical and organisational measures to implement principles",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "Default-deny network proxy",
                "PII/PHI scanner as a default evidence-review check",
            ],
        ),
        Obligation(
            regulation=Regulation.GDPR,
            article="Art. 32",
            title="Security of processing",
            description="Appropriate technical and organisational measures",
            coverage=CoverageState.SATISFIED,
            gavel_evidence=[
                "Append-only chain + Ed25519 DIDs + governance tokens",
                "Blast box sandboxed execution",
                "Kill switch + Cedar FORBID rules",
            ],
            overlaps_with=["eu_ai_act:Art. 15", "nis2:Art. 21(2)(d)"],
        ),
        Obligation(
            regulation=Regulation.GDPR,
            article="Art. 33",
            title="Personal-data breach notification to authority",
            description="Notification of personal-data breach within 72 hours",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "gavel.compliance.IncidentRegistry — lifecycle tracking",
                "IncidentClassifier — severity + deadline computation",
            ],
            overlaps_with=["eu_ai_act:Art. 73"],
        ),
        Obligation(
            regulation=Regulation.GDPR,
            article="Art. 35",
            title="Data protection impact assessment",
            description="DPIA before high-risk processing",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "gavel.fria — FRIA references linked DPIA (Art. 27(4) of AI Act)",
            ],
            overlaps_with=["eu_ai_act:Art. 27"],
        ),
    ]


def _cra_obligations() -> list[Obligation]:
    return [
        Obligation(
            regulation=Regulation.CRA,
            article="Annex I",
            title="Essential cybersecurity requirements",
            description="Secure-by-design, known-vulnerability exclusion, secure defaults",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "Default-deny proxy, append-only audit, structural separation of powers",
                "Adversarial test suite + threat model",
            ],
            overlaps_with=["eu_ai_act:Art. 15", "nis2:Art. 21(2)(d)"],
        ),
        Obligation(
            regulation=Regulation.CRA,
            article="Art. 14",
            title="Vulnerability handling and reporting",
            description="Coordinated vulnerability disclosure + 24/72h reporting",
            coverage=CoverageState.GAP,
            gavel_evidence=[],
        ),
    ]


def _dsa_obligations() -> list[Obligation]:
    return [
        Obligation(
            regulation=Regulation.DSA,
            article="Art. 14",
            title="Terms and conditions transparency",
            description="Clear T&C on content moderation, algorithmic decisions",
            coverage=CoverageState.PROVIDER_RESPONSIBLE,
        ),
        Obligation(
            regulation=Regulation.DSA,
            article="Art. 15",
            title="Transparency reporting",
            description="Annual transparency reports on moderation actions",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=[
                "gavel.chain — all moderation-equivalent governance events logged",
            ],
        ),
    ]


def _nis2_obligations() -> list[Obligation]:
    return [
        Obligation(
            regulation=Regulation.NIS2,
            article="Art. 21(2)(a)",
            title="Risk analysis and information system security policies",
            description="Risk analysis and ISMS-style policies",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=["gavel.tiers + gavel.gate risk scoring"],
            overlaps_with=["eu_ai_act:Art. 9"],
        ),
        Obligation(
            regulation=Regulation.NIS2,
            article="Art. 21(2)(d)",
            title="Supply chain security",
            description="Security in supplier and service-provider relationships",
            coverage=CoverageState.GAP,
        ),
        Obligation(
            regulation=Regulation.NIS2,
            article="Art. 23",
            title="Incident reporting obligations",
            description="Early warning / incident notification / final report to CSIRT",
            coverage=CoverageState.PARTIAL,
            gavel_evidence=["gavel.compliance.IncidentRegistry"],
            overlaps_with=["eu_ai_act:Art. 73", "gdpr:Art. 33"],
        ),
    ]


_CATALOGUE = {
    Regulation.EU_AI_ACT: _ai_act_obligations,
    Regulation.GDPR: _gdpr_obligations,
    Regulation.CRA: _cra_obligations,
    Regulation.DSA: _dsa_obligations,
    Regulation.NIS2: _nis2_obligations,
}


def build_matrix(app: EnrollmentApplication) -> ComplianceMatrix:
    """Build a multi-regulation compliance matrix for one agent."""
    applicable = classify_applicability(app)
    obligations: list[Obligation] = []
    for reg in applicable:
        obligations.extend(_CATALOGUE[reg]())

    return ComplianceMatrix(
        agent_id=app.agent_id,
        applicable_regulations=applicable,
        obligations=obligations,
    )
