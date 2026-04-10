"""
Quality Management System — EU AI Act Article 17 / prEN 18286.

Article 17 of Regulation (EU) 2024/1689 requires providers of high-risk
AI systems to put in place a systematic, documented Quality Management
System covering the full lifecycle: design, development, testing,
post-market monitoring, corrective action, and record-keeping.

prEN 18286 (the draft harmonised standard) structures a QMS into the
13 subclauses mirroring Art. 17(1)(a)–(m). This module implements a
Pydantic schema for those subclauses, a coverage report that identifies
which clauses Gavel can evidence from its own runtime data (and which
require provider-supplied documentation), and a Markdown exporter that
produces a human-readable QMS manual suitable for regulator review.

Gavel is a governance framework, not a training-lifecycle tool. For
clauses that concern pre-deployment development (e.g. "techniques for
design, design control, and design verification"), we acknowledge the
clause and flag it as "provider_must_document" rather than fabricating
evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class QmsCoverage(str, Enum):
    AUTOMATED = "automated"                 # Gavel emits evidence for this clause
    PROVIDER_DOCUMENTED = "provider_must_document"  # Gavel cannot provide; provider supplies
    PARTIAL = "partial"                     # Gavel covers part; provider fills the rest


class QmsClause(BaseModel):
    """One of the 13 clauses enumerated in Art. 17(1)."""

    article_ref: str                         # "Art. 17(1)(a)"
    title: str
    description: str
    coverage: QmsCoverage
    gavel_evidence: list[str] = Field(default_factory=list)
    provider_required_input: list[str] = Field(default_factory=list)


class QmsManual(BaseModel):
    """Full QMS manual for one provider."""

    provider_name: str
    system_name: str
    manual_version: str = "1.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    clauses: list[QmsClause] = Field(default_factory=list)

    def coverage_summary(self) -> dict[str, int]:
        summary = {c.value: 0 for c in QmsCoverage}
        for cl in self.clauses:
            summary[cl.coverage.value] += 1
        return summary

    def to_markdown(self) -> str:
        lines = [
            f"# QMS Manual — {self.system_name}",
            f"**Provider:** {self.provider_name}  ",
            f"**Version:** {self.manual_version}  ",
            f"**Generated:** {self.generated_at.isoformat()}",
            "",
            "Prepared in accordance with **EU AI Act Art. 17** and the "
            "draft harmonised standard **prEN 18286**.",
            "",
            "## Coverage summary",
            "",
        ]
        summary = self.coverage_summary()
        for k, v in summary.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")
        for cl in self.clauses:
            lines.append(f"## {cl.article_ref} — {cl.title}")
            lines.append("")
            lines.append(cl.description)
            lines.append("")
            lines.append(f"**Coverage:** `{cl.coverage.value}`")
            lines.append("")
            if cl.gavel_evidence:
                lines.append("**Gavel evidence:**")
                for ev in cl.gavel_evidence:
                    lines.append(f"- {ev}")
                lines.append("")
            if cl.provider_required_input:
                lines.append("**Provider must supply:**")
                for inp in cl.provider_required_input:
                    lines.append(f"- {inp}")
                lines.append("")
        return "\n".join(lines)


# ── Generator ──────────────────────────────────────────────────

class QmsGenerator:
    """Build a QMS manual from Gavel's runtime data + provider metadata."""

    def __init__(
        self,
        provider_name: str,
        system_name: str,
        enrollment_record: Any = None,
        chains: Optional[list[Any]] = None,
        incidents: Optional[list[Any]] = None,
        reviews: Optional[list[Any]] = None,
    ):
        self.provider_name = provider_name
        self.system_name = system_name
        self._enrollment = enrollment_record
        self._chains = chains or []
        self._incidents = incidents or []
        self._reviews = reviews or []

    def generate(self) -> QmsManual:
        clauses = [
            self._clause_a_compliance_strategy(),
            self._clause_b_design_control(),
            self._clause_c_development_verification(),
            self._clause_d_data_management(),
            self._clause_e_risk_management(),
            self._clause_f_post_market_monitoring(),
            self._clause_g_serious_incident_reporting(),
            self._clause_h_communication_authorities(),
            self._clause_i_record_keeping(),
            self._clause_j_resource_management(),
            self._clause_k_accountability_framework(),
            self._clause_l_testing_validation(),
            self._clause_m_continuous_improvement(),
        ]
        return QmsManual(
            provider_name=self.provider_name,
            system_name=self.system_name,
            clauses=clauses,
        )

    # ---- individual clauses ----

    def _clause_a_compliance_strategy(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(a)",
            title="Strategy for regulatory compliance",
            description=(
                "A documented strategy covering conformity-assessment procedures and "
                "the handling of modifications to the AI system."
            ),
            coverage=QmsCoverage.PARTIAL,
            gavel_evidence=[
                "Constitution (gavel.constitution) — 11 enforced invariants",
                "Cedar policy rules (gavel/policies/) loaded into Agent OS",
                "AnnexIVGenerator (gavel.compliance) emits conformity documentation",
            ],
            provider_required_input=[
                "Conformity-assessment procedure declaration (Annex VI or VII)",
                "Change-management policy for system modifications",
            ],
        )

    def _clause_b_design_control(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(b)",
            title="Techniques for design, design control, and design verification",
            description=(
                "Methods used during development to control and verify the AI system's "
                "design against requirements."
            ),
            coverage=QmsCoverage.PROVIDER_DOCUMENTED,
            provider_required_input=[
                "Design control procedures and verification reports",
                "Model card or equivalent design record",
            ],
        )

    def _clause_c_development_verification(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(c)",
            title="Examination, test and validation procedures",
            description=(
                "Procedures applied before, during, and after development of the AI "
                "system and frequency of their application."
            ),
            coverage=QmsCoverage.PROVIDER_DOCUMENTED,
            provider_required_input=[
                "Pre-deployment test reports",
                "Validation dataset documentation",
            ],
        )

    def _clause_d_data_management(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(d)",
            title="Technical specifications and data management procedures",
            description=(
                "Including data acquisition, collection, analysis, labelling, storage, "
                "filtration, mining, aggregation and retention."
            ),
            coverage=QmsCoverage.PARTIAL,
            gavel_evidence=[
                "Enrollment CapabilityManifest declares data surfaces",
                "ResourceAllowlist (S-1) enumerates allowed paths/hosts",
                "Privacy scanner (gavel.privacy) scrubs PII/PHI from evidence",
            ],
            provider_required_input=[
                "Training-data provenance and licensing records",
                "Data preparation pipeline documentation",
            ],
        )

    def _clause_e_risk_management(self) -> QmsClause:
        total_chains = len(self._chains)
        return QmsClause(
            article_ref="Art. 17(1)(e)",
            title="Risk management system (Article 9)",
            description=(
                "An iterative risk management process identifying, analysing, and "
                "mitigating foreseeable risks across the lifecycle."
            ),
            coverage=QmsCoverage.AUTOMATED,
            gavel_evidence=[
                f"Tiered autonomy (gavel.tiers) — {4} tiers with SLA escalation",
                f"Governance chains audited: {total_chains}",
                "Risk scoring at propose-time (gavel.gate)",
                "Blast box sandboxed speculative execution produces evidence packets",
                "Deterministic evidence review (gavel.evidence) — 7 checks + PII scan",
            ],
        )

    def _clause_f_post_market_monitoring(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(f)",
            title="Post-market monitoring system (Article 72)",
            description=(
                "Continuous collection and review of real-world performance data after "
                "deployment."
            ),
            coverage=QmsCoverage.AUTOMATED,
            gavel_evidence=[
                "Behavioral baseline (gavel.baseline) per-agent rolling stats",
                "Drift detection against enrollment snapshot",
                "Liveness monitor (gavel.liveness) with SLA-based escalation",
                "Event bus with Server-Sent Events for real-time monitoring",
            ],
        )

    def _clause_g_serious_incident_reporting(self) -> QmsClause:
        open_incidents = sum(1 for i in self._incidents if getattr(i, "status", None) != "closed")
        return QmsClause(
            article_ref="Art. 17(1)(g)",
            title="Reporting of serious incidents (Article 73)",
            description=(
                "Procedures for detecting, investigating, and reporting serious "
                "incidents within the statutory time windows."
            ),
            coverage=QmsCoverage.AUTOMATED,
            gavel_evidence=[
                "IncidentRegistry (gavel.compliance) with full lifecycle",
                "IncidentClassifier with 2-day / 15-day deadline computation",
                f"Currently tracked open incidents: {open_incidents}",
                "Dashboard incident panel with deadline countdowns",
            ],
        )

    def _clause_h_communication_authorities(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(h)",
            title="Communication with national authorities and bodies",
            description=(
                "Channels for communication with national competent authorities, "
                "market surveillance authorities, notified bodies, and customers."
            ),
            coverage=QmsCoverage.PARTIAL,
            gavel_evidence=[
                "FriaNotificationPacket (gavel.fria) ready for Art. 27(3) submission",
                "Incident report export to JSON/Markdown",
            ],
            provider_required_input=[
                "Contact list for market surveillance authorities per jurisdiction",
                "Escalation procedures for notified bodies",
            ],
        )

    def _clause_i_record_keeping(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(i)",
            title="Record-keeping of documentation and logs",
            description=(
                "Systems for record-keeping of all relevant documentation and logs "
                "per Article 12."
            ),
            coverage=QmsCoverage.AUTOMATED,
            gavel_evidence=[
                "Append-only governance chain (gavel.chain) with SHA-256 linkage",
                "Tamper detection via chain integrity verification",
                "GovernanceArtifact export with artifact_hash + genesis_hash",
                "Enrollment ledger with cryptographic audit trail",
            ],
        )

    def _clause_j_resource_management(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(j)",
            title="Resource management and supply chain",
            description=(
                "Management of resources including security-of-supply-related "
                "measures."
            ),
            coverage=QmsCoverage.PROVIDER_DOCUMENTED,
            provider_required_input=[
                "Supplier list and supply-chain risk assessment",
                "Security review of third-party dependencies",
            ],
        )

    def _clause_k_accountability_framework(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(k)",
            title="Accountability framework",
            description=(
                "Clear definition of responsibilities of management and staff with "
                "regard to all aspects of the QMS."
            ),
            coverage=QmsCoverage.PARTIAL,
            gavel_evidence=[
                "Separation of powers enforced structurally (gavel.separation)",
                "Proposer ≠ reviewer ≠ approver at chain append site",
                "Enrollment application records accountable owner + contact",
                "Agent maturity model (gavel.agents) with promotion/demotion",
            ],
            provider_required_input=[
                "Organisational responsibility matrix",
                "Roles and reporting lines for AI governance",
            ],
        )

    def _clause_l_testing_validation(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(l)",
            title="Adversarial testing and validation",
            description=(
                "Procedures for adversarial testing, robustness validation, and "
                "cybersecurity (Article 15)."
            ),
            coverage=QmsCoverage.AUTOMATED,
            gavel_evidence=[
                "tests/test_adversarial.py — self-approval, hash tampering, collusion, SLA stalling",
                "tests/test_adversarial_threat_model.py — STRIDE-based resilience coverage",
                "Constitutional FORBID rules for kill switch, registration gate",
            ],
        )

    def _clause_m_continuous_improvement(self) -> QmsClause:
        return QmsClause(
            article_ref="Art. 17(1)(m)",
            title="Continuous improvement procedure",
            description=(
                "Procedures ensuring continuous compliance and improvement across the "
                "AI system lifecycle."
            ),
            coverage=QmsCoverage.PARTIAL,
            gavel_evidence=[
                "Roadmap-driven phased implementation with versioned releases",
                "Automatic demotion on violations feeds back into risk scoring",
                "Drift detection triggers behavioral baseline refresh",
            ],
            provider_required_input=[
                "Review cadence for QMS effectiveness",
                "Corrective-action log template",
            ],
        )
