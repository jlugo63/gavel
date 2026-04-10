"""
Compliance Export Bundles — SOC 2, ISO 42001, EU AI Act.

Enterprise customers need to hand auditors a single package that proves
their AI governance meets the relevant framework's requirements. This
module collects evidence from Gavel's audit trail, enrollment records,
RBAC decisions, incidents, and constitutional invariants, then structures
it into framework-specific export bundles.

Each bundle is a JSON-serializable dict with:
  - Framework metadata (version, scope, generated_at)
  - Control-by-control evidence mapping
  - Gap analysis (controls without evidence)
  - Bundle hash for tamper detection
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Framework definitions ─────────────────────────────────────

class ComplianceFramework(str, Enum):
    SOC2 = "soc2"
    ISO_42001 = "iso_42001"
    EU_AI_ACT = "eu_ai_act"


class ControlStatus(str, Enum):
    MET = "met"
    PARTIALLY_MET = "partially_met"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"


class ControlEvidence(BaseModel):
    """Evidence mapped to a specific compliance control."""
    control_id: str
    control_name: str
    description: str
    status: ControlStatus
    evidence_sources: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    gap_description: str = ""


class ComplianceBundle(BaseModel):
    """A complete compliance export bundle for one framework."""
    bundle_id: str = Field(default_factory=lambda: f"bundle-{uuid.uuid4().hex[:8]}")
    framework: ComplianceFramework
    framework_version: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scope: str = "Gavel AI Governance Platform"
    controls: list[ControlEvidence] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    bundle_hash: str = ""

    def compute_hash(self) -> str:
        content = json.dumps(
            {
                "bundle_id": self.bundle_id,
                "framework": self.framework.value,
                "controls": [c.model_dump(mode="json") for c in self.controls],
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def finalize(self) -> None:
        self.bundle_hash = self.compute_hash()
        met = sum(1 for c in self.controls if c.status == ControlStatus.MET)
        partial = sum(1 for c in self.controls if c.status == ControlStatus.PARTIALLY_MET)
        not_met = sum(1 for c in self.controls if c.status == ControlStatus.NOT_MET)
        na = sum(1 for c in self.controls if c.status == ControlStatus.NOT_APPLICABLE)
        total = len(self.controls)
        self.summary = {
            "total_controls": total,
            "met": met,
            "partially_met": partial,
            "not_met": not_met,
            "not_applicable": na,
            "coverage_pct": round((met + partial) / total * 100, 1) if total else 0.0,
        }


# ── SOC 2 Trust Service Criteria ──────────────────────────────

_SOC2_CONTROLS = [
    ("CC1.1", "Control Environment", "The entity demonstrates a commitment to integrity and ethical values"),
    ("CC1.2", "Control Environment", "The board of directors demonstrates independence from management and exercises oversight"),
    ("CC2.1", "Communication and Information", "The entity obtains or generates relevant, quality information to support internal control"),
    ("CC3.1", "Risk Assessment", "The entity specifies objectives with sufficient clarity to identify and assess risks"),
    ("CC3.2", "Risk Assessment", "The entity identifies risks to the achievement of objectives and analyzes risks"),
    ("CC4.1", "Monitoring Activities", "The entity selects, develops, and performs ongoing evaluations to determine whether controls are present and functioning"),
    ("CC5.1", "Control Activities", "The entity selects and develops control activities that contribute to mitigation of risks"),
    ("CC5.2", "Control Activities", "The entity deploys control activities through policies that establish what is expected"),
    ("CC6.1", "Logical and Physical Access Controls", "The entity implements logical access security over protected information assets"),
    ("CC6.2", "Logical and Physical Access Controls", "The entity assesses and manages risks associated with identified system changes"),
    ("CC6.3", "Logical and Physical Access Controls", "The entity restricts access rights to system functionality based on role/responsibilities"),
    ("CC7.1", "System Operations", "The entity detects and monitors changes in infrastructure and software that may affect the system of internal controls"),
    ("CC7.2", "System Operations", "The entity monitors system components for anomalies that are indicative of malicious acts and errors"),
    ("CC7.3", "System Operations", "The entity evaluates security events to determine whether they could or have resulted in failure to meet objectives"),
    ("CC8.1", "Change Management", "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes"),
    ("CC9.1", "Risk Mitigation", "The entity identifies, selects, and develops risk mitigation activities for risks from business processes"),
]


def _build_soc2_evidence(context: dict[str, Any]) -> list[ControlEvidence]:
    """Map Gavel capabilities to SOC 2 Trust Service Criteria."""
    chain_count = context.get("chain_count", 0)
    has_rbac = context.get("has_rbac", False)
    has_audit_trail = context.get("has_audit_trail", False)
    has_enrollment = context.get("has_enrollment", False)
    incident_count = context.get("incident_count", 0)
    has_separation = context.get("has_separation_of_powers", False)
    has_evidence_review = context.get("has_evidence_review", False)
    has_monitoring = context.get("has_monitoring", False)
    has_killswitch = context.get("has_killswitch", False)

    controls = []
    for cid, cname, cdesc in _SOC2_CONTROLS:
        sources = []
        findings = []
        status = ControlStatus.NOT_MET
        gap = ""

        if cid == "CC1.1":
            if has_audit_trail and has_separation:
                status = ControlStatus.MET
                sources = ["gavel/constitution.py — 9 immutable invariants", "gavel/separation.py — role exclusion matrix"]
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "Constitution or separation of powers not fully configured"

        elif cid == "CC1.2":
            status = ControlStatus.PARTIALLY_MET
            sources = ["gavel/rbac.py — operator role hierarchy"]
            gap = "Board-level oversight is organizational, not software-enforced"

        elif cid == "CC2.1":
            if has_audit_trail:
                status = ControlStatus.MET
                sources = ["gavel/chain.py — hash-chained governance events", "gavel/events.py — real-time event bus"]
            else:
                gap = "Audit trail not active"

        elif cid == "CC3.1":
            if has_enrollment:
                status = ControlStatus.MET
                sources = ["gavel/enrollment.py — purpose declaration (ATF I-4)", "gavel/tiers.py — risk-based tier assignment"]
            else:
                gap = "Agent enrollment not configured"

        elif cid == "CC3.2":
            if has_evidence_review:
                status = ControlStatus.MET
                sources = ["gavel/evidence.py — 7 deterministic checks", "gavel/baseline.py — behavioral drift detection"]
                findings.append(f"{chain_count} governance chains processed")
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "Evidence review not active"

        elif cid == "CC4.1":
            if has_monitoring:
                status = ControlStatus.MET
                sources = ["gavel/liveness.py — SLA escalation", "gavel/agents.py — heartbeat monitoring", "gavel/evasion.py — oversight evasion detection"]
            else:
                gap = "Monitoring not active"

        elif cid == "CC5.1":
            if has_separation and has_evidence_review:
                status = ControlStatus.MET
                sources = ["gavel/separation.py — proposer ≠ reviewer ≠ approver", "gavel/blastbox.py — sandboxed execution"]
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "Separation or evidence review not fully configured"

        elif cid == "CC5.2":
            if has_enrollment:
                status = ControlStatus.MET
                sources = ["gavel/enrollment.py — action boundaries (ATF S-2)", "gavel/constitution.py — constitutional invariants"]
            else:
                gap = "Enrollment policies not configured"

        elif cid == "CC6.1":
            if has_rbac:
                status = ControlStatus.MET
                sources = ["gavel/rbac.py — RBAC + ABAC access control", "gavel/enrollment.py — governance tokens (gvl_tok_)"]
            else:
                gap = "RBAC not configured"

        elif cid == "CC6.2":
            status = ControlStatus.MET
            sources = ["gavel/chain.py — hash-chain integrity verification", "gavel/rollback.py — state rollback capability"]

        elif cid == "CC6.3":
            if has_rbac:
                status = ControlStatus.MET
                sources = ["gavel/rbac.py — 5 roles × 16 permissions", "gavel/separation.py — agent role exclusions"]
            else:
                gap = "RBAC not configured"

        elif cid == "CC7.1":
            if has_monitoring:
                status = ControlStatus.MET
                sources = ["gavel/events.py — governance event bus", "gavel/baseline.py — drift detection"]
            else:
                gap = "Monitoring not active"

        elif cid == "CC7.2":
            if has_monitoring:
                status = ControlStatus.MET
                sources = ["gavel/evasion.py — 6 adversarial signal detectors", "gavel/collusion.py — 4 collusion patterns"]
            else:
                gap = "Anomaly detection not active"

        elif cid == "CC7.3":
            status = ControlStatus.MET
            sources = ["gavel/compliance.py — incident classification (4 severity levels)", "gavel/compliance.py — Art. 73 deadline tracking"]
            findings.append(f"{incident_count} incidents tracked")

        elif cid == "CC8.1":
            if has_audit_trail and has_separation:
                status = ControlStatus.MET
                sources = ["gavel/chain.py — propose→evaluate→evidence→review→approve→execute flow", "gavel/separation.py — multi-principal review"]
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "Change management flow not fully configured"

        elif cid == "CC9.1":
            if has_enrollment and has_killswitch:
                status = ControlStatus.MET
                sources = ["gavel/enrollment.py — pre-deployment risk gates", "gavel/agents.py — kill switch", "gavel/tiers.py — tiered autonomy"]
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "Risk mitigation controls not fully configured"

        controls.append(ControlEvidence(
            control_id=cid, control_name=cname, description=cdesc,
            status=status, evidence_sources=sources, findings=findings, gap_description=gap,
        ))
    return controls


# ── ISO 42001 Controls ────────────────────────────────────────

_ISO_42001_CONTROLS = [
    ("4.1", "Context of the Organization", "Understanding the organization and its context for AI management"),
    ("4.2", "Interested Parties", "Understanding the needs and expectations of interested parties"),
    ("5.1", "Leadership and Commitment", "Top management demonstrates leadership and commitment to the AIMS"),
    ("5.2", "AI Policy", "Top management establishes an AI policy appropriate to the purpose of the organization"),
    ("5.3", "Organizational Roles", "Top management ensures responsibilities and authorities for relevant roles are assigned"),
    ("6.1", "Actions to Address Risks", "The organization determines risks and opportunities to be addressed"),
    ("6.2", "AI Objectives", "The organization establishes AI objectives at relevant functions and levels"),
    ("7.1", "Resources", "The organization determines and provides resources needed for the AIMS"),
    ("7.2", "Competence", "The organization determines competence of persons doing work under its control"),
    ("7.5", "Documented Information", "The AIMS includes documented information required by this document"),
    ("8.1", "Operational Planning", "The organization plans, implements, and controls processes needed"),
    ("8.2", "AI Risk Assessment", "The organization performs AI risk assessments at planned intervals"),
    ("8.3", "AI Risk Treatment", "The organization implements the AI risk treatment plan"),
    ("8.4", "AI System Impact Assessment", "The organization conducts AI system impact assessments"),
    ("9.1", "Monitoring and Measurement", "The organization determines what needs to be monitored and measured"),
    ("9.2", "Internal Audit", "The organization conducts internal audits at planned intervals"),
    ("9.3", "Management Review", "Top management reviews the AIMS at planned intervals"),
    ("10.1", "Nonconformity and Corrective Action", "The organization determines actions to address nonconformities"),
    ("10.2", "Continual Improvement", "The organization continually improves the AIMS"),
]


def _build_iso42001_evidence(context: dict[str, Any]) -> list[ControlEvidence]:
    """Map Gavel capabilities to ISO 42001 AIMS controls."""
    has_rbac = context.get("has_rbac", False)
    has_audit_trail = context.get("has_audit_trail", False)
    has_enrollment = context.get("has_enrollment", False)
    has_evidence_review = context.get("has_evidence_review", False)
    has_monitoring = context.get("has_monitoring", False)
    has_fria = context.get("has_fria", False)
    has_qms = context.get("has_qms", False)
    has_data_governance = context.get("has_data_governance", False)

    controls = []
    for cid, cname, cdesc in _ISO_42001_CONTROLS:
        sources = []
        status = ControlStatus.NOT_MET
        gap = ""

        if cid == "4.1":
            status = ControlStatus.MET if has_enrollment else ControlStatus.PARTIALLY_MET
            sources = ["gavel/enrollment.py — operational scope declarations", "gavel/regulations.py — multi-regulation mapping"]
            if not has_enrollment:
                gap = "Enrollment not configured"

        elif cid == "4.2":
            status = ControlStatus.MET
            sources = ["gavel/enrollment.py — owner + owner_contact per agent", "gavel/rbac.py — operator roles"]

        elif cid == "5.1":
            status = ControlStatus.PARTIALLY_MET
            sources = ["gavel/rbac.py — admin role with full access"]
            gap = "Top management commitment is organizational, not software-enforced"

        elif cid == "5.2":
            status = ControlStatus.MET
            sources = ["gavel/constitution.py — 9 invariant AI governance rules", "gavel/enrollment.py — action boundaries + resource allowlists"]

        elif cid == "5.3":
            if has_rbac:
                status = ControlStatus.MET
                sources = ["gavel/rbac.py — 5 roles with scoped permissions", "gavel/separation.py — agent role assignments"]
            else:
                gap = "RBAC not configured"

        elif cid == "6.1":
            if has_evidence_review:
                status = ControlStatus.MET
                sources = ["gavel/evidence.py — 7 risk checks per action", "gavel/tiers.py — risk factor scoring"]
            else:
                gap = "Evidence review not active"

        elif cid == "6.2":
            status = ControlStatus.MET
            sources = ["gavel/enrollment.py — purpose declaration per agent", "gavel/tiers.py — tiered autonomy objectives"]

        elif cid == "7.1":
            status = ControlStatus.MET
            sources = ["gavel/enrollment.py — budget limits (tokens + USD)", "gavel/enrollment.py — resource allowlist"]

        elif cid == "7.2":
            status = ControlStatus.PARTIALLY_MET
            sources = ["gavel/agents.py — agent maturity model (Intern→Principal)"]
            gap = "Human operator competence tracking is organizational"

        elif cid == "7.5":
            if has_audit_trail:
                status = ControlStatus.MET
                sources = ["gavel/chain.py — hash-chained governance events", "gavel/compliance.py — Annex IV documentation generator"]
            else:
                gap = "Audit trail not active"

        elif cid == "8.1":
            status = ControlStatus.MET
            sources = ["gavel/gateway.py — propose→approve→execute pipeline", "gavel/enrollment.py — pre-flight validation"]

        elif cid == "8.2":
            if has_evidence_review:
                status = ControlStatus.MET
                sources = ["gavel/evidence.py — deterministic risk assessment", "gavel/hooks.py — classify_risk()"]
            else:
                gap = "Risk assessment not active"

        elif cid == "8.3":
            status = ControlStatus.MET
            sources = ["gavel/tiers.py — graduated oversight modes", "gavel/blastbox.py — sandboxed execution"]

        elif cid == "8.4":
            if has_fria:
                status = ControlStatus.MET
                sources = ["gavel/fria.py — fundamental rights impact assessment", "gavel/data_governance.py — data governance policy"]
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "FRIA not configured"

        elif cid == "9.1":
            if has_monitoring:
                status = ControlStatus.MET
                sources = ["gavel/liveness.py — SLA monitoring", "gavel/baseline.py — behavioral drift", "gavel/evasion.py — evasion detection"]
            else:
                gap = "Monitoring not active"

        elif cid == "9.2":
            status = ControlStatus.PARTIALLY_MET
            sources = ["gavel/chain.py — verify_integrity()", "gavel/chain.py — verify_artifact()"]
            gap = "Internal audit scheduling is organizational"

        elif cid == "9.3":
            status = ControlStatus.PARTIALLY_MET
            sources = ["gavel/compliance.py — compliance status reporting"]
            gap = "Management review scheduling is organizational"

        elif cid == "10.1":
            status = ControlStatus.MET
            sources = ["gavel/compliance.py — incident classification + deadline tracking", "gavel/rollback.py — compensating actions"]

        elif cid == "10.2":
            status = ControlStatus.MET
            sources = ["gavel/agents.py — agent maturity promotion", "gavel/baseline.py — behavioral baseline evolution"]

        controls.append(ControlEvidence(
            control_id=cid, control_name=cname, description=cdesc,
            status=status, evidence_sources=sources, gap_description=gap,
        ))
    return controls


# ── EU AI Act Evidence (leverages existing AnnexIVGenerator) ──

_EU_AI_ACT_CONTROLS = [
    ("Art.9", "Risk Management System", "Providers establish, implement, document and maintain a risk management system"),
    ("Art.10", "Data and Data Governance", "Training, validation and testing data sets are subject to appropriate data governance"),
    ("Art.11", "Technical Documentation", "Technical documentation shall be drawn up before the system is placed on the market"),
    ("Art.12", "Record-Keeping", "High-risk AI systems shall allow for automatic recording of events (logs)"),
    ("Art.13", "Transparency", "High-risk AI systems shall be designed to ensure operation is sufficiently transparent"),
    ("Art.14", "Human Oversight", "High-risk AI systems shall be designed to allow effective human oversight"),
    ("Art.15", "Accuracy, Robustness and Cybersecurity", "High-risk AI systems shall be designed to achieve appropriate levels of accuracy, robustness and cybersecurity"),
    ("Art.17", "Quality Management System", "Providers establish a quality management system"),
    ("Art.26", "Obligations of Deployers", "Deployers use high-risk AI systems in accordance with instructions"),
    ("Art.27", "Fundamental Rights Impact Assessment", "Deployers perform impact assessment for fundamental rights"),
    ("Art.72", "Post-Market Monitoring", "Providers establish a post-market monitoring system"),
    ("Art.73", "Incident Reporting", "Providers report serious incidents to market surveillance authorities"),
]


def _build_eu_ai_act_evidence(context: dict[str, Any]) -> list[ControlEvidence]:
    """Map Gavel capabilities to EU AI Act articles."""
    has_audit_trail = context.get("has_audit_trail", False)
    has_enrollment = context.get("has_enrollment", False)
    has_evidence_review = context.get("has_evidence_review", False)
    has_monitoring = context.get("has_monitoring", False)
    has_fria = context.get("has_fria", False)
    has_qms = context.get("has_qms", False)
    has_data_governance = context.get("has_data_governance", False)
    incident_count = context.get("incident_count", 0)

    controls = []
    for cid, cname, cdesc in _EU_AI_ACT_CONTROLS:
        sources = []
        status = ControlStatus.NOT_MET
        gap = ""

        if cid == "Art.9":
            if has_evidence_review:
                status = ControlStatus.MET
                sources = ["gavel/evidence.py — 7 deterministic risk checks", "gavel/tiers.py — risk factor scoring", "gavel/enrollment.py — risk_tier classification"]
            else:
                gap = "Evidence review not active"

        elif cid == "Art.10":
            if has_data_governance:
                status = ControlStatus.MET
                sources = ["gavel/data_governance.py — Art. 10(2)(a)-(h) + Art. 10(3)", "gavel/privacy.py — PII/PHI detection"]
            else:
                status = ControlStatus.PARTIALLY_MET
                sources = ["gavel/privacy.py — PII/PHI detection in evidence"]
                gap = "Full data governance policy not configured"

        elif cid == "Art.11":
            status = ControlStatus.MET
            sources = ["gavel/compliance.py — AnnexIVGenerator (9 mandatory sections)"]

        elif cid == "Art.12":
            if has_audit_trail:
                status = ControlStatus.MET
                sources = ["gavel/chain.py — hash-chained event logging", "gavel/events.py — real-time event bus"]
            else:
                gap = "Audit trail not active"

        elif cid == "Art.13":
            if has_enrollment:
                status = ControlStatus.MET
                sources = ["gavel/enrollment.py — interaction_type + synthetic_content fields", "gavel/chain.py — to_artifact() for portable records"]
            else:
                gap = "Enrollment not configured"

        elif cid == "Art.14":
            status = ControlStatus.MET
            sources = [
                "gavel/separation.py — proposer ≠ reviewer ≠ approver",
                "gavel/tiers.py — SUPERVISED tier requires human for all actions",
                "gavel/agents.py — kill switch for immediate suspension",
            ]

        elif cid == "Art.15":
            if has_evidence_review:
                status = ControlStatus.MET
                sources = ["gavel/evidence.py — scope + secrets + network checks", "gavel/blastbox.py — sandboxed execution", "gavel/evasion.py — adversarial detection"]
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "Evidence review not active"

        elif cid == "Art.17":
            if has_qms:
                status = ControlStatus.MET
                sources = ["gavel/qms.py — 13 Art. 17(1)(a)-(m) clauses"]
            else:
                status = ControlStatus.PARTIALLY_MET
                gap = "QMS not fully configured"

        elif cid == "Art.26":
            if has_enrollment:
                status = ControlStatus.MET
                sources = ["gavel/enrollment.py — owner + owner_contact per agent", "gavel/enrollment.py — action boundaries + resource allowlists"]
            else:
                gap = "Enrollment not configured"

        elif cid == "Art.27":
            if has_fria:
                status = ControlStatus.MET
                sources = ["gavel/fria.py — Art. 27(1)(a)-(f) FRIA schema + validation"]
            else:
                status = ControlStatus.NOT_MET
                gap = "FRIA not configured"

        elif cid == "Art.72":
            if has_monitoring:
                status = ControlStatus.MET
                sources = ["gavel/liveness.py — continuous monitoring", "gavel/baseline.py — drift detection", "gavel/agents.py — heartbeat monitoring"]
            else:
                gap = "Post-market monitoring not active"

        elif cid == "Art.73":
            status = ControlStatus.MET
            sources = ["gavel/compliance.py — IncidentRegistry with severity classification", "gavel/compliance.py — 2-day/15-day deadline tracking"]

        controls.append(ControlEvidence(
            control_id=cid, control_name=cname, description=cdesc,
            status=status, evidence_sources=sources, gap_description=gap,
        ))
    return controls


# ── Bundle generator ──────────────────────────────────────────

class ComplianceExporter:
    """Generate compliance export bundles for supported frameworks."""

    def __init__(self, context: Optional[dict[str, Any]] = None):
        self._context = context or {}

    def export(self, framework: ComplianceFramework) -> ComplianceBundle:
        """Generate a compliance bundle for the given framework."""
        if framework == ComplianceFramework.SOC2:
            controls = _build_soc2_evidence(self._context)
            version = "SOC 2 Type II (AICPA 2017)"
        elif framework == ComplianceFramework.ISO_42001:
            controls = _build_iso42001_evidence(self._context)
            version = "ISO/IEC 42001:2023"
        elif framework == ComplianceFramework.EU_AI_ACT:
            controls = _build_eu_ai_act_evidence(self._context)
            version = "EU AI Act (Regulation 2024/1689)"
        else:
            raise ValueError(f"Unsupported framework: {framework}")

        bundle = ComplianceBundle(
            framework=framework,
            framework_version=version,
            controls=controls,
        )
        bundle.finalize()
        return bundle

    def export_all(self) -> list[ComplianceBundle]:
        """Generate compliance bundles for all supported frameworks."""
        return [self.export(fw) for fw in ComplianceFramework]
