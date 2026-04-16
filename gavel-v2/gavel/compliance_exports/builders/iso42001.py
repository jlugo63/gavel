"""ISO/IEC 42001:2023 AIMS controls evidence builder."""

from __future__ import annotations

from typing import Any

from gavel.compliance_exports.types import ControlEvidence, ControlStatus


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


def build_iso42001_evidence(context: dict[str, Any]) -> list[ControlEvidence]:
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
