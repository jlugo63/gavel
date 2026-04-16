"""EU AI Act article evidence builder."""

from __future__ import annotations

from typing import Any

from gavel.compliance_exports.types import ControlEvidence, ControlStatus


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


def build_eu_ai_act_evidence(context: dict[str, Any]) -> list[ControlEvidence]:
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
