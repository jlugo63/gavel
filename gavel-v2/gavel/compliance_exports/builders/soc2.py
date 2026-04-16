"""SOC 2 Trust Service Criteria evidence builder."""

from __future__ import annotations

from typing import Any

from gavel.compliance_exports.types import ControlEvidence, ControlStatus


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


def build_soc2_evidence(context: dict[str, Any]) -> list[ControlEvidence]:
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
