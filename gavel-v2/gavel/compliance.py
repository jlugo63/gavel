"""EU AI Act Compliance Module — Annex IV Technical Documentation Generator.

Article 11 of the EU AI Act requires providers of high-risk AI systems to
maintain technical documentation demonstrating compliance. Annex IV specifies
9 mandatory sections. This module generates those sections from Gavel's
existing enrollment, chain, evidence, and constitutional data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from gavel.enrollment import HighRiskCategory


class ComplianceStatus(str, Enum):
    """Overall compliance assessment status."""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    ASSESSMENT_REQUIRED = "assessment_required"


class IncidentSeverity(str, Enum):
    """EU AI Act Article 73 incident severity levels."""
    CRITICAL = "critical"      # 2-day reporting window
    SERIOUS = "serious"        # 2-day reporting window
    STANDARD = "standard"      # 15-day reporting window
    MINOR = "minor"            # Internal record only


class IncidentStatus(str, Enum):
    """Incident lifecycle status."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    REPORTED = "reported"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentReport(BaseModel):
    """Auto-generated incident report per EU AI Act Article 73."""
    incident_id: str = Field(default_factory=lambda: f"inc-{__import__('uuid').uuid4().hex[:8]}")
    agent_id: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    title: str
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reported_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    deadline: Optional[datetime] = None
    chain_ids: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    regulatory_references: list[str] = Field(default_factory=list)

    @property
    def is_overdue(self) -> bool:
        if self.deadline is None or self.reported_at is not None:
            return False
        return datetime.now(timezone.utc) > self.deadline

    @property
    def days_remaining(self) -> float:
        if self.deadline is None:
            return float("inf")
        delta = self.deadline - datetime.now(timezone.utc)
        return max(0.0, delta.total_seconds() / 86400)


class IncidentClassifier:
    """Classify governance events into incident severity levels."""

    CRITICAL_PATTERNS = [
        "kill_switch_activated",
        "chain_integrity_violated",
        "prohibited_practice_detected",
        "unauthorized_access",
        "data_breach",
    ]

    SERIOUS_PATTERNS = [
        "evidence_review_failed",
        "scope_violation",
        "forbidden_path_access",
        "secrets_detected",
        "trust_score_critical",
    ]

    STANDARD_PATTERNS = [
        "sla_timeout",
        "auto_denied",
        "enrollment_rejected",
        "demotion",
    ]

    @classmethod
    def classify(cls, event_type: str, payload: dict[str, Any] = None) -> IncidentSeverity:
        """Classify an event into an incident severity level."""
        payload = payload or {}
        event_lower = event_type.lower()
        payload_text = str(payload).lower()
        combined = f"{event_lower} {payload_text}"

        for pattern in cls.CRITICAL_PATTERNS:
            if pattern in combined:
                return IncidentSeverity.CRITICAL

        for pattern in cls.SERIOUS_PATTERNS:
            if pattern in combined:
                return IncidentSeverity.SERIOUS

        for pattern in cls.STANDARD_PATTERNS:
            if pattern in combined:
                return IncidentSeverity.STANDARD

        return IncidentSeverity.MINOR

    @classmethod
    def compute_deadline(cls, severity: IncidentSeverity, detected_at: datetime) -> Optional[datetime]:
        """Compute reporting deadline based on severity (Art. 73)."""
        from datetime import timedelta
        if severity in (IncidentSeverity.CRITICAL, IncidentSeverity.SERIOUS):
            return detected_at + timedelta(days=2)
        elif severity == IncidentSeverity.STANDARD:
            return detected_at + timedelta(days=15)
        return None  # MINOR — no external reporting required


class IncidentRegistry:
    """Track and manage incidents per EU AI Act Article 73."""

    def __init__(self):
        self._incidents: dict[str, IncidentReport] = {}

    def report(
        self,
        agent_id: str,
        title: str,
        description: str,
        severity: IncidentSeverity | None = None,
        event_type: str = "",
        payload: dict[str, Any] | None = None,
        chain_ids: list[str] | None = None,
    ) -> IncidentReport:
        """Create a new incident report."""
        if severity is None:
            severity = IncidentClassifier.classify(event_type, payload)

        deadline = IncidentClassifier.compute_deadline(
            severity, datetime.now(timezone.utc)
        )

        incident = IncidentReport(
            agent_id=agent_id,
            severity=severity,
            title=title,
            description=description,
            deadline=deadline,
            chain_ids=chain_ids or [],
            findings=[],
            regulatory_references=_get_regulatory_refs(severity),
        )
        self._incidents[incident.incident_id] = incident
        return incident

    def get(self, incident_id: str) -> IncidentReport | None:
        return self._incidents.get(incident_id)

    def get_all(self) -> list[IncidentReport]:
        return list(self._incidents.values())

    def get_by_agent(self, agent_id: str) -> list[IncidentReport]:
        return [i for i in self._incidents.values() if i.agent_id == agent_id]

    def get_overdue(self) -> list[IncidentReport]:
        return [i for i in self._incidents.values() if i.is_overdue]

    def get_by_severity(self, severity: IncidentSeverity) -> list[IncidentReport]:
        return [i for i in self._incidents.values() if i.severity == severity]

    def mark_reported(self, incident_id: str) -> IncidentReport | None:
        incident = self._incidents.get(incident_id)
        if incident:
            incident.reported_at = datetime.now(timezone.utc)
            incident.status = IncidentStatus.REPORTED
        return incident

    def mark_resolved(self, incident_id: str) -> IncidentReport | None:
        incident = self._incidents.get(incident_id)
        if incident:
            incident.resolved_at = datetime.now(timezone.utc)
            incident.status = IncidentStatus.RESOLVED
        return incident


def _get_regulatory_refs(severity: IncidentSeverity) -> list[str]:
    """Return applicable regulatory references for an incident severity."""
    refs = ["EU AI Act Article 73 — Reporting of serious incidents"]
    if severity in (IncidentSeverity.CRITICAL, IncidentSeverity.SERIOUS):
        refs.append("EU AI Act Article 73(1) — 2-day reporting window for serious incidents")
        refs.append("EU AI Act Article 62 — Cooperation with market surveillance authorities")
    elif severity == IncidentSeverity.STANDARD:
        refs.append("EU AI Act Article 73(1) — 15-day reporting window for standard incidents")
    refs.append("EU AI Act Article 72 — Post-market monitoring obligations")
    return refs


class AnnexIVGenerator:
    """Generate EU AI Act Annex IV Technical Documentation.

    Builds the 9 mandatory sections from Gavel's existing data:
    enrollment metadata, governance chains, evidence reviews,
    constitutional invariants, and tier policy configuration.
    """

    def __init__(
        self,
        enrollment_record: Any = None,
        chains: list[Any] | None = None,
        review_results: list[Any] | None = None,
        constitution: Any = None,
        tier_policy: Any = None,
        incidents: list[IncidentReport] | None = None,
    ):
        self._enrollment = enrollment_record
        self._chains = chains or []
        self._reviews = review_results or []
        self._constitution = constitution
        self._tier_policy = tier_policy
        self._incidents = incidents or []

    def generate(self) -> dict[str, Any]:
        """Generate complete Annex IV technical documentation."""
        now = datetime.now(timezone.utc).isoformat()
        app = self._enrollment.application if self._enrollment else None

        doc = {
            "annex_iv_version": "1.0",
            "generated_at": now,
            "regulation": "EU AI Act (Regulation 2024/1689)",
            "annex": "IV — Technical Documentation (Article 11)",
            "sections": {
                "1_general_description": self._section_1_general(app),
                "2_development_and_design": self._section_2_development(app),
                "3_monitoring_and_control": self._section_3_monitoring(app),
                "4_performance_metrics": self._section_4_performance(),
                "5_risk_management": self._section_5_risk(app),
                "6_lifecycle_changes": self._section_6_lifecycle(),
                "7_applied_standards": self._section_7_standards(),
                "8_eu_declaration": self._section_8_declaration(app),
                "9_post_market_monitoring": self._section_9_monitoring(),
            },
            "compliance_status": self._assess_compliance(app),
        }
        return doc

    def _section_1_general(self, app) -> dict[str, Any]:
        """Section 1: General description of the AI system."""
        if not app:
            return {"status": "incomplete", "reason": "No enrollment application"}

        return {
            "title": "General Description",
            "system_name": app.display_name,
            "agent_id": app.agent_id,
            "agent_type": app.agent_type,
            "intended_purpose": app.purpose.summary,
            "operational_scope": app.purpose.operational_scope,
            "expected_lifetime": app.purpose.expected_lifetime,
            "risk_tier": app.purpose.risk_tier,
            "high_risk_category": getattr(app, "high_risk_category", "none"),
            "interaction_type": getattr(app, "interaction_type", "system_only"),
            "generates_synthetic_content": getattr(app, "synthetic_content", False),
            "capabilities": {
                "tools": app.capabilities.tools,
                "max_concurrent_chains": app.capabilities.max_concurrent_chains,
                "can_spawn_subagents": app.capabilities.can_spawn_subagents,
                "network_access": app.capabilities.network_access,
                "file_system_access": app.capabilities.file_system_access,
                "execution_access": app.capabilities.execution_access,
            },
            "accountability": {
                "owner": app.owner,
                "owner_contact": app.owner_contact,
            },
        }

    def _section_2_development(self, app) -> dict[str, Any]:
        """Section 2: Development and design specifications."""
        if not app:
            return {"status": "incomplete", "reason": "No enrollment application"}

        return {
            "title": "Development and Design",
            "governance_framework": "Gavel Constitutional Governance v0.2.0",
            "design_methodology": "Constitutional control plane with separation of powers",
            "resource_allowlist": {
                "allowed_paths": app.resources.allowed_paths,
                "allowed_hosts": app.resources.allowed_hosts,
                "allowed_env_vars": app.resources.allowed_env_vars,
                "max_file_size_mb": app.resources.max_file_size_mb,
            },
            "action_boundaries": {
                "allowed_actions": app.boundaries.allowed_actions,
                "blocked_patterns": app.boundaries.blocked_patterns,
                "max_actions_per_minute": app.boundaries.max_actions_per_minute,
                "max_risk_threshold": app.boundaries.max_risk_threshold,
            },
            "fallback_behavior": {
                "on_gateway_unreachable": app.fallback.on_gateway_unreachable,
                "on_budget_exceeded": app.fallback.on_budget_exceeded,
                "on_sla_timeout": app.fallback.on_sla_timeout,
                "graceful_shutdown": app.fallback.graceful_shutdown,
            },
            "budget_limits": {
                "tokens": app.budget_tokens,
                "usd": app.budget_usd,
            },
        }

    def _section_3_monitoring(self, app) -> dict[str, Any]:
        """Section 3: Monitoring, functioning, and control."""
        constitutional_rules = []
        if self._constitution:
            for inv in self._constitution.invariants.values():
                constitutional_rules.append({
                    "article": inv.id,
                    "text": inv.text,
                    "enforcement": inv.enforcement,
                })

        return {
            "title": "Monitoring, Functioning, and Control",
            "governance_model": "Constitutional control plane with hash-chained audit trail",
            "monitoring_mechanisms": [
                "Real-time liveness monitoring with SLA escalation (Article IV.2)",
                "Agent heartbeat monitoring with automatic death detection",
                "Trust score tracking with automatic tier demotion on violations",
                "Event bus with Server-Sent Events for real-time dashboard",
            ],
            "human_oversight_mechanisms": [
                "Human operator can deny any proposal at any stage (Article IV.1)",
                "Kill switch for immediate agent suspension",
                "Separation of powers: proposer \u2260 reviewer \u2260 approver (Article III)",
                "Tiered autonomy: SUPERVISED requires human approval for all actions",
                "Dashboard with live governance chain status",
            ],
            "control_mechanisms": [
                "Constitutional invariants \u2014 immutable, hardcoded rules",
                "Cedar policy engine \u2014 configurable FORBID/PERMIT rules",
                "Enrollment gate \u2014 pre-deployment capability declaration",
                "Evidence review \u2014 deterministic 7-check review before execution",
                "Blast box \u2014 sandboxed speculative execution",
            ],
            "constitutional_invariants": constitutional_rules,
            "logging_mechanism": {
                "type": "Hash-chained governance events (SHA-256)",
                "tamper_detection": "Each event hashes over previous event hash",
                "artifact_export": "Portable JSON artifacts with independent verification",
                "retention": "Append-only \u2014 events cannot be modified or deleted",
            },
        }

    def _section_4_performance(self) -> dict[str, Any]:
        """Section 4: Performance metrics."""
        total_chains = len(self._chains)
        completed = sum(1 for c in self._chains if getattr(c, "status", None) == "COMPLETED")
        denied = sum(1 for c in self._chains if getattr(c, "status", None) in ("DENIED", "TIMED_OUT"))

        reviews_passed = sum(1 for r in self._reviews if getattr(r, "verdict", None) == "PASS")
        reviews_failed = sum(1 for r in self._reviews if getattr(r, "verdict", None) == "FAIL")

        return {
            "title": "Performance Metrics",
            "governance_chains": {
                "total": total_chains,
                "completed": completed,
                "denied": denied,
                "completion_rate": round(completed / total_chains, 3) if total_chains else 0.0,
            },
            "evidence_reviews": {
                "total": len(self._reviews),
                "passed": reviews_passed,
                "failed": reviews_failed,
                "pass_rate": round(reviews_passed / len(self._reviews), 3) if self._reviews else 0.0,
            },
            "integrity": {
                "chain_integrity_verified": all(
                    getattr(c, "verify_integrity", lambda: True)() for c in self._chains
                ),
            },
        }

    def _section_5_risk(self, app) -> dict[str, Any]:
        """Section 5: Risk management documentation."""
        risk_tier = app.purpose.risk_tier if app else "unknown"
        high_risk = getattr(app, "high_risk_category", "none") if app else "none"

        return {
            "title": "Risk Management",
            "risk_classification": {
                "declared_risk_tier": risk_tier,
                "eu_ai_act_category": str(high_risk),
                "risk_assessment_method": "Tiered autonomy with multi-factor risk scoring",
            },
            "risk_factors_evaluated": [
                "action_type_base \u2014 inherent risk of the action category",
                "touches_production \u2014 whether action affects production systems",
                "touches_financial \u2014 whether action involves financial operations",
                "touches_pii \u2014 whether action processes personal data",
                "scope_breadth \u2014 how many systems/files are affected",
                "precedent_count \u2014 how many times similar actions have been approved",
                "time_of_day_risk \u2014 temporal risk factor",
            ],
            "risk_mitigation_measures": [
                "Enrollment gate rejects high-risk agents without appropriate declarations",
                "Tiered autonomy escalates oversight requirements with risk level",
                "Blast box provides sandboxed speculative execution before approval",
                "Evidence review performs 7 deterministic safety checks",
                "Constitutional invariants prevent self-approval and audit tampering",
                "Kill switch enables immediate agent suspension",
                "Auto-deny on SLA timeout (fail-safe default)",
            ],
            "incidents": {
                "total": len(self._incidents),
                "critical": sum(1 for i in self._incidents if i.severity == IncidentSeverity.CRITICAL),
                "serious": sum(1 for i in self._incidents if i.severity == IncidentSeverity.SERIOUS),
                "overdue": sum(1 for i in self._incidents if i.is_overdue),
            },
        }

    def _section_6_lifecycle(self) -> dict[str, Any]:
        """Section 6: Lifecycle changes documentation."""
        return {
            "title": "Lifecycle Changes",
            "change_tracking": "All governance decisions recorded in hash-chained audit trail",
            "substantial_modification_detection": (
                "Enrollment re-validation required on capability changes. "
                "Trust score and tier adjustments tracked per agent."
            ),
            "version_control": "Git-based source control with signed commits",
            "chain_history": {
                "total_events": sum(len(getattr(c, "events", [])) for c in self._chains),
                "total_chains": len(self._chains),
            },
        }

    def _section_7_standards(self) -> dict[str, Any]:
        """Section 7: Applied standards and specifications."""
        return {
            "title": "Applied Standards",
            "harmonised_standards": [
                {
                    "standard": "prEN 18286",
                    "topic": "Quality Management System for AI",
                    "status": "Draft \u2014 alignment tracked",
                    "ai_act_article": "Article 17",
                },
                {
                    "standard": "prEN 18228",
                    "topic": "Risk Management for AI Systems",
                    "status": "Draft \u2014 alignment tracked",
                    "ai_act_article": "Article 9",
                },
                {
                    "standard": "prEN 18229-1",
                    "topic": "Trustworthiness: Logging, Transparency, Human Oversight",
                    "status": "Draft \u2014 alignment tracked",
                    "ai_act_article": "Articles 12-14",
                },
            ],
            "international_standards": [
                {"standard": "ISO/IEC 42001:2023", "topic": "AI Management Systems", "note": "Not harmonised with EU AI Act"},
            ],
            "framework_references": [
                {"framework": "Agentic Trust Framework (ATF) v0.9.1", "coverage": "14/25 fully met, 7 partial"},
                {"framework": "NIST AI RMF 1.0", "coverage": "Partial alignment via ATF mapping"},
            ],
            "cryptographic_standards": [
                "SHA-256 for hash-chain integrity",
                "Ed25519 for agent DID generation",
                "HMAC-SHA256 for governance token signing",
            ],
        }

    def _section_8_declaration(self, app) -> dict[str, Any]:
        """Section 8: EU Declaration of Conformity."""
        return {
            "title": "EU Declaration of Conformity",
            "status": "Pre-conformity \u2014 formal declaration pending harmonised standards publication",
            "provider": app.owner if app else "Not declared",
            "provider_contact": app.owner_contact if app else "Not declared",
            "system_name": app.display_name if app else "Not declared",
            "conformity_procedure": "Internal control (Annex VI) \u2014 self-assessment",
            "note": (
                "Full EU Declaration of Conformity will be issued upon publication of "
                "harmonised standards by CEN-CENELEC JTC 21 and completion of conformity "
                "assessment procedure per Article 43."
            ),
        }

    def _section_9_monitoring(self) -> dict[str, Any]:
        """Section 9: Post-market monitoring plan."""
        return {
            "title": "Post-Market Monitoring Plan",
            "monitoring_mechanisms": [
                "Continuous governance chain monitoring via liveness probes",
                "Real-time trust score tracking with automatic demotion on violations",
                "Agent heartbeat monitoring with automatic death detection after 3 missed beats",
                "Event bus with SSE stream for real-time operational dashboard",
                "Hash-chain integrity verification on every decision",
            ],
            "incident_reporting": {
                "classification": "Automatic severity classification (CRITICAL/SERIOUS/STANDARD/MINOR)",
                "critical_deadline": "2 days (EU AI Act Article 73)",
                "standard_deadline": "15 days (EU AI Act Article 73)",
                "reporting_channel": "Incident registry with automated deadline tracking",
            },
            "drift_detection": {
                "status": "Planned \u2014 behavioral baseline comparison against enrollment declaration",
                "mechanism": "Compare runtime actions against declared capabilities and boundaries",
            },
            "data_retention": {
                "governance_chains": "Append-only, indefinite retention",
                "agent_logs": "Minimum 6 months per Article 26(6)",
                "incident_reports": "10 years per Article 18",
            },
        }

    def _assess_compliance(self, app) -> dict[str, Any]:
        """Overall compliance status assessment."""
        issues = []

        if not app:
            return {"status": ComplianceStatus.NON_COMPLIANT, "issues": ["No enrollment application"]}

        high_risk = getattr(app, "high_risk_category", "none")
        if high_risk and high_risk != "none" and high_risk != HighRiskCategory.NONE:
            if not app.owner_contact:
                issues.append("High-risk system missing deployer contact (Art. 26)")
            if app.purpose.risk_tier not in ("high", "critical"):
                issues.append("High-risk system not declaring appropriate risk tier")

        overdue_incidents = [i for i in self._incidents if i.is_overdue]
        if overdue_incidents:
            issues.append(f"{len(overdue_incidents)} overdue incident report(s) (Art. 73)")

        if not issues:
            status = ComplianceStatus.COMPLIANT
        elif len(issues) <= 2:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT

        return {
            "status": status,
            "issues": issues,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }
