"""
Natural-language explainability — ATF B-5.

Translates Gavel's structured governance data (chains, drift reports,
evasion findings, risk scores) into plain-English narratives suitable
for regulators, auditors, and non-technical stakeholders.

Template-based rendering only — no LLM in the loop. Maps technical
fields to human-readable descriptions with ATF and EU AI Act references.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from gavel.baseline import DriftReport
from gavel.chain import ChainEvent, ChainStatus, EventType, GovernanceChain
from gavel.evasion import EvasionFinding, EvasionSeverity, EvasionSignal


# ── Explanation Report ────────────────────────────────────────

class ExplanationReport(BaseModel):
    """A plain-English explanation of a governance artifact."""

    subject_type: str
    subject_id: str
    summary: str
    timeline: list[str] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)
    recommendation: str = ""
    regulatory_context: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Human-readable mappings ───────────────────────────────────

_EVENT_DESCRIPTIONS: dict[EventType, str] = {
    EventType.INBOUND_INTENT: "An agent submitted a proposal for action",
    EventType.POLICY_EVAL: "The proposal was evaluated against governance policies",
    EventType.BLASTBOX_EVIDENCE: "The action was executed speculatively in an isolated sandbox to gather evidence",
    EventType.EVIDENCE_REVIEW: "The sandbox evidence was reviewed for safety and compliance",
    EventType.REVIEW_ATTESTATION: "A reviewer attested to the evidence review findings",
    EventType.APPROVAL_GRANTED: "The action was approved for execution",
    EventType.APPROVAL_DENIED: "The action was denied",
    EventType.EXECUTION_TOKEN: "An execution token was issued authorizing the action",
    EventType.EXECUTION_STARTED: "Execution of the approved action began",
    EventType.EXECUTION_COMPLETED: "Execution completed successfully",
    EventType.POST_EXECUTION_VERIFICATION: "Post-execution verification confirmed the outcome",
    EventType.ESCALATED: "The action was escalated for higher-authority review",
    EventType.AUTO_DENIED: "The action was automatically denied by policy",
    EventType.ROLLBACK_TRIGGERED: "A rollback was triggered to undo the action",
}

_STATUS_DESCRIPTIONS: dict[ChainStatus, str] = {
    ChainStatus.PENDING: "awaiting evaluation",
    ChainStatus.EVALUATING: "being evaluated",
    ChainStatus.ESCALATED: "escalated for human review",
    ChainStatus.APPROVED: "approved",
    ChainStatus.DENIED: "denied",
    ChainStatus.EXECUTING: "executing",
    ChainStatus.COMPLETED: "completed successfully",
    ChainStatus.ROLLED_BACK: "rolled back",
    ChainStatus.TIMED_OUT: "timed out without resolution",
}

_EVASION_DESCRIPTIONS: dict[EvasionSignal, str] = {
    EvasionSignal.FRAGMENTED_ACTIONS: (
        "The agent submitted many small, individually low-risk proposals that would "
        "have triggered review if submitted as a single action"
    ),
    EvasionSignal.TIMING_ARBITRAGE: (
        "The agent consistently submitted proposals outside declared oversight windows, "
        "suggesting an attempt to avoid scrutiny"
    ),
    EvasionSignal.REVIEWER_ROTATION_ABUSE: (
        "The agent's proposals were reviewed by an unusually narrow set of reviewers, "
        "suggesting possible reviewer capture"
    ),
    EvasionSignal.SCOPE_CREEP: (
        "The agent accessed resources outside its declared scope over a rolling window"
    ),
    EvasionSignal.HEARTBEAT_BURST: (
        "The agent went quiet for an extended period then submitted a burst of proposals "
        "in a short window"
    ),
    EvasionSignal.KILL_SWITCH_EVASION: (
        "A new agent enrollment matches the owner and display name of a previously "
        "suspended agent, suggesting an attempt to circumvent a kill-switch action"
    ),
}

_SEVERITY_LABELS: dict[EvasionSeverity, str] = {
    EvasionSeverity.LOW: "low",
    EvasionSeverity.MEDIUM: "moderate",
    EvasionSeverity.HIGH: "high",
}


# ── Renderer ──────────────────────────────────────────────────

def _pct(value: float) -> str:
    """Format a 0..1 float as percentage points."""
    return f"{abs(value) * 100:.0f} percentage points"


def _direction(delta: float) -> str:
    if delta > 0:
        return "increased"
    elif delta < 0:
        return "decreased"
    return "remained unchanged"


class ExplainabilityRenderer:
    """Renders Gavel governance data as plain-English explanations.

    All rendering is template-based — no LLM, no external calls.
    Suitable for regulator-facing reports and audit logs.
    """

    def explain_chain(self, chain: GovernanceChain) -> ExplanationReport:
        """Explain a governance chain as a human-readable narrative."""
        status_desc = _STATUS_DESCRIPTIONS.get(chain.status, chain.status.value)
        event_count = len(chain.events)
        actors = set()
        for evt in chain.events:
            actors.add(evt.actor_id)

        summary = (
            f"Governance chain {chain.chain_id} is currently {status_desc}. "
            f"It contains {event_count} event{'s' if event_count != 1 else ''} "
            f"involving {len(actors)} participant{'s' if len(actors) != 1 else ''}."
        )

        timeline: list[str] = []
        for evt in chain.events:
            desc = _EVENT_DESCRIPTIONS.get(evt.event_type, evt.event_type.value)
            ts = evt.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            line = f"[{ts}] {desc} (by {evt.actor_id}, role: {evt.role_used})"
            if evt.payload:
                reason = evt.payload.get("reason") or evt.payload.get("detail")
                if reason:
                    line += f" — {reason}"
            timeline.append(line)

        risk_factors: list[str] = []
        integrity_ok = chain.verify_integrity()
        if not integrity_ok:
            risk_factors.append(
                "The hash chain integrity check FAILED — the decision trail "
                "may have been tampered with"
            )
        if chain.status == ChainStatus.ROLLED_BACK:
            risk_factors.append(
                "This action was rolled back, indicating the post-execution "
                "verification found problems"
            )
        if chain.status == ChainStatus.TIMED_OUT:
            risk_factors.append(
                "This action timed out without resolution, which may indicate "
                "a liveness or escalation failure"
            )

        # Check for denied events
        denied = chain.get_event(EventType.APPROVAL_DENIED) or chain.get_event(EventType.AUTO_DENIED)
        if denied:
            denial_reason = denied.payload.get("reason", "No reason recorded")
            risk_factors.append(f"The action was denied: {denial_reason}")

        recommendation = self._chain_recommendation(chain)

        return ExplanationReport(
            subject_type="governance_chain",
            subject_id=chain.chain_id,
            summary=summary,
            timeline=timeline,
            risk_factors=risk_factors,
            recommendation=recommendation,
            regulatory_context=[
                "ATF A-1: Governance chain provides tamper-evident decision trail",
                "ATF B-5: This explanation provides natural-language explainability",
                "EU AI Act Article 12: Logging and traceability of AI system decisions",
                "EU AI Act Article 14: Human oversight of high-risk AI systems",
            ],
        )

    def explain_drift(self, report: DriftReport) -> ExplanationReport:
        """Explain a behavioral drift report in plain English."""
        if report.is_significant:
            summary = (
                f"Agent {report.agent_id} has drifted significantly from its enrollment "
                f"baseline (drift score: {report.drift_score:.2f}). "
                f"This may indicate changed behavior requiring review."
            )
        else:
            summary = (
                f"Agent {report.agent_id} shows minimal drift from its enrollment "
                f"baseline (drift score: {report.drift_score:.2f}). "
                f"Current behavior is consistent with historical patterns."
            )

        timeline = [
            f"Enrollment baseline captured from {report.enrollment_sample_size} observations",
            f"Current baseline computed from {report.current_sample_size} observations",
            f"Drift score: {report.drift_score:.2f} "
            f"({'SIGNIFICANT' if report.is_significant else 'within normal range'})",
        ]

        risk_factors: list[str] = []

        if abs(report.risk_delta) > 0.01:
            risk_factors.append(
                f"The agent's average risk level {_direction(report.risk_delta)} by "
                f"{_pct(report.risk_delta)} compared to its enrollment baseline"
            )

        if abs(report.network_delta) > 0.01:
            risk_factors.append(
                f"Network access rate {_direction(report.network_delta)} by "
                f"{_pct(report.network_delta)}"
            )

        if report.new_tools:
            tools_str = ", ".join(report.new_tools)
            risk_factors.append(
                f"The agent is using tools not seen during enrollment: {tools_str}"
            )

        if report.tool_distribution_shift > 0.05:
            risk_factors.append(
                f"The distribution of tool usage has shifted "
                f"(L1 distance: {report.tool_distribution_shift:.2f})"
            )

        if report.new_paths:
            paths_str = ", ".join(report.new_paths[:5])
            risk_factors.append(
                f"The agent is accessing new resource paths not seen at enrollment: {paths_str}"
            )

        if abs(report.denial_delta) > 0.01:
            risk_factors.append(
                f"The denial rate {_direction(report.denial_delta)} by "
                f"{_pct(report.denial_delta)}"
            )

        if abs(report.escalation_delta) > 0.01:
            risk_factors.append(
                f"The escalation rate {_direction(report.escalation_delta)} by "
                f"{_pct(report.escalation_delta)}"
            )

        if report.is_significant:
            recommendation = (
                "Investigate the behavioral drift. Consider re-evaluating the agent's "
                "autonomy tier and reviewing recent governance chains for anomalies. "
                "If drift is expected (e.g., after a legitimate scope change), "
                "reset the enrollment baseline."
            )
        else:
            recommendation = (
                "No action required. Continue monitoring. The agent's behavior "
                "remains within acceptable bounds of its enrollment baseline."
            )

        return ExplanationReport(
            subject_type="drift_report",
            subject_id=report.agent_id,
            summary=summary,
            timeline=timeline,
            risk_factors=risk_factors,
            recommendation=recommendation,
            regulatory_context=[
                "ATF B-3: Behavioral baseline monitoring and drift detection",
                "ATF B-5: This explanation provides natural-language explainability",
                "EU AI Act Article 9: Risk management for high-risk AI systems",
                "EU AI Act Article 72: Post-market monitoring obligations",
            ],
        )

    def explain_denial(self, chain_event: ChainEvent) -> ExplanationReport:
        """Explain why an action was denied, in plain language."""
        payload = chain_event.payload
        reason = payload.get("reason", "No specific reason was recorded")
        policy = payload.get("policy", "")
        risk_score = payload.get("risk_score")

        if chain_event.event_type == EventType.AUTO_DENIED:
            denial_type = "automatically denied by governance policy"
        else:
            denial_type = "denied by a governance reviewer"

        summary = (
            f"A proposed action in chain {chain_event.chain_id} was {denial_type}. "
            f"Reason: {reason}."
        )

        timeline = [
            f"Denial recorded at {chain_event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Denied by: {chain_event.actor_id} (role: {chain_event.role_used})",
            f"Denial type: {chain_event.event_type.value}",
        ]

        risk_factors: list[str] = [f"Stated denial reason: {reason}"]
        if policy:
            risk_factors.append(f"Triggered policy: {policy}")
        if risk_score is not None:
            risk_factors.append(
                f"The assessed risk score was {risk_score:.2f}, which "
                f"{'exceeded the acceptable threshold' if risk_score > 0.5 else 'was within normal range but other factors led to denial'}"
            )

        # Extract any additional payload context
        violations = payload.get("violations", [])
        if violations:
            for v in violations[:5]:
                risk_factors.append(f"Policy violation: {v}")

        recommendation = (
            "Review the denial reason and adjust the proposed action to comply "
            "with governance policies. If the denial is believed to be incorrect, "
            "escalate to a governance administrator for review."
        )

        return ExplanationReport(
            subject_type="denial_event",
            subject_id=chain_event.event_id,
            summary=summary,
            timeline=timeline,
            risk_factors=risk_factors,
            recommendation=recommendation,
            regulatory_context=[
                "ATF A-2: Separation of powers — denial decisions require justification",
                "ATF B-5: This explanation provides natural-language explainability",
                "EU AI Act Article 14: Human oversight — denied actions must be explainable",
                "EU AI Act Article 86: Right to explanation for AI-assisted decisions",
            ],
        )

    def explain_risk(
        self, risk_score: float, factors: dict[str, Any]
    ) -> ExplanationReport:
        """Explain a risk assessment in plain English."""
        if risk_score >= 0.8:
            level = "very high"
        elif risk_score >= 0.6:
            level = "high"
        elif risk_score >= 0.4:
            level = "moderate"
        elif risk_score >= 0.2:
            level = "low"
        else:
            level = "very low"

        agent_id = factors.get("agent_id", "unknown")
        action = factors.get("action", "unknown action")

        summary = (
            f"The risk assessment for {action} by agent {agent_id} resulted in a "
            f"{level} risk score of {risk_score:.2f} (on a 0 to 1 scale)."
        )

        timeline = [
            f"Risk assessment computed for agent {agent_id}",
            f"Action evaluated: {action}",
            f"Composite risk score: {risk_score:.2f} ({level})",
        ]

        risk_factors: list[str] = []

        network = factors.get("network", False)
        if network:
            risk_factors.append("The action requires network access")

        tools = factors.get("tools", [])
        if tools:
            risk_factors.append(f"Tools involved: {', '.join(tools)}")

        paths = factors.get("paths", [])
        if paths:
            risk_factors.append(
                f"Resource paths affected: {', '.join(paths[:5])}"
            )

        scope_violation = factors.get("scope_violation", False)
        if scope_violation:
            risk_factors.append(
                "The action affects resources outside the agent's declared scope"
            )

        evidence_failed = factors.get("evidence_failed", False)
        if evidence_failed:
            risk_factors.append(
                "Sandbox evidence review found problems with the proposed action"
            )

        secret_detected = factors.get("secret_detected", False)
        if secret_detected:
            risk_factors.append(
                "Potential secrets or credentials were detected in the action output"
            )

        history_risk = factors.get("history_risk")
        if history_risk is not None:
            risk_factors.append(
                f"The agent's historical average risk is {history_risk:.2f}"
            )

        # Include any custom factors not covered above
        known_keys = {
            "agent_id", "action", "network", "tools", "paths",
            "scope_violation", "evidence_failed", "secret_detected",
            "history_risk",
        }
        for key, value in factors.items():
            if key not in known_keys:
                risk_factors.append(f"{key.replace('_', ' ').capitalize()}: {value}")

        if risk_score >= 0.6:
            recommendation = (
                "This action carries significant risk and should undergo full "
                "governance review including sandbox evidence collection before approval. "
                "Consider whether escalation to a human reviewer is appropriate."
            )
        elif risk_score >= 0.3:
            recommendation = (
                "This action carries moderate risk. Standard governance review "
                "is recommended before approval."
            )
        else:
            recommendation = (
                "This action carries low risk. Standard automated governance "
                "evaluation should be sufficient."
            )

        return ExplanationReport(
            subject_type="risk_assessment",
            subject_id=agent_id,
            summary=summary,
            timeline=timeline,
            risk_factors=risk_factors,
            recommendation=recommendation,
            regulatory_context=[
                "ATF B-1: Risk-based tiered autonomy",
                "ATF B-5: This explanation provides natural-language explainability",
                "EU AI Act Article 9: Risk management system requirements",
                "EU AI Act Article 43: Conformity assessment for high-risk AI",
            ],
        )

    def explain_evasion(self, finding: EvasionFinding) -> ExplanationReport:
        """Explain an evasion finding in plain English."""
        desc = _EVASION_DESCRIPTIONS.get(finding.signal, finding.signal.value)
        severity_label = _SEVERITY_LABELS.get(finding.severity, finding.severity.value)

        summary = (
            f"A {severity_label}-severity oversight evasion pattern was detected "
            f"for agent {finding.agent_id}: {finding.signal.value}."
        )

        timeline = [
            f"Evasion pattern detected at {finding.observed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Signal type: {finding.signal.value}",
            f"Severity: {severity_label}",
        ]
        if finding.supporting_chain_ids:
            timeline.append(
                f"Related governance chains: {', '.join(finding.supporting_chain_ids[:5])}"
            )

        risk_factors = [
            desc,
            f"Detection detail: {finding.detail}",
        ]

        if finding.severity == EvasionSeverity.HIGH:
            recommendation = (
                "Immediately investigate this agent's recent activity. Consider "
                "suspending the agent pending review. This pattern indicates a "
                "deliberate attempt to circumvent oversight controls."
            )
        elif finding.severity == EvasionSeverity.MEDIUM:
            recommendation = (
                "Investigate this agent's recent activity patterns. Review the "
                "supporting governance chains for anomalies and consider increasing "
                "the agent's oversight level."
            )
        else:
            recommendation = (
                "Monitor this agent for continued patterns. This detection alone "
                "may not indicate malicious intent but warrants attention if it recurs."
            )

        return ExplanationReport(
            subject_type="evasion_finding",
            subject_id=finding.agent_id,
            summary=summary,
            timeline=timeline,
            risk_factors=risk_factors,
            recommendation=recommendation,
            regulatory_context=[
                "ATF C-1: Oversight evasion detection",
                "ATF B-5: This explanation provides natural-language explainability",
                "EU AI Act Article 9: Risk management — evasion undermines risk controls",
                "EU AI Act Article 26: Obligations of deployers to monitor AI systems",
            ],
        )

    # ── Internal helpers ──────────────────────────────────────

    @staticmethod
    def _chain_recommendation(chain: GovernanceChain) -> str:
        if chain.status == ChainStatus.DENIED:
            return (
                "Review the denial reason. If the proposed action should proceed, "
                "modify it to comply with governance policies and resubmit."
            )
        if chain.status == ChainStatus.ESCALATED:
            return (
                "A human reviewer must evaluate this escalated action. "
                "Check the escalation reason and respond within the SLA window."
            )
        if chain.status == ChainStatus.ROLLED_BACK:
            return (
                "The action was rolled back after post-execution verification failed. "
                "Investigate the root cause before re-attempting."
            )
        if chain.status == ChainStatus.TIMED_OUT:
            return (
                "The governance chain timed out. Check for liveness issues "
                "and ensure escalation handlers are responsive."
            )
        if chain.status in (ChainStatus.COMPLETED, ChainStatus.APPROVED):
            return "No action required. The governance process completed successfully."
        return "Continue monitoring the governance chain as it progresses."
