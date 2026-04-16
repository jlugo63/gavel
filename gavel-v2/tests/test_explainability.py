"""Tests for gavel.explainability — ATF B-5 natural-language explainability."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gavel.baseline import DriftReport
from gavel.chain import ChainEvent, ChainStatus, EventType, GovernanceChain
from gavel.evasion import EvasionFinding, EvasionSeverity, EvasionSignal
from gavel.explainability import ExplainabilityRenderer, ExplanationReport


@pytest.fixture
def renderer() -> ExplainabilityRenderer:
    return ExplainabilityRenderer()


# ── ExplanationReport model ──────────────────────────────────


class TestExplanationReport:
    def test_default_fields(self):
        report = ExplanationReport(
            subject_type="test",
            subject_id="id-1",
            summary="A test summary.",
        )
        assert report.subject_type == "test"
        assert report.subject_id == "id-1"
        assert report.summary == "A test summary."
        assert report.timeline == []
        assert report.risk_factors == []
        assert report.recommendation == ""
        assert report.regulatory_context == []
        assert report.generated_at is not None

    def test_all_fields(self):
        now = datetime.now(timezone.utc)
        report = ExplanationReport(
            subject_type="chain",
            subject_id="c-abc",
            summary="Summary here.",
            timeline=["Step 1", "Step 2"],
            risk_factors=["Risk A"],
            recommendation="Do something.",
            regulatory_context=["ATF B-5"],
            generated_at=now,
        )
        assert len(report.timeline) == 2
        assert len(report.risk_factors) == 1
        assert report.generated_at == now


# ── explain_chain ─────────────────────────────────────────────


class TestExplainChain:
    def test_empty_chain(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-empty")
        result = renderer.explain_chain(chain)
        assert result.subject_type == "governance_chain"
        assert result.subject_id == "c-empty"
        assert "0 events" in result.summary
        assert "0 participants" in result.summary
        assert result.timeline == []
        assert "ATF B-5" in " ".join(result.regulatory_context)

    def test_approved_chain(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-ok")
        chain.append(EventType.INBOUND_INTENT, "agent:writer", "proposer", {"action": "write"})
        chain.append(EventType.POLICY_EVAL, "gavel:evaluator", "evaluator", {"risk_score": 0.3})
        chain.append(EventType.APPROVAL_GRANTED, "human:alice", "reviewer")
        chain.status = ChainStatus.APPROVED

        result = renderer.explain_chain(chain)
        assert "approved" in result.summary
        assert "3 events" in result.summary
        assert len(result.timeline) == 3
        assert "agent:writer" in result.timeline[0]
        assert "No action required" in result.recommendation

    def test_denied_chain_has_risk_factors(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-denied")
        chain.append(EventType.INBOUND_INTENT, "agent:x", "proposer")
        chain.append(
            EventType.APPROVAL_DENIED, "human:bob", "reviewer",
            {"reason": "Exceeds scope"},
        )
        chain.status = ChainStatus.DENIED

        result = renderer.explain_chain(chain)
        assert "denied" in result.summary
        assert any("Exceeds scope" in rf for rf in result.risk_factors)
        assert "resubmit" in result.recommendation.lower()

    def test_auto_denied_chain(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-auto")
        chain.append(
            EventType.AUTO_DENIED, "gavel:policy", "evaluator",
            {"reason": "Forbidden tool"},
        )
        chain.status = ChainStatus.DENIED

        result = renderer.explain_chain(chain)
        assert any("Forbidden tool" in rf for rf in result.risk_factors)

    def test_rolled_back_chain(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-rb")
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.ROLLBACK_TRIGGERED, "gavel:verifier", "verifier")
        chain.status = ChainStatus.ROLLED_BACK

        result = renderer.explain_chain(chain)
        assert any("rolled back" in rf.lower() for rf in result.risk_factors)
        assert "rolled back" in result.recommendation.lower()

    def test_timed_out_chain(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-to")
        chain.status = ChainStatus.TIMED_OUT

        result = renderer.explain_chain(chain)
        assert any("timed out" in rf.lower() for rf in result.risk_factors)

    def test_integrity_failure(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-tamper")
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        # Tamper with the hash
        chain.events[0].event_hash = "deadbeef"

        result = renderer.explain_chain(chain)
        assert any("tampered" in rf.lower() for rf in result.risk_factors)

    def test_payload_reason_in_timeline(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-reason")
        chain.append(
            EventType.ESCALATED, "gavel:eval", "evaluator",
            {"reason": "Risk too high"},
        )
        chain.status = ChainStatus.ESCALATED

        result = renderer.explain_chain(chain)
        assert "Risk too high" in result.timeline[0]
        assert "escalat" in result.recommendation.lower()

    def test_regulatory_context_present(self, renderer: ExplainabilityRenderer):
        chain = GovernanceChain(chain_id="c-reg")
        result = renderer.explain_chain(chain)
        contexts = " ".join(result.regulatory_context)
        assert "ATF" in contexts
        assert "EU AI Act" in contexts


# ── explain_drift ─────────────────────────────────────────────


class TestExplainDrift:
    def _make_report(self, **overrides) -> DriftReport:
        defaults = dict(
            agent_id="agent:drifter",
            enrollment_sample_size=50,
            current_sample_size=60,
            risk_delta=0.0,
            network_delta=0.0,
            denial_delta=0.0,
            escalation_delta=0.0,
            new_tools=[],
            tool_distribution_shift=0.0,
            path_novelty=0.0,
            new_paths=[],
            drift_score=0.05,
            is_significant=False,
            reasons=[],
        )
        defaults.update(overrides)
        return DriftReport(**defaults)

    def test_no_drift(self, renderer: ExplainabilityRenderer):
        report = self._make_report()
        result = renderer.explain_drift(report)
        assert result.subject_type == "drift_report"
        assert result.subject_id == "agent:drifter"
        assert "minimal drift" in result.summary
        assert "No action required" in result.recommendation

    def test_significant_drift(self, renderer: ExplainabilityRenderer):
        report = self._make_report(
            drift_score=0.45,
            is_significant=True,
            risk_delta=0.35,
            reasons=["risk_delta=+0.350"],
        )
        result = renderer.explain_drift(report)
        assert "significantly" in result.summary
        assert any("increased" in rf for rf in result.risk_factors)
        assert any("35 percentage points" in rf for rf in result.risk_factors)
        assert "investigate" in result.recommendation.lower()

    def test_new_tools(self, renderer: ExplainabilityRenderer):
        report = self._make_report(
            new_tools=["curl", "wget"],
            drift_score=0.15,
        )
        result = renderer.explain_drift(report)
        assert any("curl" in rf and "wget" in rf for rf in result.risk_factors)

    def test_new_paths(self, renderer: ExplainabilityRenderer):
        report = self._make_report(
            new_paths=["/etc/config", "/var/secrets"],
            path_novelty=0.6,
        )
        result = renderer.explain_drift(report)
        assert any("/etc/config" in rf for rf in result.risk_factors)

    def test_network_delta(self, renderer: ExplainabilityRenderer):
        report = self._make_report(network_delta=0.25)
        result = renderer.explain_drift(report)
        assert any("Network" in rf and "increased" in rf for rf in result.risk_factors)

    def test_denial_delta(self, renderer: ExplainabilityRenderer):
        report = self._make_report(denial_delta=-0.15)
        result = renderer.explain_drift(report)
        assert any("denial rate" in rf.lower() and "decreased" in rf for rf in result.risk_factors)

    def test_escalation_delta(self, renderer: ExplainabilityRenderer):
        report = self._make_report(escalation_delta=0.10)
        result = renderer.explain_drift(report)
        assert any("escalation rate" in rf.lower() for rf in result.risk_factors)

    def test_tool_distribution_shift(self, renderer: ExplainabilityRenderer):
        report = self._make_report(tool_distribution_shift=0.8)
        result = renderer.explain_drift(report)
        assert any("tool usage" in rf.lower() for rf in result.risk_factors)

    def test_regulatory_context(self, renderer: ExplainabilityRenderer):
        report = self._make_report()
        result = renderer.explain_drift(report)
        contexts = " ".join(result.regulatory_context)
        assert "ATF B-3" in contexts
        assert "ATF B-5" in contexts
        assert "EU AI Act" in contexts


# ── explain_denial ────────────────────────────────────────────


class TestExplainDenial:
    def _make_denial_event(self, **payload_overrides) -> ChainEvent:
        payload = {"reason": "Action exceeds risk threshold"}
        payload.update(payload_overrides)
        return ChainEvent(
            chain_id="c-deny-test",
            event_type=EventType.APPROVAL_DENIED,
            actor_id="human:reviewer",
            role_used="reviewer",
            payload=payload,
        )

    def test_basic_denial(self, renderer: ExplainabilityRenderer):
        event = self._make_denial_event()
        result = renderer.explain_denial(event)
        assert result.subject_type == "denial_event"
        assert "denied by a governance reviewer" in result.summary
        assert "Action exceeds risk threshold" in result.summary
        assert any("Action exceeds risk threshold" in rf for rf in result.risk_factors)

    def test_auto_denial(self, renderer: ExplainabilityRenderer):
        event = ChainEvent(
            chain_id="c-auto-deny",
            event_type=EventType.AUTO_DENIED,
            actor_id="gavel:policy",
            role_used="evaluator",
            payload={"reason": "Forbidden tool invocation"},
        )
        result = renderer.explain_denial(event)
        assert "automatically denied" in result.summary

    def test_denial_with_policy(self, renderer: ExplainabilityRenderer):
        event = self._make_denial_event(
            policy="no-network-access",
            risk_score=0.75,
        )
        result = renderer.explain_denial(event)
        assert any("no-network-access" in rf for rf in result.risk_factors)
        assert any("0.75" in rf for rf in result.risk_factors)

    def test_denial_with_high_risk_score(self, renderer: ExplainabilityRenderer):
        event = self._make_denial_event(risk_score=0.85)
        result = renderer.explain_denial(event)
        assert any("exceeded the acceptable threshold" in rf for rf in result.risk_factors)

    def test_denial_with_low_risk_score(self, renderer: ExplainabilityRenderer):
        event = self._make_denial_event(risk_score=0.3)
        result = renderer.explain_denial(event)
        assert any("other factors" in rf for rf in result.risk_factors)

    def test_denial_with_violations(self, renderer: ExplainabilityRenderer):
        event = self._make_denial_event(
            violations=["scope_exceeded", "forbidden_tool"],
        )
        result = renderer.explain_denial(event)
        assert any("scope_exceeded" in rf for rf in result.risk_factors)
        assert any("forbidden_tool" in rf for rf in result.risk_factors)

    def test_denial_regulatory_context(self, renderer: ExplainabilityRenderer):
        event = self._make_denial_event()
        result = renderer.explain_denial(event)
        contexts = " ".join(result.regulatory_context)
        assert "ATF A-2" in contexts
        assert "ATF B-5" in contexts
        assert "Article 14" in contexts


# ── explain_risk ──────────────────────────────────────────────


class TestExplainRisk:
    def test_low_risk(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.15, {"agent_id": "agent:safe", "action": "read file"})
        assert result.subject_type == "risk_assessment"
        assert "very low" in result.summary
        assert "0.15" in result.summary
        assert "low risk" in result.recommendation.lower()

    def test_moderate_risk(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.45, {"agent_id": "agent:mid", "action": "write file"})
        assert "moderate" in result.summary
        assert "moderate risk" in result.recommendation.lower()

    def test_high_risk(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.75, {
            "agent_id": "agent:risky",
            "action": "deploy service",
            "network": True,
            "tools": ["curl", "docker"],
            "paths": ["/var/deploy", "/etc/config"],
            "scope_violation": True,
            "evidence_failed": True,
            "secret_detected": True,
        })
        assert "high" in result.summary
        assert any("network" in rf.lower() for rf in result.risk_factors)
        assert any("curl" in rf for rf in result.risk_factors)
        assert any("/var/deploy" in rf for rf in result.risk_factors)
        assert any("scope" in rf.lower() for rf in result.risk_factors)
        assert any("evidence" in rf.lower() for rf in result.risk_factors)
        assert any("secret" in rf.lower() for rf in result.risk_factors)
        assert "significant risk" in result.recommendation.lower()

    def test_very_high_risk(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.90, {"agent_id": "agent:x", "action": "exec"})
        assert "very high" in result.summary

    def test_history_risk_factor(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.50, {
            "agent_id": "agent:h",
            "action": "write",
            "history_risk": 0.35,
        })
        assert any("historical" in rf.lower() for rf in result.risk_factors)

    def test_custom_factors(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.30, {
            "agent_id": "agent:c",
            "action": "edit",
            "custom_metric": "elevated",
        })
        assert any("Custom metric" in rf for rf in result.risk_factors)

    def test_no_network_no_factor(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.20, {
            "agent_id": "agent:a",
            "action": "read",
            "network": False,
        })
        assert not any("network" in rf.lower() for rf in result.risk_factors)

    def test_risk_regulatory_context(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.50, {"agent_id": "a", "action": "x"})
        contexts = " ".join(result.regulatory_context)
        assert "ATF B-1" in contexts
        assert "ATF B-5" in contexts
        assert "Article 9" in contexts

    def test_default_agent_and_action(self, renderer: ExplainabilityRenderer):
        result = renderer.explain_risk(0.10, {})
        assert "unknown" in result.summary


# ── explain_evasion (bonus method) ────────────────────────────


class TestExplainEvasion:
    def _make_finding(self, **overrides) -> EvasionFinding:
        defaults = dict(
            agent_id="agent:sneaky",
            signal=EvasionSignal.FRAGMENTED_ACTIONS,
            severity=EvasionSeverity.MEDIUM,
            detail="5 low-risk proposals in 10min summing to risk 0.75",
            supporting_chain_ids=["c-1", "c-2", "c-3"],
        )
        defaults.update(overrides)
        return EvasionFinding(**defaults)

    def test_basic_evasion(self, renderer: ExplainabilityRenderer):
        finding = self._make_finding()
        result = renderer.explain_evasion(finding)
        assert result.subject_type == "evasion_finding"
        assert result.subject_id == "agent:sneaky"
        assert "moderate" in result.summary
        assert "fragmented_actions" in result.summary
        assert any("c-1" in t for t in result.timeline)

    def test_high_severity(self, renderer: ExplainabilityRenderer):
        finding = self._make_finding(
            signal=EvasionSignal.KILL_SWITCH_EVASION,
            severity=EvasionSeverity.HIGH,
            detail="Re-registration detected",
        )
        result = renderer.explain_evasion(finding)
        assert "high" in result.summary
        assert "suspend" in result.recommendation.lower()

    def test_low_severity(self, renderer: ExplainabilityRenderer):
        finding = self._make_finding(
            signal=EvasionSignal.HEARTBEAT_BURST,
            severity=EvasionSeverity.LOW,
            detail="5 proposals in 2min after 45min quiet",
        )
        result = renderer.explain_evasion(finding)
        assert "low" in result.summary
        assert "Monitor" in result.recommendation

    def test_evasion_regulatory_context(self, renderer: ExplainabilityRenderer):
        finding = self._make_finding()
        result = renderer.explain_evasion(finding)
        contexts = " ".join(result.regulatory_context)
        assert "ATF C-1" in contexts
        assert "ATF B-5" in contexts
