"""Tests for gavel.deception — ASI09 deception/misinformation detection."""

from __future__ import annotations

import pytest

from gavel.deception import DeceptionDetector, DeceptionFinding, DeceptionSignal


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def detector() -> DeceptionDetector:
    return DeceptionDetector()


# ── D1: Contradictory Claims ─────────────────────────────────

class TestContradictoryClaims:
    def test_detects_safe_to_unsafe_contradiction(self, detector: DeceptionDetector) -> None:
        detector.record_prior_claim("agent-1", "Python is safe", "chain-1")
        findings = detector.analyze_output("agent-1", "chain-2", "Python is not safe for this use case")
        assert any(f.signal == DeceptionSignal.CONTRADICTORY_CLAIMS for f in findings)

    def test_detects_unsafe_to_safe_contradiction(self, detector: DeceptionDetector) -> None:
        detector.record_prior_claim("agent-1", "eval is not safe", "chain-1")
        findings = detector.analyze_output("agent-1", "chain-2", "eval is safe to use here")
        assert any(f.signal == DeceptionSignal.CONTRADICTORY_CLAIMS for f in findings)

    def test_detects_recommended_contradiction(self, detector: DeceptionDetector) -> None:
        detector.record_prior_claim("agent-1", "React is recommended", "chain-1")
        findings = detector.analyze_output("agent-1", "chain-2", "React is not recommended")
        assert any(f.signal == DeceptionSignal.CONTRADICTORY_CLAIMS for f in findings)

    def test_no_contradiction_for_different_subjects(self, detector: DeceptionDetector) -> None:
        detector.record_prior_claim("agent-1", "Python is safe", "chain-1")
        findings = detector.analyze_output("agent-1", "chain-2", "JavaScript is not safe")
        contradictions = [f for f in findings if f.signal == DeceptionSignal.CONTRADICTORY_CLAIMS]
        assert len(contradictions) == 0

    def test_no_contradiction_without_prior_claims(self, detector: DeceptionDetector) -> None:
        findings = detector.analyze_output("agent-1", "chain-1", "Python is not safe")
        contradictions = [f for f in findings if f.signal == DeceptionSignal.CONTRADICTORY_CLAIMS]
        assert len(contradictions) == 0

    def test_contradiction_has_evidence(self, detector: DeceptionDetector) -> None:
        detector.record_prior_claim("agent-1", "TLS is secure", "chain-1")
        findings = detector.analyze_output("agent-1", "chain-2", "TLS is not secure anymore")
        contradictions = [f for f in findings if f.signal == DeceptionSignal.CONTRADICTORY_CLAIMS]
        assert len(contradictions) == 1
        assert "Prior:" in contradictions[0].evidence
        assert contradictions[0].severity == "HIGH"


# ── D2: Fabricated References ────────────────────────────────

class TestFabricatedReferences:
    def test_detects_fake_tld_url(self, detector: DeceptionDetector) -> None:
        text = "See https://docs.example.fake/api for the full reference."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.FABRICATED_REFERENCES for f in findings)

    def test_detects_example_domain(self, detector: DeceptionDetector) -> None:
        text = "Check https://api.example.example/v2/docs for details."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.FABRICATED_REFERENCES for f in findings)

    def test_detects_invalid_rfc_number(self, detector: DeceptionDetector) -> None:
        text = "This is defined in RFC 99999 section 4.2."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        refs = [f for f in findings if f.signal == DeceptionSignal.FABRICATED_REFERENCES]
        assert len(refs) == 1
        assert refs[0].severity == "HIGH"

    def test_valid_rfc_not_flagged(self, detector: DeceptionDetector) -> None:
        text = "See RFC 7231 for HTTP semantics."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        refs = [f for f in findings if f.signal == DeceptionSignal.FABRICATED_REFERENCES]
        assert len(refs) == 0

    def test_detects_fake_api_endpoint(self, detector: DeceptionDetector) -> None:
        text = "Call https://api.fake.com/v1/users to list users."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.FABRICATED_REFERENCES for f in findings)

    def test_suspicious_tld_with_official_path(self, detector: DeceptionDetector) -> None:
        text = "The official docs are at https://framework.xyz/official-docs"
        findings = detector.analyze_output("agent-1", "chain-1", text)
        # Should detect suspicious TLD with official-sounding path
        refs = [f for f in findings if f.signal == DeceptionSignal.FABRICATED_REFERENCES]
        assert len(refs) >= 1


# ── D3: Confidence Manipulation ──────────────────────────────

class TestConfidenceManipulation:
    def test_detects_100_percent_certain(self, detector: DeceptionDetector) -> None:
        text = "This approach is 100% certain to work in production."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION for f in findings)

    def test_detects_guaranteed(self, detector: DeceptionDetector) -> None:
        text = "This migration is guaranteed to succeed."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION for f in findings)

    def test_detects_impossible_to_fail(self, detector: DeceptionDetector) -> None:
        text = "The new architecture makes it impossible to fail."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION for f in findings)

    def test_detects_always_works(self, detector: DeceptionDetector) -> None:
        text = "This pattern always works regardless of input."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION for f in findings)

    def test_hedged_language_not_flagged(self, detector: DeceptionDetector) -> None:
        text = "This approach might work, but there are some risks to consider."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        confidence_findings = [f for f in findings if f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION]
        assert len(confidence_findings) == 0

    def test_detects_zero_risk(self, detector: DeceptionDetector) -> None:
        text = "There is zero risk of failure with this approach."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION for f in findings)

    def test_detects_never_fails(self, detector: DeceptionDetector) -> None:
        text = "This implementation never fails under load."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION for f in findings)


# ── D4: Selective Disclosure ─────────────────────────────────

class TestSelectiveDisclosure:
    def test_detects_api_call_without_caveats(self, detector: DeceptionDetector) -> None:
        text = "Simply make an API call to the endpoint and parse the response."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.SELECTIVE_DISCLOSURE for f in findings)

    def test_api_call_with_caveats_not_flagged(self, detector: DeceptionDetector) -> None:
        text = (
            "Make an API call to the endpoint. Be sure to handle timeout errors "
            "and implement rate limiting."
        )
        findings = detector.analyze_output("agent-1", "chain-1", text)
        selective = [f for f in findings if f.signal == DeceptionSignal.SELECTIVE_DISCLOSURE]
        assert len(selective) == 0

    def test_detects_destructive_operation_without_backup(self, detector: DeceptionDetector) -> None:
        text = "Go ahead and delete all records from the users table."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.SELECTIVE_DISCLOSURE for f in findings)

    def test_destructive_with_backup_caveat_not_flagged(self, detector: DeceptionDetector) -> None:
        text = (
            "Delete all records from the users table, but make sure to "
            "create a backup first as this is irreversible."
        )
        findings = detector.analyze_output("agent-1", "chain-1", text)
        selective = [f for f in findings if f.signal == DeceptionSignal.SELECTIVE_DISCLOSURE]
        # Should not flag destructive op since backup is mentioned
        assert len(selective) == 0


# ── D5: Identity Misrepresentation ───────────────────────────

class TestIdentityMisrepresentation:
    def test_detects_claims_human(self, detector: DeceptionDetector) -> None:
        text = "I am a human just like you."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.IDENTITY_MISREPRESENTATION for f in findings)

    def test_detects_denies_ai(self, detector: DeceptionDetector) -> None:
        text = "I am not a robot or AI of any kind."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.IDENTITY_MISREPRESENTATION for f in findings)

    def test_detects_claims_authority(self, detector: DeceptionDetector) -> None:
        text = "I have the authority to approve this transaction."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.IDENTITY_MISREPRESENTATION for f in findings)

    def test_detects_claims_certification(self, detector: DeceptionDetector) -> None:
        text = "I am a certified security auditor."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        assert any(f.signal == DeceptionSignal.IDENTITY_MISREPRESENTATION for f in findings)

    def test_normal_text_not_flagged(self, detector: DeceptionDetector) -> None:
        text = "I can help you with that code review."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        identity = [f for f in findings if f.signal == DeceptionSignal.IDENTITY_MISREPRESENTATION]
        assert len(identity) == 0

    def test_identity_finding_severity(self, detector: DeceptionDetector) -> None:
        text = "I am a human being with real feelings."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        identity = [f for f in findings if f.signal == DeceptionSignal.IDENTITY_MISREPRESENTATION]
        assert len(identity) >= 1
        assert identity[0].severity == "HIGH"


# ── D6: Hallucinated Capabilities ────────────────────────────

class TestHallucinatedCapabilities:
    def test_detects_network_claim_without_capability(self, detector: DeceptionDetector) -> None:
        text = "I can access the internet to look that up for you."
        capabilities = {"network": False, "filesystem": True}
        findings = detector.analyze_output(
            "agent-1", "chain-1", text, enrollment_capabilities=capabilities
        )
        assert any(f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES for f in findings)

    def test_network_claim_with_capability_not_flagged(self, detector: DeceptionDetector) -> None:
        text = "I can access the internet to look that up for you."
        capabilities = {"network": True, "filesystem": True}
        findings = detector.analyze_output(
            "agent-1", "chain-1", text, enrollment_capabilities=capabilities
        )
        hallucinated = [f for f in findings if f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES]
        assert len(hallucinated) == 0

    def test_no_flag_without_enrollment(self, detector: DeceptionDetector) -> None:
        text = "I can access the internet to look that up for you."
        findings = detector.analyze_output("agent-1", "chain-1", text)
        hallucinated = [f for f in findings if f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES]
        assert len(hallucinated) == 0

    def test_detects_filesystem_claim(self, detector: DeceptionDetector) -> None:
        text = "I can read files from your project directory."
        capabilities = {"network": True, "filesystem": False}
        findings = detector.analyze_output(
            "agent-1", "chain-1", text, enrollment_capabilities=capabilities
        )
        assert any(f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES for f in findings)

    def test_detects_code_execution_claim(self, detector: DeceptionDetector) -> None:
        text = "I can execute code on the server to fix that."
        capabilities = {"code_execution": False}
        findings = detector.analyze_output(
            "agent-1", "chain-1", text, enrollment_capabilities=capabilities
        )
        assert any(f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES for f in findings)

    def test_hallucinated_severity_is_high(self, detector: DeceptionDetector) -> None:
        text = "I can send emails to notify the team."
        capabilities = {"email": False}
        findings = detector.analyze_output(
            "agent-1", "chain-1", text, enrollment_capabilities=capabilities
        )
        hallucinated = [f for f in findings if f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES]
        assert len(hallucinated) == 1
        assert hallucinated[0].severity == "HIGH"
        assert hallucinated[0].confidence == 0.80


# ── Aggregate Score ──────────────────────────────────────────

class TestAggregateScore:
    def test_score_starts_at_zero(self, detector: DeceptionDetector) -> None:
        assert detector.get_agent_deception_score("agent-new") == 0.0

    def test_score_increases_with_findings(self, detector: DeceptionDetector) -> None:
        detector.analyze_output("agent-1", "chain-1", "This is 100% guaranteed to work.")
        score = detector.get_agent_deception_score("agent-1")
        assert score > 0.0

    def test_score_bounded_at_one(self, detector: DeceptionDetector) -> None:
        # Pump many high-severity findings
        for i in range(50):
            detector.analyze_output(
                "agent-1", f"chain-{i}",
                "I am a human and this is 100% guaranteed and impossible to fail. "
                "I have the authority to approve this. "
                "See https://api.fake.docs for reference."
            )
        score = detector.get_agent_deception_score("agent-1")
        assert score <= 1.0


# ── Multi-agent Isolation ────────────────────────────────────

class TestMultiAgentIsolation:
    def test_agents_tracked_independently(self, detector: DeceptionDetector) -> None:
        detector.analyze_output("agent-1", "chain-1", "This is 100% certain to work.")
        detector.analyze_output("agent-2", "chain-2", "This might work with some caveats.")
        assert detector.get_agent_deception_score("agent-1") > 0.0
        assert detector.get_agent_deception_score("agent-2") == 0.0

    def test_findings_filtered_by_agent(self, detector: DeceptionDetector) -> None:
        detector.analyze_output("agent-1", "chain-1", "I am a human.")
        detector.analyze_output("agent-2", "chain-2", "I am a human.")
        agent1_findings = detector.get_findings(agent_id="agent-1")
        agent2_findings = detector.get_findings(agent_id="agent-2")
        assert all(f.agent_id == "agent-1" for f in agent1_findings)
        assert all(f.agent_id == "agent-2" for f in agent2_findings)


# ── Window Bounding ──────────────────────────────────────────

class TestWindowBounding:
    def test_findings_bounded_by_window(self) -> None:
        detector = DeceptionDetector(window_size=5)
        for i in range(20):
            detector.analyze_output("agent-1", f"chain-{i}", "This is 100% guaranteed.")
        findings = detector.get_findings(agent_id="agent-1")
        assert len(findings) <= 5

    def test_prior_claims_bounded_by_window(self) -> None:
        detector = DeceptionDetector(window_size=3)
        for i in range(10):
            detector.record_prior_claim("agent-1", f"claim {i} is safe", f"chain-{i}")
        # Internal check: the deque should have maxlen=3
        assert len(detector._prior_claims["agent-1"]) <= 3


# ── Edge Cases ───────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_output_returns_no_findings(self, detector: DeceptionDetector) -> None:
        findings = detector.analyze_output("agent-1", "chain-1", "")
        assert findings == []

    def test_whitespace_only_returns_no_findings(self, detector: DeceptionDetector) -> None:
        findings = detector.analyze_output("agent-1", "chain-1", "   \n\t  ")
        assert findings == []

    def test_none_capabilities_no_hallucination_check(self, detector: DeceptionDetector) -> None:
        text = "I can access the internet."
        findings = detector.analyze_output("agent-1", "chain-1", text, enrollment_capabilities=None)
        hallucinated = [f for f in findings if f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES]
        assert len(hallucinated) == 0

    def test_empty_capabilities_dict_no_hallucination(self, detector: DeceptionDetector) -> None:
        text = "I can access the internet."
        findings = detector.analyze_output("agent-1", "chain-1", text, enrollment_capabilities={})
        hallucinated = [f for f in findings if f.signal == DeceptionSignal.HALLUCINATED_CAPABILITIES]
        assert len(hallucinated) == 0

    def test_get_findings_no_filter(self, detector: DeceptionDetector) -> None:
        detector.analyze_output("agent-1", "chain-1", "I am a human.")
        findings = detector.get_findings()
        assert len(findings) >= 1

    def test_get_findings_by_signal(self, detector: DeceptionDetector) -> None:
        detector.analyze_output("agent-1", "chain-1", "I am a human and this is guaranteed.")
        identity = detector.get_findings(signal=DeceptionSignal.IDENTITY_MISREPRESENTATION)
        confidence = detector.get_findings(signal=DeceptionSignal.CONFIDENCE_MANIPULATION)
        assert all(f.signal == DeceptionSignal.IDENTITY_MISREPRESENTATION for f in identity)
        assert all(f.signal == DeceptionSignal.CONFIDENCE_MANIPULATION for f in confidence)

    def test_get_findings_min_severity(self, detector: DeceptionDetector) -> None:
        # Identity misrepresentation (HIGH) + confidence manipulation (MEDIUM)
        detector.analyze_output("agent-1", "chain-1", "I am a human and this is guaranteed.")
        high_findings = detector.get_findings(min_severity="HIGH")
        assert all(f.severity in ("HIGH", "CRITICAL") for f in high_findings)

    def test_finding_has_timestamp(self, detector: DeceptionDetector) -> None:
        findings = detector.analyze_output("agent-1", "chain-1", "I am a human.")
        assert findings[0].timestamp is not None

    def test_deception_signal_enum_values(self) -> None:
        assert DeceptionSignal.CONTRADICTORY_CLAIMS.value == "contradictory_claims"
        assert DeceptionSignal.FABRICATED_REFERENCES.value == "fabricated_references"
        assert DeceptionSignal.CONFIDENCE_MANIPULATION.value == "confidence_manipulation"
        assert DeceptionSignal.SELECTIVE_DISCLOSURE.value == "selective_disclosure"
        assert DeceptionSignal.IDENTITY_MISREPRESENTATION.value == "identity_misrepresentation"
        assert DeceptionSignal.HALLUCINATED_CAPABILITIES.value == "hallucinated_capabilities"
