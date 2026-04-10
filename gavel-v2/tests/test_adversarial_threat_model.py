"""Adversarial resilience tests — full STRIDE-based threat model coverage.

This complements tests/test_adversarial.py (which focuses on concrete
attack patterns like self-approval and chain tampering) with coverage
for items enumerated in docs/threat-model.md that were previously not
exercised directly. Each test is tagged with the threat ID from the
threat model so a reviewer can trace test → threat → Article 15 control.
"""

from __future__ import annotations

import hashlib

import pytest

from gavel.baseline import BehavioralBaselineRegistry, BehavioralObservation
from gavel.blastbox import EvidencePacket, ScopeDeclaration
from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    FallbackBehavior,
    PurposeDeclaration,
    ResourceAllowlist,
)
from gavel.evidence import EvidenceReviewer


# ── T-T2: Evidence packet tamper-detection ─────────────────────

class TestEvidencePacketTamperDetection:
    """Threat T-T2: rewriting an evidence packet field should invalidate its hash."""

    def _mk_packet(self) -> EvidencePacket:
        return EvidencePacket(
            chain_id="c-1",
            command_argv=["echo", "hello"],
            exit_code=0,
            files_modified=["src/app.py"],
            image_digest="sha256:deadbeef",
            network_mode="none",
        )

    def test_baseline_hash_stable(self):
        p = self._mk_packet()
        assert p.compute_hash() == p.compute_hash()

    def test_tampered_exit_code_changes_hash(self):
        p = self._mk_packet()
        h1 = p.compute_hash()
        p.exit_code = 1
        assert p.compute_hash() != h1

    def test_tampered_files_changes_hash(self):
        p = self._mk_packet()
        h1 = p.compute_hash()
        p.files_modified.append("src/other.py")
        assert p.compute_hash() != h1

    def test_tampered_image_digest_changes_hash(self):
        p = self._mk_packet()
        h1 = p.compute_hash()
        p.image_digest = "sha256:cafef00d"
        assert p.compute_hash() != h1


# ── T-D2: Rate limit enforcement ───────────────────────────────

class TestRateLimitEnforcement:
    """Threat T-D2: ActionBoundaries must declare a hard rate limit."""

    def test_rate_limit_declared_on_enrollment(self):
        boundaries = ActionBoundaries(
            allowed_actions=["read"],
            max_actions_per_minute=30,
        )
        assert boundaries.max_actions_per_minute > 0
        assert boundaries.max_actions_per_minute <= 1000  # sanity

    def test_rate_limit_honored(self):
        """A deployer must be able to declare aggressive rate limits."""
        b = ActionBoundaries(allowed_actions=["read"], max_actions_per_minute=1)
        assert b.is_valid() == (True, "")
        assert b.max_actions_per_minute == 1


# ── T-D3: Blast box scope limits ───────────────────────────────

class TestBlastBoxScopeLimits:
    """Threat T-D3: declared scope limits must be first-class fields."""

    def test_scope_limits_enforced(self):
        scope = ScopeDeclaration(
            allow_paths=["/tmp"],
            max_duration_seconds=5,
            max_memory_mb=128,
            max_cpu=1,
        )
        assert scope.max_duration_seconds == 5
        assert scope.max_memory_mb == 128
        assert scope.max_cpu == 1

    def test_blastbox_no_privileged_flags(self):
        """The scope declaration shape has no field for privileged execution."""
        scope = ScopeDeclaration()
        # The data class has no 'privileged' field; any attempt to pass one
        # during construction must fail at runtime.
        with pytest.raises(TypeError):
            ScopeDeclaration(privileged=True)  # type: ignore[call-arg]


# ── T-I1/T-I2: Evidence reviewer privacy + secret scans ────────

class TestEvidenceReviewPrivacyControls:
    """Threats T-I1 and T-I2: stdout must not leak secrets or PII/PHI."""

    def _mk(self) -> tuple[EvidencePacket, ScopeDeclaration, EvidenceReviewer]:
        scope = ScopeDeclaration(allow_paths=["src/"], allow_network=False)
        packet = EvidencePacket(
            chain_id="c-1",
            scope=scope,
            exit_code=0,
            network_mode="none",
        )
        return packet, scope, EvidenceReviewer()

    def test_api_key_in_stdout_fails_review(self):
        packet, scope, reviewer = self._mk()
        result = reviewer.review(
            packet,
            scope,
            stdout_content="api_key=sk-abc123xyz",
            stderr_content="",
        )
        assert not result.passed
        assert any("secret" in f.check.lower() for f in result.findings)

    def test_phi_in_stdout_is_redacted_in_artifact(self):
        packet, scope, reviewer = self._mk()
        result = reviewer.review(
            packet,
            scope,
            stdout_content="Patient MRN: ABC-12345",
            stderr_content="",
        )
        assert "ABC-12345" not in result.redacted_stdout
        assert result.privacy_findings


# ── Enrollment bias toward safety on invalid applications ──────

class TestEnrollmentDefaultDeny:
    """Threat T-S1: unenrolled or invalid agents must be blocked."""

    def test_missing_budget_blocks_enrollment(self):
        from gavel.enrollment import EnrollmentRegistry

        app = EnrollmentApplication(
            agent_id="agent:rogue",
            display_name="Rogue Agent",
            owner="someone",
            owner_contact="someone@example.com",
            budget_tokens=0,
            budget_usd=0.0,
            purpose=PurposeDeclaration(
                summary="A perfectly normal agent that needs to run",
                operational_scope="general",
            ),
            capabilities=CapabilityManifest(tools=["edit"]),
            resources=ResourceAllowlist(allowed_paths=["/tmp"]),
            boundaries=ActionBoundaries(allowed_actions=["read"]),
            fallback=FallbackBehavior(),
        )
        reg = EnrollmentRegistry()
        record = reg.submit(app)
        assert record.status.value == "INCOMPLETE"
        assert any("budget" in v.lower() for v in record.violations)


# ── Drift detection as a lagging safety net (R-2) ──────────────

class TestDriftDetectionIsLagging:
    """Residual risk R-2: drift detection is a signal, not a hard block."""

    def test_drift_flags_significant_but_does_not_prevent(self):
        reg = BehavioralBaselineRegistry(window=50, min_samples_for_snapshot=5)
        for _ in range(5):
            reg.observe(BehavioralObservation(
                agent_id="agent:drift",
                chain_id="c",
                tool="edit",
                risk_score=0.1,
                outcome="APPROVED",
            ))
        # Abrupt shift in behavior — higher risk, new tools, more denials.
        for i in range(20):
            reg.observe(BehavioralObservation(
                agent_id="agent:drift",
                chain_id=f"c-{i}",
                tool="bash",
                risk_score=0.9,
                network=True,
                outcome="DENIED",
            ))
        drift = reg.drift("agent:drift")
        assert drift is not None
        assert drift.is_significant
        assert "bash" in drift.new_tools
