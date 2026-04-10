"""Tests for gavel_governance artifact schema, adapter, and verification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from gavel_governance import (
    GovernanceArtifact,
    PolicyDecisionAdapter,
    Principal,
    ArtifactEvent,
    EvidenceSummary,
    from_governance_chain,
    verify_artifact,
)


def _make_events() -> list[dict[str, str]]:
    """Create a minimal set of governance chain events."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "event_id": "evt-001",
            "event_type": "INBOUND_INTENT",
            "actor_id": "agent:proposer",
            "role": "proposer",
            "timestamp": now,
            "event_hash": hashlib.sha256(b"evt-001").hexdigest(),
        },
        {
            "event_id": "evt-002",
            "event_type": "POLICY_EVAL",
            "actor_id": "system:evaluator",
            "role": "evaluator",
            "timestamp": now,
            "event_hash": hashlib.sha256(b"evt-002").hexdigest(),
        },
        {
            "event_id": "evt-003",
            "event_type": "APPROVAL_GRANTED",
            "actor_id": "agent:approver",
            "role": "approver",
            "timestamp": now,
            "event_hash": hashlib.sha256(b"evt-003").hexdigest(),
        },
    ]


def _make_artifact(
    status: str = "APPROVED",
    evidence: dict | None = None,
) -> GovernanceArtifact:
    """Create a test artifact via the factory."""
    return from_governance_chain(
        chain_id="gc-test-001",
        status=status,
        created_at=datetime.now(timezone.utc).isoformat(),
        events=_make_events(),
        integrity=True,
        evidence=evidence,
    )


# ── Schema tests ──────────────────────────────────────────────


class TestGovernanceArtifactSchema:
    def test_artifact_version(self) -> None:
        artifact = _make_artifact()
        assert artifact.artifact_version == "1.0"

    def test_artifact_id_format(self) -> None:
        artifact = _make_artifact()
        assert artifact.artifact_id.startswith("ga-")
        assert len(artifact.artifact_id) == 15  # "ga-" + 12 hex chars

    def test_chain_id_preserved(self) -> None:
        artifact = _make_artifact()
        assert artifact.chain_id == "gc-test-001"

    def test_verdict_allow(self) -> None:
        artifact = _make_artifact("APPROVED")
        assert artifact.verdict == "allow"

    def test_verdict_deny(self) -> None:
        artifact = _make_artifact("DENIED")
        assert artifact.verdict == "deny"

    def test_verdict_escalate(self) -> None:
        artifact = _make_artifact("PENDING")
        assert artifact.verdict == "escalate"

    def test_verdict_timed_out(self) -> None:
        artifact = _make_artifact("TIMED_OUT")
        assert artifact.verdict == "deny"

    def test_principals_extracted(self) -> None:
        artifact = _make_artifact()
        actor_ids = {p.actor_id for p in artifact.principals}
        assert actor_ids == {"agent:proposer", "system:evaluator", "agent:approver"}

    def test_event_count(self) -> None:
        artifact = _make_artifact()
        assert artifact.event_count == 3
        assert len(artifact.events) == 3

    def test_finalized_at_terminal(self) -> None:
        artifact = _make_artifact("APPROVED")
        assert artifact.finalized_at is not None

    def test_finalized_at_nonterminal(self) -> None:
        artifact = _make_artifact("PENDING")
        assert artifact.finalized_at is None


# ── Hash integrity tests ──────────────────────────────────────


class TestArtifactHash:
    def test_hash_computed(self) -> None:
        artifact = _make_artifact()
        assert artifact.artifact_hash != ""
        assert len(artifact.artifact_hash) == 64  # SHA-256 hex

    def test_hash_reproducible(self) -> None:
        artifact = _make_artifact()
        assert artifact.artifact_hash == artifact.compute_artifact_hash()

    def test_hash_tamper_detection(self) -> None:
        artifact = _make_artifact()
        original = artifact.artifact_hash
        artifact.status = "DENIED"
        assert artifact.compute_artifact_hash() != original

    def test_genesis_hash(self) -> None:
        artifact = _make_artifact()
        expected = hashlib.sha256(b"gc-test-001").hexdigest()
        assert artifact.genesis_hash == expected


# ── Verification tests ────────────────────────────────────────


class TestVerifyArtifact:
    def test_valid_artifact(self) -> None:
        artifact = _make_artifact()
        result = verify_artifact(artifact.model_dump(mode="json"))
        assert result["valid"] is True
        assert result["errors"] == []

    def test_tampered_artifact_hash(self) -> None:
        artifact = _make_artifact()
        data = artifact.model_dump(mode="json")
        data["artifact_hash"] = "0" * 64
        result = verify_artifact(data)
        assert result["valid"] is False
        assert any("artifact_hash mismatch" in e for e in result["errors"])

    def test_tampered_genesis_hash(self) -> None:
        artifact = _make_artifact()
        data = artifact.model_dump(mode="json")
        data["genesis_hash"] = "0" * 64
        result = verify_artifact(data)
        assert result["valid"] is False
        assert any("genesis_hash mismatch" in e for e in result["errors"])

    def test_roundtrip(self) -> None:
        artifact = _make_artifact(
            evidence={
                "checks_total": 5,
                "checks_passed": 5,
                "risk_delta": 0.1,
                "scope_compliance": "FULL",
                "review_verdict": "PASS",
            }
        )
        data = artifact.model_dump(mode="json")
        result = verify_artifact(data)
        assert result["valid"] is True

        restored = GovernanceArtifact(**data)
        assert restored.artifact_hash == artifact.artifact_hash
        assert restored.chain_id == artifact.chain_id


# ── PolicyDecisionAdapter tests ───────────────────────────────


class TestPolicyDecisionAdapter:
    def test_allow_verdict(self) -> None:
        artifact = _make_artifact("APPROVED")
        decision = PolicyDecisionAdapter.to_policy_decision(artifact)
        assert decision["verdict"] == "allow"

    def test_deny_verdict(self) -> None:
        artifact = _make_artifact("DENIED")
        decision = PolicyDecisionAdapter.to_policy_decision(artifact)
        assert decision["verdict"] == "deny"

    def test_escalate_verdict(self) -> None:
        artifact = _make_artifact("ESCALATED")
        decision = PolicyDecisionAdapter.to_policy_decision(artifact)
        assert decision["verdict"] == "escalate"

    def test_decision_fields(self) -> None:
        artifact = _make_artifact()
        decision = PolicyDecisionAdapter.to_policy_decision(artifact)

        assert "verdict" in decision
        assert "reason" in decision
        assert "matched_rule" in decision
        assert "metadata" in decision
        assert decision["matched_rule"].startswith("article-")

    def test_metadata_contents(self) -> None:
        artifact = _make_artifact()
        decision = PolicyDecisionAdapter.to_policy_decision(artifact)
        meta = decision["metadata"]

        assert meta["artifact_id"] == artifact.artifact_id
        assert meta["chain_id"] == artifact.chain_id
        assert meta["integrity"] is True
        assert meta["principal_count"] == 3
        assert "evidence" in meta
        assert meta["artifact_hash"] == artifact.artifact_hash
        assert meta["artifact_version"] == "1.0"

    def test_reason_includes_chain_id(self) -> None:
        artifact = _make_artifact()
        decision = PolicyDecisionAdapter.to_policy_decision(artifact)
        assert artifact.chain_id in decision["reason"]

    def test_matched_rule_integrity_failure(self) -> None:
        artifact = from_governance_chain(
            chain_id="gc-bad",
            status="DENIED",
            created_at=datetime.now(timezone.utc).isoformat(),
            events=_make_events(),
            integrity=False,
        )
        decision = PolicyDecisionAdapter.to_policy_decision(artifact)
        assert decision["matched_rule"] == "article-I:chain-integrity"


# ── Evidence tests ────────────────────────────────────────────


class TestEvidenceSummary:
    def test_default_evidence(self) -> None:
        artifact = _make_artifact()
        assert artifact.evidence.checks_total == 0
        assert artifact.evidence.review_verdict == "NONE"

    def test_evidence_populated(self) -> None:
        artifact = _make_artifact(
            evidence={
                "checks_total": 5,
                "checks_passed": 4,
                "risk_delta": 0.15,
                "scope_compliance": "FULL",
                "review_verdict": "PASS",
            }
        )
        assert artifact.evidence.checks_total == 5
        assert artifact.evidence.checks_passed == 4
        assert artifact.evidence.risk_delta == 0.15
        assert artifact.evidence.scope_compliance == "FULL"
        assert artifact.evidence.review_verdict == "PASS"
