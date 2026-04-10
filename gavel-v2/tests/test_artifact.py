from __future__ import annotations

import copy
import hashlib
import json

import pytest

from gavel.chain import GovernanceChain, EventType, ChainStatus
from gavel.artifact import (
    GovernanceArtifact,
    PolicyDecisionAdapter,
    from_chain,
    verify_artifact,
    Principal,
    ArtifactEvent,
    EvidenceSummary,
)
from gavel.evidence import ReviewResult, ReviewVerdict, Finding


def _build_chain(status: ChainStatus = ChainStatus.APPROVED) -> GovernanceChain:
    chain = GovernanceChain()
    chain.append(EventType.INBOUND_INTENT, "agent:proposer", "proposer", {"goal": "deploy"})
    chain.append(EventType.POLICY_EVAL, "system:evaluator", "evaluator", {"risk": 0.2})
    chain.append(EventType.APPROVAL_GRANTED, "agent:approver", "approver", {"decision": "yes"})
    chain.status = status
    return chain


def _build_evidence(verdict: ReviewVerdict = ReviewVerdict.PASS) -> ReviewResult:
    return ReviewResult(
        verdict=verdict,
        findings=[
            Finding(check="exit_code", passed=True, detail="Exit code: 0"),
            Finding(check="scope_compliance", passed=True, detail="All files in scope"),
            Finding(check="secret_detection", passed=False, detail="Potential secret", severity="warn"),
        ],
        risk_delta=0.1,
        scope_compliance="FULL",
    )


def test_from_chain_basic():
    chain = _build_chain()
    artifact = from_chain(chain)

    assert artifact.chain_id == chain.chain_id
    assert artifact.status == "APPROVED"
    assert artifact.verdict == "allow"
    assert artifact.integrity is True
    assert artifact.event_count == 3
    assert len(artifact.events) == 3
    assert artifact.artifact_version == "1.0"
    assert artifact.genesis_hash == hashlib.sha256(chain.chain_id.encode()).hexdigest()
    assert artifact.created_at == chain.created_at.isoformat()


def test_from_chain_with_evidence():
    chain = _build_chain()
    evidence = _build_evidence()
    artifact = from_chain(chain, evidence_result=evidence)

    assert artifact.evidence.checks_total == 3
    assert artifact.evidence.checks_passed == 2
    assert artifact.evidence.risk_delta == 0.1
    assert artifact.evidence.scope_compliance == "FULL"
    assert artifact.evidence.review_verdict == "PASS"


def test_artifact_hash_computation():
    chain = _build_chain()
    artifact = from_chain(chain)

    assert artifact.artifact_hash != ""
    recomputed = artifact.compute_artifact_hash()
    assert artifact.artifact_hash == recomputed


def test_artifact_hash_tamper_detection():
    chain = _build_chain()
    artifact = from_chain(chain)
    original_hash = artifact.artifact_hash

    artifact.status = "DENIED"
    assert artifact.compute_artifact_hash() != original_hash


def test_verify_artifact_valid():
    chain = _build_chain()
    artifact = from_chain(chain)
    artifact_dict = artifact.model_dump(mode="json")

    result = verify_artifact(artifact_dict)
    assert result["valid"] is True
    assert result["errors"] == []
    assert result["artifact_id"] == artifact.artifact_id
    assert result["chain_id"] == chain.chain_id


def test_verify_artifact_tampered_hash():
    chain = _build_chain()
    artifact = from_chain(chain)
    artifact_dict = artifact.model_dump(mode="json")

    artifact_dict["artifact_hash"] = "0" * 64
    result = verify_artifact(artifact_dict)
    assert result["valid"] is False
    assert any("artifact_hash mismatch" in e for e in result["errors"])


def test_verify_artifact_tampered_genesis():
    chain = _build_chain()
    artifact = from_chain(chain)
    artifact_dict = artifact.model_dump(mode="json")

    artifact_dict["genesis_hash"] = "0" * 64
    result = verify_artifact(artifact_dict)
    assert result["valid"] is False
    assert any("genesis_hash mismatch" in e for e in result["errors"])


def test_policy_decision_allow():
    chain = _build_chain(ChainStatus.APPROVED)
    artifact = from_chain(chain)
    decision = PolicyDecisionAdapter.to_policy_decision(artifact)
    assert decision["verdict"] == "allow"


def test_policy_decision_deny():
    chain = _build_chain(ChainStatus.DENIED)
    artifact = from_chain(chain)
    decision = PolicyDecisionAdapter.to_policy_decision(artifact)
    assert decision["verdict"] == "deny"


def test_policy_decision_escalate():
    chain = _build_chain(ChainStatus.ESCALATED)
    artifact = from_chain(chain)
    decision = PolicyDecisionAdapter.to_policy_decision(artifact)
    assert decision["verdict"] == "escalate"


def test_policy_decision_timed_out():
    chain = _build_chain(ChainStatus.TIMED_OUT)
    artifact = from_chain(chain)
    decision = PolicyDecisionAdapter.to_policy_decision(artifact)
    assert decision["verdict"] == "deny"


def test_policy_decision_fields():
    chain = _build_chain()
    evidence = _build_evidence()
    artifact = from_chain(chain, evidence_result=evidence)
    decision = PolicyDecisionAdapter.to_policy_decision(artifact)

    assert "reason" in decision
    assert chain.chain_id in decision["reason"]
    assert "matched_rule" in decision
    assert decision["matched_rule"].startswith("article-")
    assert "metadata" in decision
    meta = decision["metadata"]
    assert meta["artifact_id"] == artifact.artifact_id
    assert meta["chain_id"] == chain.chain_id
    assert meta["integrity"] is True
    assert meta["principal_count"] == 3
    assert "evidence" in meta
    assert meta["artifact_hash"] == artifact.artifact_hash
    assert meta["artifact_version"] == "1.0"


def test_principals_extracted():
    chain = _build_chain()
    artifact = from_chain(chain)

    actor_ids = {p.actor_id for p in artifact.principals}
    assert actor_ids == {"agent:proposer", "system:evaluator", "agent:approver"}

    roles = {p.role for p in artifact.principals}
    assert roles == {"proposer", "evaluator", "approver"}

    for p in artifact.principals:
        assert p.did is None


def test_finalized_at_set():
    chain = _build_chain(ChainStatus.APPROVED)
    artifact = from_chain(chain)
    assert artifact.finalized_at is not None
    assert artifact.finalized_at == chain.events[-1].timestamp.isoformat()


def test_finalized_at_none():
    chain = _build_chain(ChainStatus.PENDING)
    artifact = from_chain(chain)
    assert artifact.finalized_at is None


def test_artifact_roundtrip():
    chain = _build_chain()
    evidence = _build_evidence()
    artifact = from_chain(chain, evidence_result=evidence)

    artifact_dict = artifact.model_dump(mode="json")
    result = verify_artifact(artifact_dict)
    assert result["valid"] is True
    assert result["errors"] == []

    restored = GovernanceArtifact(**artifact_dict)
    assert restored.artifact_hash == artifact.artifact_hash
    assert restored.chain_id == artifact.chain_id
    assert restored.status == artifact.status
    assert len(restored.events) == len(artifact.events)
    assert restored.evidence.checks_total == artifact.evidence.checks_total
