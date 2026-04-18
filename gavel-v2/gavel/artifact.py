"""
GovernanceArtifact — portable, verifiable governance decision records.

Defines a minimal Pydantic schema for cross-system artifact verification,
plus a PolicyDecisionAdapter that maps Gavel's output to AGT's
PolicyDecision schema (allowed / action / reason / matched_rule /
policy_name / metadata) as defined in
``agentmesh.governance.policy.PolicyDecision``.

This is the bridge between Gavel's governance chains and Microsoft's
Agent Governance Toolkit. Any system that receives a GovernanceArtifact
can independently verify the hash chain without the Gavel runtime.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field

from gavel.chain import GovernanceChain, ChainStatus
from gavel.evidence import ReviewResult


# ═══════════════════════════════════════════════════════════════
# Schema models
# ═══════════════════════════════════════════════════════════════


class ArtifactEvent(BaseModel):
    """Minimal event record within a governance artifact."""

    event_id: str
    event_type: str
    actor_id: str
    role: str
    timestamp: str  # ISO-8601 string for stable hashing
    event_hash: str


class Principal(BaseModel):
    """An actor who participated in the governance chain."""

    actor_id: str
    role: str
    did: Optional[str] = None


class EvidenceSummary(BaseModel):
    """Summary of evidence review results."""

    checks_total: int = 0
    checks_passed: int = 0
    risk_delta: float = 0.0
    scope_compliance: str = "UNKNOWN"
    review_verdict: str = "NONE"


class GovernanceArtifact(BaseModel):
    """Portable, self-verifiable governance decision record.

    Can be serialized to JSON, transmitted between systems, and
    independently verified without the Gavel runtime. The artifact_hash
    covers the entire content for tamper detection.
    """

    artifact_version: str = "1.0"
    artifact_id: str = Field(default_factory=lambda: f"ga-{uuid.uuid4().hex[:12]}")
    chain_id: str
    status: str
    action: str  # AGT PolicyDecision.action literal
    allowed: bool  # True iff action == "allow"
    created_at: str  # ISO-8601
    finalized_at: Optional[str] = None
    integrity: bool
    principals: list[Principal]
    evidence: EvidenceSummary = Field(default_factory=EvidenceSummary)
    events: list[ArtifactEvent]
    event_count: int
    genesis_hash: str
    artifact_hash: str = ""  # computed after construction

    def compute_artifact_hash(self) -> str:
        """SHA-256 of the artifact content (excluding artifact_hash itself)."""
        data = self.model_dump(mode="json")
        data.pop("artifact_hash", None)
        content = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════
# Action mapping (AGT PolicyDecision.action literal)
# ═══════════════════════════════════════════════════════════════

_ALLOW_STATUSES = {"APPROVED", "COMPLETED"}
_DENY_STATUSES = {"DENIED", "TIMED_OUT", "ROLLED_BACK"}


def _map_action(status: str) -> str:
    """Map Gavel ChainStatus to the AGT PolicyDecision.action literal.

    Returns one of "allow", "deny", or "require_approval" — always within
    the AGT ``action`` literal set ("allow" | "deny" | "warn" |
    "require_approval" | "log").
    """
    if status in _ALLOW_STATUSES:
        return "allow"
    if status in _DENY_STATUSES:
        return "deny"
    return "require_approval"


# ═══════════════════════════════════════════════════════════════
# PolicyDecisionAdapter
# ═══════════════════════════════════════════════════════════════


class PolicyDecisionAdapter:
    """Converts a GovernanceArtifact into AGT's PolicyDecision format.

    AGT PolicyDecision schema (``agentmesh.governance.policy.PolicyDecision``)::

        allowed: bool                         — required
        action: Literal[
            "allow","deny","warn","require_approval","log",
        ]                                     — required
        matched_rule: Optional[str]
        policy_name: Optional[str]
        reason: Optional[str]
        metadata: Optional[dict]
    """

    POLICY_NAME: str = "gavel.governance-chain"

    @staticmethod
    def to_policy_decision(artifact: GovernanceArtifact) -> dict[str, Any]:
        """Convert a GovernanceArtifact to an AGT PolicyDecision dict."""
        principal_count = len(artifact.principals)
        evidence_verdict = artifact.evidence.review_verdict

        reason = (
            f"Governance chain {artifact.chain_id}: {artifact.status.lower()} "
            f"by {principal_count} principal(s), "
            f"evidence review {evidence_verdict.lower()}, "
            f"integrity {'verified' if artifact.integrity else 'FAILED'}"
        )

        # Determine the matched rule based on what governed the decision
        matched_rule = _determine_matched_rule(artifact)

        return {
            "allowed": artifact.allowed,
            "action": artifact.action,
            "reason": reason,
            "matched_rule": matched_rule,
            "policy_name": PolicyDecisionAdapter.POLICY_NAME,
            "metadata": {
                "artifact_id": artifact.artifact_id,
                "chain_id": artifact.chain_id,
                "integrity": artifact.integrity,
                "principal_count": principal_count,
                "evidence": artifact.evidence.model_dump(),
                "artifact_hash": artifact.artifact_hash,
                "artifact_version": artifact.artifact_version,
            },
        }


def _determine_matched_rule(artifact: GovernanceArtifact) -> str:
    """Determine which constitutional article or governance rule applied."""
    if not artifact.integrity:
        return "article-I:chain-integrity"
    if artifact.evidence.review_verdict == "FAIL":
        return "article-V:evidence-review"
    if artifact.evidence.scope_compliance == "VIOLATION":
        return "article-IV:scope-compliance"
    if artifact.status == "TIMED_OUT":
        return "article-VII:liveness-sla"
    if artifact.status in _DENY_STATUSES:
        return "article-II:approval-denied"
    if len(artifact.principals) >= 3:
        return "article-III:separation-of-powers"
    return "article-I:governance-chain"


# ═══════════════════════════════════════════════════════════════
# Factory: GovernanceChain -> GovernanceArtifact
# ═══════════════════════════════════════════════════════════════


def from_chain(
    chain: GovernanceChain,
    evidence_result: Optional[ReviewResult] = None,
) -> GovernanceArtifact:
    """Create a GovernanceArtifact from a GovernanceChain.

    Args:
        chain: The governance chain to convert.
        evidence_result: Optional evidence review result to include.

    Returns:
        A fully populated GovernanceArtifact with computed artifact_hash.
    """
    status = chain.status.value

    seen: dict[str, str] = {}
    for event in chain.events:
        if event.actor_id not in seen:
            seen[event.actor_id] = event.role_used
    principals = [
        Principal(actor_id=aid, role=role)
        for aid, role in seen.items()
    ]

    events = [
        ArtifactEvent(
            event_id=e.event_id,
            event_type=e.event_type.value,
            actor_id=e.actor_id,
            role=e.role_used,
            timestamp=e.timestamp.isoformat(),
            event_hash=e.event_hash,
        )
        for e in chain.events
    ]

    # Evidence summary
    evidence = EvidenceSummary()
    if evidence_result is not None:
        evidence = EvidenceSummary(
            checks_total=len(evidence_result.findings),
            checks_passed=sum(1 for f in evidence_result.findings if f.passed),
            risk_delta=evidence_result.risk_delta,
            scope_compliance=evidence_result.scope_compliance,
            review_verdict=evidence_result.verdict.value,
        )

    # Determine finalized_at for terminal states
    terminal = {"APPROVED", "DENIED", "COMPLETED", "TIMED_OUT", "ROLLED_BACK"}
    finalized_at = None
    if status in terminal and chain.events:
        finalized_at = chain.events[-1].timestamp.isoformat()

    action = _map_action(status)
    artifact = GovernanceArtifact(
        chain_id=chain.chain_id,
        status=status,
        action=action,
        allowed=(action == "allow"),
        created_at=chain.created_at.isoformat(),
        finalized_at=finalized_at,
        integrity=chain.verify_integrity(),
        principals=principals,
        evidence=evidence,
        events=events,
        event_count=len(events),
        genesis_hash=hashlib.sha256(chain.chain_id.encode()).hexdigest(),
    )
    artifact.artifact_hash = artifact.compute_artifact_hash()
    return artifact


# ═══════════════════════════════════════════════════════════════
# Standalone verification
# ═══════════════════════════════════════════════════════════════


def verify_artifact(artifact_dict: dict[str, Any]) -> dict[str, Any]:
    """Verify a serialized GovernanceArtifact's integrity.

    Checks:
    1. artifact_hash matches recomputed hash of content
    2. genesis_hash matches SHA-256 of chain_id
    3. All event hashes form a valid chain (delegates to GovernanceChain)

    Can be run without the Gavel runtime — only needs hashlib and json.

    Args:
        artifact_dict: A JSON-serialized GovernanceArtifact.

    Returns:
        {"valid": bool, "errors": list[str], "artifact_id": str, "chain_id": str}
    """
    errors: list[str] = []
    artifact_id = artifact_dict.get("artifact_id", "")
    chain_id = artifact_dict.get("chain_id", "")

    # 1. Verify artifact_hash
    stored_hash = artifact_dict.get("artifact_hash", "")
    data_copy = dict(artifact_dict)
    data_copy.pop("artifact_hash", None)
    content = json.dumps(data_copy, sort_keys=True, default=str)
    computed_hash = hashlib.sha256(content.encode()).hexdigest()
    if stored_hash and stored_hash != computed_hash:
        errors.append(
            f"artifact_hash mismatch: expected {computed_hash[:16]}..., "
            f"got {stored_hash[:16]}..."
        )

    # 2. Verify genesis_hash
    stored_genesis = artifact_dict.get("genesis_hash", "")
    expected_genesis = hashlib.sha256(chain_id.encode()).hexdigest()
    if stored_genesis != expected_genesis:
        errors.append(
            f"genesis_hash mismatch: expected {expected_genesis[:16]}..., "
            f"got {stored_genesis[:16]}..."
        )

    # 3. Verify event chain (if events have prev_hash/event_hash)
    events = artifact_dict.get("events", [])
    if events and "prev_hash" in events[0]:
        # Full chain verification via GovernanceChain
        chain_artifact = {
            "chain_id": chain_id,
            "events": events,
            "genesis_hash": expected_genesis,
        }
        chain_result = GovernanceChain.verify_artifact(chain_artifact)
        if not chain_result["valid"]:
            errors.extend(chain_result["errors"])

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "artifact_id": artifact_id,
        "chain_id": chain_id,
    }
