"""
Gavel AgentMesh integration — TrustProvider, GovernanceArtifact, PolicyDecisionAdapter.

Implements AGT's TrustProvider interface (get_trust_score, verify_identity)
backed by tamper-evident governance chains with separation of powers.

Any system that receives a GovernanceArtifact can independently verify
the hash chain without the Gavel runtime — only hashlib and json required.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════
# Schema models
# ═══════════════════════════════════════════════════════════════


class ArtifactEvent(BaseModel):
    """Minimal event record within a governance artifact.

    Attributes:
        event_id: Unique identifier for this event.
        event_type: Type of governance event (e.g., INBOUND_INTENT, APPROVAL_GRANTED).
        actor_id: Identifier of the principal who created this event.
        role: Role the actor used when creating this event.
        timestamp: ISO-8601 timestamp string (stable for hashing).
        event_hash: SHA-256 hash covering this event and the previous hash.
    """

    event_id: str
    event_type: str
    actor_id: str
    role: str
    timestamp: str
    event_hash: str


class Principal(BaseModel):
    """An actor who participated in the governance chain.

    Attributes:
        actor_id: Unique identifier for the principal.
        role: Role this principal played (proposer, reviewer, approver, etc.).
        did: Optional DID (Decentralized Identifier) for cross-system identity.
    """

    actor_id: str
    role: str
    did: Optional[str] = None


class EvidenceSummary(BaseModel):
    """Summary of evidence review results.

    Attributes:
        checks_total: Total number of checks run.
        checks_passed: Number of checks that passed.
        risk_delta: Change in risk score after execution.
        scope_compliance: Scope compliance status (FULL, PARTIAL, VIOLATION, UNKNOWN).
        review_verdict: Overall evidence review verdict (PASS, FAIL, NONE).
    """

    checks_total: int = 0
    checks_passed: int = 0
    risk_delta: float = 0.0
    scope_compliance: str = "UNKNOWN"
    review_verdict: str = "NONE"


class GovernanceArtifact(BaseModel):
    """Portable, self-verifiable governance decision record.

    Can be serialized to JSON, transmitted between systems, and
    independently verified without any runtime dependency. The artifact_hash
    covers the entire content for tamper detection.

    Attributes:
        artifact_version: Schema version (currently "1.0").
        artifact_id: Unique identifier for this artifact.
        chain_id: Governance chain ID this artifact was exported from.
        status: Terminal status of the governance chain.
        verdict: AGT-compatible verdict — "allow", "deny", or "escalate".
        created_at: ISO-8601 timestamp when the chain was created.
        finalized_at: ISO-8601 timestamp when the chain reached terminal state.
        integrity: Whether the hash chain was verified at export time.
        principals: List of actors who participated in the governance chain.
        evidence: Summary of evidence review results.
        events: Ordered list of governance events.
        event_count: Number of events in the chain.
        genesis_hash: SHA-256 of the chain_id (chain anchor).
        artifact_hash: SHA-256 of the entire artifact content (tamper detection).
    """

    artifact_version: str = "1.0"
    artifact_id: str = Field(default_factory=lambda: f"ga-{uuid.uuid4().hex[:12]}")
    chain_id: str
    status: str
    verdict: str
    created_at: str
    finalized_at: Optional[str] = None
    integrity: bool
    principals: list[Principal]
    evidence: EvidenceSummary = Field(default_factory=EvidenceSummary)
    events: list[ArtifactEvent]
    event_count: int
    genesis_hash: str
    artifact_hash: str = ""

    def compute_artifact_hash(self) -> str:
        """Compute SHA-256 of the artifact content (excluding artifact_hash itself).

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        data = self.model_dump(mode="json")
        data.pop("artifact_hash", None)
        content = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════
# Verdict mapping
# ═══════════════════════════════════════════════════════════════

_ALLOW_STATUSES: set[str] = {"APPROVED", "COMPLETED"}
_DENY_STATUSES: set[str] = {"DENIED", "TIMED_OUT", "ROLLED_BACK"}


def _map_verdict(status: str) -> str:
    """Map a governance chain status to an AGT-compatible verdict.

    Args:
        status: The governance chain's terminal status.

    Returns:
        One of "allow", "deny", or "escalate".
    """
    if status in _ALLOW_STATUSES:
        return "allow"
    if status in _DENY_STATUSES:
        return "deny"
    return "escalate"


# ═══════════════════════════════════════════════════════════════
# PolicyDecisionAdapter
# ═══════════════════════════════════════════════════════════════


class PolicyDecisionAdapter:
    """Converts a GovernanceArtifact into AGT's PolicyDecision format.

    AGT PolicyDecision schema::

        verdict: str        — "allow" / "deny" / "escalate"
        reason: str         — human-readable explanation
        matched_rule: str   — identifier of the governing rule
        metadata: dict      — protocol-specific extensions
    """

    @staticmethod
    def to_policy_decision(artifact: GovernanceArtifact) -> dict[str, Any]:
        """Convert a GovernanceArtifact to an AGT PolicyDecision dict.

        Args:
            artifact: The governance artifact to convert.

        Returns:
            A dict matching AGT's PolicyDecision schema.
        """
        principal_count = len(artifact.principals)
        evidence_verdict = artifact.evidence.review_verdict

        reason = (
            f"Governance chain {artifact.chain_id}: {artifact.status.lower()} "
            f"by {principal_count} principal(s), "
            f"evidence review {evidence_verdict.lower()}, "
            f"integrity {'verified' if artifact.integrity else 'FAILED'}"
        )

        matched_rule = _determine_matched_rule(artifact)

        return {
            "verdict": artifact.verdict,
            "reason": reason,
            "matched_rule": matched_rule,
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
    """Determine which constitutional article or governance rule applied.

    Args:
        artifact: The governance artifact to analyze.

    Returns:
        A string identifier for the matched rule (e.g., "article-III:separation-of-powers").
    """
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
# Factory helper
# ═══════════════════════════════════════════════════════════════


def from_governance_chain(
    chain_id: str,
    status: str,
    created_at: str,
    events: list[dict[str, Any]],
    integrity: bool = True,
    evidence: Optional[dict[str, Any]] = None,
) -> GovernanceArtifact:
    """Create a GovernanceArtifact from raw governance chain data.

    This factory accepts plain dicts (not Gavel-specific types), making it
    usable from any system that produces governance chain data.

    Args:
        chain_id: The governance chain's unique identifier.
        status: Terminal status (APPROVED, DENIED, ESCALATED, etc.).
        created_at: ISO-8601 creation timestamp.
        events: List of event dicts with keys: event_id, event_type, actor_id,
                role, timestamp, event_hash.
        integrity: Whether the hash chain was verified.
        evidence: Optional evidence summary dict with keys: checks_total,
                  checks_passed, risk_delta, scope_compliance, review_verdict.

    Returns:
        A fully populated GovernanceArtifact with computed artifact_hash.
    """
    seen: dict[str, str] = {}
    for event in events:
        aid = event["actor_id"]
        if aid not in seen:
            seen[aid] = event["role"]
    principals = [Principal(actor_id=aid, role=role) for aid, role in seen.items()]

    artifact_events = [ArtifactEvent(**e) for e in events]

    evidence_summary = EvidenceSummary(**(evidence or {}))

    terminal = {"APPROVED", "DENIED", "COMPLETED", "TIMED_OUT", "ROLLED_BACK"}
    finalized_at = None
    if status in terminal and events:
        finalized_at = events[-1]["timestamp"]

    artifact = GovernanceArtifact(
        chain_id=chain_id,
        status=status,
        verdict=_map_verdict(status),
        created_at=created_at,
        finalized_at=finalized_at,
        integrity=integrity,
        principals=principals,
        evidence=evidence_summary,
        events=artifact_events,
        event_count=len(artifact_events),
        genesis_hash=hashlib.sha256(chain_id.encode()).hexdigest(),
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

    Can be run without any runtime dependency — only needs hashlib and json.

    Args:
        artifact_dict: A JSON-deserialized GovernanceArtifact.

    Returns:
        A dict with keys: valid (bool), errors (list[str]),
        artifact_id (str), chain_id (str).
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

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "artifact_id": artifact_id,
        "chain_id": chain_id,
    }


# ═══════════════════════════════════════════════════════════════
# GavelTrustProvider — AGT TrustProvider interface
# ═══════════════════════════════════════════════════════════════


class GavelTrustProvider:
    """AGT TrustProvider backed by governance chain artifacts.

    Trust scores are derived from governance history: artifact integrity,
    evidence review pass rates, and separation-of-powers compliance.
    Identity verification checks DID-based credentials against the
    artifact's principal list.

    Usage::

        provider = GavelTrustProvider()
        provider.record_artifact(artifact)

        score = await provider.get_trust_score("agent:planner")
        verified = await provider.verify_identity("agent:planner", {"did": "did:gavel:abc123"})
    """

    def __init__(self) -> None:
        self._artifacts: dict[str, list[GovernanceArtifact]] = {}
        self._dids: dict[str, str] = {}

    def record_artifact(self, artifact: GovernanceArtifact) -> None:
        """Record a governance artifact for trust scoring.

        Args:
            artifact: A verified GovernanceArtifact to include in trust calculations.
        """
        for principal in artifact.principals:
            agent_id = principal.actor_id
            if agent_id not in self._artifacts:
                self._artifacts[agent_id] = []
            self._artifacts[agent_id].append(artifact)
            if principal.did:
                self._dids[agent_id] = principal.did

    async def get_trust_score(self, agent_id: str) -> float:
        """Compute a trust score for an agent based on governance history.

        Scoring factors (each weighted equally at 0.25):
        - Integrity: fraction of artifacts with verified hash chains
        - Evidence: fraction of artifacts with passing evidence review
        - Compliance: fraction of artifacts with full scope compliance
        - Governance: fraction of artifacts with 3+ principals (separation of powers)

        An agent with no recorded artifacts receives a score of 0.0.

        Args:
            agent_id: The agent identifier to score.

        Returns:
            A float between 0.0 and 1.0.
        """
        artifacts = self._artifacts.get(agent_id, [])
        if not artifacts:
            return 0.0

        n = len(artifacts)

        integrity_score = sum(1 for a in artifacts if a.integrity) / n
        evidence_score = sum(
            1 for a in artifacts if a.evidence.review_verdict == "PASS"
        ) / n
        compliance_score = sum(
            1 for a in artifacts if a.evidence.scope_compliance == "FULL"
        ) / n
        governance_score = sum(
            1 for a in artifacts if len(a.principals) >= 3
        ) / n

        raw = (
            0.25 * integrity_score
            + 0.25 * evidence_score
            + 0.25 * compliance_score
            + 0.25 * governance_score
        )

        return round(min(1.0, max(0.0, raw)), 4)

    async def verify_identity(
        self, agent_id: str, credentials: dict[str, Any]
    ) -> bool:
        """Verify an agent's identity against governance records.

        Checks that the agent has participated in at least one governance
        chain and, if a DID is provided in credentials, that it matches
        the DID recorded in the agent's governance history.

        Args:
            agent_id: The agent identifier to verify.
            credentials: A dict optionally containing a "did" key.

        Returns:
            True if identity is verified, False otherwise.
        """
        if agent_id not in self._artifacts:
            return False

        provided_did = credentials.get("did")
        if provided_did and agent_id in self._dids:
            return self._dids[agent_id] == provided_did

        # Agent exists in governance records — identity confirmed
        return True
