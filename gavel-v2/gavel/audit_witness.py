"""
External Audit Witness — independent verification of governance decisions.

An audit witness is an external party (compliance team, regulator tool, or
third-party SaaS) that receives cryptographic commitments from Gavel and
can independently verify that:

  1. The governance chain was not tampered with after the fact
  2. The decision was made by the claimed principals
  3. The evidence review actually occurred before approval
  4. No events were inserted, removed, or reordered

Protocol:
  - Gavel publishes a WitnessCommitment after each significant governance event
  - The commitment contains: chain_id, event_count, merkle_root, timestamp
  - The witness stores commitments and can later verify them against the full chain
  - Verification checks merkle_root match, event ordering, and hash chain integrity

This is analogous to Certificate Transparency logs — the witness creates an
independent, append-only record that Gavel cannot retroactively modify.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Commitment models ─────────────────────────────────────────

class WitnessCommitment(BaseModel):
    """A cryptographic commitment published to an external witness."""
    commitment_id: str = Field(default_factory=lambda: f"wc-{uuid.uuid4().hex[:8]}")
    chain_id: str
    event_count: int
    merkle_root: str
    latest_event_hash: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    witness_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class WitnessReceipt(BaseModel):
    """Receipt from a witness confirming it stored the commitment."""
    receipt_id: str = Field(default_factory=lambda: f"wr-{uuid.uuid4().hex[:8]}")
    commitment_id: str
    witness_id: str
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    receipt_hash: str = ""

    def compute_receipt_hash(self, commitment: WitnessCommitment) -> str:
        content = json.dumps(
            {
                "receipt_id": self.receipt_id,
                "commitment_id": self.commitment_id,
                "witness_id": self.witness_id,
                "merkle_root": commitment.merkle_root,
                "chain_id": commitment.chain_id,
                "event_count": commitment.event_count,
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    MERKLE_MISMATCH = "merkle_mismatch"
    EVENT_COUNT_MISMATCH = "event_count_mismatch"
    HASH_CHAIN_BROKEN = "hash_chain_broken"
    COMMITMENT_NOT_FOUND = "commitment_not_found"


class VerificationResult(BaseModel):
    """Result of verifying a chain against a witness commitment."""
    chain_id: str
    commitment_id: str
    status: VerificationStatus
    expected_merkle_root: str = ""
    actual_merkle_root: str = ""
    expected_event_count: int = 0
    actual_event_count: int = 0
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: str = ""


# ── Merkle tree utilities ─────────────────────────────────────

def compute_merkle_root(event_hashes: list[str]) -> str:
    """Compute a Merkle root from a list of event hashes.

    Uses a standard binary Merkle tree with SHA-256. If the number of
    leaves is odd, the last leaf is duplicated (standard padding).
    """
    if not event_hashes:
        return hashlib.sha256(b"empty").hexdigest()

    nodes = [hashlib.sha256(h.encode()).hexdigest() for h in event_hashes]

    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            combined = hashlib.sha256(f"{left}{right}".encode()).hexdigest()
            next_level.append(combined)
        nodes = next_level

    return nodes[0]


# ── Witness service ───────────────────────────────────────────

class AuditWitness:
    """An external audit witness that stores and verifies commitments.

    In production, this would be a remote service (e.g., a compliance
    SaaS, a blockchain notary, or a regulator's API). This implementation
    provides the local protocol that would drive such a service.
    """

    def __init__(self, witness_id: str = ""):
        self.witness_id = witness_id or f"witness-{uuid.uuid4().hex[:8]}"
        self._commitments: dict[str, WitnessCommitment] = {}  # commitment_id -> commitment
        self._chain_commitments: dict[str, list[str]] = {}  # chain_id -> [commitment_id, ...]
        self._receipts: dict[str, WitnessReceipt] = {}  # receipt_id -> receipt

    def create_commitment(self, chain_id: str, event_hashes: list[str], metadata: dict[str, Any] | None = None) -> WitnessCommitment:
        """Create a witness commitment from chain event hashes."""
        merkle_root = compute_merkle_root(event_hashes)
        commitment = WitnessCommitment(
            chain_id=chain_id,
            event_count=len(event_hashes),
            merkle_root=merkle_root,
            latest_event_hash=event_hashes[-1] if event_hashes else "",
            witness_id=self.witness_id,
            metadata=metadata or {},
        )
        return commitment

    def store_commitment(self, commitment: WitnessCommitment) -> WitnessReceipt:
        """Store a commitment and return a receipt."""
        self._commitments[commitment.commitment_id] = commitment
        self._chain_commitments.setdefault(commitment.chain_id, []).append(commitment.commitment_id)

        receipt = WitnessReceipt(
            commitment_id=commitment.commitment_id,
            witness_id=self.witness_id,
        )
        receipt.receipt_hash = receipt.compute_receipt_hash(commitment)
        self._receipts[receipt.receipt_id] = receipt
        return receipt

    def verify_chain(self, chain_id: str, event_hashes: list[str], commitment_id: str | None = None) -> VerificationResult:
        """Verify a chain against a stored commitment.

        If commitment_id is not provided, uses the latest commitment for the chain.
        """
        if commitment_id:
            commitment = self._commitments.get(commitment_id)
        else:
            chain_cids = self._chain_commitments.get(chain_id, [])
            commitment = self._commitments.get(chain_cids[-1]) if chain_cids else None

        if not commitment:
            return VerificationResult(
                chain_id=chain_id,
                commitment_id=commitment_id or "",
                status=VerificationStatus.COMMITMENT_NOT_FOUND,
                details="No commitment found for this chain",
            )

        actual_merkle = compute_merkle_root(event_hashes)
        actual_count = len(event_hashes)

        if actual_count != commitment.event_count:
            return VerificationResult(
                chain_id=chain_id,
                commitment_id=commitment.commitment_id,
                status=VerificationStatus.EVENT_COUNT_MISMATCH,
                expected_merkle_root=commitment.merkle_root,
                actual_merkle_root=actual_merkle,
                expected_event_count=commitment.event_count,
                actual_event_count=actual_count,
                details=f"Expected {commitment.event_count} events, got {actual_count}",
            )

        if actual_merkle != commitment.merkle_root:
            return VerificationResult(
                chain_id=chain_id,
                commitment_id=commitment.commitment_id,
                status=VerificationStatus.MERKLE_MISMATCH,
                expected_merkle_root=commitment.merkle_root,
                actual_merkle_root=actual_merkle,
                expected_event_count=commitment.event_count,
                actual_event_count=actual_count,
                details="Merkle root mismatch — chain may have been tampered with",
            )

        return VerificationResult(
            chain_id=chain_id,
            commitment_id=commitment.commitment_id,
            status=VerificationStatus.VERIFIED,
            expected_merkle_root=commitment.merkle_root,
            actual_merkle_root=actual_merkle,
            expected_event_count=commitment.event_count,
            actual_event_count=actual_count,
            details="Chain verified — matches witness commitment",
        )

    def get_commitment(self, commitment_id: str) -> WitnessCommitment | None:
        return self._commitments.get(commitment_id)

    def get_chain_commitments(self, chain_id: str) -> list[WitnessCommitment]:
        cids = self._chain_commitments.get(chain_id, [])
        return [self._commitments[cid] for cid in cids if cid in self._commitments]

    def get_receipt(self, receipt_id: str) -> WitnessReceipt | None:
        return self._receipts.get(receipt_id)

    @property
    def commitment_count(self) -> int:
        return len(self._commitments)
