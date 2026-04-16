"""
External audit witness — Phase 8.

Gavel's governance chain is tamper-evident internally (every event is
linked by SHA-256 to its predecessor, and the genesis hash is pinned
at startup). But internal tamper-evidence only proves that *the chain
is consistent with itself*. An external auditor wants a stronger
guarantee: that the chain we show them today is the same chain we
said existed yesterday.

This module implements a *checkpoint witness* pattern:

  1. Periodically, Gavel computes a `ChainCheckpoint` — (height,
     tip_hash, genesis_hash, taken_at) — and publishes it to one or
     more external witnesses.
  2. A witness is any party that can countersign a checkpoint and
     archive it durably: an external service, a git repo, an email
     archive, a legal time-stamping authority, a sibling Gavel
     instance in another trust domain.
  3. Later, an auditor collects checkpoints from those witnesses and
     calls `verify_against_witnesses()` with the current chain state.
     If the chain still contains every witnessed tip at the expected
     height, the chain is *externally consistent*. If any witnessed
     tip is no longer in the current chain, the verifier flags a
     `CheckpointDivergence` — proof that history was rewritten.

The witness interface is abstract — the concrete transport is the
deployer's choice (HTTP POST, git commit, IPFS CID, S3 object-lock).
This module provides:

  - `ChainCheckpoint` model
  - `WitnessEndorsement` model (countersigned checkpoint)
  - `Witness` protocol (abstract base) with an in-memory reference
    implementation `InMemoryWitness`
  - `CheckpointRegistry` for tracking submitted checkpoints
  - `verify_against_witnesses()` — divergence detector

Crypto notes: the "signature" in the in-memory witness is a
deterministic HMAC over the checkpoint tuple with a per-witness key.
Deployers using real witnesses should substitute Ed25519 or the
signing primitive their witness transport requires; the verification
flow is identical.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field


# ── Checkpoint + endorsement models ────────────────────────────

class ChainCheckpoint(BaseModel):
    """A point-in-time fingerprint of the governance chain."""

    chain_id: str                       # which chain (multichain-ready)
    height: int                         # number of events observed at checkpoint
    tip_hash: str                       # SHA-256 hex of the latest event
    genesis_hash: str                   # SHA-256 hex of the first event
    taken_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def canonical_bytes(self) -> bytes:
        """Deterministic encoding used for signing/hashing."""
        return (
            f"{self.chain_id}|{self.height}|{self.tip_hash}|"
            f"{self.genesis_hash}|{self.taken_at.isoformat()}"
        ).encode("utf-8")

    def fingerprint(self) -> str:
        """SHA-256 hex over canonical bytes — unique per checkpoint."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class WitnessEndorsement(BaseModel):
    """A witness's countersignature of one checkpoint."""

    witness_id: str
    checkpoint_fingerprint: str
    signature: str                      # hex-encoded MAC or asymmetric sig
    endorsed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckpointDivergenceKind(str, Enum):
    MISSING = "missing"                 # witnessed tip is not in the current chain
    HEIGHT_REGRESSION = "regression"    # chain is shorter than a previously witnessed height
    GENESIS_MISMATCH = "genesis"        # genesis hash changed — whole chain rewritten


class CheckpointDivergence(BaseModel):
    """A failed witness verification."""

    witness_id: str
    kind: CheckpointDivergenceKind
    witnessed: ChainCheckpoint
    current_height: int
    current_tip_hash: str
    current_genesis_hash: str
    detail: str = ""


# ── Witness protocol + reference impl ──────────────────────────

@runtime_checkable
class Witness(Protocol):
    """Abstract witness transport."""

    @property
    def witness_id(self) -> str: ...

    def endorse(self, checkpoint: ChainCheckpoint) -> WitnessEndorsement: ...

    def verify(self, endorsement: WitnessEndorsement) -> bool: ...


class InMemoryWitness:
    """Reference witness — HMAC-SHA256 with a per-instance key."""

    def __init__(self, witness_id: str, key: Optional[bytes] = None):
        self._witness_id = witness_id
        self._key = key or secrets.token_bytes(32)
        self._archive: dict[str, WitnessEndorsement] = {}

    @property
    def witness_id(self) -> str:
        return self._witness_id

    def endorse(self, checkpoint: ChainCheckpoint) -> WitnessEndorsement:
        mac = hmac.new(
            self._key,
            checkpoint.canonical_bytes(),
            hashlib.sha256,
        ).hexdigest()
        fp = checkpoint.fingerprint()
        endorsement = WitnessEndorsement(
            witness_id=self._witness_id,
            checkpoint_fingerprint=fp,
            signature=mac,
        )
        self._archive[fp] = endorsement
        return endorsement

    def verify(self, endorsement: WitnessEndorsement) -> bool:
        if endorsement.witness_id != self._witness_id:
            return False
        archived = self._archive.get(endorsement.checkpoint_fingerprint)
        return archived is not None and hmac.compare_digest(
            archived.signature, endorsement.signature
        )


# ── Registry ───────────────────────────────────────────────────

class CheckpointRegistry:
    """Track checkpoints and the witness endorsements we collected."""

    def __init__(self) -> None:
        self._checkpoints: list[ChainCheckpoint] = []
        self._endorsements: dict[str, list[WitnessEndorsement]] = {}
        self._witnesses: dict[str, Witness] = {}

    def register_witness(self, witness: Witness) -> None:
        self._witnesses[witness.witness_id] = witness

    def submit(self, checkpoint: ChainCheckpoint) -> list[WitnessEndorsement]:
        """Publish to every registered witness, collect endorsements."""
        self._checkpoints.append(checkpoint)
        fp = checkpoint.fingerprint()
        endorsements: list[WitnessEndorsement] = []
        for w in self._witnesses.values():
            endorsement = w.endorse(checkpoint)
            endorsements.append(endorsement)
        self._endorsements[fp] = endorsements
        return endorsements

    def checkpoints(self) -> list[ChainCheckpoint]:
        return list(self._checkpoints)

    def endorsements_for(self, fingerprint: str) -> list[WitnessEndorsement]:
        return list(self._endorsements.get(fingerprint, []))


# ── Divergence detection ───────────────────────────────────────

def verify_against_witnesses(
    *,
    current_height: int,
    current_tip_hash: str,
    current_genesis_hash: str,
    chain_history: list[str],
    registry: CheckpointRegistry,
) -> list[CheckpointDivergence]:
    """Return every divergence between witnessed checkpoints and the current chain.

    `chain_history` is the list of event hashes in order, index 0 being
    the genesis event. To prove a witnessed tip is still in the chain
    we just need to confirm (a) the genesis matches, (b) the chain is
    at least as long as the witnessed height, and (c) the event at
    index (witnessed.height - 1) matches the witnessed tip_hash.
    """
    divergences: list[CheckpointDivergence] = []
    for checkpoint in registry.checkpoints():
        # Genesis mismatch = total rewrite
        if checkpoint.genesis_hash != current_genesis_hash:
            divergences.append(CheckpointDivergence(
                witness_id="*",
                kind=CheckpointDivergenceKind.GENESIS_MISMATCH,
                witnessed=checkpoint,
                current_height=current_height,
                current_tip_hash=current_tip_hash,
                current_genesis_hash=current_genesis_hash,
                detail=(
                    f"genesis changed: {checkpoint.genesis_hash} → "
                    f"{current_genesis_hash}"
                ),
            ))
            continue

        # Regression = chain shorter than a known witnessed height
        if current_height < checkpoint.height:
            divergences.append(CheckpointDivergence(
                witness_id="*",
                kind=CheckpointDivergenceKind.HEIGHT_REGRESSION,
                witnessed=checkpoint,
                current_height=current_height,
                current_tip_hash=current_tip_hash,
                current_genesis_hash=current_genesis_hash,
                detail=(
                    f"current height {current_height} < witnessed "
                    f"{checkpoint.height}"
                ),
            ))
            continue

        # Missing tip = the witnessed event is not in the chain at its height
        idx = checkpoint.height - 1
        if idx >= len(chain_history) or chain_history[idx] != checkpoint.tip_hash:
            divergences.append(CheckpointDivergence(
                witness_id="*",
                kind=CheckpointDivergenceKind.MISSING,
                witnessed=checkpoint,
                current_height=current_height,
                current_tip_hash=current_tip_hash,
                current_genesis_hash=current_genesis_hash,
                detail=(
                    f"event at height {checkpoint.height} diverges from "
                    f"witnessed tip {checkpoint.tip_hash[:12]}..."
                ),
            ))

    return divergences


# ── Merkle-based audit witness ────────────────────────────────
#
# An alternative witnessing model based on Merkle tree commitments
# and receipts. Analogous to Certificate Transparency logs.

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
