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
import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Protocol, runtime_checkable

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
