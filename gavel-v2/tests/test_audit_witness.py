"""Tests for gavel.audit_witness — external verification."""

from __future__ import annotations

import pytest

from gavel.witness import (
    AuditWitness,
    VerificationStatus,
    WitnessCommitment,
    WitnessReceipt,
    compute_merkle_root,
)


class TestMerkleRoot:
    def test_empty_list(self):
        root = compute_merkle_root([])
        assert len(root) == 64  # SHA-256 hex

    def test_single_element(self):
        root = compute_merkle_root(["abc123"])
        assert len(root) == 64

    def test_deterministic(self):
        hashes = ["aaa", "bbb", "ccc"]
        assert compute_merkle_root(hashes) == compute_merkle_root(hashes)

    def test_order_matters(self):
        assert compute_merkle_root(["a", "b"]) != compute_merkle_root(["b", "a"])

    def test_odd_number_of_elements(self):
        root = compute_merkle_root(["a", "b", "c"])
        assert len(root) == 64

    def test_power_of_two_elements(self):
        root = compute_merkle_root(["a", "b", "c", "d"])
        assert len(root) == 64


class TestAuditWitness:
    def test_create_commitment(self):
        witness = AuditWitness()
        hashes = ["h1", "h2", "h3"]
        commitment = witness.create_commitment("chain-1", hashes)
        assert commitment.chain_id == "chain-1"
        assert commitment.event_count == 3
        assert commitment.merkle_root
        assert commitment.latest_event_hash == "h3"

    def test_store_commitment_returns_receipt(self):
        witness = AuditWitness()
        commitment = witness.create_commitment("chain-1", ["h1"])
        receipt = witness.store_commitment(commitment)
        assert receipt.commitment_id == commitment.commitment_id
        assert receipt.witness_id == witness.witness_id
        assert receipt.receipt_hash

    def test_verify_valid_chain(self):
        witness = AuditWitness()
        hashes = ["h1", "h2", "h3"]
        commitment = witness.create_commitment("chain-1", hashes)
        witness.store_commitment(commitment)
        result = witness.verify_chain("chain-1", hashes)
        assert result.status == VerificationStatus.VERIFIED

    def test_verify_detects_tampered_event(self):
        witness = AuditWitness()
        hashes = ["h1", "h2", "h3"]
        commitment = witness.create_commitment("chain-1", hashes)
        witness.store_commitment(commitment)
        tampered = ["h1", "TAMPERED", "h3"]
        result = witness.verify_chain("chain-1", tampered)
        assert result.status == VerificationStatus.MERKLE_MISMATCH

    def test_verify_detects_missing_event(self):
        witness = AuditWitness()
        hashes = ["h1", "h2", "h3"]
        commitment = witness.create_commitment("chain-1", hashes)
        witness.store_commitment(commitment)
        result = witness.verify_chain("chain-1", ["h1", "h2"])
        assert result.status == VerificationStatus.EVENT_COUNT_MISMATCH

    def test_verify_detects_extra_event(self):
        witness = AuditWitness()
        hashes = ["h1", "h2"]
        commitment = witness.create_commitment("chain-1", hashes)
        witness.store_commitment(commitment)
        result = witness.verify_chain("chain-1", ["h1", "h2", "h3"])
        assert result.status == VerificationStatus.EVENT_COUNT_MISMATCH

    def test_verify_unknown_chain(self):
        witness = AuditWitness()
        result = witness.verify_chain("unknown", ["h1"])
        assert result.status == VerificationStatus.COMMITMENT_NOT_FOUND

    def test_multiple_commitments_for_chain(self):
        witness = AuditWitness()
        c1 = witness.create_commitment("chain-1", ["h1"])
        witness.store_commitment(c1)
        c2 = witness.create_commitment("chain-1", ["h1", "h2"])
        witness.store_commitment(c2)
        assert len(witness.get_chain_commitments("chain-1")) == 2
        # Latest commitment used by default
        result = witness.verify_chain("chain-1", ["h1", "h2"])
        assert result.status == VerificationStatus.VERIFIED

    def test_verify_specific_commitment(self):
        witness = AuditWitness()
        c1 = witness.create_commitment("chain-1", ["h1"])
        witness.store_commitment(c1)
        c2 = witness.create_commitment("chain-1", ["h1", "h2"])
        witness.store_commitment(c2)
        # Verify against first commitment
        result = witness.verify_chain("chain-1", ["h1"], commitment_id=c1.commitment_id)
        assert result.status == VerificationStatus.VERIFIED

    def test_commitment_count(self):
        witness = AuditWitness()
        assert witness.commitment_count == 0
        c = witness.create_commitment("c1", ["h"])
        witness.store_commitment(c)
        assert witness.commitment_count == 1

    def test_receipt_hash_deterministic(self):
        witness = AuditWitness()
        commitment = witness.create_commitment("c1", ["h1"])
        receipt = witness.store_commitment(commitment)
        h1 = receipt.receipt_hash
        # Recompute
        h2 = receipt.compute_receipt_hash(commitment)
        assert h1 == h2
