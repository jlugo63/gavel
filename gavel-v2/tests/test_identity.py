"""
Tests for Mutual Agent Identity Verification — ATF I-3.

Covers challenge-response lifecycle, signature verification,
expiry, replay prevention, and full mutual verification flow.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from gavel.crypto import Ed25519KeyPair, _CRYPTO_BACKEND
from gavel.identity import (
    IdentityChallenge,
    IdentityRegistry,
    IdentityResponse,
    MutualVerifier,
    VerificationResult,
)

# Skip entire module if no real crypto backend
pytestmark = pytest.mark.skipif(
    _CRYPTO_BACKEND == "stub",
    reason="Ed25519 backend required (install 'cryptography' or 'PyNaCl')",
)


# ── Helpers ───────────────────────────────────────────────────


def _make_identity() -> tuple[str, bytes, bytes]:
    """Generate a DID + key pair, return (did, private_key, public_key)."""
    kp = Ed25519KeyPair.generate()
    did = f"did:gavel:test:{kp.public_key_hex[:16]}"
    return did, kp.private_key_bytes, kp.public_key_bytes


def _setup_two_agents():
    """Create two agents registered in a shared registry + verifier."""
    did_a, priv_a, pub_a = _make_identity()
    did_b, priv_b, pub_b = _make_identity()
    registry = IdentityRegistry()
    registry.register(did_a, pub_a)
    registry.register(did_b, pub_b)
    verifier = MutualVerifier(registry)
    return verifier, registry, did_a, priv_a, pub_a, did_b, priv_b, pub_b


# ── Challenge Creation ───────────────────────────────────────


class TestChallengeCreation:
    def test_challenge_has_uuid(self):
        verifier, _, did_a, _, _, did_b, _, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        assert len(challenge.challenge_id) == 36  # UUID format

    def test_challenge_has_random_nonce(self):
        verifier, _, did_a, _, _, did_b, _, _ = _setup_two_agents()
        c1 = verifier.create_challenge(did_a, did_b)
        c2 = verifier.create_challenge(did_a, did_b)
        assert c1.nonce != c2.nonce
        assert len(c1.nonce) == 64  # 32 bytes in hex

    def test_challenge_expires_in_30_seconds(self):
        verifier, _, did_a, _, _, did_b, _, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        delta = challenge.expires_at - challenge.timestamp
        assert 29 <= delta.total_seconds() <= 31

    def test_challenge_dids_match(self):
        verifier, _, did_a, _, _, did_b, _, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        assert challenge.challenger_did == did_a
        assert challenge.target_did == did_b


# ── Valid Signature Verification ─────────────────────────────


class TestValidVerification:
    def test_valid_signature_passes(self):
        verifier, _, did_a, _, _, did_b, priv_b, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        response = verifier.respond_to_challenge(challenge, priv_b)
        result = verifier.verify_response(challenge, response)
        assert result.verified is True
        assert result.reason == "signature_valid"
        assert result.challenger_did == did_a
        assert result.responder_did == did_b

    def test_response_echoes_nonce(self):
        verifier, _, did_a, _, _, did_b, priv_b, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        response = verifier.respond_to_challenge(challenge, priv_b)
        assert response.nonce == challenge.nonce
        assert response.challenge_id == challenge.challenge_id


# ── Invalid Signature Rejection ──────────────────────────────


class TestInvalidSignature:
    def test_wrong_key_fails(self):
        verifier, _, did_a, priv_a, _, did_b, _, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        # Sign with A's key but claim to be B
        response = verifier.respond_to_challenge(challenge, priv_a)
        result = verifier.verify_response(challenge, response)
        assert result.verified is False
        assert result.reason == "signature_invalid"

    def test_tampered_signature_fails(self):
        verifier, _, did_a, _, _, did_b, priv_b, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        response = verifier.respond_to_challenge(challenge, priv_b)
        # Tamper with signature
        bad_sig = "ff" * 64
        response.signature = bad_sig
        result = verifier.verify_response(challenge, response)
        assert result.verified is False
        assert result.reason == "signature_invalid"


# ── Expired Challenge Rejection ──────────────────────────────


class TestExpiredChallenge:
    def test_expired_challenge_rejected(self):
        verifier, _, did_a, _, _, did_b, priv_b, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        # Force expiry into the past
        challenge.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        response = verifier.respond_to_challenge(challenge, priv_b)
        result = verifier.verify_response(challenge, response)
        assert result.verified is False
        assert result.reason == "challenge_expired"


# ── Nonce Mismatch Detection ────────────────────────────────


class TestNonceMismatch:
    def test_wrong_nonce_rejected(self):
        verifier, _, did_a, _, _, did_b, priv_b, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        response = verifier.respond_to_challenge(challenge, priv_b)
        # Tamper with the nonce in the response
        response.nonce = "deadbeef" * 8
        result = verifier.verify_response(challenge, response)
        assert result.verified is False
        assert result.reason == "nonce_mismatch"


# ── Replay Prevention ───────────────────────────────────────


class TestReplayPrevention:
    def test_same_challenge_rejected_on_reuse(self):
        verifier, _, did_a, _, _, did_b, priv_b, _ = _setup_two_agents()
        challenge = verifier.create_challenge(did_a, did_b)
        response = verifier.respond_to_challenge(challenge, priv_b)

        # First use succeeds
        result1 = verifier.verify_response(challenge, response)
        assert result1.verified is True

        # Second use of same challenge fails
        response2 = verifier.respond_to_challenge(challenge, priv_b)
        result2 = verifier.verify_response(challenge, response2)
        assert result2.verified is False
        assert result2.reason == "challenge_already_used"


# ── Full Mutual Verification ────────────────────────────────


class TestMutualVerification:
    def test_mutual_verify_both_pass(self):
        verifier, _, did_a, priv_a, _, did_b, priv_b, _ = _setup_two_agents()
        result_ab, result_ba = verifier.mutual_verify(
            did_a, priv_a, did_b, priv_b
        )
        assert result_ab.verified is True
        assert result_ab.challenger_did == did_a
        assert result_ab.responder_did == did_b
        assert result_ab.reason == "signature_valid"

        assert result_ba.verified is True
        assert result_ba.challenger_did == did_b
        assert result_ba.responder_did == did_a
        assert result_ba.reason == "signature_valid"


# ── Unregistered DID Rejection ──────────────────────────────


class TestUnregisteredDID:
    def test_unregistered_responder_rejected(self):
        did_a, priv_a, pub_a = _make_identity()
        did_unknown, priv_unknown, _ = _make_identity()
        registry = IdentityRegistry()
        registry.register(did_a, pub_a)
        # did_unknown is NOT registered
        verifier = MutualVerifier(registry)

        challenge = verifier.create_challenge(did_a, did_unknown)
        response = verifier.respond_to_challenge(challenge, priv_unknown)
        result = verifier.verify_response(challenge, response)
        assert result.verified is False
        assert result.reason == "unregistered_did"


# ── Identity Registry ───────────────────────────────────────


class TestIdentityRegistry:
    def test_register_and_lookup(self):
        registry = IdentityRegistry()
        kp = Ed25519KeyPair.generate()
        did = "did:gavel:test:abc"
        registry.register(did, kp.public_key_bytes)
        assert registry.is_registered(did) is True
        assert registry.get_public_key(did) == kp.public_key_bytes

    def test_unregister(self):
        registry = IdentityRegistry()
        did = "did:gavel:test:xyz"
        registry.register(did, b"\x00" * 32)
        assert registry.is_registered(did) is True
        registry.unregister(did)
        assert registry.is_registered(did) is False
        assert registry.get_public_key(did) is None

    def test_unknown_did(self):
        registry = IdentityRegistry()
        assert registry.is_registered("did:gavel:nonexistent") is False
        assert registry.get_public_key("did:gavel:nonexistent") is None
