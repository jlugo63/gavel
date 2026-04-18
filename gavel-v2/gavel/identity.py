"""
Mutual Agent Identity Verification — ATF I-3

Implements challenge-response mutual verification between agents using
Ed25519 signatures. Each agent proves its identity by signing a
cryptographic challenge, and both sides verify each other before
establishing trust.

Security properties:
  - Nonces are cryptographically random (secrets module)
  - Challenges expire after 30 seconds (replay prevention)
  - Each challenge can only be used once (one-time use tracking)
  - Signatures cover both challenge_id and nonce
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, Field

from gavel.crypto import Ed25519KeyPair, _validate_bytes, _validate_hex


# ── Models ────────────────────────────────────────────────────


class IdentityChallenge(BaseModel):
    """A challenge issued by one agent to another for identity verification."""

    challenge_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    challenger_did: str
    target_did: str
    nonce: str = Field(default_factory=lambda: secrets.token_hex(32))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(seconds=30)
    )


class IdentityResponse(BaseModel):
    """A signed response to an identity challenge."""

    challenge_id: str
    responder_did: str
    nonce: str
    signature: str  # hex-encoded Ed25519 signature over challenge_id + nonce


class IdentityVerificationResult(BaseModel):
    """The outcome of verifying an identity response."""

    verified: bool
    challenger_did: str
    responder_did: str
    reason: str  # e.g. "signature_valid", "signature_invalid", "challenge_expired", "nonce_mismatch"
    verified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

# Backward-compatible alias
VerificationResult = IdentityVerificationResult


# ── Identity Registry ────────────────────────────────────────


class IdentityRegistry:
    """Maps DIDs to Ed25519 public keys for verification lookups."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}  # did -> public_key_bytes

    def register(self, did: str, public_key: bytes) -> None:
        """Store a DID -> public key mapping."""
        self._keys[did] = _validate_bytes(public_key, 32, "Ed25519 public key")

    def get_public_key(self, did: str) -> Optional[bytes]:
        """Look up public key by DID."""
        return self._keys.get(did)

    def is_registered(self, did: str) -> bool:
        """Check if a DID exists in the registry."""
        return did in self._keys

    def unregister(self, did: str) -> None:
        """Remove a DID from the registry."""
        self._keys.pop(did, None)


# ── Mutual Verifier ──────────────────────────────────────────


def _sign_message(challenge_id: str, nonce: str) -> bytes:
    """Build the canonical message bytes that get signed/verified."""
    return (challenge_id + nonce).encode("utf-8")


class MutualVerifier:
    """Challenge-response mutual identity verification between agents.

    Usage:
        registry = IdentityRegistry()
        registry.register(did_a, pub_a)
        registry.register(did_b, pub_b)
        verifier = MutualVerifier(registry)

        # A challenges B
        challenge = verifier.create_challenge(did_a, did_b)
        response = verifier.respond_to_challenge(challenge, private_key_b)
        result = verifier.verify_response(challenge, response)

        # Full mutual verification
        result_a, result_b = verifier.mutual_verify(did_a, key_a, did_b, key_b)
    """

    def __init__(self, registry: IdentityRegistry) -> None:
        self._registry = registry
        self._used_challenges: set[str] = set()

    def create_challenge(
        self, challenger_did: str, target_did: str
    ) -> IdentityChallenge:
        """Generate a challenge with a random nonce."""
        return IdentityChallenge(
            challenger_did=challenger_did,
            target_did=target_did,
        )

    def respond_to_challenge(
        self, challenge: IdentityChallenge, private_key: bytes
    ) -> IdentityResponse:
        """Sign the challenge using the responder's private key.

        Args:
            challenge: The identity challenge to respond to.
            private_key: 32-byte Ed25519 private key (seed) of the responder.

        Returns:
            A signed IdentityResponse.
        """
        private_key = _validate_bytes(private_key, 32, "Ed25519 private key")
        # Derive the real public key from the private key seed
        from gavel.crypto import _CRYPTO_BACKEND
        if _CRYPTO_BACKEND == "cryptography":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            _priv = Ed25519PrivateKey.from_private_bytes(private_key)
            public_key = _priv.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        elif _CRYPTO_BACKEND == "nacl":
            import nacl.signing
            public_key = bytes(nacl.signing.SigningKey(private_key).verify_key)
        else:
            import hashlib as _hl
            public_key = _hl.sha256(private_key).digest()

        key_pair = Ed25519KeyPair(
            private_key_bytes=private_key,
            public_key_bytes=public_key,
        )
        message = _sign_message(challenge.challenge_id, challenge.nonce)
        signature = key_pair.sign(message)

        return IdentityResponse(
            challenge_id=challenge.challenge_id,
            responder_did=challenge.target_did,
            nonce=challenge.nonce,
            signature=signature.hex(),
        )

    def verify_response(
        self, challenge: IdentityChallenge, response: IdentityResponse
    ) -> VerificationResult:
        """Verify a signed response against the registry's public key.

        Checks (in order):
          1. Challenge not already used (replay prevention)
          2. Challenge not expired
          3. Nonce matches
          4. Responder DID is registered
          5. Ed25519 signature is valid
        """
        challenger_did = challenge.challenger_did
        responder_did = response.responder_did

        # Replay prevention — each challenge can only be used once
        if challenge.challenge_id in self._used_challenges:
            return VerificationResult(
                verified=False,
                challenger_did=challenger_did,
                responder_did=responder_did,
                reason="challenge_already_used",
            )

        # Mark as used immediately
        self._used_challenges.add(challenge.challenge_id)

        # Expiry check
        if datetime.now(timezone.utc) > challenge.expires_at:
            return VerificationResult(
                verified=False,
                challenger_did=challenger_did,
                responder_did=responder_did,
                reason="challenge_expired",
            )

        # Nonce match
        if not hmac.compare_digest(response.nonce, challenge.nonce):
            return VerificationResult(
                verified=False,
                challenger_did=challenger_did,
                responder_did=responder_did,
                reason="nonce_mismatch",
            )

        # Lookup public key
        public_key = self._registry.get_public_key(responder_did)
        if public_key is None:
            return VerificationResult(
                verified=False,
                challenger_did=challenger_did,
                responder_did=responder_did,
                reason="unregistered_did",
            )

        # Verify signature
        message = _sign_message(challenge.challenge_id, challenge.nonce)
        try:
            signature_bytes = _validate_hex(response.signature, 64, "Ed25519 signature")
        except ValueError:
            return VerificationResult(
                verified=False,
                challenger_did=challenger_did,
                responder_did=responder_did,
                reason="signature_invalid",
            )

        valid = Ed25519KeyPair.verify(public_key, message, signature_bytes)
        return VerificationResult(
            verified=valid,
            challenger_did=challenger_did,
            responder_did=responder_did,
            reason="signature_valid" if valid else "signature_invalid",
        )

    def mutual_verify(
        self,
        did_a: str,
        key_a: bytes,
        did_b: str,
        key_b: bytes,
    ) -> tuple[VerificationResult, VerificationResult]:
        """Full mutual verification: A challenges B, then B challenges A.

        Args:
            did_a: DID of agent A.
            key_a: 32-byte Ed25519 private key (seed) of agent A.
            did_b: DID of agent B.
            key_b: 32-byte Ed25519 private key (seed) of agent B.

        Returns:
            Tuple of (result_a_verifies_b, result_b_verifies_a).
        """
        # A challenges B
        challenge_ab = self.create_challenge(did_a, did_b)
        response_ab = self.respond_to_challenge(challenge_ab, key_b)
        result_ab = self.verify_response(challenge_ab, response_ab)

        # B challenges A
        challenge_ba = self.create_challenge(did_b, did_a)
        response_ba = self.respond_to_challenge(challenge_ba, key_a)
        result_ba = self.verify_response(challenge_ba, response_ba)

        return result_ab, result_ba
