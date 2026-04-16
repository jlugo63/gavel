"""Tests for input validation at Ed25519 crypto boundaries."""

from __future__ import annotations

import pytest

from gavel.crypto import (
    Ed25519KeyPair,
    PrincipalIdentity,
    _CRYPTO_BACKEND,
    _validate_bytes,
    _validate_hex,
)
from gavel.identity import IdentityRegistry, MutualVerifier


pytestmark = pytest.mark.skipif(
    _CRYPTO_BACKEND == "stub",
    reason="Ed25519 backend required (install 'cryptography' or 'PyNaCl')",
)


# ── _validate_hex ──────────────────────────────────────────


class TestValidateHex:
    def test_valid_hex_returns_bytes(self):
        result = _validate_hex("ab" * 32, 32, "key")
        assert result == b"\xab" * 32

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="must be 64 hex chars"):
            _validate_hex("ab" * 30, 32, "key")

    def test_non_hex_chars_raise(self):
        with pytest.raises(ValueError, match="invalid hex characters"):
            _validate_hex("zz" * 32, 32, "key")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="must be 64 hex chars"):
            _validate_hex("", 32, "key")

    def test_odd_length_raises(self):
        with pytest.raises(ValueError, match="must be 64 hex chars"):
            _validate_hex("a" * 63, 32, "key")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="must be a hex string"):
            _validate_hex(b"ab" * 32, 32, "key")

    def test_uppercase_hex_accepted(self):
        result = _validate_hex("AB" * 32, 32, "key")
        assert result == b"\xab" * 32


# ── _validate_bytes ────────────────────────────────────────


class TestValidateBytes:
    def test_valid_bytes_pass(self):
        result = _validate_bytes(b"\x01" * 32, 32, "key")
        assert result == b"\x01" * 32

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError, match="must be 32 bytes"):
            _validate_bytes(b"\x01" * 30, 32, "key")

    def test_non_bytes_raises(self):
        with pytest.raises(ValueError, match="must be bytes"):
            _validate_bytes("ab" * 32, 32, "key")


# ── Ed25519KeyPair construction ────────────────────────────


class TestKeyPairConstruction:
    def test_generate_is_valid(self):
        kp = Ed25519KeyPair.generate()
        assert len(kp.private_key_bytes) == 32
        assert len(kp.public_key_bytes) == 32

    def test_short_private_key_rejected(self):
        with pytest.raises(ValueError, match="private key must be 32 bytes"):
            Ed25519KeyPair(private_key_bytes=b"\x00" * 30, public_key_bytes=b"\x00" * 32)

    def test_short_public_key_rejected(self):
        with pytest.raises(ValueError, match="public key must be 32 bytes"):
            Ed25519KeyPair(private_key_bytes=b"\x00" * 32, public_key_bytes=b"\x00" * 16)


# ── Ed25519KeyPair.verify ──────────────────────────────────


class TestVerifyValidation:
    def test_short_public_key_raises(self):
        with pytest.raises(ValueError, match="public key must be 32 bytes"):
            Ed25519KeyPair.verify(b"\x00" * 16, b"msg", b"\x00" * 64)

    def test_short_signature_raises(self):
        with pytest.raises(ValueError, match="signature must be 64 bytes"):
            Ed25519KeyPair.verify(b"\x00" * 32, b"msg", b"\x00" * 32)

    def test_non_bytes_message_raises(self):
        with pytest.raises(ValueError, match="message must be bytes"):
            Ed25519KeyPair.verify(b"\x00" * 32, "not bytes", b"\x00" * 64)

    def test_valid_inputs_happy_path(self):
        kp = Ed25519KeyPair.generate()
        sig = kp.sign(b"hello")
        assert Ed25519KeyPair.verify(kp.public_key_bytes, b"hello", sig) is True


# ── PrincipalIdentity.verify_event ─────────────────────────


class TestVerifyEventValidation:
    def test_bad_hex_sig_raises(self):
        kp = Ed25519KeyPair.generate()
        p = PrincipalIdentity(agent_id="a", key_pair=kp)
        with pytest.raises(ValueError, match="invalid hex characters"):
            p.verify_event("event_hash", "zz" * 64)

    def test_wrong_length_sig_raises(self):
        kp = Ed25519KeyPair.generate()
        p = PrincipalIdentity(agent_id="a", key_pair=kp)
        with pytest.raises(ValueError, match="must be 128 hex chars"):
            p.verify_event("event_hash", "ab" * 30)

    def test_valid_sign_verify_roundtrip(self):
        kp = Ed25519KeyPair.generate()
        p = PrincipalIdentity(agent_id="a", key_pair=kp)
        sig_hex = p.sign_event("some_hash")
        assert p.verify_event("some_hash", sig_hex) is True


# ── IdentityRegistry.register ──────────────────────────────


class TestRegistryValidation:
    def test_short_pubkey_rejected(self):
        registry = IdentityRegistry()
        with pytest.raises(ValueError, match="public key must be 32 bytes"):
            registry.register("did:gavel:x", b"\x00" * 16)

    def test_non_bytes_pubkey_rejected(self):
        registry = IdentityRegistry()
        with pytest.raises(ValueError, match="public key must be bytes"):
            registry.register("did:gavel:x", "deadbeef")

    def test_valid_pubkey_accepted(self):
        registry = IdentityRegistry()
        kp = Ed25519KeyPair.generate()
        registry.register("did:gavel:x", kp.public_key_bytes)
        assert registry.is_registered("did:gavel:x")


# ── MutualVerifier.respond_to_challenge ────────────────────


class TestRespondValidation:
    def test_short_private_key_rejected(self):
        registry = IdentityRegistry()
        kp = Ed25519KeyPair.generate()
        registry.register("did:gavel:a", kp.public_key_bytes)
        verifier = MutualVerifier(registry)
        challenge = verifier.create_challenge("did:gavel:a", "did:gavel:b")
        with pytest.raises(ValueError, match="private key must be 32 bytes"):
            verifier.respond_to_challenge(challenge, b"\x00" * 16)
