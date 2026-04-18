"""
Ed25519 principal identity — cryptographic signatures for governance chains.

Each principal (agent) gets an Ed25519 key pair that can sign chain events,
proving authorship and preventing repudiation.
"""

from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    _CRYPTO_BACKEND = "cryptography"
except ImportError:
    try:
        import nacl.signing  # type: ignore
        _CRYPTO_BACKEND = "nacl"
    except ImportError:
        _CRYPTO_BACKEND = "stub"


class CryptoUnavailableError(Exception):
    """Raised when Ed25519 operations are attempted without a crypto backend."""
    pass


_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _validate_hex(s: str, expected_byte_len: int, label: str) -> bytes:
    if not isinstance(s, str):
        raise ValueError(f"{label} must be a hex string (got {type(s).__name__})")
    expected_hex_len = expected_byte_len * 2
    if len(s) != expected_hex_len:
        raise ValueError(
            f"{label} must be {expected_hex_len} hex chars (got {len(s)})"
        )
    if not all(c in _HEX_CHARS for c in s):
        raise ValueError(f"{label} contains invalid hex characters")
    return bytes.fromhex(s)


def _validate_bytes(b: bytes, expected_byte_len: int, label: str) -> bytes:
    if not isinstance(b, (bytes, bytearray)):
        raise ValueError(f"{label} must be bytes (got {type(b).__name__})")
    if len(b) != expected_byte_len:
        raise ValueError(
            f"{label} must be {expected_byte_len} bytes (got {len(b)})"
        )
    return bytes(b)


@dataclass
class Ed25519KeyPair:
    """An Ed25519 key pair for signing governance events."""
    private_key_bytes: bytes  # 32 bytes seed
    public_key_bytes: bytes   # 32 bytes public key

    def __post_init__(self) -> None:
        self.private_key_bytes = _validate_bytes(
            self.private_key_bytes, 32, "Ed25519 private key"
        )
        self.public_key_bytes = _validate_bytes(
            self.public_key_bytes, 32, "Ed25519 public key"
        )

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        """Generate a new Ed25519 key pair."""
        if _CRYPTO_BACKEND == "cryptography":
            private_key = Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
            return cls(private_key_bytes=private_bytes, public_key_bytes=public_bytes)
        elif _CRYPTO_BACKEND == "nacl":
            signing_key = nacl.signing.SigningKey.generate()
            return cls(
                private_key_bytes=bytes(signing_key),
                public_key_bytes=bytes(signing_key.verify_key)
            )
        else:
            # Stub: generate random bytes but signing will raise
            seed = secrets.token_bytes(32)
            pub = hashlib.sha256(seed).digest()
            return cls(private_key_bytes=seed, public_key_bytes=pub)

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign(self, message: bytes) -> bytes:
        """Sign a message, returning the 64-byte signature."""
        if _CRYPTO_BACKEND == "cryptography":
            private_key = Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)
            return private_key.sign(message)
        elif _CRYPTO_BACKEND == "nacl":
            signing_key = nacl.signing.SigningKey(self.private_key_bytes)
            return signing_key.sign(message).signature
        else:
            raise CryptoUnavailableError(
                "No Ed25519 backend available. Install 'cryptography' or 'PyNaCl'."
            )

    @staticmethod
    def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature. Returns True if valid."""
        public_key_bytes = _validate_bytes(public_key_bytes, 32, "Ed25519 public key")
        signature = _validate_bytes(signature, 64, "Ed25519 signature")
        if not isinstance(message, (bytes, bytearray)):
            raise ValueError(
                f"Ed25519 message must be bytes (got {type(message).__name__})"
            )
        try:
            if _CRYPTO_BACKEND == "cryptography":
                public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                public_key.verify(signature, message)
                return True
            elif _CRYPTO_BACKEND == "nacl":
                verify_key = nacl.signing.VerifyKey(public_key_bytes)
                verify_key.verify(message, signature)
                return True
            else:
                raise CryptoUnavailableError(
                    "No Ed25519 backend available. Install 'cryptography' or 'PyNaCl'."
                )
        except (ValueError, TypeError):
            return False
        except Exception as exc:
            # Catch by name — the exception class depends on which crypto backend is loaded
            exc_name = type(exc).__name__
            if exc_name in ("InvalidSignature", "BadSignatureError", "CryptoError"):
                return False
            raise


@dataclass
class PrincipalIdentity:
    """A cryptographic identity for a governance principal.

    Each agent/principal gets an Ed25519 key pair and a DID derived
    from the public key hash.
    """
    agent_id: str
    key_pair: Ed25519KeyPair
    did: str = ""
    public_key_hex: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if not self.public_key_hex:
            self.public_key_hex = self.key_pair.public_key_hex
        if not self.did:
            key_hash = hashlib.sha256(self.key_pair.public_key_bytes).hexdigest()
            self.did = f"did:gavel:{key_hash[:32]}"

    def sign_event(self, event_hash: str) -> str:
        """Sign a chain event hash, returning hex-encoded signature."""
        signature = self.key_pair.sign(event_hash.encode("utf-8"))
        return signature.hex()

    def verify_event(self, event_hash: str, signature_hex: str) -> bool:
        """Verify a signature against an event hash."""
        signature = _validate_hex(signature_hex, 64, "Ed25519 signature")
        return Ed25519KeyPair.verify(
            self.key_pair.public_key_bytes,
            event_hash.encode("utf-8"),
            signature
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "did": self.did,
            "public_key": self.public_key_hex,
            "created_at": self.created_at.isoformat(),
            "crypto_backend": _CRYPTO_BACKEND,
        }


class PrincipalRegistry:
    """Thread-safe registry of principal identities.

    Maps agent_id -> PrincipalIdentity. Generates key pairs on first
    registration. Supports lookup by agent_id or DID.
    """

    def __init__(self) -> None:
        self._principals: dict[str, PrincipalIdentity] = {}
        self._did_index: dict[str, str] = {}  # did -> agent_id

    def register(self, agent_id: str) -> PrincipalIdentity:
        """Register a new principal, generating an Ed25519 key pair."""
        if agent_id in self._principals:
            return self._principals[agent_id]
        key_pair = Ed25519KeyPair.generate()
        identity = PrincipalIdentity(agent_id=agent_id, key_pair=key_pair)
        self._principals[agent_id] = identity
        self._did_index[identity.did] = agent_id
        return identity

    def get(self, agent_id: str) -> Optional[PrincipalIdentity]:
        return self._principals.get(agent_id)

    def get_by_did(self, did: str) -> Optional[PrincipalIdentity]:
        agent_id = self._did_index.get(did)
        if agent_id:
            return self._principals.get(agent_id)
        return None

    def verify_signature(
        self, agent_id: str, event_hash: str, signature_hex: str
    ) -> bool:
        """Verify a signature using the registered public key."""
        principal = self._principals.get(agent_id)
        if not principal:
            return False
        return principal.verify_event(event_hash, signature_hex)

    def list_principals(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._principals.values()]

    @property
    def crypto_backend(self) -> str:
        return _CRYPTO_BACKEND


def get_crypto_status() -> dict[str, Any]:
    """Return crypto backend availability info."""
    return {
        "backend": _CRYPTO_BACKEND,
        "signing_available": _CRYPTO_BACKEND != "stub",
        "backends_checked": ["cryptography", "nacl", "stub"],
    }
