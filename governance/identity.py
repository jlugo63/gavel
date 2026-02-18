"""
Identity Validation Module
Constitutional Reference: §I.2 — Authority Decoupling

Actor allowlist and validation for the governance control plane.
The identities.json file is protected by the §I.2 check in policy_engine.py
(governance/ path protection).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

@dataclass
class Identity:
    actor_id: str
    role: str
    status: str
    key_fingerprint: Optional[str] = None


# ---------------------------------------------------------------------------
# Identity loading
# ---------------------------------------------------------------------------

_IDENTITIES_PATH = os.path.join(os.path.dirname(__file__), "identities.json")
_cache: dict[str, Identity] | None = None


def load_identities() -> dict[str, Identity]:
    """Load actor allowlist from identities.json."""
    global _cache
    if _cache is not None:
        return _cache
    with open(_IDENTITIES_PATH, "r") as f:
        data = json.load(f)
    result: dict[str, Identity] = {}
    for actor_id, info in data["actors"].items():
        result[actor_id] = Identity(
            actor_id=actor_id,
            role=info["role"],
            status=info["status"],
            key_fingerprint=info.get("key_fingerprint"),
        )
    _cache = result
    return result


def reload_identities() -> dict[str, Identity]:
    """Force reload from disk (useful after identity changes)."""
    global _cache
    _cache = None
    return load_identities()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_actor(actor_id: str) -> Identity:
    """Validate actor_id exists and is active. Raises ValueError if not."""
    identities = load_identities()
    if actor_id not in identities:
        raise ValueError(f"Unknown actor: {actor_id}")
    identity = identities[actor_id]
    if identity.status != "active":
        raise ValueError(f"Actor {actor_id} is {identity.status}")
    return identity


def get_role(actor_id: str) -> str:
    """Get role for a validated actor."""
    return validate_actor(actor_id).role
