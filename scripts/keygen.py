#!/usr/bin/env python3
"""
Gavel API Key Generator

Generates a new operator API key with a `gvl_` prefix and prints:
  - The raw key (give to the operator, store securely)
  - The SHA-256 fingerprint (store in identities.json)
  - A ready-to-paste JSON snippet for identities.json

Usage:  python scripts/keygen.py [actor_id]
        actor_id defaults to "human:operator"
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys


def generate_key() -> str:
    """Return a `gvl_` prefixed key with 32 bytes of URL-safe randomness."""
    return "gvl_" + secrets.token_urlsafe(32)


def fingerprint(raw_key: str) -> str:
    """Return `sha256:<hex>` fingerprint."""
    return "sha256:" + hashlib.sha256(raw_key.encode()).hexdigest()


def main():
    actor_id = sys.argv[1] if len(sys.argv) > 1 else "human:operator"
    raw = generate_key()
    fp = fingerprint(raw)

    print()
    print("=== Gavel API Key ===")
    print()
    print(f"  Actor ID:    {actor_id}")
    print(f"  Raw Key:     {raw}")
    print(f"  Fingerprint: {fp}")
    print()
    print("--- Paste into governance/identities.json under \"actors\" ---")
    entry = {actor_id: {"role": "admin", "status": "active", "key_fingerprint": fp}}
    print(json.dumps(entry, indent=2))
    print()


if __name__ == "__main__":
    main()
