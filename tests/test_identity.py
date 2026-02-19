"""
Identity Model Test Suite
Tests actor validation, role extraction, and status enforcement.

Usage:  python tests/test_identity.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from governance.identity import (
    Identity,
    authenticate_human,
    hash_api_key,
    load_identities,
    reload_identities,
    validate_actor,
    get_role,
)

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

passed = 0
failed = 0


def check(label: str, condition: bool):
    global passed, failed
    tag = "PASS" if condition else "FAIL"
    if condition:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] {label}")


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("IDENTITY MODEL TESTS")
    print("=" * 60)
    print()

    # --- Load identities ---
    identities = load_identities()
    check("load_identities returns dict", isinstance(identities, dict))
    check("At least 6 actors loaded", len(identities) >= 6)
    print()

    # --- Known actors validate ---
    print("Known active actors:")
    for actor_id in ["agent:architect", "agent:coder", "agent:reviewer",
                     "agent:risk", "human:admin", "system:gateway"]:
        identity = validate_actor(actor_id)
        check(
            f"  {actor_id} -> role={identity.role}, status={identity.status}",
            identity.status == "active" and identity.role != "",
        )
    print()

    # --- Role extraction ---
    print("Role extraction:")
    check("agent:architect -> architect", get_role("agent:architect") == "architect")
    check("agent:coder -> coder", get_role("agent:coder") == "coder")
    check("human:admin -> admin", get_role("human:admin") == "admin")
    check("system:gateway -> system", get_role("system:gateway") == "system")
    print()

    # --- Unknown actor rejected ---
    print("Unknown actor rejection:")
    try:
        validate_actor("agent:unknown")
        check("agent:unknown raises ValueError", False)
    except ValueError as e:
        check(f"agent:unknown raises ValueError: {e}", True)

    try:
        validate_actor("rogue:hacker")
        check("rogue:hacker raises ValueError", False)
    except ValueError as e:
        check(f"rogue:hacker raises ValueError: {e}", True)
    print()

    # --- Identity dataclass ---
    print("Identity dataclass:")
    ident = Identity(actor_id="test:x", role="tester", status="active")
    check("Identity fields accessible", ident.actor_id == "test:x" and ident.role == "tester")
    check("key_fingerprint defaults to None", ident.key_fingerprint is None)
    print()

    # --- hash_api_key ---
    print("hash_api_key:")
    fp = hash_api_key("test-key-change-me")
    check(
        "hash_api_key returns sha256: prefix",
        fp.startswith("sha256:"),
    )
    check(
        "hash_api_key is deterministic",
        hash_api_key("test-key-change-me") == fp,
    )
    check(
        "hash_api_key differs for different keys",
        hash_api_key("other-key") != fp,
    )
    expected_fp = "sha256:f2379873bb44b73c4d33761ac17a76879931895a6f497d174b3401bbf5108072"
    check(
        "hash_api_key matches known SHA-256 for dev key",
        fp == expected_fp,
    )
    print()

    # --- authenticate_human ---
    print("authenticate_human:")
    # Force reload so the fingerprint from identities.json is picked up
    reload_identities()

    identity = authenticate_human("test-key-change-me")
    check(
        "authenticate_human resolves dev key -> human:admin",
        identity.actor_id == "human:admin",
    )
    check(
        "resolved identity has admin role",
        identity.role == "admin",
    )

    try:
        authenticate_human("wrong-key-12345")
        check("authenticate_human rejects wrong key", False)
    except ValueError as e:
        check(
            f"authenticate_human rejects wrong key: {e}",
            "no matching identity" in str(e).lower(),
        )

    try:
        authenticate_human("")
        check("authenticate_human rejects empty key", False)
    except ValueError as e:
        check(
            f"authenticate_human rejects empty key: {e}",
            "no matching identity" in str(e).lower(),
        )
    print()

    # --- Reload works ---
    print("Reload:")
    reloaded = reload_identities()
    check("reload_identities returns dict", isinstance(reloaded, dict))
    check("reload has same keys", set(reloaded.keys()) == set(identities.keys()))
    print()

    # --- Summary ---
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
