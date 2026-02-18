"""
Identity Model Test Suite
Tests actor validation, role extraction, and status enforcement.

Usage:  python test_identity.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from governance.identity import (
    Identity,
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
