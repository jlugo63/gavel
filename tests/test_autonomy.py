"""
Tiered Autonomy Contract Test Suite
Tests tier policies, execution checks, and gateway integration.

Usage:
    1. Start DB:      docker compose up -d
    2. Start gateway: uvicorn main:app --port 8000
    3. Run tests:     python tests/test_autonomy.py  (from project root)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from governance.autonomy import (
    TIER_POLICIES,
    TierPolicy,
    check_execution_allowed,
    get_tier_policy,
)
from governance.identity import reload_identities

import httpx

BASE_URL = "http://localhost:8000"

passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = ""):
    global passed, failed
    tag = "PASS" if condition else "FAIL"
    if condition:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] {label}")
    if detail:
        print(f"         {detail}")


def main() -> bool:
    global passed, failed

    # Force reload identities to pick up tier fields
    reload_identities()

    # =================================================================
    # TIER POLICY UNIT TESTS
    # =================================================================
    print("=" * 60)
    print("TIER POLICY UNIT TESTS")
    print("=" * 60)

    # Test 1: get_tier_policy returns correct policies
    print("\n--- Test 1: get_tier_policy for each known actor ---")
    p0 = get_tier_policy("agent:reviewer")
    check("agent:reviewer -> tier 0", p0.tier == 0,
          f"got tier={p0.tier}")
    check("tier 0 cannot execute", p0.can_execute is False)

    p1 = get_tier_policy("agent:coder")
    check("agent:coder -> tier 1", p1.tier == 1,
          f"got tier={p1.tier}")
    check("tier 1 can execute", p1.can_execute is True)
    check("tier 1 requires sandbox", p1.requires_sandbox is True)

    p3 = get_tier_policy("human:admin")
    check("human:admin -> tier 3", p3.tier == 3,
          f"got tier={p3.tier}")
    check("tier 3 requires human approval", p3.requires_human_approval is True)

    # =================================================================
    # EXECUTION CHECK UNIT TESTS
    # =================================================================
    print()
    print("=" * 60)
    print("EXECUTION CHECK UNIT TESTS")
    print("=" * 60)

    # Test 2: Tier 0 actor cannot execute
    print("\n--- Test 2: Tier 0 -> cannot execute ---")
    allowed, reason = check_execution_allowed("agent:reviewer")
    check("not allowed", allowed is False)
    check("reason mentions Tier 0", "Tier 0" in reason,
          f"reason={reason!r}")

    # Test 3: Tier 1 actor can execute
    print("\n--- Test 3: Tier 1 -> can execute ---")
    allowed, reason = check_execution_allowed("agent:coder")
    check("allowed", allowed is True)
    check("reason mentions Tier 1", "Tier 1" in reason,
          f"reason={reason!r}")

    # Test 4: Tier 2 actor blocked (not yet implemented)
    print("\n--- Test 4: Tier 2 -> blocked (not yet implemented) ---")
    # No tier 2 actor in identities.json, test via TIER_POLICIES directly
    check("tier 2 policy exists", 2 in TIER_POLICIES)
    check("tier 2 description mentions not yet implemented",
          "not yet implemented" in TIER_POLICIES[2].description,
          f"desc={TIER_POLICIES[2].description!r}")

    # Test 5: Tier 3 actor without approval -> blocked
    print("\n--- Test 5: Tier 3 without approval -> blocked ---")
    allowed, reason = check_execution_allowed("human:admin", has_human_approval=False)
    check("not allowed", allowed is False)
    check("reason mentions requires human approval", "requires human approval" in reason,
          f"reason={reason!r}")

    # Test 6: Tier 3 actor with approval -> allowed
    print("\n--- Test 6: Tier 3 with approval -> allowed ---")
    allowed, reason = check_execution_allowed("human:admin", has_human_approval=True)
    check("allowed", allowed is True)
    check("reason mentions human approval", "human approval" in reason,
          f"reason={reason!r}")

    # Test 7: Unknown actor raises ValueError
    print("\n--- Test 7: Unknown actor -> ValueError ---")
    try:
        check_execution_allowed("agent:nonexistent")
        check("raises ValueError", False, "no exception raised")
    except ValueError as exc:
        check("raises ValueError", True, f"msg={exc}")

    # =================================================================
    # GATEWAY INTEGRATION TESTS
    # =================================================================
    print()
    print("=" * 60)
    print("GATEWAY INTEGRATION TESTS")
    print("=" * 60)

    # Check gateway is reachable
    try:
        health = httpx.get(f"{BASE_URL}/health", timeout=5)
        gateway_ok = health.status_code == 200
    except Exception:
        gateway_ok = False

    if not gateway_ok:
        print("  [SKIP] Gateway not reachable -- skipping integration tests")
        print()
    else:
        # Test 8: /propose includes actor_tier
        print("\n--- Test 8: /propose includes actor_tier ---")
        resp = httpx.post(f"{BASE_URL}/propose", json={
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "echo tier-test",
        })
        body = resp.json()
        check("/propose returns actor_tier",
              "actor_tier" in body,
              f"keys={list(body.keys())}")
        check("actor_tier == 1",
              body.get("actor_tier") == 1,
              f"got {body.get('actor_tier')}")
        check("/propose returns tier_description",
              "tier_description" in body,
              f"keys={list(body.keys())}")

        # Test 9: /execute with Tier 0 actor -> 403
        print("\n--- Test 9: /execute with Tier 0 actor -> 403 ---")
        # Propose as tier 0 actor (agent:reviewer)
        resp = httpx.post(f"{BASE_URL}/propose", json={
            "actor_id": "agent:reviewer",
            "action_type": "bash",
            "content": "echo tier0-test",
        })
        t0_body = resp.json()
        t0_intent = t0_body.get("intent_event_id")
        # agent:reviewer is tier 0, propose should work
        check("/propose with tier 0 actor works",
              resp.status_code == 200,
              f"HTTP {resp.status_code}")

        if t0_intent:
            exec_resp = httpx.post(f"{BASE_URL}/execute", json={
                "proposal_id": t0_intent,
            })
            check("/execute tier 0 -> 403",
                  exec_resp.status_code == 403,
                  f"HTTP {exec_resp.status_code}, body={exec_resp.json()}")
            exec_body = exec_resp.json()
            check("error mentions Tier 0",
                  "Tier 0" in exec_body.get("error", ""),
                  f"error={exec_body.get('error', '')!r}")

        # Test 10: /execute with Tier 1 actor -> runs in Blast Box
        print("\n--- Test 10: /execute with Tier 1 actor -> Blast Box ---")
        resp = httpx.post(f"{BASE_URL}/propose", json={
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "echo tier1-test",
        })
        t1_body = resp.json()
        t1_intent = t1_body.get("intent_event_id")
        check("/propose with tier 1 actor -> APPROVED",
              resp.status_code == 200,
              f"HTTP {resp.status_code}")

        if t1_intent:
            exec_resp = httpx.post(f"{BASE_URL}/execute", json={
                "proposal_id": t1_intent,
            }, timeout=60)
            check("/execute tier 1 -> 200",
                  exec_resp.status_code == 200,
                  f"HTTP {exec_resp.status_code}")
            exec_body = exec_resp.json()
            check("evidence_packet returned",
                  "evidence_packet" in exec_body,
                  f"keys={list(exec_body.keys())}")
            check("tier metadata in response",
                  exec_body.get("tier") == 1,
                  f"tier={exec_body.get('tier')}")

    # Summary
    print()
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
