"""
Policy Engine Integration Test Suite
Tests evidence-based auto-approve for tiered autonomy.

Usage:
    1. Start DB:      docker compose up -d
    2. Start gateway: uvicorn main:app --port 8000
    3. Run tests:     python tests/test_policy_integration.py  (from project root)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from governance.evidence_review import ReviewFinding, ReviewResult
from governance.policy_engine import evaluate_evidence_for_auto_approve

import httpx

BASE_URL = "http://localhost:8000"

passed = 0
failed = 0
total = 0


def check(condition: bool, label: str, detail: str = ""):
    global passed, failed, total
    total += 1
    if condition:
        passed += 1
        print(f"  [PASS] {label}")
    else:
        failed += 1
        print(f"  [FAIL] {label}")
    if detail:
        print(f"         {detail}")


def main() -> bool:
    global passed, failed, total

    # =================================================================
    # UNIT TESTS: evaluate_evidence_for_auto_approve
    # =================================================================
    print("=" * 60)
    print("UNIT TESTS: evaluate_evidence_for_auto_approve")
    print("=" * 60)

    # --- Test 1: Tier 1 + clean evidence -> auto-approved ---
    print("\n--- Test 1: Tier 1 + clean evidence -> auto-approved ---")
    clean_result = ReviewResult(
        passed=True,
        findings=[],
        risk_delta=0.0,
        scope_compliant=True,
    )
    approved, reason = evaluate_evidence_for_auto_approve(clean_result, tier=1)
    check(approved is True, "Tier 1 clean -> approved", f"approved={approved}")
    check("auto-approved" in reason, "reason mentions auto-approved", f"reason={reason!r}")

    # --- Test 2: Tier 1 + failed evidence (critical finding) -> not auto-approved ---
    print("\n--- Test 2: Tier 1 + failed evidence -> not auto-approved ---")
    failed_result = ReviewResult(
        passed=False,
        findings=[ReviewFinding(
            category="forbidden_path",
            severity="critical",
            description="Forbidden path touched: CONSTITUTION.md",
            file_path="CONSTITUTION.md",
        )],
        risk_delta=0.5,
        scope_compliant=True,
    )
    approved, reason = evaluate_evidence_for_auto_approve(failed_result, tier=1)
    check(approved is False, "Tier 1 failed -> not approved", f"approved={approved}")
    check("failed" in reason, "reason mentions failed", f"reason={reason!r}")
    check("1 findings" in reason, "reason includes findings count", f"reason={reason!r}")

    # --- Test 3: Tier 1 + passed but high risk_delta -> not auto-approved ---
    print("\n--- Test 3: Tier 1 + passed but high risk_delta -> not auto-approved ---")
    high_risk_result = ReviewResult(
        passed=True,
        findings=[],
        risk_delta=0.5,
        scope_compliant=True,
    )
    approved, reason = evaluate_evidence_for_auto_approve(high_risk_result, tier=1)
    check(approved is False, "Tier 1 high risk_delta -> not approved", f"approved={approved}")
    check("failed" in reason, "reason mentions failed", f"reason={reason!r}")

    # --- Test 4: Tier 0 -> never auto-approved ---
    print("\n--- Test 4: Tier 0 -> never auto-approved ---")
    approved, reason = evaluate_evidence_for_auto_approve(clean_result, tier=0)
    check(approved is False, "Tier 0 -> not approved", f"approved={approved}")
    check("Tier 0" in reason, "reason mentions Tier 0", f"reason={reason!r}")

    # --- Test 5: Tier 3 -> never auto-approved ---
    print("\n--- Test 5: Tier 3 -> never auto-approved ---")
    approved, reason = evaluate_evidence_for_auto_approve(clean_result, tier=3)
    check(approved is False, "Tier 3 -> not approved", f"approved={approved}")
    check("human approval" in reason, "reason mentions human approval", f"reason={reason!r}")

    # =================================================================
    # INTEGRATION TESTS
    # =================================================================
    print()
    print("=" * 60)
    print("INTEGRATION TESTS: /execute auto-approve")
    print("=" * 60)

    # Check gateway is reachable
    try:
        health = httpx.get(f"{BASE_URL}/health", timeout=5)
        gateway_ok = health.status_code == 200
    except Exception:
        gateway_ok = False

    if not gateway_ok:
        print("  [SKIP] Gateway not reachable -- skipping integration tests")
    else:
        # --- Test 6: POST /execute as Tier 1 agent -> auto_approved in response ---
        print("\n--- Test 6: /execute as Tier 1 -> auto_approved ---")
        # Step A: Propose
        resp = httpx.post(f"{BASE_URL}/propose", json={
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "echo hello",
        })
        check(resp.status_code == 200, "/propose -> 200", f"HTTP {resp.status_code}")
        propose_body = resp.json()
        intent_id = propose_body.get("intent_event_id")
        check(intent_id is not None, "intent_event_id returned", f"keys={list(propose_body.keys())}")

        if intent_id:
            # Step B: Execute
            exec_resp = httpx.post(f"{BASE_URL}/execute", json={
                "proposal_id": intent_id,
            }, timeout=60)
            check(exec_resp.status_code == 200, "/execute -> 200", f"HTTP {exec_resp.status_code}")
            exec_body = exec_resp.json()

            check("auto_approved" in exec_body, "response includes auto_approved",
                  f"keys={list(exec_body.keys())}")
            check(exec_body.get("auto_approved") is True, "auto_approved == True",
                  f"got {exec_body.get('auto_approved')}")
            check("auto_approve_reason" in exec_body, "response includes auto_approve_reason",
                  f"keys={list(exec_body.keys())}")
            check("auto-approved" in exec_body.get("auto_approve_reason", ""),
                  "reason mentions auto-approved",
                  f"reason={exec_body.get('auto_approve_reason')!r}")

            # --- Test 7: EVIDENCE_AUTO_APPROVE event in audit spine ---
            print("\n--- Test 7: EVIDENCE_AUTO_APPROVE in audit spine ---")
            import psycopg2
            conn = psycopg2.connect(
                host="localhost",
                port=5433,
                dbname="governance_control_plane",
                user="admin",
                password="password123",
            )
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT id, action_type, intent_payload
                    FROM audit_events
                    WHERE action_type = 'EVIDENCE_AUTO_APPROVE'
                    AND intent_payload->>'proposal_id' = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (intent_id,),
                )
                row = cur.fetchone()
                cur.close()
            finally:
                conn.close()

            check(row is not None, "EVIDENCE_AUTO_APPROVE event found in spine",
                  f"proposal_id={intent_id[:8]}...")
            if row:
                import json
                payload = row[2]
                if isinstance(payload, str):
                    payload = json.loads(payload)
                check(payload.get("auto_approved") is True, "event payload auto_approved=True",
                      f"payload auto_approved={payload.get('auto_approved')}")
                check(payload.get("reason", "").startswith("Tier 1"),
                      "event payload reason starts with Tier 1",
                      f"reason={payload.get('reason')!r}")

    # Summary
    print()
    print("=" * 60)
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
