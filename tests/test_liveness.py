"""
Liveness Model Test Suite
Tests escalation timeout handling, auto-deny logic, and gateway integration.

Usage:
    1. Start DB:      docker compose up -d
    2. Start gateway: uvicorn main:app --port 8000
    3. Run tests:     python tests/test_liveness.py  (from project root)
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from uuid import uuid4

# Set short timeouts BEFORE importing liveness so module-level constants pick
# them up.  Tests that need to observe timeout transitions use time.sleep().
os.environ["ESCALATION_INITIAL_TIMEOUT_SECONDS"] = "2"
os.environ["ESCALATION_MAX_TIMEOUT_SECONDS"] = "5"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from governance.audit import AuditSpineManager
from governance.liveness import (
    EscalationState,
    EscalationTracker,
    check_escalation_status,
    auto_deny_expired_escalations,
    get_escalation_summary,
    build_escalation_tracker,
    ESCALATION_INITIAL_TIMEOUT_SECONDS,
    ESCALATION_MAX_TIMEOUT_SECONDS,
)
import governance.liveness as liveness_mod

import httpx
import psycopg2

BASE_URL = "http://localhost:8000"
HUMAN_API_KEY = os.environ.get("HUMAN_API_KEY", "test-key-change-me")

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


def _create_escalated_proposal(audit: AuditSpineManager) -> tuple[str, str]:
    """Helper: create an INBOUND_INTENT + ESCALATED POLICY_EVAL pair directly in DB."""
    from governance.policy_engine import PolicyEngine

    actor_id = "agent:coder"
    content = f"curl https://api.example.com/liveness-test-{uuid4().hex[:8]}"

    # Log inbound intent
    intent_event_id = audit.log_event(
        actor_id=actor_id,
        action_type="INBOUND_INTENT",
        intent_payload={
            "chain_id": str(uuid4()),
            "role": "coder",
            "tier_request": 0,
            "goal": "test",
            "scope": {},
            "expected_outcomes": [],
            "action_type": "bash",
            "content": content,
        },
    )

    # Evaluate via policy engine (curl triggers ESCALATED)
    engine = PolicyEngine(audit=audit)
    result, policy_event_id = engine.evaluate_proposal({
        "actor_id": actor_id,
        "action_type": "bash",
        "content": content,
    })

    return intent_event_id, policy_event_id


def main() -> bool:
    global passed, failed

    audit = AuditSpineManager()

    # Confirm that the short timeouts were picked up at module level
    print(f"  ESCALATION_INITIAL_TIMEOUT_SECONDS = {ESCALATION_INITIAL_TIMEOUT_SECONDS}")
    print(f"  ESCALATION_MAX_TIMEOUT_SECONDS     = {ESCALATION_MAX_TIMEOUT_SECONDS}")

    # =================================================================
    # UNIT TESTS
    # =================================================================
    print("=" * 60)
    print("LIVENESS MODEL UNIT TESTS")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Test 1: Fresh escalation -> PENDING_REVIEW
    # ------------------------------------------------------------------
    print("\n--- Test 1: Fresh escalation -> PENDING_REVIEW ---")
    intent_id_1, policy_id_1 = _create_escalated_proposal(audit)
    state = check_escalation_status(audit, intent_id_1)
    check("fresh escalation is PENDING_REVIEW",
          state == EscalationState.PENDING_REVIEW,
          f"got {state}")

    # ------------------------------------------------------------------
    # Test 2: Escalation with approval -> RESOLVED
    # ------------------------------------------------------------------
    print("\n--- Test 2: Escalation with approval -> RESOLVED ---")
    intent_id_2, policy_id_2 = _create_escalated_proposal(audit)
    # Log a HUMAN_APPROVAL_GRANTED event that references this intent
    audit.log_event(
        actor_id="human:admin",
        action_type="HUMAN_APPROVAL_GRANTED",
        intent_payload={
            "intent_event_id": intent_id_2,
            "policy_event_id": policy_id_2,
            "approved_scope": "allow_execute_once",
            "approved_by": "human:admin",
        },
    )
    state = check_escalation_status(audit, intent_id_2)
    check("approved escalation is RESOLVED",
          state == EscalationState.RESOLVED,
          f"got {state}")

    # ------------------------------------------------------------------
    # Test 3: Escalation with denial -> RESOLVED
    # ------------------------------------------------------------------
    print("\n--- Test 3: Escalation with denial -> RESOLVED ---")
    intent_id_3, policy_id_3 = _create_escalated_proposal(audit)
    audit.log_event(
        actor_id="human:admin",
        action_type="HUMAN_DENIAL",
        intent_payload={
            "intent_event_id": intent_id_3,
            "policy_event_id": policy_id_3,
            "reason": "test denial",
            "denied_by": "human:admin",
        },
    )
    state = check_escalation_status(audit, intent_id_3)
    check("denied escalation is RESOLVED",
          state == EscalationState.RESOLVED,
          f"got {state}")

    # ------------------------------------------------------------------
    # Test 4: Escalation past initial timeout -> HUMAN_REQUIRED
    # ------------------------------------------------------------------
    print("\n--- Test 4: Past initial timeout -> HUMAN_REQUIRED ---")
    # With ESCALATION_INITIAL_TIMEOUT_SECONDS=2 and MAX=5, sleeping 3s
    # puts us past the initial timeout but well before the hard deadline.
    intent_id_4, policy_id_4 = _create_escalated_proposal(audit)
    time.sleep(3)

    state = check_escalation_status(audit, intent_id_4)
    check("past initial timeout is HUMAN_REQUIRED",
          state == EscalationState.HUMAN_REQUIRED,
          f"got {state}")

    # ------------------------------------------------------------------
    # Test 5: Escalation past hard deadline -> AUTO_DENIED_TIMEOUT
    # ------------------------------------------------------------------
    print("\n--- Test 5: Past hard deadline -> AUTO_DENIED_TIMEOUT ---")
    intent_id_5, policy_id_5 = _create_escalated_proposal(audit)
    # ESCALATION_MAX_TIMEOUT_SECONDS=10 -> monkey-patch to 1s then sleep
    original_max = liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS
    liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS = 1
    time.sleep(2)

    state = check_escalation_status(audit, intent_id_5)
    check("past hard deadline is AUTO_DENIED_TIMEOUT",
          state == EscalationState.AUTO_DENIED_TIMEOUT,
          f"got {state}")
    # Restore
    liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS = original_max

    # ------------------------------------------------------------------
    # Test 6: auto_deny_expired_escalations logs AUTO_DENIED_TIMEOUT events
    # ------------------------------------------------------------------
    print("\n--- Test 6: auto_deny_expired_escalations logs events ---")
    intent_id_6, policy_id_6 = _create_escalated_proposal(audit)
    # Monkey-patch to short timeout for this test
    liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS = 1
    time.sleep(2)  # past hard deadline (1s)

    denied_ids = auto_deny_expired_escalations(audit)
    check("auto_deny returns list", isinstance(denied_ids, list),
          f"got type {type(denied_ids)}")
    check("intent_id_6 in auto-denied list",
          intent_id_6 in denied_ids,
          f"denied_ids includes our intent: {intent_id_6 in denied_ids}")

    # Verify the AUTO_DENIED_TIMEOUT event exists in the spine
    conn = audit._connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id FROM audit_events
            WHERE action_type = 'AUTO_DENIED_TIMEOUT'
            AND intent_payload->>'intent_event_id' = %s
            LIMIT 1
            """,
            (intent_id_6,),
        )
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()
    check("AUTO_DENIED_TIMEOUT event exists in spine", row is not None)

    # After auto-deny, check_escalation_status should return RESOLVED
    state = check_escalation_status(audit, intent_id_6)
    check("after auto-deny, state is RESOLVED",
          state == EscalationState.RESOLVED,
          f"got {state}")
    # Restore
    liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS = original_max

    # ------------------------------------------------------------------
    # Test 7: get_escalation_summary returns correct counts
    # ------------------------------------------------------------------
    print("\n--- Test 7: get_escalation_summary returns correct counts ---")
    summary = get_escalation_summary(audit)
    check("summary has 'pending' key", "pending" in summary,
          f"keys={list(summary.keys())}")
    check("summary has 'human_required' key", "human_required" in summary,
          f"keys={list(summary.keys())}")
    check("summary has 'auto_denied' key", "auto_denied" in summary,
          f"keys={list(summary.keys())}")
    check("summary has 'resolved' key", "resolved" in summary,
          f"keys={list(summary.keys())}")
    check("resolved count > 0",
          summary.get("resolved", 0) > 0,
          f"summary={summary}")

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
        # --------------------------------------------------------------
        # Test 8: GET /escalations returns summary with correct keys
        # --------------------------------------------------------------
        print("\n--- Test 8: GET /escalations returns summary ---")
        try:
            resp = httpx.get(f"{BASE_URL}/escalations", timeout=60)
            check("/escalations returns 200",
                  resp.status_code == 200,
                  f"HTTP {resp.status_code}")
            body = resp.json()
            check("response has 'summary' key",
                  "summary" in body,
                  f"keys={list(body.keys())}")
            check("response has 'initial_timeout_seconds'",
                  "initial_timeout_seconds" in body,
                  f"keys={list(body.keys())}")
            check("response has 'max_timeout_seconds'",
                  "max_timeout_seconds" in body,
                  f"keys={list(body.keys())}")
            if "summary" in body:
                s = body["summary"]
                check("summary has pending/human_required/auto_denied/resolved",
                      all(k in s for k in ["pending", "human_required", "auto_denied", "resolved"]),
                      f"summary keys={list(s.keys())}")
                check("initial_timeout_seconds is int",
                      isinstance(body["initial_timeout_seconds"], int),
                      f"type={type(body['initial_timeout_seconds'])}")
        except Exception as exc:
            check("/escalations endpoint reachable", False,
                  f"error: {exc}")

        # --------------------------------------------------------------
        # Test 9: /execute on expired escalation -> 410
        # Test the unit-level auto-deny + DB check. The gateway endpoint
        # returns 410 only after the gateway process is restarted to pick
        # up the latest main.py. We verify the DB-level plumbing here.
        # --------------------------------------------------------------
        print("\n--- Test 9: Expired escalation auto-denied in DB ---")
        try:
            # Submit an ESCALATED proposal via the gateway
            esc_resp = httpx.post(f"{BASE_URL}/propose", json={
                "actor_id": "agent:coder",
                "action_type": "bash",
                "content": f"curl https://api.example.com/expire-test-{uuid4().hex[:8]}",
            }, timeout=15)
            esc_body = esc_resp.json()
            esc_intent_id = esc_body.get("intent_event_id")
            check("/propose ESCALATED for expire test -> 202",
                  esc_resp.status_code == 202,
                  f"HTTP {esc_resp.status_code}, decision={esc_body.get('decision')}")

            # Monkey-patch to short timeout so 3s sleep exceeds the deadline
            saved_max = liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS
            liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS = 1
            time.sleep(3)

            # Run auto-deny sweep so the timeout event is logged to DB
            denied = auto_deny_expired_escalations(audit)
            check("auto-deny sweep includes this intent",
                  esc_intent_id in denied,
                  f"denied list includes {esc_intent_id}: {esc_intent_id in denied}")

            # Verify the event exists in the DB
            conn = audit._connect()
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT id FROM audit_events
                    WHERE action_type = 'AUTO_DENIED_TIMEOUT'
                    AND intent_payload->>'intent_event_id' = %s
                    LIMIT 1
                    """,
                    (esc_intent_id,),
                )
                row = cur.fetchone()
                cur.close()
            finally:
                conn.close()
            check("AUTO_DENIED_TIMEOUT event in spine for this intent",
                  row is not None)

            # Restore
            liveness_mod.ESCALATION_MAX_TIMEOUT_SECONDS = saved_max

            # Try the gateway endpoint -- will return 410 if gateway has
            # the latest code, 202 if it needs a restart.
            exec_resp = httpx.post(
                f"{BASE_URL}/execute",
                json={"proposal_id": esc_intent_id},
                timeout=30,
            )
            check("/execute returns 410 (requires gateway restart if 202)",
                  exec_resp.status_code == 410,
                  f"HTTP {exec_resp.status_code} "
                  f"(410=new code, 202=gateway needs restart)")
        except Exception as exc:
            check("/execute expired escalation test", False,
                  f"error: {exc}")

        # --------------------------------------------------------------
        # Test 10: /propose ESCALATED response includes expires_at
        # --------------------------------------------------------------
        print("\n--- Test 10: /propose ESCALATED has expires_at + hard_deadline ---")
        try:
            resp = httpx.post(f"{BASE_URL}/propose", json={
                "actor_id": "agent:coder",
                "action_type": "bash",
                "content": f"curl https://api.example.com/liveness-gw-{uuid4().hex[:8]}",
            }, timeout=15)
            check("/propose ESCALATED returns 202",
                  resp.status_code == 202,
                  f"HTTP {resp.status_code}")
            body = resp.json()
            check("response has 'expires_at'",
                  "expires_at" in body,
                  f"keys={list(body.keys())}")
            check("response has 'hard_deadline'",
                  "hard_deadline" in body,
                  f"keys={list(body.keys())}")
            if "expires_at" in body:
                check("expires_at is ISO format string",
                      isinstance(body["expires_at"], str) and "T" in body["expires_at"],
                      f"expires_at={body['expires_at']}")
            if "hard_deadline" in body:
                check("hard_deadline is ISO format string",
                      isinstance(body["hard_deadline"], str) and "T" in body["hard_deadline"],
                      f"hard_deadline={body['hard_deadline']}")
        except Exception as exc:
            check("/propose ESCALATED test", False,
                  f"error: {exc}")

    # =================================================================
    # Summary
    # =================================================================
    print()
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
