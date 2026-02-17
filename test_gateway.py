"""
Governance Gateway Test Suite
Sends proposals to the live /propose and /approve endpoints and verifies
correct HTTP status codes, response structure, and audit chain integrity.

Usage:
    1. Set env:   export HUMAN_API_KEY=test-key-change-me
    2. Start:     uvicorn main:app --port 8000
    3. Run tests: python test_gateway.py
"""

from __future__ import annotations

import os
import sys

import httpx

BASE_URL = "http://localhost:8000"
HUMAN_API_KEY = os.environ.get("HUMAN_API_KEY", "test-key-change-me")

passed = 0
failed = 0


def run_test(label: str, payload: dict, expected_status: int,
             expected_decision: str):
    global passed, failed

    resp = httpx.post(f"{BASE_URL}/propose", json=payload)
    body = resp.json()

    status_ok = resp.status_code == expected_status
    decision_ok = body.get("decision") == expected_decision
    has_intent_id = bool(body.get("intent_event_id"))
    has_policy_id = bool(body.get("policy_event_id"))

    ok = status_ok and decision_ok and has_intent_id and has_policy_id
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1

    print(f"  [{tag}] {label}")
    print(f"         HTTP:       {resp.status_code} (expected {expected_status})")
    print(f"         Decision:   {body.get('decision')} (expected {expected_decision})")
    print(f"         Risk Score: {body.get('risk_score')}")
    print(f"         Intent ID:  {body.get('intent_event_id', 'MISSING')}")
    print(f"         Policy ID:  {body.get('policy_event_id', 'MISSING')}")
    if body.get("violations"):
        for v in body["violations"]:
            print(f"         Violation:  [{v['rule']}] {v['description']}")
    print()


def main():
    global passed, failed

    # Health check
    health = httpx.get(f"{BASE_URL}/health")
    print(f"Gateway health: {health.json()}\n")

    # ----- APPROVED (200) -----
    print("=" * 60)
    print("APPROVED PROPOSALS (expect 200)")
    print("=" * 60)

    run_test(
        "Safe file read",
        {
            "actor_id": "agent:executor",
            "action_type": "file_read",
            "content": "src/main.py",
        },
        expected_status=200,
        expected_decision="APPROVED",
    )

    run_test(
        "Harmless bash command",
        {
            "actor_id": "agent:executor",
            "action_type": "bash",
            "content": "echo hello world",
        },
        expected_status=200,
        expected_decision="APPROVED",
    )

    # ----- ESCALATED (202) -----
    print("=" * 60)
    print("ESCALATED PROPOSALS (expect 202)")
    print("=" * 60)

    run_test(
        "Unproxied curl (gateway bypass)",
        {
            "actor_id": "agent:executor",
            "action_type": "bash",
            "content": "curl https://api.example.com/data",
        },
        expected_status=202,
        expected_decision="ESCALATED",
    )

    run_test(
        "chmod 777 (operational constraint)",
        {
            "actor_id": "agent:executor",
            "action_type": "bash",
            "content": "chmod 777 /tmp/myfile",
        },
        expected_status=202,
        expected_decision="ESCALATED",
    )

    # ----- DENIED (403) -----
    print("=" * 60)
    print("DENIED PROPOSALS (expect 403)")
    print("=" * 60)

    run_test(
        "sudo rm -rf / (destructive + sudo)",
        {
            "actor_id": "agent:rogue",
            "action_type": "bash",
            "content": "sudo rm -rf /",
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    run_test(
        "Modify CONSTITUTION.md (authority decoupling)",
        {
            "actor_id": "agent:rogue",
            "action_type": "file_edit",
            "content": "CONSTITUTION.md",
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    run_test(
        "Write to governance/ (authority decoupling)",
        {
            "actor_id": "agent:rogue",
            "action_type": "file_write",
            "content": "governance/policy_engine.py",
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    run_test(
        "Dict content — sudo + rm -rf in nested payload",
        {
            "actor_id": "agent:rogue",
            "action_type": "bash",
            "content": {"cmd": "sudo rm -rf /", "reason": "cleanup"},
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    # ----- HUMAN APPROVAL FLOW -----
    print("=" * 60)
    print("HUMAN APPROVAL FLOW")
    print("=" * 60)

    # Step 1: Submit an escalatable proposal
    escalated_resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:executor",
        "action_type": "bash",
        "content": "curl https://api.example.com/data",
    })
    esc_body = escalated_resp.json()
    esc_intent_id = esc_body.get("intent_event_id")
    esc_policy_id = esc_body.get("policy_event_id")

    # Test: approve without auth header -> 422 (missing header)
    resp_no_auth = httpx.post(f"{BASE_URL}/approve", json={
        "intent_event_id": esc_intent_id,
        "policy_event_id": esc_policy_id,
    })
    ok = resp_no_auth.status_code == 422
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] Missing auth header -> {resp_no_auth.status_code} (expect 422)")
    print()

    # Test: approve with wrong key -> 401
    resp_bad_key = httpx.post(
        f"{BASE_URL}/approve",
        json={
            "intent_event_id": esc_intent_id,
            "policy_event_id": esc_policy_id,
        },
        headers={"Authorization": "Bearer wrong-key-12345"},
    )
    ok = resp_bad_key.status_code == 401
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] Invalid API key -> {resp_bad_key.status_code} (expect 401)")
    print()

    # Test: approve with bogus event IDs -> 404
    resp_bad_id = httpx.post(
        f"{BASE_URL}/approve",
        json={
            "intent_event_id": "00000000-0000-0000-0000-000000000000",
            "policy_event_id": esc_policy_id,
        },
        headers={"Authorization": f"Bearer {HUMAN_API_KEY}"},
    )
    ok = resp_bad_id.status_code == 404
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] Bogus intent_event_id -> {resp_bad_id.status_code} (expect 404)")
    print()

    # Test: try to approve a DENIED proposal -> should fail with 422
    denied_resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:rogue",
        "action_type": "bash",
        "content": "sudo rm -rf /",
    })
    denied_body = denied_resp.json()
    resp_denied_approve = httpx.post(
        f"{BASE_URL}/approve",
        json={
            "intent_event_id": denied_body["intent_event_id"],
            "policy_event_id": denied_body["policy_event_id"],
        },
        headers={"Authorization": f"Bearer {HUMAN_API_KEY}"},
    )
    ok = resp_denied_approve.status_code == 422
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] Approve DENIED proposal -> {resp_denied_approve.status_code} (expect 422)")
    print()

    # Test: valid approval of ESCALATED proposal -> 200
    resp_approve = httpx.post(
        f"{BASE_URL}/approve",
        json={
            "intent_event_id": esc_intent_id,
            "policy_event_id": esc_policy_id,
        },
        headers={"Authorization": f"Bearer {HUMAN_API_KEY}"},
    )
    approve_body = resp_approve.json()
    has_approval_id = bool(approve_body.get("approval_event_id"))
    ok = (
        resp_approve.status_code == 200
        and approve_body.get("status") == "HUMAN_APPROVAL_GRANTED"
        and has_approval_id
    )
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] Valid approval of ESCALATED proposal")
    print(f"         HTTP:        {resp_approve.status_code} (expect 200)")
    print(f"         Status:      {approve_body.get('status')}")
    print(f"         Scope:       {approve_body.get('scope')}")
    print(f"         Approval ID: {approve_body.get('approval_event_id', 'MISSING')}")
    print()

    # ----- CHAIN INTEGRITY CHECK -----
    print("=" * 60)
    print("CHAIN INTEGRITY VERIFICATION")
    print("=" * 60)

    import psycopg2
    conn = psycopg2.connect(
        host="localhost", port=5433,
        dbname="governance_control_plane",
        user="admin", password="password123",
    )
    cur = conn.cursor()
    cur.execute("SELECT total_events, chain_valid, break_at FROM audit_spine_verify_chain()")
    chain = cur.fetchone()

    # Verify HUMAN_APPROVAL_GRANTED exists in the ledger
    cur.execute(
        "SELECT count(*) FROM audit_events WHERE action_type = 'HUMAN_APPROVAL_GRANTED'"
    )
    approval_count = cur.fetchone()[0]
    cur.close()
    conn.close()

    chain_ok = chain[1] is True
    approval_logged = approval_count > 0
    ok = chain_ok and approval_logged
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] Chain integrity after approvals")
    print(f"         Total events:   {chain[0]}")
    print(f"         Chain valid:    {chain[1]}")
    print(f"         Approvals:      {approval_count}")
    if not chain_ok:
        print(f"         Break at:       {chain[2]}")
    print()

    # ----- Summary -----
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
