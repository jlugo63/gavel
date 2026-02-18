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


def run_test(label: str, payload: dict, expected_status: int,
             expected_decision: str):
    global passed, failed

    resp = httpx.post(f"{BASE_URL}/propose", json=payload)
    body = resp.json()

    status_ok = resp.status_code == expected_status
    decision_ok = body.get("decision") == expected_decision
    has_intent_id = bool(body.get("intent_event_id"))
    has_policy_id = bool(body.get("policy_event_id"))
    has_chain_id = bool(body.get("chain_id"))

    ok = status_ok and decision_ok and has_intent_id and has_policy_id and has_chain_id
    tag = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1

    print(f"  [{tag}] {label}")
    print(f"         HTTP:       {resp.status_code} (expected {expected_status})")
    print(f"         Decision:   {body.get('decision')} (expected {expected_decision})")
    print(f"         Risk Score: {body.get('risk_score')}")
    print(f"         Chain ID:   {body.get('chain_id', 'MISSING')}")
    print(f"         Intent ID:  {body.get('intent_event_id', 'MISSING')}")
    print(f"         Policy ID:  {body.get('policy_event_id', 'MISSING')}")
    if body.get("violations"):
        for v in body["violations"]:
            print(f"         Violation:  [{v['rule']}] {v['description']}")
    print()
    return body


def main():
    global passed, failed

    # Health check
    health = httpx.get(f"{BASE_URL}/health")
    print(f"Gateway health: {health.json()}\n")

    # =================================================================
    # PHASE 1.6: IDENTITY VALIDATION
    # =================================================================
    print("=" * 60)
    print("IDENTITY VALIDATION (Phase 1.6)")
    print("=" * 60)

    # Unknown actor -> 403 (no ledger entry)
    resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:unknown",
        "action_type": "bash",
        "content": "echo hello",
    })
    body = resp.json()
    check(
        "Unknown actor rejected with 403",
        resp.status_code == 403 and "Unknown actor" in body.get("error", ""),
        f"HTTP {resp.status_code}: {body.get('error', '')}",
    )

    # Unknown actor should NOT have intent_event_id (no ledger write)
    check(
        "No ledger entry for unknown actor",
        "intent_event_id" not in body,
        f"Keys in response: {list(body.keys())}",
    )
    print()

    # =================================================================
    # APPROVED (200) — using valid actor_ids
    # =================================================================
    print("=" * 60)
    print("APPROVED PROPOSALS (expect 200)")
    print("=" * 60)

    run_test(
        "Safe file read (legacy format)",
        {
            "actor_id": "agent:coder",
            "action_type": "file_read",
            "content": "src/main.py",
        },
        expected_status=200,
        expected_decision="APPROVED",
    )

    run_test(
        "Harmless bash command (legacy format)",
        {
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "echo hello world",
        },
        expected_status=200,
        expected_decision="APPROVED",
    )

    # =================================================================
    # PHASE 1.6: ENVELOPE FORMAT
    # =================================================================
    print("=" * 60)
    print("PROPOSAL ENVELOPE FORMAT (Phase 1.6)")
    print("=" * 60)

    envelope_body = run_test(
        "Envelope format -> APPROVED",
        {
            "actor_id": "agent:architect",
            "role": "architect",
            "tier_request": 0,
            "goal": "Read project structure",
            "scope": {"allow_paths": ["src/"], "allow_commands": ["ls"]},
            "expected_outcomes": ["Directory listing"],
            "action": {
                "action_type": "bash",
                "content": "ls -la src/",
            },
        },
        expected_status=200,
        expected_decision="APPROVED",
    )

    # Verify chain_id is a UUID
    chain_id = envelope_body.get("chain_id", "")
    check(
        "chain_id is UUID format",
        len(chain_id) == 36 and chain_id.count("-") == 4,
        f"chain_id: {chain_id}",
    )
    print()

    # =================================================================
    # PHASE 1.6: STRUCTURED POLICY OUTPUT
    # =================================================================
    print("=" * 60)
    print("STRUCTURED POLICY OUTPUT (Phase 1.6)")
    print("=" * 60)

    # APPROVED should have rationale + signals
    resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
        "action_type": "bash",
        "content": "echo test",
    })
    body = resp.json()
    check(
        "APPROVED has rationale[]",
        isinstance(body.get("rationale"), list) and len(body["rationale"]) > 0,
        f"rationale: {body.get('rationale')}",
    )
    check(
        "APPROVED has signals[]",
        isinstance(body.get("signals"), list) and len(body["signals"]) > 0,
        f"signals: {body.get('signals')}",
    )
    check(
        "APPROVED has matched_rules[]",
        isinstance(body.get("matched_rules"), list),
        f"matched_rules: {body.get('matched_rules')}",
    )
    print()

    # DENIED should have rationale + matched_rules + signals
    resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
        "action_type": "file_edit",
        "content": "CONSTITUTION.md",
    })
    body = resp.json()
    check(
        "DENIED has rationale with path info",
        isinstance(body.get("rationale"), list) and len(body["rationale"]) > 0,
        f"rationale: {body.get('rationale')}",
    )
    check(
        "DENIED has matched_rules with section refs",
        isinstance(body.get("matched_rules"), list)
        and any("§" in r for r in body.get("matched_rules", [])),
        f"matched_rules: {body.get('matched_rules')}",
    )
    check(
        "DENIED has signals with risk tokens",
        isinstance(body.get("signals"), list) and len(body["signals"]) > 0,
        f"signals: {body.get('signals')}",
    )
    print()

    # =================================================================
    # PHASE 1.6: ROLE AUTO-FILL
    # =================================================================
    print("=" * 60)
    print("ROLE AUTO-FILL (Phase 1.6)")
    print("=" * 60)

    # Legacy format (no role) -> role filled from identity
    resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:architect",
        "action_type": "file_read",
        "content": "README.md",
    })
    # We can't see the role in the response directly, but we can verify
    # the proposal was accepted (meaning identity validation passed)
    check(
        "Legacy format with no role -> accepted (role auto-filled)",
        resp.status_code == 200,
        f"HTTP {resp.status_code}",
    )
    print()

    # =================================================================
    # ESCALATED (202)
    # =================================================================
    print("=" * 60)
    print("ESCALATED PROPOSALS (expect 202)")
    print("=" * 60)

    run_test(
        "Unproxied curl (gateway bypass)",
        {
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "curl https://api.example.com/data",
        },
        expected_status=202,
        expected_decision="ESCALATED",
    )

    run_test(
        "chmod 777 (operational constraint)",
        {
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "chmod 777 /tmp/myfile",
        },
        expected_status=202,
        expected_decision="ESCALATED",
    )

    # =================================================================
    # DENIED (403)
    # =================================================================
    print("=" * 60)
    print("DENIED PROPOSALS (expect 403)")
    print("=" * 60)

    run_test(
        "sudo rm -rf / (destructive + sudo)",
        {
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "sudo rm -rf /",
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    run_test(
        "Modify CONSTITUTION.md (authority decoupling)",
        {
            "actor_id": "agent:coder",
            "action_type": "file_edit",
            "content": "CONSTITUTION.md",
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    run_test(
        "Write to governance/ (authority decoupling)",
        {
            "actor_id": "agent:coder",
            "action_type": "file_write",
            "content": "governance/policy_engine.py",
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    run_test(
        "Dict content -- sudo + rm -rf in nested payload",
        {
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": {"cmd": "sudo rm -rf /", "reason": "cleanup"},
        },
        expected_status=403,
        expected_decision="DENIED",
    )

    # =================================================================
    # HUMAN APPROVAL FLOW
    # =================================================================
    print("=" * 60)
    print("HUMAN APPROVAL FLOW")
    print("=" * 60)

    # Step 1: Submit an escalatable proposal
    escalated_resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
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
    check(
        f"Missing auth header -> {resp_no_auth.status_code} (expect 422)",
        resp_no_auth.status_code == 422,
    )

    # Test: approve with wrong key -> 401
    resp_bad_key = httpx.post(
        f"{BASE_URL}/approve",
        json={
            "intent_event_id": esc_intent_id,
            "policy_event_id": esc_policy_id,
        },
        headers={"Authorization": "Bearer wrong-key-12345"},
    )
    check(
        f"Invalid API key -> {resp_bad_key.status_code} (expect 401)",
        resp_bad_key.status_code == 401,
    )

    # Test: approve with bogus event IDs -> 404
    resp_bad_id = httpx.post(
        f"{BASE_URL}/approve",
        json={
            "intent_event_id": "00000000-0000-0000-0000-000000000000",
            "policy_event_id": esc_policy_id,
        },
        headers={"Authorization": f"Bearer {HUMAN_API_KEY}"},
    )
    check(
        f"Bogus intent_event_id -> {resp_bad_id.status_code} (expect 404)",
        resp_bad_id.status_code == 404,
    )

    # Test: try to approve a DENIED proposal -> should fail with 422
    denied_resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
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
    check(
        f"Approve DENIED proposal -> {resp_denied_approve.status_code} (expect 422)",
        resp_denied_approve.status_code == 422,
    )

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
    check(
        "Valid approval of ESCALATED proposal",
        ok,
        f"HTTP {resp_approve.status_code}, status={approve_body.get('status')}, "
        f"approval_id={approve_body.get('approval_event_id', 'MISSING')}",
    )
    print()

    # =================================================================
    # PHASE 1.6: LEGACY FORMAT BACKWARD COMPATIBILITY
    # =================================================================
    print("=" * 60)
    print("LEGACY FORMAT BACKWARD COMPATIBILITY (Phase 1.6)")
    print("=" * 60)

    # Legacy format should still work and return chain_id
    resp = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
        "action_type": "bash",
        "content": "echo legacy test",
    })
    body = resp.json()
    check(
        "Legacy format returns chain_id",
        bool(body.get("chain_id")),
        f"chain_id: {body.get('chain_id')}",
    )
    check(
        "Legacy format returns rationale",
        isinstance(body.get("rationale"), list),
        f"rationale: {body.get('rationale')}",
    )
    check(
        "Legacy format returns signals",
        isinstance(body.get("signals"), list),
        f"signals: {body.get('signals')}",
    )
    print()

    # =================================================================
    # CHAIN INTEGRITY CHECK
    # =================================================================
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
    check(
        "Chain integrity after all tests",
        chain_ok and approval_logged,
        f"Total events: {chain[0]}, chain_valid: {chain[1]}, approvals: {approval_count}",
    )
    if not chain_ok:
        print(f"         Break at: {chain[2]}")
    print()

    # =================================================================
    # Summary
    # =================================================================
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
