"""
Governance Gateway Test Suite
Sends proposals to the live /propose endpoint and verifies
correct HTTP status codes and response structure.

Usage:
    1. Start the gateway:  uvicorn main:app --port 8000
    2. Run tests:          python test_gateway.py
"""

from __future__ import annotations

import sys

import httpx

BASE_URL = "http://localhost:8000"

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

    # ----- Summary -----
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
