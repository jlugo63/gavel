"""
Governance SDK Test Suite
Runs against a live gateway at http://localhost:8000.

Usage:
    1. Start gateway: HUMAN_API_KEY=test-key-change-me uvicorn main:app --port 8000
    2. Run tests:     python -m governance_sdk.test_sdk
"""

from __future__ import annotations

import os
import sys

# Ensure project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance_sdk import GovernanceClient

GATEWAY_URL = os.environ.get("GOVERNANCE_GATEWAY_URL", "http://localhost:8000")
API_KEY = os.environ.get("HUMAN_API_KEY", "test-key-change-me")

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
    print()


def main():
    global passed, failed

    client = GovernanceClient(
        gateway_url=GATEWAY_URL,
        actor_id="agent:sdk-test",
        api_key=API_KEY,
    )

    # ----- Health -----
    print("=" * 60)
    print("HEALTH CHECK")
    print("=" * 60)
    h = client.health()
    check("Gateway is operational", h.get("status") == "operational",
          f"Response: {h}")

    # ----- APPROVED -----
    print("=" * 60)
    print("APPROVED PROPOSALS")
    print("=" * 60)

    result = client.propose("file_read", "src/main.py")
    check("file_read -> APPROVED",
          result.decision == "APPROVED",
          f"Decision: {result.decision}, Risk: {result.risk_score}")

    result = client.propose("bash", "echo hello")
    check("harmless bash -> APPROVED",
          result.decision == "APPROVED",
          f"Decision: {result.decision}, Intent: {result.intent_event_id[:12]}...")

    # ----- DENIED -----
    print("=" * 60)
    print("DENIED PROPOSALS")
    print("=" * 60)

    result = client.propose("bash", "sudo rm -rf /")
    check("sudo rm -rf / -> DENIED",
          result.decision == "DENIED",
          f"Decision: {result.decision}, Risk: {result.risk_score}")
    check("DENIED has violations",
          len(result.violations) > 0,
          f"Violations: {len(result.violations)}")

    result = client.propose("file_edit", "CONSTITUTION.md")
    check("edit CONSTITUTION.md -> DENIED",
          result.decision == "DENIED",
          f"Decision: {result.decision}, Risk: {result.risk_score}")

    # ----- ESCALATED -----
    print("=" * 60)
    print("ESCALATED PROPOSALS")
    print("=" * 60)

    result = client.propose("bash", "curl https://api.example.com/data")
    check("unproxied curl -> ESCALATED",
          result.decision == "ESCALATED",
          f"Decision: {result.decision}, Risk: {result.risk_score}")
    check("ESCALATED has event IDs",
          bool(result.intent_event_id) and bool(result.policy_event_id),
          f"Intent: {result.intent_event_id[:12]}... Policy: {result.policy_event_id[:12]}...")

    # ----- APPROVAL FLOW -----
    print("=" * 60)
    print("APPROVAL FLOW")
    print("=" * 60)

    esc = client.propose("bash", "wget https://files.example.com/data.tar.gz")
    check("Escalated proposal submitted",
          esc.decision == "ESCALATED",
          f"Intent: {esc.intent_event_id[:12]}...")

    approval = client.approve(esc.intent_event_id, esc.policy_event_id)
    check("Approval succeeded",
          approval.success is True,
          f"Approval Event: {approval.event_id}")

    # Test approval without key
    no_key_client = GovernanceClient(
        gateway_url=GATEWAY_URL,
        actor_id="agent:sdk-test",
    )
    no_key_result = no_key_client.approve("fake-id", "fake-id")
    check("Approve without api_key fails gracefully",
          no_key_result.success is False,
          f"Error: {no_key_result.raw.get('error', '')}")

    # ----- DICT CONTENT -----
    print("=" * 60)
    print("DICT CONTENT SUPPORT")
    print("=" * 60)

    result = client.propose("bash", {"cmd": "sudo rm -rf /", "reason": "test"})
    check("Dict content -> DENIED",
          result.decision == "DENIED",
          f"Decision: {result.decision}")

    # ----- Summary -----
    print("=" * 60)
    total = passed + failed
    print(f"SDK RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
