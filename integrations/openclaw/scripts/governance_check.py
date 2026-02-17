#!/usr/bin/env python3
"""
Governance Check — OpenClaw Skill Script

Intercepts proposed agent actions and routes them through the
Constitutional AI Governance Gateway for policy evaluation.

Exit codes:
    0 — APPROVED (action may proceed)
    1 — DENIED   (action blocked)
    2 — ESCALATED and user declined approval
    3 — Error communicating with the gateway
"""

from __future__ import annotations

import json
import os
import sys

# Ensure the project root is importable so governance_sdk resolves
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from governance_sdk import GovernanceClient


def main() -> int:
    gateway_url = os.environ.get("GOVERNANCE_GATEWAY_URL", "http://localhost:8000")
    actor_id = os.environ.get("GOVERNANCE_ACTOR_ID", "agent:openclaw")
    api_key = os.environ.get("HUMAN_API_KEY", "")

    # ---- Parse input from OpenClaw ----
    # OpenClaw passes the action context as a JSON blob on stdin.
    # Expected shape: {"action_type": "bash", "content": "echo hello"}
    raw_input = sys.stdin.read().strip()
    if not raw_input:
        # Fallback: read from CLI args
        if len(sys.argv) >= 3:
            action_type = sys.argv[1]
            content = sys.argv[2]
        else:
            print("[governance] ERROR: No action provided via stdin or args.", file=sys.stderr)
            return 3
    else:
        try:
            payload = json.loads(raw_input)
            action_type = payload["action_type"]
            content = payload["content"]
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"[governance] ERROR: Invalid input — {exc}", file=sys.stderr)
            return 3

    # ---- Submit proposal ----
    client = GovernanceClient(
        gateway_url=gateway_url,
        actor_id=actor_id,
        api_key=api_key or None,
    )

    try:
        result = client.propose(action_type, content)
    except Exception as exc:
        print(f"[governance] ERROR: Gateway unreachable — {exc}", file=sys.stderr)
        return 3

    # ---- Handle decision ----
    if result.decision == "APPROVED":
        print(f"[governance] APPROVED (risk={result.risk_score})")
        return 0

    if result.decision == "DENIED":
        print(f"[governance] DENIED (risk={result.risk_score})")
        for v in result.violations:
            rule = v.get("rule", "unknown")
            desc = v.get("description", "")
            print(f"  - [{rule}] {desc}")
        return 1

    if result.decision == "ESCALATED":
        print(f"[governance] ESCALATED (risk={result.risk_score})")
        print(f"  Intent:  {result.intent_event_id}")
        print(f"  Policy:  {result.policy_event_id}")

        if not api_key:
            print("[governance] No HUMAN_API_KEY set — cannot approve. Blocking action.")
            return 2

        # Prompt user for approval
        print()
        try:
            answer = input("Approve this action? [y/N] ").strip().lower()
        except EOFError:
            answer = "n"

        if answer in ("y", "yes"):
            approval = client.approve(result.intent_event_id, result.policy_event_id)
            if approval.success:
                print(f"[governance] APPROVED by human (event={approval.event_id})")
                return 0
            else:
                print(f"[governance] Approval failed: {approval.raw}")
                return 2
        else:
            print("[governance] User declined. Action blocked.")
            return 2

    # Unknown decision
    print(f"[governance] UNKNOWN decision: {result.decision}", file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main())
