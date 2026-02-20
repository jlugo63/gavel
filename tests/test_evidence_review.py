"""
Deterministic Evidence Review Test Suite
Tests scope enforcement, forbidden paths, secret detection, dependency changes,
risk delta calculation, and audit spine integration.

Usage:
    1. Start DB:      docker compose up -d
    2. Run tests:     python tests/test_evidence_review.py  (from project root)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from governance.evidence import EvidencePacket
from governance.evidence_review import (
    ReviewFinding,
    ReviewResult,
    review_scope,
    review_forbidden_paths,
    review_secrets,
    review_dependencies,
    review_evidence,
    log_review_to_spine,
    RISK_DELTA_MAP,
    RISK_MAP_VERSION_HASH,
)
from governance.audit import AuditSpineManager

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


def make_packet(
    workspace_diff=None,
    stdout="",
    stderr="",
) -> EvidencePacket:
    if workspace_diff is None:
        workspace_diff = {"added": {}, "modified": {}, "deleted": {}, "unchanged": {}}
    return EvidencePacket(
        proposal_id="test-proposal",
        chain_id="test-chain",
        actor_id="agent:coder",
        action_type="bash",
        command="echo test",
        blast_box={
            "exit_code": 0,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": 100,
            "workspace_diff": workspace_diff,
            "timed_out": False,
            "oom_killed": False,
        },
        environment={
            "image": "python:3.12-slim",
            "network_mode": "none",
            "memory_limit": "256m",
            "cpu_limit": 1.0,
            "timeout_seconds": 30,
        },
        created_at="2026-02-19T00:00:00+00:00",
        evidence_hash="a" * 64,
    )


def main() -> bool:
    global passed, failed

    # ================================================================
    # SCOPE ENFORCEMENT TESTS
    # ================================================================
    print("=" * 60)
    print("SCOPE ENFORCEMENT TESTS")
    print("=" * 60)

    # Test 1: Clean evidence packet -> passed=True, no findings
    print("\n--- Test 1: Clean packet -> pass, no findings ---")
    packet = make_packet()
    result = review_evidence(packet, allow_paths=["src/"])
    check("result.passed is True", result.passed is True)
    check("no findings", len(result.findings) == 0)
    check("scope_compliant is True", result.scope_compliant is True)
    check("risk_delta is 0.0", result.risk_delta == 0.0,
          f"got {result.risk_delta}")

    # Test 2: File outside allow_paths -> scope_violation
    print("\n--- Test 2: File outside allow_paths -> scope_violation ---")
    diff = {
        "added": {"outside/hack.py": "abc123"},
        "modified": {},
        "deleted": {},
        "unchanged": {},
    }
    findings = review_scope(diff, ["src/"])
    check("one scope finding", len(findings) == 1,
          f"got {len(findings)}")
    if findings:
        check("category == scope_violation",
              findings[0].category == "scope_violation",
              f"got {findings[0].category}")
        check("severity == high",
              findings[0].severity == "high",
              f"got {findings[0].severity}")

    # ================================================================
    # FORBIDDEN PATH TESTS
    # ================================================================
    print()
    print("=" * 60)
    print("FORBIDDEN PATH TESTS")
    print("=" * 60)

    # Test 3: CONSTITUTION.md -> forbidden_path, critical
    print("\n--- Test 3: CONSTITUTION.md -> forbidden_path, critical ---")
    diff = {
        "added": {},
        "modified": {"CONSTITUTION.md": "abc123"},
        "deleted": {},
        "unchanged": {},
    }
    findings = review_forbidden_paths(diff)
    check("at least one finding", len(findings) >= 1,
          f"got {len(findings)}")
    has_constitution = any(
        f.category == "forbidden_path"
        and f.severity == "critical"
        and "CONSTITUTION" in (f.file_path or "")
        for f in findings
    )
    check("forbidden_path critical for CONSTITUTION", has_constitution)

    # Test 4: .env -> forbidden_path, critical
    print("\n--- Test 4: .env -> forbidden_path, critical ---")
    diff = {
        "added": {".env": "abc123"},
        "modified": {},
        "deleted": {},
        "unchanged": {},
    }
    findings = review_forbidden_paths(diff)
    check("at least one finding", len(findings) >= 1,
          f"got {len(findings)}")
    has_env = any(
        f.category == "forbidden_path" and f.severity == "critical"
        for f in findings
    )
    check("forbidden_path critical for .env", has_env)

    # ================================================================
    # SECRET EXPOSURE TESTS
    # ================================================================
    print()
    print("=" * 60)
    print("SECRET EXPOSURE TESTS")
    print("=" * 60)

    # Test 5: AWS key in stdout -> secret_exposure, critical
    print("\n--- Test 5: AWS key in stdout -> secret_exposure ---")
    findings = review_secrets("Found key: AKIAIOSFODNN7EXAMPLE", "")
    check("at least one finding", len(findings) >= 1,
          f"got {len(findings)}")
    has_aws = any(
        f.category == "secret_exposure"
        and f.severity == "critical"
        and "AWS" in (f.description or "")
        for f in findings
    )
    check("secret_exposure critical with AWS", has_aws)

    # Test 6: GitHub token in stderr -> secret_exposure, critical
    print("\n--- Test 6: GitHub token in stderr -> secret_exposure ---")
    findings = review_secrets(
        "", "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
    )
    check("at least one finding", len(findings) >= 1,
          f"got {len(findings)}")
    has_github = any(
        f.category == "secret_exposure"
        and f.severity == "critical"
        and "GitHub" in (f.description or "")
        for f in findings
    )
    check("secret_exposure critical with GitHub", has_github)

    # ================================================================
    # DEPENDENCY CHANGE TESTS
    # ================================================================
    print()
    print("=" * 60)
    print("DEPENDENCY CHANGE TESTS")
    print("=" * 60)

    # Test 7: package-lock.json modified -> dependency_change, medium
    print("\n--- Test 7: package-lock.json -> dependency_change ---")
    diff = {
        "added": {},
        "modified": {"package-lock.json": "abc123"},
        "deleted": {},
        "unchanged": {},
    }
    findings = review_dependencies(diff)
    check("one finding", len(findings) == 1,
          f"got {len(findings)}")
    if findings:
        check("category == dependency_change",
              findings[0].category == "dependency_change",
              f"got {findings[0].category}")
        check("severity == medium",
              findings[0].severity == "medium",
              f"got {findings[0].severity}")

    # ================================================================
    # RISK DELTA TESTS
    # ================================================================
    print()
    print("=" * 60)
    print("RISK DELTA TESTS")
    print("=" * 60)

    # Test 8: Multiple findings -> risk_delta sums correctly, capped at 1.0
    print("\n--- Test 8: Multiple findings -> risk_delta capped at 1.0 ---")
    diff = {
        "added": {
            "outside/rogue.py": "abc123",
            "requirements.txt": "def456",
        },
        "modified": {"CONSTITUTION.md": "abc123"},
        "deleted": {},
        "unchanged": {},
    }
    packet = make_packet(
        workspace_diff=diff,
        stdout="Found key: AKIAIOSFODNN7EXAMPLE",
    )
    result = review_evidence(packet, allow_paths=["src/"])
    # forbidden(0.5) + secret(0.5) + dependency(0.1) + scope(0.3) = 1.4 -> capped at 1.0
    check("risk_delta capped at 1.0", result.risk_delta == 1.0,
          f"got {result.risk_delta}")

    # Test 9: Critical finding -> passed=False
    print("\n--- Test 9: Critical finding -> passed=False ---")
    diff = {
        "added": {},
        "modified": {"CONSTITUTION.md": "abc123"},
        "deleted": {},
        "unchanged": {},
    }
    packet = make_packet(workspace_diff=diff)
    result = review_evidence(packet)
    check("result.passed is False", result.passed is False,
          f"got passed={result.passed}")

    # Test 10: Only medium findings -> passed=True
    print("\n--- Test 10: Only medium findings -> passed=True ---")
    diff = {
        "added": {},
        "modified": {"package-lock.json": "abc123"},
        "deleted": {},
        "unchanged": {},
    }
    packet = make_packet(workspace_diff=diff)
    result = review_evidence(packet)
    check("result.passed is True", result.passed is True,
          f"got passed={result.passed}")
    check("has findings", len(result.findings) > 0,
          f"got {len(result.findings)} findings")

    # ================================================================
    # INTEGRATION TESTS
    # ================================================================
    print()
    print("=" * 60)
    print("INTEGRATION TESTS")
    print("=" * 60)

    # Test 11: Review event logged to audit spine as EVIDENCE_REVIEW_DETERMINISTIC
    print("\n--- Test 11: log_review_to_spine -> EVIDENCE_REVIEW_DETERMINISTIC ---")
    audit = AuditSpineManager()
    packet = make_packet()
    result = review_evidence(packet)
    event_id = log_review_to_spine(audit, packet, result)
    check("event_id returned", event_id is not None and len(event_id) > 0,
          f"got {event_id!r}")

    event = audit.get_event(event_id)
    check("event exists in spine", event is not None)
    if event:
        check("action_type == EVIDENCE_REVIEW_DETERMINISTIC",
              event["action_type"] == "EVIDENCE_REVIEW_DETERMINISTIC",
              f"got {event['action_type']!r}")
        payload = event.get("intent_payload", {})
        if isinstance(payload, str):
            import json as _json
            payload = _json.loads(payload)
        check("payload contains 'passed'", "passed" in payload,
              f"keys: {list(payload.keys())}")
        check("payload contains 'risk_delta'", "risk_delta" in payload,
              f"keys: {list(payload.keys())}")
        check("payload contains 'risk_map_version_hash'",
              "risk_map_version_hash" in payload,
              f"keys: {list(payload.keys())}")

    # Test 12: Risk map version hash is deterministic
    print("\n--- Test 12: RISK_MAP_VERSION_HASH is deterministic ---")
    recomputed = hashlib.sha256(
        json.dumps(RISK_DELTA_MAP, sort_keys=True).encode()
    ).hexdigest()
    check("recomputed hash matches RISK_MAP_VERSION_HASH",
          recomputed == RISK_MAP_VERSION_HASH,
          f"expected {recomputed}, got {RISK_MAP_VERSION_HASH}")
    check("hash is 64 hex chars",
          len(RISK_MAP_VERSION_HASH) == 64,
          f"got length {len(RISK_MAP_VERSION_HASH)}")

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
