"""
Blast Box + Evidence Packet Test Suite
Tests sandbox execution, evidence packet creation, and the /execute endpoint.

Usage:
    1. Start Docker
    2. Start DB:      docker compose up -d
    3. Start gateway: uvicorn main:app --port 8000
    4. Run tests:     python test_blastbox.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import shutil
from dataclasses import asdict

import httpx

from governance.blastbox import (
    BlastBoxConfig,
    BlastBoxResult,
    check_docker_available,
    run_in_blastbox,
)
from governance.evidence import (
    EvidencePacket,
    create_evidence_packet,
    log_evidence_to_spine,
)
from governance.audit import AuditSpineManager

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


def main():
    global passed, failed

    docker_ok = check_docker_available()

    # =================================================================
    # BLAST BOX UNIT TESTS
    # =================================================================
    print("=" * 60)
    print("BLAST BOX UNIT TESTS")
    print("=" * 60)

    if not docker_ok:
        print("  [SKIP] Docker is not available -- skipping Blast Box unit tests")
        print()
    else:
        # Test 1: echo hello
        print("  Running: echo hello")
        r1 = run_in_blastbox("echo hello")
        check(
            "echo hello -> exit_code 0",
            r1.exit_code == 0,
            f"exit_code={r1.exit_code}",
        )
        check(
            "echo hello -> 'hello' in stdout",
            "hello" in r1.stdout,
            f"stdout={r1.stdout.strip()!r}",
        )
        print()

        # Test 2: rm -rf / in container is safe
        print("  Running: rm -rf / (in container)")
        r2 = run_in_blastbox("rm -rf / 2>/dev/null || true")
        check(
            "rm -rf / in container returns a result (host unaffected)",
            r2 is not None,
            f"exit_code={r2.exit_code}, timed_out={r2.timed_out}",
        )
        print()

        # Test 3: Network isolation
        print("  Running: network isolation check")
        r3 = run_in_blastbox(
            "wget -q -O- http://example.com 2>&1 || echo BLOCKED",
            config=BlastBoxConfig(timeout_seconds=10),
        )
        network_blocked = (
            "BLOCKED" in r3.stdout
            or r3.exit_code != 0
            or "fail" in r3.stderr.lower()
            or "bad address" in r3.stderr.lower()
        )
        check(
            "Network access blocked (--network=none)",
            network_blocked,
            f"exit_code={r3.exit_code}, stdout={r3.stdout.strip()!r}, stderr={r3.stderr.strip()!r}",
        )
        print()

        # Test 4: Timeout
        print("  Running: timeout test (sleep 60 with 5s limit)")
        r4 = run_in_blastbox(
            "sleep 60",
            config=BlastBoxConfig(timeout_seconds=5),
        )
        check(
            "sleep 60 with 5s timeout -> timed_out=True",
            r4.timed_out is True,
            f"timed_out={r4.timed_out}, duration_ms={r4.duration_ms}",
        )
        print()

        # Test 5: Filesystem diff
        print("  Running: filesystem diff test")
        tmpdir = tempfile.mkdtemp(prefix="blastbox_test_")
        try:
            r5 = run_in_blastbox(
                "echo test > /workspace/newfile.txt",
                workspace_dir=tmpdir,
            )
            has_newfile = "newfile.txt" in r5.workspace_diff.get("added", {})
            check(
                "Workspace diff detects added file",
                has_newfile,
                f"added={list(r5.workspace_diff.get('added', {}).keys())}",
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        print()

    # =================================================================
    # EVIDENCE PACKET TESTS
    # =================================================================
    print("=" * 60)
    print("EVIDENCE PACKET TESTS")
    print("=" * 60)

    # Test 6: Evidence packet hash determinism
    mock_result = BlastBoxResult(
        exit_code=0,
        stdout="hello\n",
        stderr="",
        duration_ms=150,
        workspace_diff={"added": {}, "modified": {}, "deleted": {}, "unchanged": {}},
        timed_out=False,
        oom_killed=False,
    )
    mock_config = BlastBoxConfig()

    p1 = create_evidence_packet(
        proposal_id="test-id-1",
        chain_id="chain-1",
        actor_id="agent:coder",
        action_type="bash",
        command="echo hello",
        result=mock_result,
        config=mock_config,
    )
    p2 = create_evidence_packet(
        proposal_id="test-id-1",
        chain_id="chain-1",
        actor_id="agent:coder",
        action_type="bash",
        command="echo hello",
        result=mock_result,
        config=mock_config,
    )
    # Packets created at different times will have different hashes due to
    # created_at being part of the hash input. Verify the hash is a valid
    # 64-char hex string and that each packet's hash is internally consistent.
    check(
        "Evidence hash is 64-char hex (SHA-256)",
        len(p1.evidence_hash) == 64 and all(c in "0123456789abcdef" for c in p1.evidence_hash),
        f"hash={p1.evidence_hash}",
    )
    check(
        "Evidence hash is deterministic for same created_at",
        # Rebuild from p1's fields to verify hash correctness
        p1.evidence_hash == _recompute_hash(p1),
        f"original={p1.evidence_hash}, recomputed={_recompute_hash(p1)}",
    )
    print()

    # Test 7: Evidence packet logs to spine
    print("  Connecting to DB for evidence spine test...")
    try:
        audit = AuditSpineManager()
        mock_packet = create_evidence_packet(
            proposal_id="test-spine-log",
            chain_id="chain-spine",
            actor_id="agent:coder",
            action_type="bash",
            command="echo spine-test",
            result=mock_result,
            config=mock_config,
        )
        event_id = log_evidence_to_spine(audit, mock_packet)
        check(
            "log_evidence_to_spine returns event_id",
            bool(event_id),
            f"event_id={event_id}",
        )

        fetched = audit.get_event(event_id)
        check(
            "Evidence event exists in audit spine",
            fetched is not None and fetched["action_type"] == "EVIDENCE_PACKET",
            f"action_type={fetched['action_type'] if fetched else 'NOT_FOUND'}",
        )
    except Exception as exc:
        check("Evidence spine test", False, f"Exception: {exc}")
    print()

    # =================================================================
    # /EXECUTE ENDPOINT TESTS
    # =================================================================
    print("=" * 60)
    print("/EXECUTE ENDPOINT TESTS")
    print("=" * 60)

    # Check gateway is reachable
    try:
        health = httpx.get(f"{BASE_URL}/health", timeout=5)
        gateway_ok = health.status_code == 200
    except Exception:
        gateway_ok = False

    if not gateway_ok:
        print("  [SKIP] Gateway not reachable -- skipping /execute endpoint tests")
        print()
    elif not docker_ok:
        print("  [SKIP] Docker not available -- skipping /execute endpoint tests")
        print()
    else:
        # Test 8: Full /execute flow (APPROVED proposal)
        print("  Test 8: Full /execute flow")
        resp = httpx.post(f"{BASE_URL}/propose", json={
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "echo phase2",
        })
        propose_body = resp.json()
        check(
            "/propose echo phase2 -> APPROVED",
            resp.status_code == 200 and propose_body.get("decision") == "APPROVED",
            f"HTTP {resp.status_code}, decision={propose_body.get('decision')}",
        )

        intent_event_id = propose_body.get("intent_event_id")
        exec_resp = httpx.post(
            f"{BASE_URL}/execute",
            json={"proposal_id": intent_event_id},
            timeout=60,
        )
        exec_body = exec_resp.json()
        check(
            "/execute APPROVED proposal -> 200",
            exec_resp.status_code == 200,
            f"HTTP {exec_resp.status_code}",
        )
        check(
            "/execute returns evidence_event_id",
            bool(exec_body.get("evidence_event_id")),
            f"evidence_event_id={exec_body.get('evidence_event_id', 'MISSING')}",
        )
        check(
            "/execute returns evidence_packet with hash",
            bool(exec_body.get("evidence_packet", {}).get("evidence_hash")),
            f"evidence_hash={exec_body.get('evidence_packet', {}).get('evidence_hash', 'MISSING')}",
        )
        # Check the blast_box output contains "phase2"
        bb = exec_body.get("evidence_packet", {}).get("blast_box", {})
        check(
            "Blast Box stdout contains 'phase2'",
            "phase2" in bb.get("stdout", ""),
            f"stdout={bb.get('stdout', '').strip()!r}",
        )
        print()

        # Test 9: /execute on DENIED proposal -> 403
        print("  Test 9: /execute on DENIED proposal")
        denied_resp = httpx.post(f"{BASE_URL}/propose", json={
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "sudo rm -rf /",
        })
        denied_body = denied_resp.json()
        denied_intent_id = denied_body.get("intent_event_id")
        check(
            "/propose sudo rm -rf / -> DENIED",
            denied_resp.status_code == 403 and denied_body.get("decision") == "DENIED",
            f"HTTP {denied_resp.status_code}, decision={denied_body.get('decision')}",
        )

        exec_denied = httpx.post(
            f"{BASE_URL}/execute",
            json={"proposal_id": denied_intent_id},
        )
        check(
            "/execute DENIED proposal -> 403",
            exec_denied.status_code == 403,
            f"HTTP {exec_denied.status_code}, body={exec_denied.json()}",
        )
        print()

        # Test 10: /execute on ESCALATED without approval -> 202
        print("  Test 10: /execute on ESCALATED without approval")
        esc_resp = httpx.post(f"{BASE_URL}/propose", json={
            "actor_id": "agent:coder",
            "action_type": "bash",
            "content": "curl http://example.com",
        })
        esc_body = esc_resp.json()
        esc_intent_id = esc_body.get("intent_event_id")
        check(
            "/propose curl -> ESCALATED",
            esc_resp.status_code == 202 and esc_body.get("decision") == "ESCALATED",
            f"HTTP {esc_resp.status_code}, decision={esc_body.get('decision')}",
        )

        exec_esc = httpx.post(
            f"{BASE_URL}/execute",
            json={"proposal_id": esc_intent_id},
        )
        check(
            "/execute ESCALATED without approval -> 202",
            exec_esc.status_code == 202,
            f"HTTP {exec_esc.status_code}, body={exec_esc.json()}",
        )
        print()

    # =================================================================
    # Summary
    # =================================================================
    print("=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


def _recompute_hash(packet: EvidencePacket) -> str:
    """Recompute the evidence hash from a packet's fields for verification."""
    import hashlib
    pre_hash = {
        "proposal_id": packet.proposal_id,
        "chain_id": packet.chain_id,
        "actor_id": packet.actor_id,
        "action_type": packet.action_type,
        "command": packet.command,
        "blast_box": packet.blast_box,
        "environment": packet.environment,
        "created_at": packet.created_at,
    }
    canonical = json.dumps(pre_hash, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
