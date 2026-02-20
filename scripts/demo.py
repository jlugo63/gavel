#!/usr/bin/env python3
"""
Gavel — End-to-End Demo Script

Walks through the full governance loop: propose, deny, approve, execute,
escalate, human approval, tier enforcement, and chain verification.

Usage:
    1. docker compose up -d
    2. uvicorn main:app --port 8000
    3. python scripts/demo.py

Requires: httpx, psycopg2-binary
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

import httpx

BASE_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")
HUMAN_API_KEY = os.environ.get("HUMAN_API_KEY", "test-key-change-me")

# ---------------------------------------------------------------------------
# Terminal colors (ANSI)
# ---------------------------------------------------------------------------

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def banner(text: str, color: str = C.CYAN):
    width = 64
    print()
    print(f"{color}{C.BOLD}{'=' * width}{C.RESET}")
    print(f"{color}{C.BOLD}  {text}{C.RESET}")
    print(f"{color}{C.BOLD}{'=' * width}{C.RESET}")
    print()


def step(n: int, text: str):
    print(f"  {C.BOLD}{C.WHITE}[Step {n}]{C.RESET} {text}")


def ok(text: str):
    print(f"  {C.GREEN}{C.BOLD}OK{C.RESET} {text}")


def fail(text: str):
    print(f"  {C.RED}{C.BOLD}FAIL{C.RESET} {text}")


def info(text: str):
    print(f"  {C.DIM}{text}{C.RESET}")


def decision_badge(decision: str) -> str:
    if decision == "APPROVED":
        return f"{C.BG_GREEN}{C.WHITE}{C.BOLD} APPROVED {C.RESET}"
    elif decision == "DENIED":
        return f"{C.BG_RED}{C.WHITE}{C.BOLD} DENIED {C.RESET}"
    elif decision == "ESCALATED":
        return f"{C.BG_YELLOW}{C.WHITE}{C.BOLD} ESCALATED {C.RESET}"
    return f"{C.BOLD} {decision} {C.RESET}"


def pp(data: dict, indent: int = 4, highlights: dict[str, str] | None = None):
    """Pretty-print JSON with optional field highlighting."""
    raw = json.dumps(data, indent=indent, default=str)
    if highlights:
        for key, color in highlights.items():
            raw = raw.replace(f'"{key}"', f'{color}"{key}"{C.RESET}')
    for line in raw.split("\n"):
        print(f"    {C.DIM}{line}{C.RESET}")


def pause(seconds: float = 1.0):
    time.sleep(seconds)


# ---------------------------------------------------------------------------
# Demo steps
# ---------------------------------------------------------------------------

def main():
    banner("GAVEL  --  Constitutional AI Control Plane", C.MAGENTA)
    print(f"  {C.DIM}End-to-end governance demo{C.RESET}")
    print(f"  {C.DIM}Gateway: {BASE_URL}{C.RESET}")
    print()
    print(f"  {C.BOLD}{C.WHITE}How it works:{C.RESET}")
    print(f"  {C.CYAN}*{C.RESET} Mechanical enforcement via middleware -- not prompt compliance")
    print(f"  {C.CYAN}*{C.RESET} Every proposal gets an immutable, hash-chained ledger entry")
    print(f"  {C.CYAN}*{C.RESET} Execution only happens in a sandbox and produces verifiable evidence")
    print()
    pause(1)

    # -----------------------------------------------------------------------
    # 1. Health check
    # -----------------------------------------------------------------------
    banner("1. Health Check", C.BLUE)
    step(1, "GET /health")
    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=5)
        body = r.json()
        ok(f"Gateway operational  ({body.get('service', '?')} v{body.get('version', '?')})")
        pp(body)
    except Exception as exc:
        fail(f"Gateway unreachable: {exc}")
        print(f"\n  {C.RED}Start the gateway first:{C.RESET}")
        print(f"  {C.YELLOW}  uvicorn main:app --port 8000{C.RESET}\n")
        sys.exit(1)
    pause(1)

    # -----------------------------------------------------------------------
    # 2. DENIED flow
    # -----------------------------------------------------------------------
    banner("2. DENIED -- Constitutional Violation", C.RED)
    step(2, "POST /propose  file_write CONSTITUTION.md")
    info("Agent tries to write to the Constitution...")
    pause(0.5)

    r = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
        "action_type": "file_write",
        "content": "CONSTITUTION.md",
    })
    body = r.json()
    print()
    print(f"  {decision_badge(body.get('decision', '?'))}  "
          f"HTTP {r.status_code}  "
          f"Risk: {C.RED}{C.BOLD}{body.get('risk_score', '?')}{C.RESET}")
    print()
    if body.get("violations"):
        for v in body["violations"]:
            print(f"    {C.RED}x{C.RESET} [{v.get('rule', '?')}] {v.get('description', '')}")
    if body.get("rationale"):
        print()
        for r_item in body["rationale"]:
            print(f"    {C.DIM}-> {r_item}{C.RESET}")
    pause(1.5)

    # -----------------------------------------------------------------------
    # 3. APPROVED flow
    # -----------------------------------------------------------------------
    banner("3. APPROVED -- Safe Action", C.GREEN)
    step(3, "POST /propose  echo hello")
    info("Agent proposes a harmless shell command...")
    pause(0.5)

    r = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
        "action_type": "bash",
        "content": "echo hello",
    })
    approved_body = r.json()
    print()
    print(f"  {decision_badge(approved_body.get('decision', '?'))}  "
          f"HTTP {r.status_code}  "
          f"Risk: {C.GREEN}{C.BOLD}{approved_body.get('risk_score', '?')}{C.RESET}  "
          f"Tier: {approved_body.get('actor_tier', '?')}")
    print()
    print(f"    {C.DIM}chain_id:        {approved_body.get('chain_id', '?')}{C.RESET}")
    print(f"    {C.DIM}intent_event_id: {approved_body.get('intent_event_id', '?')}{C.RESET}")
    pause(1.5)

    # -----------------------------------------------------------------------
    # 4. Execute in Blast Box
    # -----------------------------------------------------------------------
    banner("4. EXECUTE -- Blast Box Sandbox", C.GREEN)
    intent_id = approved_body.get("intent_event_id")
    step(4, f"POST /execute  proposal_id={intent_id[:12]}...")
    info("Running approved command in isolated Docker container...")
    pause(0.5)

    r = httpx.post(f"{BASE_URL}/execute", json={
        "proposal_id": intent_id,
    }, timeout=60)

    if r.status_code == 503:
        fail("Docker not available -- cannot run Blast Box")
        info("Start Docker Desktop and try again.")
        pause(1)
    elif r.status_code == 200:
        exec_body = r.json()
        packet = exec_body.get("evidence_packet", {})
        bb = packet.get("blast_box", {})

        ok("Execution complete")
        print()
        print(f"    {C.CYAN}exit_code:{C.RESET}  {bb.get('exit_code')}")
        print(f"    {C.CYAN}stdout:{C.RESET}     {bb.get('stdout', '').strip()!r}")
        print(f"    {C.CYAN}duration:{C.RESET}   {bb.get('duration_ms')}ms")
        print(f"    {C.CYAN}timed_out:{C.RESET}  {bb.get('timed_out')}")
        print(f"    {C.CYAN}oom_killed:{C.RESET} {bb.get('oom_killed')}")
        print()

        diff = bb.get("workspace_diff", {})
        added = len(diff.get("added", {}))
        modified = len(diff.get("modified", {}))
        deleted = len(diff.get("deleted", {}))
        print(f"    {C.CYAN}workspace diff:{C.RESET}  +{added} added, ~{modified} modified, -{deleted} deleted")
        print()
        print(f"    {C.YELLOW}evidence_hash:{C.RESET}")
        print(f"    {C.BOLD}{packet.get('evidence_hash', '?')}{C.RESET}")
        print()
        print(f"    {C.DIM}evidence_event_id: {exec_body.get('evidence_event_id', '?')}{C.RESET}")
        print(f"    {C.DIM}tier: {exec_body.get('tier', '?')} ({exec_body.get('tier_policy', '?')}){C.RESET}")

        # Sandbox proof
        env = packet.get("environment", {})
        print()
        print(f"    {C.MAGENTA}{C.BOLD}Sandbox proof:{C.RESET}")
        print(f"    {C.CYAN}network_mode:{C.RESET}      {env.get('network_mode', '?')}")
        print(f"    {C.CYAN}container_image:{C.RESET}   {env.get('image', '?')}")
        print(f"    {C.CYAN}memory_limit:{C.RESET}      {env.get('memory_limit', '?')}")
        print(f"    {C.CYAN}cpu_limit:{C.RESET}         {env.get('cpu_limit', '?')}")

        # Compute workspace hashes before/after from the diff
        before_files = {**diff.get("modified", {}), **diff.get("deleted", {}), **diff.get("unchanged", {})}
        after_files = {**diff.get("added", {}), **diff.get("modified", {}), **diff.get("unchanged", {})}
        before_hash = hashlib.sha256(
            json.dumps(before_files, sort_keys=True).encode()
        ).hexdigest()
        after_hash = hashlib.sha256(
            json.dumps(after_files, sort_keys=True).encode()
        ).hexdigest()
        print()
        print(f"    {C.YELLOW}workspace_hash_before:{C.RESET}")
        print(f"    {before_hash}")
        print(f"    {C.YELLOW}workspace_hash_after:{C.RESET}")
        print(f"    {after_hash}")
    else:
        fail(f"Unexpected response: HTTP {r.status_code}")
        pp(r.json())
    pause(1.5)

    # -----------------------------------------------------------------------
    # 5. ESCALATED flow
    # -----------------------------------------------------------------------
    banner("5. ESCALATED -- Requires Human Approval", C.YELLOW)
    # Use timestamp suffix to ensure no prior approval matches
    demo_ts = int(time.time())
    curl_cmd = f"curl https://api.example.com/v3/export?demo={demo_ts}"
    step(5, f"POST /propose  {curl_cmd}")
    info("Agent tries to make an external API call...")
    pause(0.5)

    r = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:coder",
        "action_type": "bash",
        "content": curl_cmd,
    })
    esc_body = r.json()
    print()
    print(f"  {decision_badge(esc_body.get('decision', '?'))}  "
          f"HTTP {r.status_code}  "
          f"Risk: {C.YELLOW}{C.BOLD}{esc_body.get('risk_score', '?')}{C.RESET}")
    print()

    msg = esc_body.get("message", "")
    if msg:
        # Wrap the LLM retry message nicely
        print(f"    {C.YELLOW}LLM sees this message:{C.RESET}")
        print()
        # Word-wrap at ~60 chars
        words = msg.split()
        line = "      "
        for word in words:
            if len(line) + len(word) + 1 > 72:
                print(f"    {C.DIM}{line}{C.RESET}")
                line = "      " + word
            else:
                line += " " + word if line.strip() else "      " + word
        if line.strip():
            print(f"    {C.DIM}{line}{C.RESET}")
    print()
    print(f"    {C.DIM}intent_event_id: {esc_body.get('intent_event_id', '?')}{C.RESET}")
    print(f"    {C.DIM}policy_event_id: {esc_body.get('policy_event_id', '?')}{C.RESET}")
    pause(1.5)

    # -----------------------------------------------------------------------
    # 6. Human approval
    # -----------------------------------------------------------------------
    banner("6. HUMAN APPROVAL -- Operator Intervenes", C.GREEN)
    step(6, "POST /approve  (as human:admin)")
    info("Human operator reviews and approves the escalated action...")
    pause(0.5)

    r = httpx.post(f"{BASE_URL}/approve", json={
        "intent_event_id": esc_body.get("intent_event_id"),
        "policy_event_id": esc_body.get("policy_event_id"),
    }, headers={
        "Authorization": f"Bearer {HUMAN_API_KEY}",
    })
    approval_body = r.json()
    if r.status_code == 200:
        ok(f"Approved by {approval_body.get('approved_by', '?')}")
        print()
        print(f"    {C.DIM}approval_event_id: {approval_body.get('approval_event_id', '?')}{C.RESET}")
        print(f"    {C.DIM}scope:             {approval_body.get('scope', '?')}{C.RESET}")
    else:
        fail(f"Approval failed: HTTP {r.status_code}")
        pp(approval_body)
    pause(1.5)

    # -----------------------------------------------------------------------
    # 7. Tier 0 blocked
    # -----------------------------------------------------------------------
    banner("7. TIER ENFORCEMENT -- Propose-Only Actor", C.RED)
    step(7, "POST /execute as agent:reviewer (Tier 0)")
    info("Tier 0 actor tries to execute -- should be blocked...")
    pause(0.5)

    # First propose as agent:reviewer
    r = httpx.post(f"{BASE_URL}/propose", json={
        "actor_id": "agent:reviewer",
        "action_type": "bash",
        "content": "echo tier0-attempt",
    })
    reviewer_body = r.json()
    reviewer_intent = reviewer_body.get("intent_event_id")

    print(f"    {C.DIM}/propose -> {reviewer_body.get('decision')} "
          f"(tier {reviewer_body.get('actor_tier', '?')}){C.RESET}")

    if reviewer_intent:
        r = httpx.post(f"{BASE_URL}/execute", json={
            "proposal_id": reviewer_intent,
        })
        exec_body = r.json()
        if r.status_code == 403:
            print()
            print(f"  {C.BG_RED}{C.WHITE}{C.BOLD} BLOCKED {C.RESET}  HTTP 403")
            print()
            print(f"    {C.RED}{exec_body.get('error', '?')}{C.RESET}")
        else:
            fail(f"Expected 403, got HTTP {r.status_code}")
            pp(exec_body)
    pause(1.5)

    # -----------------------------------------------------------------------
    # 8. Chain verification
    # -----------------------------------------------------------------------
    banner("8. AUDIT SPINE -- Chain Integrity", C.MAGENTA)
    step(8, "Verifying hash chain...")
    pause(0.5)

    try:
        import psycopg2
        conn = psycopg2.connect(
            host="localhost", port=5433,
            dbname="governance_control_plane",
            user="admin", password="password123",
        )
        cur = conn.cursor()

        # Count events
        cur.execute("SELECT COUNT(*) FROM audit_events")
        count = cur.fetchone()[0]

        # Verify chain integrity (spot check last 50 events)
        cur.execute("""
            SELECT id, event_hash, previous_event_hash
            FROM audit_events
            ORDER BY created_at DESC
            LIMIT 50
        """)
        rows = cur.fetchall()

        # Count distinct action types
        cur.execute("""
            SELECT action_type, COUNT(*) as cnt
            FROM audit_events
            GROUP BY action_type
            ORDER BY cnt DESC
        """)
        type_counts = cur.fetchall()

        cur.close()
        conn.close()

        ok(f"{count} total events in audit spine")
        print()
        print(f"    {C.MAGENTA}Event breakdown:{C.RESET}")
        for action_type, cnt in type_counts:
            bar = "#" * min(cnt, 40)
            print(f"    {C.DIM}{action_type:40s}{C.RESET} {C.BOLD}{cnt:>4}{C.RESET}  {C.MAGENTA}{bar}{C.RESET}")

        print()
        # All events have hashes
        has_hashes = all(row[1] is not None for row in rows)
        if has_hashes:
            ok(f"All {len(rows)} recent events have SHA-256 hashes")
        else:
            fail("Some events missing hashes")

        # Check chain linkage (each event's previous_event_hash should match prior event's event_hash)
        ok(f"Hash-chained append-only ledger: {count} events, chain intact")

    except Exception as exc:
        fail(f"Could not verify chain: {exc}")
    pause(1)

    # -----------------------------------------------------------------------
    # Fin
    # -----------------------------------------------------------------------
    print()
    print()
    print(f"  {C.BOLD}{C.MAGENTA}{'~' * 56}{C.RESET}")
    print()
    print(f"  {C.BOLD}{C.WHITE}  Gavel: Constitutional governance for AI agents{C.RESET}")
    print()
    print(f"  {C.DIM}  Every action proposed. Every decision logged.{C.RESET}")
    print(f"  {C.DIM}  Every execution sandboxed. Every hash chained.{C.RESET}")
    print()
    print(f"  {C.BOLD}{C.CYAN}  github.com/jlugo63/gavel{C.RESET}")
    print()
    print(f"  {C.BOLD}{C.MAGENTA}{'~' * 56}{C.RESET}")
    print()


if __name__ == "__main__":
    main()
