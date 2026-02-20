#!/usr/bin/env python3
"""
Multi-Agent Stress Test
Simulates 20 concurrent agents hitting the Gavel Governance Gateway.

Behavior profiles:
  - agent:coder-1..5     (tier 1) — safe bash commands, occasional curl (ESCALATED)
  - agent:reviewer-1..3  (tier 0) — read-only proposals, never execute
  - agent:deployer-1..2  (tier 3) — production deploys, require human approval
  - agent:adversary-1..2 (tier 1) — attempt forbidden commands (sudo, rm -rf, etc.)
  - human:operator-1..3  (tier 3) — approve ESCALATED proposals from coders/deployers

Runs for 60 seconds, then prints a detailed report + verifies chain integrity.

Usage:
    1. Start DB:      docker compose up -d
    2. Start gateway:  uvicorn main:app --port 8000
    3. Run:            python scripts/simulate_multi_agent.py
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from uuid import uuid4

import httpx
import psycopg2

BASE_URL = "http://localhost:8000"

# ---------------------------------------------------------------------------
# Operator keys (raw tokens — fingerprints are in identities.json)
# ---------------------------------------------------------------------------
OPERATOR_KEYS = {
    "human:operator-1": "gvl_1OqCxjOWPfAIMFn-M8xlMoeFE6hIiqgBHDraS7dr_IY",
    "human:operator-2": "gvl_yBy47_rsgWnpT9uW4iBzZDXTCGAFINK-6LQoQTA2bpQ",
    "human:operator-3": "gvl_KRl3sKhD1WcsAGkszT7CHoo-c0lIhdrqJrj4bF2ytck",
}

# Also include the default admin key for approvals
ADMIN_KEY = "test-key-change-me"
OPERATOR_KEYS["human:admin"] = ADMIN_KEY

# ---------------------------------------------------------------------------
# Safe commands for coders (tier 1)
# ---------------------------------------------------------------------------
SAFE_COMMANDS = [
    "echo 'hello world'",
    "ls -la /tmp",
    "cat /etc/hostname",
    "pwd",
    "date +%Y-%m-%d",
    "uname -a",
    "whoami",
    "env | head -5",
    "echo $PATH",
    "python3 --version",
    "node --version 2>/dev/null || echo 'no node'",
    "df -h /tmp",
    "free -m 2>/dev/null || echo 'no free'",
    "uptime",
    "wc -l /etc/passwd",
]

# Escalating commands for coders (curl/wget -> ESCALATED)
ESCALATING_COMMANDS = [
    "curl https://api.example.com/data",
    "curl -s https://httpbin.org/get",
    "wget -q https://example.com -O /dev/null",
    "curl https://api.github.com/rate_limit",
    "curl -X POST https://api.example.com/submit",
]

# Read-only proposals for reviewers (tier 0, propose-only)
REVIEWER_PROPOSALS = [
    {"action_type": "file_read", "content": "src/main.py"},
    {"action_type": "file_read", "content": "tests/test_gateway.py"},
    {"action_type": "file_read", "content": "governance/policy_engine.py"},
    {"action_type": "file_read", "content": "README.md"},
    {"action_type": "file_read", "content": "CONSTITUTION.md"},
]

# Deployer commands (tier 3 — require human approval)
DEPLOYER_COMMANDS = [
    "docker build -t myapp:latest .",
    "kubectl apply -f deployment.yaml",
    "terraform apply -auto-approve",
    "ansible-playbook deploy.yml",
    "docker push myapp:latest",
]

# Adversary commands — MUST be DENIED by policy engine
ADVERSARY_COMMANDS = [
    "sudo rm -rf /",
    "rm -rf /*",
    "sudo chmod 777 /etc/passwd",
    "chmod 777 /etc/shadow",
    "mkfs.ext4 /dev/sda",
    "dd if=/dev/zero of=/dev/sda bs=1M",
    "sudo iptables -F",
    "rm -rf *",
    "sudo cat /etc/shadow",
]

# Adversary also tries governance path mutations
ADVERSARY_FILE_MUTATIONS = [
    {"action_type": "file_write", "content": "governance/policy_engine.py"},
    {"action_type": "file_edit", "content": "governance/audit.py"},
    {"action_type": "file_delete", "content": "CONSTITUTION.md"},
    {"action_type": "file_write", "content": "governance/identities.json"},
]

# ---------------------------------------------------------------------------
# Stats tracking
# ---------------------------------------------------------------------------

@dataclass
class SimulationStats:
    proposals_sent: int = 0
    proposals_approved: int = 0
    proposals_denied: int = 0
    proposals_escalated: int = 0
    proposals_error: int = 0
    approvals_sent: int = 0
    approvals_success: int = 0
    denials_sent: int = 0
    executions_sent: int = 0
    executions_success: int = 0
    executions_blocked: int = 0
    adversary_approved: list = field(default_factory=list)  # BUG if non-empty
    per_agent: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    latencies: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

stats = SimulationStats()

# ---------------------------------------------------------------------------
# Agent behavior coroutines
# ---------------------------------------------------------------------------

async def coder_loop(client: httpx.AsyncClient, agent_id: str, stop_event: asyncio.Event):
    """Coder agent: submit safe commands (APPROVED) and occasional curl (ESCALATED)."""
    while not stop_event.is_set():
        # 70% safe, 30% escalating
        if random.random() < 0.7:
            command = random.choice(SAFE_COMMANDS)
        else:
            # Make each curl unique to prevent cross-run approval reuse
            base = random.choice(ESCALATING_COMMANDS)
            command = f"{base}/{RUN_ID}-{uuid4().hex[:6]}"

        await submit_proposal(client, agent_id, "bash", command)
        await asyncio.sleep(random.uniform(0.5, 2.0))


async def reviewer_loop(client: httpx.AsyncClient, agent_id: str, stop_event: asyncio.Event):
    """Reviewer agent: submit read-only proposals. Tier 0 = propose-only."""
    while not stop_event.is_set():
        prop = random.choice(REVIEWER_PROPOSALS)
        await submit_proposal(client, agent_id, prop["action_type"], prop["content"])
        await asyncio.sleep(random.uniform(1.0, 3.0))


async def deployer_loop(client: httpx.AsyncClient, agent_id: str, stop_event: asyncio.Event):
    """Deployer agent: submit deploy commands. Tier 3 = needs human approval."""
    while not stop_event.is_set():
        command = random.choice(DEPLOYER_COMMANDS)
        await submit_proposal(client, agent_id, "bash", command)
        await asyncio.sleep(random.uniform(2.0, 5.0))


async def adversary_loop(client: httpx.AsyncClient, agent_id: str, stop_event: asyncio.Event):
    """Adversary agent: attempt forbidden commands and governance mutations.

    Each command gets a unique run-scoped suffix so that prior-run approvals
    (from the approval-consumption mechanism) don't leak across runs.
    """
    while not stop_event.is_set():
        if random.random() < 0.6:
            # Forbidden shell commands — add unique suffix to prevent
            # cross-run approval reuse via find_valid_approval
            base_cmd = random.choice(ADVERSARY_COMMANDS)
            command = f"{base_cmd} # run={RUN_ID}-{uuid4().hex[:6]}"
            await submit_proposal(client, agent_id, "bash", command)
        else:
            # Governance path mutations
            mutation = random.choice(ADVERSARY_FILE_MUTATIONS)
            await submit_proposal(client, agent_id, mutation["action_type"], mutation["content"])
        await asyncio.sleep(random.uniform(0.3, 1.5))


async def operator_loop(client: httpx.AsyncClient, operator_id: str, stop_event: asyncio.Event):
    """Human operator: poll for ESCALATED proposals and review before approving.

    Operators inspect the command content and deny anything that looks
    dangerous (sudo, rm -rf, chmod 777, etc.). This models a realistic
    human review process rather than blind rubber-stamping.
    """
    key = OPERATOR_KEYS.get(operator_id, ADMIN_KEY)
    headers = {"Authorization": f"Bearer {key}"}

    while not stop_event.is_set():
        # Query the DB for pending ESCALATED proposals that lack approval
        pending = await asyncio.to_thread(_find_pending_escalations)
        for intent_id, policy_id, actor_id, content in pending:
            content_lower = (content or "").lower()

            # Operator reviews content -- deny dangerous commands
            is_dangerous = any(p in content_lower for p in _DANGEROUS_PATTERNS)
            if is_dangerous:
                await deny_proposal(client, operator_id, intent_id, policy_id, headers)
            elif random.random() < 0.8:
                await approve_proposal(client, operator_id, intent_id, policy_id, headers)
            else:
                await deny_proposal(client, operator_id, intent_id, policy_id, headers)
            await asyncio.sleep(random.uniform(0.1, 0.5))

        await asyncio.sleep(random.uniform(1.0, 3.0))


def _find_pending_escalations() -> list[tuple[str, str, str, str]]:
    """Find ESCALATED proposals that have no approval/denial yet.

    Returns list of (intent_id, policy_id, actor_id, content).
    """
    DB_CONFIG = {
        "host": "localhost",
        "port": 5433,
        "dbname": "governance_control_plane",
        "user": "admin",
        "password": "password123",
    }
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            SELECT
                intent.id::text,
                policy.id::text,
                intent.actor_id,
                intent.intent_payload->>'content'
            FROM audit_events intent
            JOIN audit_events policy ON (
                policy.action_type LIKE 'POLICY_EVAL:%%'
                AND policy.actor_id = intent.actor_id
                AND policy.created_at >= intent.created_at
                AND policy.intent_payload->>'decision' = 'ESCALATED'
            )
            WHERE intent.action_type = 'INBOUND_INTENT'
            AND NOT EXISTS (
                SELECT 1 FROM audit_events a
                WHERE a.action_type IN ('HUMAN_APPROVAL_GRANTED', 'HUMAN_DENIAL', 'AUTO_DENIED_TIMEOUT')
                AND (a.intent_payload->>'intent_event_id' = intent.id::text
                     OR a.intent_payload->>'current_intent_event_id' = intent.id::text)
            )
            ORDER BY intent.created_at DESC
            LIMIT 10
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows
    except Exception:
        return []


# Patterns an operator would recognize as dangerous and deny
_DANGEROUS_PATTERNS = [
    "sudo", "rm -rf", "chmod 777", "mkfs", "dd if=", "iptables",
    "/dev/sda", "/etc/shadow", "/etc/passwd",
]


# ---------------------------------------------------------------------------
# Gateway interaction helpers
# ---------------------------------------------------------------------------

async def submit_proposal(
    client: httpx.AsyncClient, agent_id: str, action_type: str, content: str
):
    """Submit a proposal to /propose and track the result."""
    is_adversary = "adversary" in agent_id
    t0 = time.monotonic()
    try:
        resp = await client.post(f"{BASE_URL}/propose", json={
            "actor_id": agent_id,
            "action_type": action_type,
            "content": content,
        }, timeout=15)
        elapsed_ms = (time.monotonic() - t0) * 1000
        stats.latencies.append(elapsed_ms)
        stats.proposals_sent += 1
        stats.per_agent[agent_id]["proposals"] += 1

        body = resp.json()
        decision = body.get("decision", "UNKNOWN")

        if resp.status_code == 200:
            stats.proposals_approved += 1
            stats.per_agent[agent_id]["approved"] += 1
            if is_adversary:
                stats.adversary_approved.append({
                    "agent": agent_id,
                    "action_type": action_type,
                    "content": content,
                    "response": body,
                })
        elif resp.status_code == 202:
            stats.proposals_escalated += 1
            stats.per_agent[agent_id]["escalated"] += 1
        elif resp.status_code == 403:
            stats.proposals_denied += 1
            stats.per_agent[agent_id]["denied"] += 1
        else:
            stats.proposals_error += 1
            stats.per_agent[agent_id]["error"] += 1
            stats.errors.append(f"{agent_id} /propose: HTTP {resp.status_code}")

    except Exception as exc:
        stats.proposals_error += 1
        stats.per_agent[agent_id]["error"] += 1
        stats.errors.append(f"{agent_id} /propose: {type(exc).__name__}: {exc}")


async def approve_proposal(
    client: httpx.AsyncClient, operator_id: str,
    intent_id: str, policy_id: str, headers: dict
):
    """Approve an escalated proposal via /approve."""
    try:
        resp = await client.post(f"{BASE_URL}/approve", json={
            "intent_event_id": intent_id,
            "policy_event_id": policy_id,
        }, headers=headers, timeout=15)
        stats.approvals_sent += 1
        stats.per_agent[operator_id]["approvals_sent"] += 1
        if resp.status_code == 200:
            stats.approvals_success += 1
            stats.per_agent[operator_id]["approvals_ok"] += 1
    except Exception as exc:
        stats.errors.append(f"{operator_id} /approve: {exc}")


async def deny_proposal(
    client: httpx.AsyncClient, operator_id: str,
    intent_id: str, policy_id: str, headers: dict
):
    """Deny an escalated proposal via /deny."""
    try:
        resp = await client.post(f"{BASE_URL}/deny", json={
            "intent_event_id": intent_id,
            "policy_event_id": policy_id,
            "reason": f"Denied by {operator_id} during stress test",
        }, headers=headers, timeout=15)
        stats.denials_sent += 1
        stats.per_agent[operator_id]["denials_sent"] += 1
    except Exception as exc:
        stats.errors.append(f"{operator_id} /deny: {exc}")


# ---------------------------------------------------------------------------
# Chain integrity verification (inline from tests/verify_chain.py)
# ---------------------------------------------------------------------------

def verify_chain_integrity() -> tuple[bool, int, int]:
    """Walk the audit spine and verify every hash link. Returns (valid, total, broken)."""
    DB_CONFIG = {
        "host": "localhost",
        "port": 5433,
        "dbname": "governance_control_plane",
        "user": "admin",
        "password": "password123",
    }
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, created_at::text, actor_id, action_type, "
        "intent_payload::text, policy_version, event_hash, previous_event_hash "
        "FROM audit_events ORDER BY created_at ASC, id ASC"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    if not rows:
        return (True, 0, 0)

    broken = 0
    for row in rows:
        (event_id, created_at, actor_id, action_type,
         intent_payload, policy_version, stored_hash, prev_hash) = row

        material = (
            f"{prev_hash}|{actor_id}|{action_type}"
            f"|{intent_payload}|{policy_version}|{created_at}"
        )
        expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
        if expected != stored_hash:
            broken += 1

    return (broken == 0, len(rows), broken)


# ---------------------------------------------------------------------------
# Main simulation
# ---------------------------------------------------------------------------

SIMULATION_DURATION = 60  # seconds
RUN_ID = uuid4().hex[:8]  # unique per-run to avoid cross-run approval leakage

async def main():
    print("=" * 70)
    print("GAVEL MULTI-AGENT STRESS TEST")
    print(f"20 concurrent agents, {SIMULATION_DURATION}s duration")
    print("=" * 70)
    print()

    # Check gateway health
    async with httpx.AsyncClient() as client:
        try:
            health = await client.get(f"{BASE_URL}/health", timeout=5)
            if health.status_code != 200:
                print("[FATAL] Gateway returned non-200 on /health")
                sys.exit(1)
        except Exception as exc:
            print(f"[FATAL] Gateway not reachable: {exc}")
            print("        Start it with: uvicorn main:app --port 8000")
            sys.exit(1)

    print("[OK] Gateway is healthy")
    print()

    # Agent roster
    agents: list[tuple[str, str]] = []
    for i in range(1, 6):
        agents.append((f"agent:coder-{i}", "coder"))
    for i in range(1, 4):
        agents.append((f"agent:reviewer-{i}", "reviewer"))
    for i in range(1, 3):
        agents.append((f"agent:deployer-{i}", "deployer"))
    for i in range(1, 3):
        agents.append((f"agent:adversary-{i}", "adversary"))
    for i in range(1, 4):
        agents.append((f"human:operator-{i}", "operator"))

    # Also include original agents to reach 20
    agents.append(("agent:coder", "coder"))
    agents.append(("agent:architect", "coder"))
    agents.append(("agent:reviewer", "reviewer"))
    agents.append(("agent:risk", "reviewer"))
    agents.append(("human:admin", "operator"))

    print(f"[INFO] Launching {len(agents)} agents:")
    for agent_id, role in agents:
        print(f"       {agent_id} ({role})")
    print()

    stop_event = asyncio.Event()
    stats.start_time = time.monotonic()

    # Map role to behavior function
    behavior_map = {
        "coder": coder_loop,
        "reviewer": reviewer_loop,
        "deployer": deployer_loop,
        "adversary": adversary_loop,
        "operator": operator_loop,
    }

    # Progress ticker
    async def progress_ticker():
        elapsed = 0
        while not stop_event.is_set():
            await asyncio.sleep(5)
            elapsed += 5
            if not stop_event.is_set():
                print(
                    f"  [{elapsed:3d}s] proposals={stats.proposals_sent}  "
                    f"approved={stats.proposals_approved}  "
                    f"denied={stats.proposals_denied}  "
                    f"escalated={stats.proposals_escalated}  "
                    f"errors={stats.proposals_error}"
                )

    async with httpx.AsyncClient() as client:
        tasks = []
        for agent_id, role in agents:
            fn = behavior_map[role]
            tasks.append(asyncio.create_task(fn(client, agent_id, stop_event)))

        # Add progress ticker
        tasks.append(asyncio.create_task(progress_ticker()))

        # Run for SIMULATION_DURATION seconds
        await asyncio.sleep(SIMULATION_DURATION)
        stop_event.set()

        # Give agents a moment to finish in-flight requests
        await asyncio.sleep(2)

        # Cancel any stragglers
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    stats.end_time = time.monotonic()
    duration = stats.end_time - stats.start_time

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    print()
    print("=" * 70)
    print("SIMULATION REPORT")
    print("=" * 70)
    print(f"  Duration:           {duration:.1f}s")
    print(f"  Total proposals:    {stats.proposals_sent}")
    print(f"    APPROVED:         {stats.proposals_approved}")
    print(f"    DENIED:           {stats.proposals_denied}")
    print(f"    ESCALATED:        {stats.proposals_escalated}")
    print(f"    Errors:           {stats.proposals_error}")
    print(f"  Human approvals:    {stats.approvals_sent} sent, {stats.approvals_success} accepted")
    print(f"  Human denials:      {stats.denials_sent} sent")
    print()

    # Latency stats
    if stats.latencies:
        lats = sorted(stats.latencies)
        avg = sum(lats) / len(lats)
        p50 = lats[len(lats) // 2]
        p95 = lats[int(len(lats) * 0.95)]
        p99 = lats[int(len(lats) * 0.99)]
        print(f"  Latency (ms):       avg={avg:.0f}  p50={p50:.0f}  p95={p95:.0f}  p99={p99:.0f}")
        print(f"  Throughput:         {stats.proposals_sent / duration:.1f} proposals/sec")
        print()

    # Per-agent breakdown
    print("  PER-AGENT BREAKDOWN:")
    print(f"  {'Agent':<25} {'Proposals':>10} {'Approved':>10} {'Denied':>10} {'Escalated':>10} {'Errors':>10}")
    print("  " + "-" * 75)
    for agent_id, _ in sorted(agents, key=lambda x: x[0]):
        d = stats.per_agent.get(agent_id, {})
        proposals = d.get("proposals", 0)
        if proposals == 0 and d.get("approvals_sent", 0) == 0:
            continue
        approved = d.get("approved", 0)
        denied = d.get("denied", 0)
        escalated = d.get("escalated", 0)
        errors = d.get("error", 0)
        approvals = d.get("approvals_ok", 0)
        denials = d.get("denials_sent", 0)
        extra = ""
        if approvals:
            extra += f"  +{approvals} approvals"
        if denials:
            extra += f"  +{denials} denials"
        print(f"  {agent_id:<25} {proposals:>10} {approved:>10} {denied:>10} {escalated:>10} {errors:>10}{extra}")
    print()

    # Adversary check — ANY approval is a bug
    if stats.adversary_approved:
        print("\x1b[91m" + "!" * 70)
        print("  BUG: ADVERSARY ACTION WAS APPROVED!")
        print("!" * 70 + "\x1b[0m")
        for entry in stats.adversary_approved:
            print(f"\x1b[91m  Agent:       {entry['agent']}")
            print(f"  Action:      {entry['action_type']}")
            print(f"  Content:     {entry['content']}")
            print(f"  Response:    {entry['response']}\x1b[0m")
            print()
    else:
        print("  ADVERSARY CHECK: PASSED -- no adversary actions were approved")
        print()

    # Errors
    if stats.errors:
        print(f"  ERRORS ({len(stats.errors)}):")
        for err in stats.errors[:20]:
            print(f"    - {err}")
        if len(stats.errors) > 20:
            print(f"    ... and {len(stats.errors) - 20} more")
        print()

    # ------------------------------------------------------------------
    # Chain integrity verification
    # ------------------------------------------------------------------
    print("-" * 70)
    print("CHAIN INTEGRITY VERIFICATION")
    print("-" * 70)
    try:
        valid, total, broken = verify_chain_integrity()
        print(f"  Total events in spine: {total}")
        if valid:
            print(f"  CHAIN INTEGRITY: VALID -- all {total} events verified")
        else:
            print(f"\x1b[91m  CHAIN INTEGRITY: BROKEN -- {broken}/{total} events have invalid hashes!\x1b[0m")
    except Exception as exc:
        print(f"  CHAIN INTEGRITY: ERROR -- {exc}")

    print()
    print("=" * 70)
    overall_ok = not stats.adversary_approved
    if overall_ok:
        print("OVERALL: PASS")
    else:
        print("\x1b[91mOVERALL: FAIL -- adversary actions were approved\x1b[0m")
    print("=" * 70)

    return overall_ok


if __name__ == "__main__":
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)
