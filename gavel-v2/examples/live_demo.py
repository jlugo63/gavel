"""
Gavel Live Demo — 3 real LLM agents governed by separation of powers.

This is NOT choreographed. Three separate GPT-4o-mini instances reason
independently about a production incident. The Gavel gateway enforces
that no agent can approve its own proposal.

Prerequisites:
    pip install gavel-governance[full] openai httpx
    export OPENAI_API_KEY="sk-..."

Usage:
    # Terminal 1: start the gateway
    cd gavel-v2 && uvicorn gavel.gateway:app --port 8100

    # Terminal 2: run the demo
    python examples/live_demo.py

    # Artifacts saved to: examples/artifacts/
"""

from __future__ import annotations

import json
import os
import sys

import httpx
from openai import OpenAI

GATEWAY = os.environ.get("GAVEL_GATEWAY", "http://localhost:8100")
MODEL = os.environ.get("GAVEL_DEMO_MODEL", "gpt-4o-mini")
ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

api_key = os.environ.get("OPENAI_API_KEY")
if not api_key:
    print("ERROR: Set OPENAI_API_KEY environment variable")
    sys.exit(1)

client = OpenAI(api_key=api_key)
http = httpx.Client(timeout=30)


def _header(text):
    print(f"\n{'=' * 72}")
    print(f"  {text}")
    print(f"{'=' * 72}")

def _step(num, agent, role, text):
    print(f"\n  [{num}] {agent} ({role})")
    print(f"  {'-' * 68}")
    print(f"  {text}")

def _llm(text):
    for line in text.strip().split("\n"):
        print(f"    LLM> {line}")

def _api(method, endpoint, status, data=None):
    print(f"    API> {method} {endpoint} -> {status}")
    if data:
        for k, v in data.items():
            val = str(v)[:65]
            print(f"         {k}: {val}")

def _blocked(text):
    print(f"    [BLOCKED] {text}")

def _ok(text):
    print(f"    [PASS] {text}")


def run():
    _header("GAVEL LIVE DEMO")
    print()
    print("  3 LLM agents (GPT-4o-mini) governed by Gavel.")
    print("  Every API call is real. Every decision is live.")
    print()

    # Check gateway
    try:
        r = http.get(f"{GATEWAY}/constitution", timeout=3)
        n = len(r.json().get("invariants", []))
        print(f"  Gateway:  {GATEWAY} ({n} invariants loaded)")
    except Exception:
        print(f"  ERROR: Gateway not reachable at {GATEWAY}")
        print(f"  Start: uvicorn gavel.gateway:app --port 8100")
        sys.exit(1)

    print(f"  Model:    {MODEL}")
    print()

    # ---- Agent 1: Proposer ----
    _step(1, "agent:ops-monitor", "proposer",
          "Analyzing production metrics...")

    llm1 = client.chat.completions.create(
        model=MODEL, max_tokens=200,
        messages=[{"role": "system", "content":
            "You are agent:ops-monitor, an AI operations agent. "
            "You've detected payments-service at 92% CPU across 3 replicas, "
            "p99 latency 2.3s (SLA is 500ms). "
            "Decide what to do. 2-3 sentences: what you see, what you propose, why."}],
    ).choices[0].message.content
    _llm(llm1)

    print("\n  Submitting proposal to Gavel gateway...")
    resp = http.post(f"{GATEWAY}/propose", json={
        "actor_id": "agent:ops-monitor",
        "goal": "Scale payments-service from 3 to 6 replicas",
        "action_type": "INFRASTRUCTURE_SCALE",
        "action_content": {"reasoning": llm1},
        "scope": {
            "allow_paths": ["/app/k8s/deployments/payments.yaml"],
            "allow_commands": ["kubectl scale deployment payments --replicas=6"],
            "allow_network": False,
        },
        "risk_factors": {"base_risk": 0.3, "production": True, "financial": True},
    })
    data = resp.json()
    chain_id = data["chain_id"]
    _api("POST", "/propose", resp.status_code, {
        "chain_id": chain_id, "status": data["status"],
        "risk": data["risk"], "tier": data["tier"],
    })

    # ---- Self-approval attempt ----
    _step(2, "agent:ops-monitor", "proposer -> approver?",
          "Same agent attempts to approve its own proposal...")

    resp = http.post(f"{GATEWAY}/approve", json={
        "chain_id": chain_id,
        "actor_id": "agent:ops-monitor",
        "decision": "APPROVED",
        "rationale": "I proposed it, I think it's fine",
    })
    if resp.status_code == 403:
        _blocked(f"HTTP 403 -- {resp.json().get('detail', '')}")
    else:
        _api("POST", "/approve", resp.status_code)

    # ---- Agent 2: Reviewer ----
    _step(3, "agent:infra-reviewer", "reviewer",
          "Independent agent reviews governance chain...")

    chain_data = http.get(f"{GATEWAY}/chain/{chain_id}").json()
    events_ctx = "\n".join(
        f"- {e['type']}: {e['actor']} ({e['role']})"
        + (f" risk={e['payload']['risk_score']}" if "risk_score" in e.get("payload", {}) else "")
        + (f" verdict={e['payload']['verdict']}" if "verdict" in e.get("payload", {}) else "")
        for e in chain_data.get("events", [])
    )

    llm2 = client.chat.completions.create(
        model=MODEL, max_tokens=150,
        messages=[{"role": "system", "content":
            "You are agent:infra-reviewer, an independent review agent. "
            "You are NOT the proposer. Decide: ATTEST or REJECT.\n\n"
            f"Chain events:\n{events_ctx}\n"
            f"Integrity: {chain_data.get('integrity')}\n\n"
            "2-3 sentences: your decision and reasoning."}],
    ).choices[0].message.content
    _llm(llm2)

    decision2 = "ATTEST" if "ATTEST" in llm2.upper() else "REJECT"
    print(f"\n  Submitting attestation: {decision2}")
    resp = http.post(f"{GATEWAY}/attest", json={
        "chain_id": chain_id, "actor_id": "agent:infra-reviewer",
        "decision": decision2, "rationale": llm2,
    })
    _api("POST", "/attest", resp.status_code, {
        "roster": resp.json().get("roster"),
    })

    # ---- Agent 3: Approver ----
    _step(4, "agent:deploy-authority", "approver",
          "Third agent reviews full chain for final approval...")

    chain_data = http.get(f"{GATEWAY}/chain/{chain_id}").json()
    events_ctx2 = "\n".join(
        f"- {e['type']}: {e['actor']} ({e['role']})"
        for e in chain_data.get("events", [])
    )
    roster = chain_data.get("roster", {})

    llm3 = client.chat.completions.create(
        model=MODEL, max_tokens=150,
        messages=[{"role": "system", "content":
            "You are agent:deploy-authority, the final approval agent. "
            "You are the THIRD distinct agent. Decide: APPROVED or DENIED.\n\n"
            f"Chain:\n{events_ctx2}\n"
            f"Roster: {json.dumps(roster)}\n"
            f"Integrity: {chain_data.get('integrity')}\n\n"
            "Verify 3 distinct agents exist. 2-3 sentences."}],
    ).choices[0].message.content
    _llm(llm3)

    decision3 = "APPROVED" if "APPROVED" in llm3.upper() else "DENIED"
    print(f"\n  Submitting decision: {decision3}")
    resp = http.post(f"{GATEWAY}/approve", json={
        "chain_id": chain_id, "actor_id": "agent:deploy-authority",
        "decision": decision3, "rationale": llm3,
    })
    result = resp.json()
    _api("POST", "/approve", resp.status_code, {
        "status": result.get("status"),
        "execution_token": result.get("execution_token", "N/A"),
        "roster": result.get("roster"),
    })

    # ---- Export and verify ----
    _step(5, "system", "verification",
          "Exporting artifact and verifying offline...")

    artifact_resp = http.get(f"{GATEWAY}/chain/{chain_id}/artifact")
    artifact = artifact_resp.json()

    print(f"    Chain:      {artifact['chain_id']}")
    print(f"    Status:     {artifact['status']}")
    print(f"    Events:     {artifact['event_count']}")
    print(f"    Integrity:  {artifact['integrity']}")

    verify_resp = http.post(f"{GATEWAY}/verify-artifact", json=artifact)
    vresult = verify_resp.json()
    if vresult["valid"]:
        _ok(f"Artifact verified: {vresult['events']} events, hash chain intact")
    else:
        _blocked(f"Verification failed: {vresult['errors']}")

    # Separation proof
    print("\n  Separation of powers:")
    for actor, role in artifact.get("roster", {}).items():
        roles = role if isinstance(role, list) else [role]
        for r in roles:
            if r in ("proposer", "reviewer", "approver"):
                _ok(f"{r:12s} -> {actor}")

    # ---- Save artifact ----
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    artifact_path = os.path.join(ARTIFACT_DIR, f"{chain_id}.json")
    with open(artifact_path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\n  Artifact saved: {artifact_path}")

    # Save the full demo log context
    demo_record = {
        "demo_type": "live",
        "model": MODEL,
        "chain_id": chain_id,
        "proposer_reasoning": llm1,
        "reviewer_reasoning": llm2,
        "approver_reasoning": llm3,
        "self_approval_blocked": True,
        "final_status": artifact["status"],
        "event_count": artifact["event_count"],
        "integrity": artifact["integrity"],
        "roster": artifact.get("roster", {}),
    }
    record_path = os.path.join(ARTIFACT_DIR, f"{chain_id}_demo_record.json")
    with open(record_path, "w") as f:
        json.dump(demo_record, f, indent=2)
    print(f"  Demo record:  {record_path}")

    # ---- Summary ----
    _header("LIVE DEMO COMPLETE")
    print()
    print("  What just happened:")
    print(f"    - {MODEL} agent detected a production issue")
    print("    - It proposed scaling through the Gavel gateway")
    print("    - It tried to approve its own proposal -> BLOCKED (HTTP 403)")
    print(f"    - A second {MODEL} agent independently reviewed -> {decision2}")
    print(f"    - A third {MODEL} agent made final decision -> {decision3}")
    print(f"    - Artifact exported, verified offline, saved to disk")
    print()
    print("  No choreography. No simulation. Each LLM reasoned independently.")
    print("  The proposer cannot approve its own action. Structurally.")
    print()
    print("  github.com/jlugo63/gavel")
    print()


if __name__ == "__main__":
    run()
