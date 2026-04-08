# Gavel

[![CI](https://github.com/jlugo63/gavel/actions/workflows/test.yml/badge.svg)](https://github.com/jlugo63/gavel/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Constitutional governance for autonomous AI agents. Built on [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## The Problem

In December 2025, Amazon's Kiro AI agent was told to fix a minor bug. It decided to delete the entire production environment and rebuild from scratch. Thirteen-hour outage. The agent that found the problem also decided the fix and executed it — no independent review, no sandbox, no approval gate.

Microsoft's Agent Governance Toolkit answers: *"Is this agent allowed to do this?"*

Gavel answers: *"Who proposed this, who reviewed it, who approved it, and can we prove it?"*

## How It Works

Gavel adds a governance chain layer on top of the toolkit. Every consequential agent action flows through:

```
Proposal → Policy Check → Sandbox Evidence → Deterministic Review → Independent Attestation → Independent Approval → Scoped Execution Token → Verified Outcome
```

Every event is hash-chained (SHA-256 of previous event). The proposer cannot review or approve their own action — enforced structurally at the API level.

**Microsoft's toolkit provides:** Agent OS (policy engine), Agent Mesh (cryptographic identity + trust scoring), Agent Runtime (execution rings)

**Gavel adds:** Governance chains, separation of powers, blast box evidence, deterministic review, tiered autonomy, SLA-based liveness, constitutional invariants

## Install

```bash
pip install gavel-governance        # core library (pydantic only)
pip install gavel-governance[api]   # + FastAPI gateway
pip install gavel-governance[full]  # + Microsoft Agent Governance Toolkit
```

## Quick Start (Docker)

```bash
git clone https://github.com/jlugo63/constitutional-control-plane.git
cd constitutional-control-plane/gavel-v2
cp .env.example .env
docker compose up
# Open http://localhost:8100/dashboard
```

## Quick Start

```bash
# Start the gateway
pip install gavel-governance[full]
uvicorn gavel.gateway:app --port 8000
```

```python
import httpx

# 1. Agent proposes a production fix
resp = httpx.post("http://localhost:8000/propose", json={
    "actor_id": "agent:code-analyzer",
    "goal": "Fix race condition in payments endpoint",
    "action_type": "CODE_DEPLOY",
    "scope": {
        "allow_paths": ["payments/transaction.py"],
        "allow_commands": ["git apply hotfix.patch"],
        "allow_network": False
    },
    "risk_factors": {"base_risk": 0.4, "production": True, "financial": True}
})
chain_id = resp.json()["chain_id"]
# -> Status: ESCALATED, risk: 0.75, tier: AUTONOMOUS
# -> Blast box evidence + deterministic review already ran

# 2. Same agent tries to self-approve -> BLOCKED
resp = httpx.post("http://localhost:8000/approve", json={
    "chain_id": chain_id,
    "actor_id": "agent:code-analyzer",  # same as proposer
    "decision": "APPROVED",
    "rationale": "Trust me"
})
# -> 403: Separation violation: agent:code-analyzer has role 'proposer', cannot also be 'approver'

# 3. Independent reviewer attests
httpx.post("http://localhost:8000/attest", json={
    "chain_id": chain_id,
    "actor_id": "agent:code-reviewer",
    "decision": "ATTEST",
    "rationale": "Minimal diff, addresses race condition"
})

# 4. Third agent approves -> execution token minted
resp = httpx.post("http://localhost:8000/approve", json={
    "chain_id": chain_id,
    "actor_id": "agent:deploy-authority",
    "decision": "APPROVED",
    "rationale": "Evidence review passed, code review attested"
})
# -> execution_token: "exec-t-...", scoped, single-use, expires 10min

# 5. Full audit trail
chain = httpx.get(f"http://localhost:8000/chain/{chain_id}").json()
# -> integrity: true, 8 hash-chained events, 3 distinct principals
```

## What's Inside

| Module | What It Does |
|--------|-------------|
| `gavel.chain` | Hash-chained governance events with tamper detection |
| `gavel.constitution` | 9 inviolable invariants (Cedar `forbid` rules) |
| `gavel.separation` | Proposer/reviewer/approver must be distinct principals |
| `gavel.blastbox` | Sandboxed execution that produces cryptographic evidence |
| `gavel.evidence` | 7 deterministic checks (scope, secrets, network, paths) |
| `gavel.tiers` | Risk-based governance tiers (0-3) with escalation |
| `gavel.liveness` | SLA timers that auto-deny on timeout |
| `gavel.gateway` | FastAPI server tying it all together |

## Microsoft Toolkit Integration

Gavel uses the real Agent Governance Toolkit at runtime:

- **Agent Mesh** — Ed25519 cryptographic identity (DIDs) and trust scoring for every agent on a chain
- **Agent OS** — Policy violation checks (blocked patterns, dangerous commands) before proposals enter the governance workflow
- **Cedar policies** — Constitutional invariants expressed as `forbid` rules loaded into Agent OS

## Tests

```bash
pip install -e ".[dev]"
pytest -v --cov=gavel
```

158 tests across three layers:
- **Unit** (92 tests) — each module in isolation
- **Integration** (17 tests) — full governance flows through the FastAPI gateway
- **Adversarial** (19 tests) — self-approval, hash tampering, role switching, two-agent collusion, SLA stalling

97.5% coverage.

## Why Now

- [Amazon Kiro deleted production](https://particula.tech/blog/ai-agent-production-safety-kiro-incident) (Dec 2025, 13-hour outage)
- [Alibaba ROME hijacked GPUs](https://www.scworld.com/perspective/the-rome-incident-when-the-ai-agent-becomes-the-insider-threat) (March 2026, crypto mining)
- [97% of enterprises expect a major AI agent incident](https://securityboulevard.com/2026/04/97-of-enterprises-expect-a-major-ai-agent-security-incident-within-the-year/)
- EU AI Act high-risk obligations take effect **August 2, 2026**

## License

MIT
