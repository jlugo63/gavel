# Gavel

[![CI](https://github.com/jlugo63/gavel/actions/workflows/test.yml/badge.svg)](https://github.com/jlugo63/gavel/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Constitutional governance for autonomous AI agents. Built on [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## The Problem

In December 2025, Amazon's Kiro AI agent was told to fix a minor bug. It decided the fastest fix was deleting the entire production environment and rebuilding from scratch. Thirteen-hour outage. The agent that found the problem also decided the fix and executed it. No independent review. No sandbox. No approval gate.

Policy engines answer: *"Is this agent allowed to do this?"*

Gavel answers: *"Who proposed this, who reviewed it, who approved it, and can we prove it?"*

## How It Works

Every consequential agent action flows through a governance chain:

```
Proposal -> Policy Check -> Sandbox Evidence -> Deterministic Review ->
Independent Attestation -> Independent Approval -> Scoped Execution Token -> Verified Outcome
```

- Every event is hash-chained (SHA-256 of previous event)
- The proposer cannot review or approve their own action — enforced structurally at the API
- Three distinct principals required on every governance chain
- SLA timers auto-deny on timeout — the system degrades toward safety, never toward action

## Quick Start

```bash
pip install gavel-governance[full]
uvicorn gavel.gateway:app --port 8000
```

```python
import httpx

# Agent proposes a production fix
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

# Same agent tries to self-approve -> BLOCKED (403)
# Independent reviewer attests -> OK (200)
# Reviewer tries to also approve -> BLOCKED (403)
# Third agent approves -> execution token minted
```

See [gavel-v2/README.md](gavel-v2/README.md) for full documentation and API examples.

## Architecture

**Microsoft's toolkit provides:**
- Agent Mesh — Ed25519 cryptographic identity (DIDs) and trust scoring
- Agent OS — Policy engine with blocked pattern enforcement
- Cedar — Policy language for constitutional `forbid` rules

**Gavel adds:**
- Governance chains — hash-linked decision trails from proposal to verified execution
- Separation of powers — proposer, reviewer, approver must be distinct principals
- Blast box — sandboxed execution that produces cryptographic evidence packets
- Deterministic evidence review — 7 automated checks, no LLM in the loop
- Tiered autonomy — risk-based governance tiers (0-3) with escalation
- Liveness monitor — SLA timers that auto-deny on timeout
- Constitutional invariants — Cedar `forbid` rules that no `permit` can override

## What's Inside

```
gavel-v2/
  gavel/
    chain.py          # Hash-chained governance events
    constitution.py   # 9 inviolable invariants
    separation.py     # Proposer/reviewer/approver must be distinct
    blastbox.py       # Sandboxed execution for evidence
    evidence.py       # 7 deterministic checks
    tiers.py          # Risk-based governance tiers
    liveness.py       # SLA timers + auto-deny
    gateway.py        # FastAPI server
    policies/
      constitution.cedar  # Cedar forbid rules for Agent OS
  pyproject.toml
  README.md
```

## Why Now

- [Amazon Kiro deleted production](https://particula.tech/blog/ai-agent-production-safety-kiro-incident) — Dec 2025, 13-hour outage
- [Alibaba ROME hijacked GPUs](https://www.scworld.com/perspective/the-rome-incident-when-the-ai-agent-becomes-the-insider-threat) — March 2026, crypto mining
- [97% of enterprises expect a major AI agent incident](https://securityboulevard.com/2026/04/97-of-enterprises-expect-a-major-ai-agent-security-incident-within-the-year/)
- EU AI Act high-risk obligations take effect **August 2, 2026**

## License

[MIT](LICENSE)
