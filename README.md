# Gavel v2

[![CI](https://github.com/jlugo63/gavel/actions/workflows/test.yml/badge.svg)](https://github.com/jlugo63/gavel/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 1929](https://img.shields.io/badge/tests-1929_passing-brightgreen.svg)]()

Open-source constitutional governance for autonomous AI agents. Built on [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## The Problem

In December 2025, Amazon's Kiro AI agent was told to fix a minor bug. It decided the fastest fix was deleting the entire production environment and rebuilding from scratch. Thirteen-hour outage. The agent that found the problem also decided the fix and executed it. No independent review. No sandbox. No approval gate.

Policy engines answer: *"Is this agent allowed to do this?"*

Gavel answers: *"Who proposed this, who reviewed it, who approved it, and can we prove it?"*

## How It Works

Every consequential agent action flows through a governance chain:

```
Proposal → Policy Check → Sandbox Evidence → Deterministic Review →
Independent Attestation → Independent Approval → Scoped Execution Token → Verified Outcome
```

- Every event is hash-chained (SHA-256 of previous event)
- The proposer cannot review or approve their own action — enforced structurally at the API
- Three distinct principals required on every governance chain
- SLA timers auto-deny on timeout — the system degrades toward safety, never toward action
- EU AI Act Article 5 prohibited practices are blocked at enrollment — before an agent ever runs

## Quick Start

```bash
pip install gavel-governance[full]
uvicorn gavel.gateway:app --port 8000
```

Open `http://localhost:8000/dashboard` for the live governance dashboard.

```python
import httpx

# Register an agent
httpx.post("http://localhost:8000/v1/agents/register", json={
    "agent_id": "agent:code-analyzer",
    "display_name": "Code Analyzer",
    "agent_type": "llm"
})

# Enroll with governance controls
httpx.post("http://localhost:8000/v1/agents/enroll", json={
    "agent_id": "agent:code-analyzer",
    "display_name": "Code Analyzer",
    "purpose_summary": "Static analysis and code review",
    "risk_tier": "high",
    "owner_contact": "team@example.com"
})

# Propose a production fix
httpx.post("http://localhost:8000/v1/governance/propose", json={
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

# Same agent tries to self-approve → BLOCKED (403)
# Independent reviewer attests → OK (200)
# Reviewer tries to also approve → BLOCKED (403)
# Third agent approves → execution token minted
```

See [gavel-v2/README.md](gavel-v2/README.md) for full API documentation.

## Architecture

**Microsoft's Agent Governance Toolkit provides:**
- Agent Mesh — Ed25519 cryptographic identity (DIDs) and trust scoring
- Agent OS — Policy engine with blocked pattern enforcement
- Cedar — Policy language for constitutional `forbid` rules

**Gavel adds:**
- **Enrollment gate** — EU AI Act Article 5 prohibited practice detection; agents attempting social scoring, subliminal manipulation, real-time biometric ID, or workplace emotion recognition are rejected before they ever run
- **Governance chains** — hash-linked decision trails from proposal to verified execution
- **Separation of powers** — proposer, reviewer, approver must be distinct principals
- **Blast box** — sandboxed execution that produces cryptographic evidence packets
- **Deterministic evidence review** — 7 automated checks, no LLM in the loop
- **Tiered autonomy** — risk-based governance tiers (0–3) with escalation
- **Liveness monitor** — SLA timers that auto-deny on timeout
- **Constitutional invariants** — Cedar `forbid` rules that no `permit` can override
- **Live dashboard** — real-time topology, agent inspector, governance chain viewer, gate activity, incident management, SSE event stream

## Dashboard

The governance dashboard provides real-time visibility into every agent, chain, and enforcement action:

- **Topology view** — D3.js graph showing agents, chains, and the Policy Engine with trust arcs and status-coded nodes (green = active, amber = suspended, red = dead)
- **Agents & Enrollment** — registration status, DID identity, autonomy tier, enrollment outcome (ENROLLED/REJECTED/PENDING)
- **Governance Chains** — live chain state with roster, evidence, and phase tracking
- **Gate Activity** — every gate check with allow/deny outcome and rule citations
- **SLA Timers** — countdown bars for active chain deadlines with escalation levels
- **Kill Switch** — immediate agent suspension with reason logging
- **Incident Management** — create, track, and resolve governance incidents
- **SSE Event Stream** — raw real-time feed of all governance events

## What's Inside

```
gavel-v2/
  gavel/
    chain.py            # Hash-chained governance events
    constitution.py     # 9 inviolable invariants
    separation.py       # Proposer/reviewer/approver must be distinct
    enrollment.py       # Agent enrollment + Article 5 detection
    blastbox.py         # Sandboxed execution for evidence
    evidence.py         # 7 deterministic checks
    tiers.py            # Risk-based governance tiers
    liveness.py         # SLA timers + auto-deny
    supervisor.py       # Agent lifecycle management
    gateway.py          # FastAPI server + dashboard
    routers/            # API route handlers
    static/             # Dashboard frontend (vanilla JS, D3.js)
    policies/
      constitution.cedar  # Cedar forbid rules for Agent OS
  tests/
    validation/         # 1,929 tests including red-team scenarios
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
