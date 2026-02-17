# Gavel Governance Skill for OpenClaw

A prompt-based skill that connects [OpenClaw](https://github.com/openclaw) to
the Gavel governance gateway, enforcing policy-as-code on every agent action.

## How It Works

OpenClaw skills are natural language instructions injected into the agent's
system prompt. This skill instructs the agent to call the Gavel governance
gateway via `curl` before executing any shell command, file modification, or
external API call. The agent reads the gateway's response and acts accordingly:

- **APPROVED** -- action proceeds
- **DENIED** -- action blocked, violations reported to user
- **ESCALATED** -- action paused, user prompted for approval

No subprocess execution, no stdin piping. The LLM follows the instructions
using its built-in tools.

## Quick Start

### 1. Start the Governance Gateway

```bash
HUMAN_API_KEY=your-secret-key uvicorn main:app --port 8000
```

### 2. Install the Skill

Copy the skill into your OpenClaw skills folder:

```bash
cp -r integrations/openclaw/ ~/.openclaw/skills/gavel-governance/
```

### 3. Configure Environment

Set these in your environment or OpenClaw config:

```bash
export GOVERNANCE_GATEWAY_URL=http://localhost:8000
export HUMAN_API_KEY=your-secret-key
```

### 4. Test It

Start an OpenClaw session and try a dangerous command:

```
> run sudo rm -rf /tmp/test
```

The agent should call the gateway first, receive a DENIED decision, and
refuse to execute -- reporting the constitutional violations to you.

## Architecture

```
User Request
    |
    v
OpenClaw Agent (LLM)
    |
    |  reads SKILL.md instructions
    |  calls curl POST /propose
    v
Gavel Governance Gateway
    |
    v
APPROVED / DENIED / ESCALATED
```

## Python SDK

For programmatic integrations (LangGraph, CrewAI, custom agents), use the
Python SDK instead:

```python
from governance_sdk import GovernanceClient

client = GovernanceClient("http://localhost:8000", "agent:my-agent")
result = client.propose("bash", "kubectl scale deployment web --replicas=3")
print(result.decision)  # APPROVED | DENIED | ESCALATED
```

See [`governance_sdk/`](../../governance_sdk/) for the full client and test suite.
