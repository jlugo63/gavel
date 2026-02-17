# Gavel Governance Plugin for OpenClaw

Mechanical enforcement of AI governance policy. This is NOT a prompt-based
skill the LLM can ignore -- it's a `before_tool_call` hook that intercepts
every tool call and requires gateway approval before execution.

## How It Works

The plugin registers a `before_tool_call` hook with OpenClaw. Every time the
agent tries to use a tool (bash, file write, web fetch, etc.), the hook fires
first and POSTs to the Gavel governance gateway. The agent cannot execute without
approval.

- **APPROVED** -- tool call proceeds
- **DENIED** -- tool call blocked, violations shown to agent
- **ESCALATED** -- tool call blocked, user prompted for human approval
- **Gateway unreachable** -- tool call blocked (fail closed by default)

## Install

```bash
cd integrations/openclaw-plugin
npm install && npm run build
```

Then register with OpenClaw (copy or symlink into your plugins directory):

```bash
cp -r integrations/openclaw-plugin/ ~/.openclaw/plugins/gavel-governance/
```

## Configure

Set environment variables (or add to `openclaw.json` under plugin config):

| Variable | Default | Description |
|---|---|---|
| `GOVERNANCE_GATEWAY_URL` | `http://localhost:8000` | Gavel governance gateway URL |
| `GOVERNANCE_ACTOR_ID` | `agent:openclaw` | Actor identity for audit trail |
| `HUMAN_API_KEY` | *(none)* | Bearer token for approval endpoint |
| `GOVERNANCE_FAIL_OPEN` | `false` | Allow actions when gateway is down |

## Belt and Suspenders

This plugin coexists with the prompt-based skill in `integrations/openclaw/`.

- **Skill** (belt) -- natural language instructions telling the LLM to check
  governance. The LLM *should* follow them, but technically can skip them.
- **Plugin** (suspenders) -- `before_tool_call` hook that mechanically blocks
  execution. The LLM *cannot* skip this.

Use both for defense in depth.

## Architecture

```
Agent decides to act
    |
    v
OpenClaw before_tool_call hook
    |
    |  POST /propose
    v
Gavel Governance Gateway
    |
    v
APPROVED → tool executes
DENIED   → tool blocked, violations shown
ESCALATED → tool blocked, human approval required
Error    → tool blocked (fail closed)
```

## Links

- [Gavel](https://github.com/jlugo63/constitutional-control-plane)
- [ClawBands](https://github.com/SeyZ/clawbands) -- reference implementation for the hook pattern
