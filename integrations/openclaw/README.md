# OpenClaw Governance Skill

An integration skill that connects [OpenClaw](https://github.com/openclaw) to
the Constitutional AI Governance Gateway, enforcing policy-as-code on every
agent action.

## Quick Start

### 1. Start the Governance Gateway

```bash
HUMAN_API_KEY=test-key-change-me uvicorn main:app --port 8000
```

### 2. Install the Skill

Copy (or symlink) the `integrations/openclaw/` directory into your OpenClaw
skills folder:

```bash
cp -r integrations/openclaw/ ~/.openclaw/skills/governance-check/
```

### 3. Configure Environment

Set the following environment variables (or add them to your `.env`):

```bash
export GOVERNANCE_GATEWAY_URL=http://localhost:8000
export GOVERNANCE_ACTOR_ID=agent:openclaw
export HUMAN_API_KEY=test-key-change-me
```

### 4. Test the Skill Manually

```bash
# Should print APPROVED
echo '{"action_type":"file_read","content":"src/main.py"}' | python scripts/governance_check.py

# Should print DENIED
echo '{"action_type":"bash","content":"sudo rm -rf /"}' | python scripts/governance_check.py

# Should print ESCALATED
echo '{"action_type":"bash","content":"curl https://api.example.com/data"}' | python scripts/governance_check.py
```

### 5. Run the SDK Test Suite

```bash
python -m governance_sdk.test_sdk
```

## Architecture

```
Agent Action
    │
    ▼
┌──────────────────────┐
│  governance_check.py │  ← OpenClaw skill script
└──────┬───────────────┘
       │ POST /propose
       ▼
┌──────────────────────┐
│  Governance Gateway  │  ← FastAPI (main.py)
│  ┌────────────────┐  │
│  │ Policy Engine  │  │  ← Evaluates CONSTITUTION.md
│  └────────────────┘  │
│  ┌────────────────┐  │
│  │  Audit Spine   │  │  ← Hash-chained PostgreSQL ledger
│  └────────────────┘  │
└──────────────────────┘
```

## Decision Flow

| Gateway Response | Skill Exit Code | Agent Behavior |
|---|---|---|
| `APPROVED` | `0` | Action proceeds |
| `DENIED` | `1` | Action blocked, violations shown |
| `ESCALATED` | `2` | User prompted; proceeds only on human approval |
| Error | `3` | Action blocked (fail-closed) |

## Dependencies

- Python 3.11+
- `httpx` (via `governance_sdk`)
- `pydantic` (via `governance_sdk`)
- A running Governance Gateway with PostgreSQL backend
