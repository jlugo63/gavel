# Gavel

**Governance runtime for AI agents.** Tamper-proof audit trail, deterministic policy enforcement, human escalation. Open source.

---

## The Problem

AI agents execute shell commands, send emails, deploy code, and install plugins with no audit trail, no policy enforcement, and no approval flow. When something goes wrong at 2 AM, there's no record of what happened or why. The [OpenClaw](https://github.com/openclaw) maintainers themselves warn agent tool use is "far too dangerous" without safeguards.

## What This Does

- **Every agent action is proposed before execution** via `POST /propose`
- **Hash-chained, append-only audit ledger** -- tamper-proof (PostgreSQL + SHA-256 chain)
- **Deterministic policy engine** evaluates risk against a written constitution
- **APPROVED / DENIED / ESCALATED** decisions with risk scores
- **Human approval flow** for high-risk actions (`POST /approve` + `POST /deny`)
- **Approval-aware re-submit** -- approved ESCALATED actions auto-clear on retry (one-time-use, time-bounded, actor-scoped)
- **Read-only governance dashboard** with live chain integrity, approve/deny buttons
- **Python SDK** for any agent framework
- **OpenClaw governance plugin** included

---

## Quickstart

```bash
git clone https://github.com/jlugo63/gavel.git
cd gavel
cp .env.example .env
docker compose up -d
```

Start the gateway:

```bash
HUMAN_API_KEY=your-secret-key uvicorn main:app --port 8000
```

Start the dashboard:

```bash
cd ui && npm install && npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

---

## Architecture

```
Agent (any framework)
  |
  |  POST /propose
  v
+---------------------------+
|    Governance Gateway     |
|  +---------------------+ |
|  |   Policy Engine     | |  <-- evaluates CONSTITUTION.md
|  +---------------------+ |
|  +---------------------+ |
|  |   Audit Spine       | |  <-- hash-chained PostgreSQL ledger
|  +---------------------+ |
+---------------------------+
  |            |           |
  v            v           v
APPROVED    ESCALATED    DENIED
(200)       (202)        (403)
              |
              v
     Dashboard / API
  Approve or Deny (human)
              |
              v
     Agent re-submits
     POST /propose
              |
              v
   APPROVED (approval consumed)
```

Every event is hash-chained: `SHA-256(previous_hash + actor + action + payload + timestamp)`. UPDATE and DELETE are blocked at the database level. Tamper with one row and the chain breaks -- the dashboard shows it immediately.

---

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/propose` | POST | Submit an action for policy evaluation |
| `/approve` | POST | Human approval for ESCALATED action (Bearer auth) |
| `/deny` | POST | Human denial for ESCALATED action (Bearer auth) |

### Proposal flow

```bash
# Submit a proposal
curl -X POST http://localhost:8000/propose \
  -H "Content-Type: application/json" \
  -d '{"actor_id": "agent:my-bot", "action_type": "bash", "content": "kubectl scale deployment web --replicas=3"}'

# Response includes: decision, risk_score, intent_event_id, policy_event_id, violations
```

### Approval re-submit flow

When an ESCALATED action is approved (via dashboard or API), the agent can re-submit the same `POST /propose` and it returns APPROVED. Approvals are:
- **One-time-use** -- consumed on first re-submit
- **Time-bounded** -- expires after 1 hour (configurable via `APPROVAL_TTL_SECONDS`)
- **Actor-scoped** -- only the original actor can consume their approval

---

## Python SDK

```bash
pip install httpx pydantic
```

```python
from governance_sdk import GovernanceClient

client = GovernanceClient("http://localhost:8000", "agent:my-agent")
result = client.propose("bash", "kubectl scale deployment web --replicas=3")
print(result.decision)    # APPROVED | DENIED | ESCALATED
print(result.risk_score)  # 0.0 - 1.0
```

See [`governance_sdk/`](governance_sdk/) for the full client, models, and test suite (12/12 passing).

---

## OpenClaw Integration

Two layers of enforcement:

- **Plugin** (Level 2 -- mechanical) -- `before_tool_call` hook blocks every tool call until the gateway approves. The LLM cannot bypass this.
- **Skill** (Level 0 -- prompt-based) -- SKILL.md injected into the LLM system prompt. Complementary guidance layer.

See [`integrations/openclaw-plugin/`](integrations/openclaw-plugin/) for the plugin, and [`integrations/openclaw/`](integrations/openclaw/) for the skill.

---

## Dashboard

Read-only admin UI with three views:

| Page | Shows |
|------|-------|
| `/admin/events` | Full audit log with expandable JSON payloads |
| `/admin/intents` | Inbound intents with policy decisions + approve/deny buttons |
| `/admin/policy` | Policy evaluations with risk scores + decision badges |

ESCALATED intents show **Approve** (green) and **Deny** (red) buttons. Approved and denied states are reflected as badges. Re-submitted intents that consumed a prior approval show as APPROVED.

A live integrity header calls `audit_spine_verify_chain()` on every page load. Green means the chain is intact. Red means tamper detected.

---

## Project Structure

```
gavel/
  CONSTITUTION.md          # governance invariants (the rules)
  main.py                  # FastAPI gateway (/propose, /approve, /deny, /health)
  governance/
    policy_engine.py       # deterministic policy evaluation
    audit.py               # append-only audit spine writer
  governance_sdk/          # Python SDK
    client.py              # GovernanceClient
    models.py              # ProposalResult, ApprovalResult
    test_sdk.py            # 12 tests
  integrations/openclaw-plugin/  # OpenClaw governance plugin (before_tool_call hook)
  integrations/openclaw/         # OpenClaw governance skill (prompt-based)
  governance_db/migrations # PostgreSQL schema + hash-chain triggers
  ui/                      # Next.js governance dashboard
  docker-compose.yml       # PostgreSQL 16
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full roadmap.

**Coming next:**
- **Phase 1.6** -- Identity model + proposal envelopes with chain IDs
- **Phase 2** -- Blast box sandboxing + evidence packets
- **Phase 3** -- Separation of powers (multi-sig attestations)
- **Phase 4** -- Risk classification + explainability
- **Phase 5** -- Execution tokens (scoped, expiring, chain-bound)

---

## License

Apache 2.0
