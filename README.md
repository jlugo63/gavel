# Gavel

**Governance runtime for AI agents.** Tamper-proof audit trail, deterministic policy enforcement, sandboxed execution, human escalation. Open source.

---

## The Problem

AI agents execute shell commands, send emails, deploy code, and install plugins with no audit trail, no policy enforcement, and no approval flow. When something goes wrong at 2 AM, there's no record of what happened or why. The [OpenClaw](https://github.com/openclaw) maintainers themselves warn agent tool use is "far too dangerous" without safeguards.

## What This Does

- **Every agent action is proposed before execution** via `POST /propose`
- **Hash-chained, append-only audit ledger** -- tamper-proof (PostgreSQL + SHA-256 chain)
- **Deterministic policy engine** evaluates risk against a written constitution
- **APPROVED / DENIED / ESCALATED** decisions with risk scores
- **Human approval flow** for high-risk actions (`POST /approve` + `POST /deny`)
- **Sandboxed execution** -- approved commands run in isolated Docker containers (`POST /execute`)
- **Tamper-evident evidence packets** -- SHA-256 hash of command, output, workspace diff, environment
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
  |            |
  v            v
POST       Dashboard / API
/execute   Approve or Deny (human)
  |            |
  v            v
+----------+  Agent re-submits
|Blast Box |  POST /propose -> APPROVED
|  Docker  |       |
| sandbox  |       v
+----------+  POST /execute
  |
  v
Evidence Packet
(logged to Audit Spine)
```

Every event is hash-chained: `SHA-256(previous_hash + actor + action + payload + timestamp)`. UPDATE and DELETE are blocked at the database level. Tamper with one row and the chain breaks -- the dashboard shows it immediately.

---

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/propose` | POST | Submit an action for policy evaluation |
| `/execute` | POST | Execute an approved proposal in a sandboxed container |
| `/approve` | POST | Human approval for ESCALATED action (Bearer auth) |
| `/deny` | POST | Human denial for ESCALATED action (Bearer auth) |

### Propose -> Execute flow

```bash
# 1. Submit a proposal
curl -X POST http://localhost:8000/propose \
  -H "Content-Type: application/json" \
  -d '{"actor_id": "agent:coder", "action_type": "bash", "content": "echo hello"}'

# Response: { "decision": "APPROVED", "intent_event_id": "abc-123", ... }

# 2. Execute the approved proposal
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{"proposal_id": "abc-123"}'

# Response: { "evidence_event_id": "def-456", "evidence_packet": { ... } }
```

The evidence packet contains: command executed, exit code, stdout/stderr, execution duration, workspace diff (files added/modified/deleted), environment config (image, network mode, resource limits), and a SHA-256 evidence hash over all fields.

### Execution decisions

| Proposal state | `/execute` result |
|----------------|-------------------|
| APPROVED | 200 -- runs in Blast Box, returns evidence packet |
| ESCALATED + human approval | 200 -- runs in Blast Box, returns evidence packet |
| ESCALATED without approval | 202 -- requires human approval first |
| DENIED | 403 -- cannot execute |
| Docker unavailable | 503 -- sandbox not available |

### Blast Box isolation

Commands execute inside Docker containers with:
- `--network none` -- no network access
- `--read-only` -- immutable root filesystem
- `--memory` / `--cpus` -- resource limits
- `--tmpfs /tmp` -- ephemeral scratch space
- Workspace mounted at `/workspace` for file I/O
- Timeout enforcement with hard kill

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
  main.py                  # FastAPI gateway (/propose, /execute, /approve, /deny)
  governance/
    policy_engine.py       # deterministic policy evaluation
    audit.py               # append-only audit spine writer
    blastbox.py            # Docker sandbox runner
    evidence.py            # evidence packet builder + spine logging
    identity.py            # actor validation + API key auth
    identities.json        # actor allowlist (protected by policy)
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

**Current:** Phase 2 -- Controlled Autonomy (sandbox execution + evidence packets)

**Coming next:**
- **Phase 2 continued** -- Tiered autonomy + deterministic evidence review
- **Phase 3** -- Separation of powers (multi-sig attestations)
- **Phase 4** -- Risk classification + explainability
- **Phase 5** -- Execution tokens (scoped, expiring, chain-bound)

---

## License

Apache 2.0
