# Constitutional Control Plane

**Governance runtime for AI agents.** Tamper-proof audit trail, deterministic policy enforcement, human escalation. Open source.

---

## The Problem

AI agents execute shell commands, send emails, deploy code, and install plugins with no audit trail, no policy enforcement, and no approval flow. When something goes wrong at 2 AM, there's no record of what happened or why. The [OpenClaw](https://github.com/openclaw) maintainers themselves warn agent tool use is "far too dangerous" without safeguards.

## What This Does

- **Every agent action is proposed before execution** via `POST /propose`
- **Hash-chained, append-only audit ledger** -- tamper-proof (PostgreSQL + SHA-256 chain)
- **Deterministic policy engine** evaluates risk against a written constitution
- **APPROVED / DENIED / ESCALATED** decisions with risk scores
- **Human approval flow** for high-risk actions (`POST /approve` with Bearer auth)
- **Read-only governance dashboard** with live chain integrity verification
- **Python SDK** for any agent framework
- **OpenClaw governance skill** included

---

## Quickstart

```bash
git clone https://github.com/jlugo63/constitutional-control-plane.git
cd constitutional-control-plane
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

Open [http://localhost:3000/admin](http://localhost:3000/admin)

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
         POST /approve
       (human decision)
```

Every event is hash-chained: `SHA-256(previous_hash + actor + action + payload + timestamp)`. UPDATE and DELETE are blocked at the database level. Tamper with one row and the chain breaks -- the dashboard shows it immediately.

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

A ready-to-use governance skill that intercepts agent actions before execution:

- **APPROVED** -- action proceeds (exit 0)
- **DENIED** -- action blocked with violation details (exit 1)
- **ESCALATED** -- user prompted for approval (exit 2)
- **Error** -- fail-closed (exit 3)

See [`integrations/openclaw/README.md`](integrations/openclaw/README.md) for setup.

---

## Dashboard

Read-only admin UI with three views:

| Page | Shows |
|------|-------|
| `/admin/events` | Full audit log with expandable JSON payloads |
| `/admin/intents` | Inbound intents with policy decisions + approve button |
| `/admin/policy` | Policy evaluations with risk scores + decision badges |

A live integrity header calls `audit_spine_verify_chain()` on every page load. Green means the chain is intact. Red means tamper detected.

---

## Project Structure

```
constitutional-control-plane/
  CONSTITUTION.md          # governance invariants (the rules)
  main.py                  # FastAPI gateway (/propose, /approve, /health)
  governance/
    policy_engine.py       # deterministic policy evaluation
    audit.py               # append-only audit spine writer
  governance_sdk/          # Python SDK
    client.py              # GovernanceClient
    models.py              # ProposalResult, ApprovalResult
    test_sdk.py            # 12 tests
  integrations/openclaw/   # OpenClaw governance skill
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
