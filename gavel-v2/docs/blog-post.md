# Constitutional Governance for Autonomous AI Agents

*How hash-chained governance workflows with separation of powers create verifiable trust for autonomous agent systems.*

## The Problem

Autonomous AI agents are making decisions with real-world consequences — deploying code, managing infrastructure, processing data. Current governance approaches fall into two camps:

1. **Policy engines** that evaluate individual decisions in isolation (allow/deny)
2. **Human-in-the-loop** gates that don't scale and create bottlenecks

Neither provides what regulated systems actually need: a tamper-evident audit trail showing that multiple independent principals reviewed and approved an action before execution, with deterministic evidence that the action stayed within its declared scope.

## Constitutional Governance

Gavel introduces **constitutional governance** — a framework where autonomous agent actions are governed by structural invariants, not just policy rules. The key insight: governance is a *process*, not a single decision point.

### Governance Chains

Every agent action flows through a governance chain — a hash-linked sequence of events:

```
INBOUND_INTENT → POLICY_EVAL → BLASTBOX_EVIDENCE → EVIDENCE_REVIEW → APPROVAL_GRANTED
```

Each event includes the SHA-256 hash of the previous event. Modifying any event invalidates all subsequent hashes. This isn't just logging — it's a cryptographic commitment to the governance process.

```python
chain = GovernanceChain()
chain.append(EventType.INBOUND_INTENT, "agent:planner", "proposer",
             {"action": "deploy_model", "target": "prod"})
chain.append(EventType.POLICY_EVAL, "system:policy", "evaluator",
             {"result": "requires_review", "tier": 3})
```

### Separation of Powers

The proposer cannot approve their own proposal. The reviewer cannot be the proposer. This is enforced structurally at chain-append time:

| Role | Cannot also be |
|------|---------------|
| Proposer | Approver, Reviewer |
| Reviewer | Proposer |
| Approver | Proposer |

An agent that proposes a deployment cannot review the evidence or approve the action. This eliminates an entire class of governance bypass attacks.

### Deterministic Evidence Review

Before approval, the agent's proposed action executes in a sandboxed "blast box." The execution produces an evidence packet:

- Exit code
- Files modified (with paths)
- Network activity
- Resource consumption

A deterministic reviewer — no LLM, no inference — checks:
- Scope compliance (did the action stay within declared paths?)
- Secret detection (regex patterns for API keys, tokens, credentials)
- Risk scoring (did the action's risk exceed the tier threshold?)

No prompt injection surface. No model hallucination. Just deterministic checks.

### SLA-Based Auto-Deny

Every governance chain has a time budget based on its risk tier. If the chain exceeds its SLA without reaching a terminal state, it is automatically denied. The system degrades toward safety, not toward inaction.

## GovernanceArtifacts: Portable Trust

The output of a governance chain is a **GovernanceArtifact** — a self-contained, independently verifiable record:

```json
{
  "artifact_version": "1.0",
  "artifact_id": "ga-a1b2c3d4e5f6",
  "chain_id": "gc-...",
  "status": "APPROVED",
  "verdict": "allow",
  "integrity": true,
  "principals": [
    {"actor_id": "agent:planner", "role": "proposer"},
    {"actor_id": "agent:reviewer", "role": "reviewer"},
    {"actor_id": "agent:supervisor", "role": "approver"}
  ],
  "evidence": {
    "checks_total": 5,
    "checks_passed": 5,
    "risk_delta": 0.1,
    "scope_compliance": "FULL"
  },
  "artifact_hash": "sha256:..."
}
```

Any system can verify this artifact with just `hashlib` and `json`:

1. Recompute `artifact_hash` from content — does it match?
2. Verify `genesis_hash` = SHA-256 of `chain_id`
3. Check event hash chain integrity

No Gavel runtime needed. No special libraries. This makes governance artifacts truly portable across systems.

## AGT Integration

Gavel maps directly to Microsoft's Agent Governance Toolkit `PolicyDecision` schema:

| Gavel | AGT PolicyDecision |
|-------|-------------------|
| `artifact.verdict` | `verdict` ("allow"/"deny"/"escalate") |
| Chain summary | `reason` |
| Constitutional article | `matched_rule` |
| Full artifact | `metadata` |

This means any system consuming AGT `PolicyDecision` objects can receive governance chain decisions without modification.

## EU AI Act Compliance

For high-risk AI systems under the EU AI Act, Gavel generates Annex IV technical documentation automatically from governance chain data:

- System description and intended purpose
- Risk management measures
- Data governance practices
- Human oversight provisions
- Accuracy and robustness metrics

Compliance isn't an afterthought — it's a natural byproduct of structured governance.

## Design Principles

1. **Structural, not configurable.** Separation of powers isn't a policy you can turn off. It's enforced at the type system level.

2. **Deterministic verification.** No LLM in the review loop. Evidence review uses regex, path matching, and exit codes.

3. **Degrade toward safety.** If anything is unclear — deny. If the SLA expires — deny. If integrity fails — deny.

4. **Portable artifacts.** Governance records should be verifiable by any system, not locked into a specific runtime.

5. **Constitutional invariants.** Some rules are not subject to policy override. They are structural properties of the system.

## Getting Started

```bash
pip install gavel-governance
```

```python
from gavel import GovernanceChain, EventType, ChainStatus
from gavel.artifact import from_chain, verify_artifact, PolicyDecisionAdapter

# Build a chain, get an artifact, verify it
chain = GovernanceChain()
# ... append events ...
artifact = from_chain(chain)
assert verify_artifact(artifact.model_dump(mode="json"))["valid"]
```

Run the demo:
```bash
python examples/artifact_demo.py
```

## What's Next

- Integration with Microsoft's Agent Governance Toolkit as a `PolicyProvider`
- DID-based principal identity with Ed25519 signatures
- Multi-chain governance for complex workflows
- Real-time governance dashboard

Governance for autonomous agents isn't optional — it's infrastructure. Gavel makes it structural.

---

*Gavel is open source under the MIT license. [GitHub](https://github.com/jlugo63/gavel)*
