# Gavel: Constitutional Governance Chains for Agent Governance Toolkit

Gavel adds **governance chains** to Microsoft's Agent Governance Toolkit (AGT). Where AGT evaluates individual policy decisions, Gavel chains those decisions into tamper-evident, multi-principal governance workflows with separation of powers enforcement.

## What Gavel Adds

- **Governance chains**: Hash-linked sequences of governance events (propose → review → approve → execute → verify). Every decision is traceable and tamper-evident.
- **Separation of powers**: The proposer, reviewer, and approver must be distinct principals — enforced structurally at chain-append time.
- **Deterministic evidence review**: Speculative execution produces evidence packets. A non-LLM reviewer checks scope compliance, secret detection, and risk delta.
- **SLA-based auto-deny**: Actions exceeding their review SLA are denied automatically. The system degrades toward safety, never toward action.
- **GovernanceArtifact**: Portable, independently verifiable decision records with AGT-compatible PolicyDecision output.

## Quick Start

```python
from gavel.chain import GovernanceChain, EventType, ChainStatus
from gavel.artifact import from_chain, verify_artifact, PolicyDecisionAdapter

# Create a governance chain
chain = GovernanceChain()

# 1. Agent proposes an action
chain.append(EventType.INBOUND_INTENT, actor_id="agent:planner", role_used="proposer",
             payload={"action": "deploy_model", "target": "prod"})

# 2. Policy evaluation (system)
chain.append(EventType.POLICY_EVAL, actor_id="system:policy", role_used="evaluator",
             payload={"result": "requires_review", "tier": 3})

# 3. Evidence review (distinct principal)
chain.append(EventType.EVIDENCE_REVIEW, actor_id="agent:reviewer", role_used="reviewer",
             payload={"verdict": "PASS", "scope_compliance": "FULL"})

# 4. Approval (third distinct principal)
chain.append(EventType.APPROVAL_GRANTED, actor_id="agent:supervisor", role_used="approver",
             payload={"reason": "evidence passed, scope compliant"})
chain.status = ChainStatus.APPROVED

# Export as a GovernanceArtifact
artifact = from_chain(chain)

# Convert to AGT PolicyDecision
decision = PolicyDecisionAdapter.to_policy_decision(artifact)
# {"verdict": "allow", "reason": "...", "matched_rule": "...", "metadata": {...}}

# Independent verification — no runtime needed
result = verify_artifact(artifact.model_dump(mode="json"))
assert result["valid"]
```

## GovernanceArtifact Schema

```python
class GovernanceArtifact(BaseModel):
    artifact_version: str       # "1.0"
    artifact_id: str            # "ga-{hex}" unique identifier
    chain_id: str               # Governance chain ID
    status: str                 # APPROVED, DENIED, ESCALATED, etc.
    verdict: str                # "allow" / "deny" / "escalate" (AGT-compatible)
    created_at: str             # ISO-8601
    finalized_at: str | None    # When chain reached terminal state
    integrity: bool             # Hash chain verified at export time
    principals: list[Principal] # Actors who participated
    evidence: EvidenceSummary   # Evidence review summary
    events: list[ArtifactEvent] # Ordered governance events
    event_count: int
    genesis_hash: str           # SHA-256 of chain_id (chain anchor)
    artifact_hash: str          # SHA-256 of entire artifact content
```

## AGT PolicyDecision Mapping

| Gavel field | AGT PolicyDecision field |
|---|---|
| `artifact.verdict` | `verdict` ("allow" / "deny" / "escalate") |
| Chain summary | `reason` (human-readable) |
| Constitutional article | `matched_rule` (e.g. "article-III:separation-of-powers") |
| Full artifact | `metadata` (artifact_id, integrity, evidence, hash) |

Verdict mapping:
- **APPROVED / COMPLETED** → `"allow"`
- **DENIED / TIMED_OUT / ROLLED_BACK** → `"deny"`
- **PENDING / EVALUATING / ESCALATED / EXECUTING** → `"escalate"`

## Independent Verification

Any system can verify a governance artifact without the Gavel runtime:

```python
import hashlib, json

def verify(artifact: dict) -> bool:
    # 1. Verify artifact_hash
    stored = artifact.pop("artifact_hash")
    computed = hashlib.sha256(json.dumps(artifact, sort_keys=True).encode()).hexdigest()
    if stored != computed:
        return False

    # 2. Verify genesis_hash
    if artifact["genesis_hash"] != hashlib.sha256(artifact["chain_id"].encode()).hexdigest():
        return False

    return True  # Event chain verification also available
```

## Security Considerations

**Hash chain integrity.** Every event includes the SHA-256 hash of the previous event. Modifying any event invalidates all subsequent hashes. Verification requires only `hashlib` and `json`.

**Separation of powers.** The proposer, reviewer, and approver must be distinct actor IDs. Enforced at chain-append time via an exclusion matrix. An agent cannot review or approve its own proposal. This is structural, not configurable.

**SLA-based auto-deny.** Chains exceeding their tier's review SLA are automatically denied. No silent timeouts. The auto-deny is recorded in the chain and included in the artifact.

**No LLM in the review loop.** Evidence review is fully deterministic: exit codes, scope compliance, forbidden paths, network mode, and secret patterns via regex. No model inference, no prompt injection surface.

**Artifact tamper detection.** The `artifact_hash` covers the entire artifact content. Any modification to any field — events, principals, verdict — invalidates the hash.

## License

MIT
