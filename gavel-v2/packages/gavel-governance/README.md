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
from gavel_governance import (
    from_governance_chain,
    verify_artifact,
    PolicyDecisionAdapter,
)

# Build an artifact from raw governance chain events
artifact = from_governance_chain(
    chain_id="gc-deploy-001",
    status="APPROVED",
    created_at="2026-04-10T12:00:00Z",
    events=[
        {"event_id": "e1", "event_type": "INBOUND_INTENT",
         "actor_id": "agent:planner", "role": "proposer",
         "timestamp": "2026-04-10T12:00:00Z", "event_hash": "..."},
        {"event_id": "e2", "event_type": "EVIDENCE_REVIEW",
         "actor_id": "agent:reviewer", "role": "reviewer",
         "timestamp": "2026-04-10T12:00:05Z", "event_hash": "..."},
        {"event_id": "e3", "event_type": "APPROVAL_GRANTED",
         "actor_id": "agent:supervisor", "role": "approver",
         "timestamp": "2026-04-10T12:00:10Z", "event_hash": "..."},
    ],
    integrity=True,
    evidence={
        "checks_total": 5, "checks_passed": 5,
        "scope_compliance": "FULL", "review_verdict": "PASS",
    },
)

# Convert to an AGT PolicyDecision dict — constructs directly into
# agentmesh.governance.policy.PolicyDecision(**decision) with no translation.
decision = PolicyDecisionAdapter.to_policy_decision(artifact)
# {
#   "allowed": True,
#   "action": "allow",
#   "reason": "Governance chain gc-deploy-001: approved by 3 principal(s), ...",
#   "matched_rule": "article-III:separation-of-powers",
#   "policy_name": "gavel.governance-chain",
#   "metadata": { "artifact_id": "ga-...", "chain_id": "gc-deploy-001", ... }
# }

# Independent verification — no runtime needed, only hashlib + json
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
    action: str                 # AGT PolicyDecision.action literal
    allowed: bool               # True iff action == "allow"
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

`PolicyDecisionAdapter.to_policy_decision(artifact)` returns a dict that
satisfies AGT's
[`agentmesh.governance.policy.PolicyDecision`](https://github.com/microsoft/agent-governance-toolkit/blob/main/packages/agent-mesh/src/agentmesh/governance/policy.py)
schema field-for-field:

| Output key | AGT `PolicyDecision` field | Value |
|---|---|---|
| `allowed` | `allowed: bool` | `action == "allow"` |
| `action` | `action: Literal[...]` | `"allow"` / `"deny"` / `"require_approval"` |
| `reason` | `reason: Optional[str]` | Human-readable chain summary |
| `matched_rule` | `matched_rule: Optional[str]` | e.g. `"article-III:separation-of-powers"` |
| `policy_name` | `policy_name: Optional[str]` | `"gavel.governance-chain"` |
| `metadata` | `metadata: Optional[dict]` | `{artifact_id, chain_id, integrity, evidence, artifact_hash, ...}` |

The dict can be passed directly to `PolicyDecision(**decision)` with no
translation. A mirror schema test in `tests/test_governance_artifact.py`
guards against drift from AGT's upstream schema.

Status → action mapping:

- **APPROVED / COMPLETED** → `"allow"`
- **DENIED / TIMED_OUT / ROLLED_BACK** → `"deny"`
- **PENDING / EVALUATING / ESCALATED / EXECUTING** → `"require_approval"`

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
