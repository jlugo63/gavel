# GitHub Issue Draft: microsoft/agent-governance-toolkit

**Title:** feat: Governance chains — tamper-evident multi-principal decision workflows

**Labels:** `enhancement`, `governance`, `community`

---

## Summary

Governance chains add **tamper-evident, multi-principal decision workflows** on top of AGT's policy evaluation. Where AGT evaluates individual policy decisions, governance chains link those decisions into hash-chained sequences with separation of powers enforcement — the proposer, reviewer, and approver must be distinct principals.

This is implemented in [Gavel](https://github.com/jlugo63/gavel), a constitutional governance framework whose output maps field-for-field to AGT's `agentmesh.governance.policy.PolicyDecision` (`allowed` / `action` / `reason` / `matched_rule` / `policy_name` / `metadata`).

## What it adds

| Capability | Description |
|---|---|
| **Governance chains** | Hash-linked sequences of governance events (propose → evaluate → review → approve → execute). Every decision is traceable and tamper-evident via SHA-256 chain integrity. |
| **Separation of powers** | Proposer, reviewer, and approver must be distinct actor IDs. Enforced structurally at chain-append time, not by policy configuration. |
| **Deterministic evidence review** | Non-LLM review of execution evidence: exit codes, scope compliance, secret detection, risk scoring. No model inference in the verification loop. |
| **GovernanceArtifact** | Portable, independently verifiable decision records. Any system can verify the artifact with only `hashlib` and `json` — no runtime dependency. |
| **PolicyDecision mapping** | Native output as AGT `PolicyDecision` with `allowed`/`action`/`reason`/`matched_rule`/`policy_name`/`metadata`. Drop-in compatible with existing AGT consumers. |
| **SLA-based auto-deny** | Chains exceeding review SLA are denied automatically. The system degrades toward safety, never toward inaction. |

## PolicyDecision integration

Gavel's `PolicyDecisionAdapter` maps governance chain outcomes directly to AGT's schema:

```python
from gavel_governance import from_governance_chain, PolicyDecisionAdapter

artifact = from_governance_chain(chain_id, status, created_at, events, evidence=ev)
decision = PolicyDecisionAdapter.to_policy_decision(artifact)
# {
#   "allowed": true,
#   "action": "allow",
#   "reason": "Governance chain gc-...: approved by 3 principal(s), evidence review pass, integrity verified",
#   "matched_rule": "article-III:separation-of-powers",
#   "policy_name": "gavel.governance-chain",
#   "metadata": {
#     "artifact_id": "ga-...",
#     "chain_id": "gc-...",
#     "integrity": true,
#     "principal_count": 3,
#     "evidence": { "checks_total": 5, "checks_passed": 5, ... },
#     "artifact_hash": "sha256:...",
#     "artifact_version": "1.0"
#   }
# }

# Construct an AGT PolicyDecision directly (AGT is not a hard dep of this package):
# from agentmesh.governance.policy import PolicyDecision
# pd = PolicyDecision(**decision)
```

## How it fits AGT's architecture

Gavel implements `PolicyProviderInterface` — it can serve as a policy evaluator that returns `PolicyDecision` objects. The difference is that each decision carries a full governance chain artifact in its metadata, enabling:

1. **Audit trails** — Every decision has a hash-chain back to the original intent
2. **Multi-principal verification** — Decisions require multiple distinct actors
3. **Independent verification** — Artifacts can be verified without Gavel or AGT runtime
4. **EU AI Act alignment** — Annex IV technical documentation generation included

## Implementation status

- 320+ tests, 97%+ coverage
- Runs on Python 3.11+, only depends on `pydantic>=2.0`
- Self-contained integration package ready at `packages/gavel-governance/`
- Runnable demo: `examples/artifact_demo.py`

## Proposed next steps

1. Review this proposal for alignment with AGT's governance roadmap
2. If aligned, I'll submit a focused PR adding governance chain support as a `PolicyProvider`
3. The PR would follow AGT's contribution guidelines: conventional commits, typed public APIs, unit + edge case tests

Happy to discuss scope, interface design, or adjust the approach based on maintainer feedback.
