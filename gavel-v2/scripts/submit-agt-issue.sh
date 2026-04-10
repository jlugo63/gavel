#!/usr/bin/env bash
# Submit the governance chains proposal issue to microsoft/agent-governance-toolkit.
# Prerequisites: gh CLI installed and authenticated (gh auth login)
set -euo pipefail

REPO="microsoft/agent-governance-toolkit"
TITLE="feat: Governance chains — tamper-evident multi-principal decision workflows"

BODY=$(cat <<'EOF'
## Summary

Governance chains add **tamper-evident, multi-principal decision workflows** on top of AGT's policy evaluation. Where AGT evaluates individual policy decisions, governance chains link those decisions into hash-chained sequences with separation of powers enforcement — the proposer, reviewer, and approver must be distinct principals.

This is implemented in [Gavel](https://github.com/jlugo63/gavel), a constitutional governance framework that already maps its output to AGT's `PolicyDecision` schema (`verdict` / `reason` / `matched_rule` / `metadata`).

## What it adds

| Capability | Description |
|---|---|
| **Governance chains** | Hash-linked sequences of governance events (propose → evaluate → review → approve → execute). Every decision is traceable and tamper-evident via SHA-256 chain integrity. |
| **Separation of powers** | Proposer, reviewer, and approver must be distinct actor IDs. Enforced structurally at chain-append time, not by policy configuration. |
| **Deterministic evidence review** | Non-LLM review of execution evidence: exit codes, scope compliance, secret detection, risk scoring. No model inference in the verification loop. |
| **GovernanceArtifact** | Portable, independently verifiable decision records. Any system can verify the artifact with only `hashlib` and `json` — no runtime dependency. |
| **PolicyDecision mapping** | Native output as AGT `PolicyDecision` with `verdict`/`reason`/`matched_rule`/`metadata`. Drop-in compatible with existing AGT consumers. |

## PolicyDecision integration

```python
from gavel.artifact import from_chain, PolicyDecisionAdapter

artifact = from_chain(chain, evidence_result)
decision = PolicyDecisionAdapter.to_policy_decision(artifact)
# {"verdict": "allow", "reason": "...", "matched_rule": "article-III:separation-of-powers", "metadata": {...}}
```

## Implementation status

- 320+ tests, 97%+ coverage
- Runs on Python 3.11+, only depends on `pydantic>=2.0`
- Self-contained integration package ready
- [Runnable demo](https://github.com/jlugo63/gavel/blob/main/examples/artifact_demo.py)

## Proposed next steps

1. Review this proposal for alignment with AGT's governance roadmap
2. If aligned, I'll submit a focused PR adding governance chain support as a `PolicyProvider`
3. The PR follows AGT contribution guidelines: conventional commits, typed public APIs, unit + edge case tests
EOF
)

echo "Creating issue on ${REPO}..."
gh issue create \
  --repo "${REPO}" \
  --title "${TITLE}" \
  --body "${BODY}" \
  --label "enhancement"

echo "Done. Issue created."
