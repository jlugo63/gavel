# ATF Ecosystem Entry — Gavel

This is the proposed entry to add to
[`massivescale-ai/agentic-trust-framework`](https://github.com/massivescale-ai/agentic-trust-framework)'s
`ECOSYSTEM.md`. It follows the existing Microsoft entry's structure
exactly: org/relationship/repo header line, one prose paragraph (≤10
lines), and a five-row ATF-element table.

---

## Gavel

**Organization**: jlugo63 (independent) | **Relationship**: Built on ATF-aligned toolchain (Microsoft Agent Governance Toolkit)
**Repository**: [jlugo63/gavel](https://github.com/jlugo63/gavel)

MIT-licensed Python (3.11+) constitutional governance layer that adds tamper-evident, multi-principal governance chains on top of Microsoft's Agent Governance Toolkit. Every consequential agent action flows through propose → policy check → sandboxed evidence → deterministic review → independent approval → scoped execution token, with hash-chained SHA-256 events and structural separation of powers (a proposer cannot review or approve its own action). Ships a standalone `gavel-governance` integration package whose `PolicyDecisionAdapter` output constructs directly into AGT's upstream `agentmesh.governance.policy.PolicyDecision` field-for-field. 351 tests passing; EU AI Act Tier 1 compliance (Annex III risk classification, Article 5 prohibited-practice detection, Annex IV doc generation, incident reporting); independently verifiable governance artifacts via `hashlib` + `json` alone.

| ATF Element | Gavel Coverage |
|---|---|
| Identity | Ed25519 DIDs at enrollment, governance tokens, proposer ≠ reviewer ≠ approver enforced structurally |
| Behavior | Tiered autonomy, risk scoring, constitutional invariants, SLA-based liveness auto-deny |
| Data Governance | Scope-compliance checks, secret-pattern detection in evidence review, tamper-evident decision artifacts |
| Segmentation | Sandboxed blast-box execution, Cedar policy enforcement, network proxy default-deny AI API traffic |
| Incident Response | Append-only audit ledger, Article 15-style incident lifecycle (report/investigate/resolve/close), 2-day/15-day deadline tracking |
