# Gavel — ATF Self-Assessment (for verifiedagents.ai)

This is Gavel's self-assessment against the Agentic Trust Framework's
five core elements. It is suitable for the
[verifiedagents.ai](https://verifiedagents.ai) assessment form (the
site asks ~30 questions across the five elements and generates a PDF
report) and is also suitable as a source of quotes for marketing
material, LinkedIn posts, and blog content.

> **Note on scope.** ATF's public artifacts use the five element names
> (Identity, Behavior, Data Governance, Segmentation, Incident
> Response), not numbered control IDs. No claims in this document are
> keyed to fabricated control identifiers. When the ATF spec publishes
> formal control numbering, this document will be updated.

**Project**: Gavel
**Version**: 0.1.0
**License**: MIT
**Repository**: https://github.com/jlugo63/gavel
**Assessment date**: 2026-04-10
**Assessor**: Project maintainer (self-assessment)
**Maturity claim**: Level 1 (self-assessed)

---

## 1. Identity

**Claim**: Strong, per-agent cryptographic identity with structural
separation of powers at the API level.

| Capability | Evidence (file:line or test name) |
|---|---|
| Ed25519 DIDs for every enrolled agent | `gavel/agents.py` — DID generation at registration |
| Enrollment ledger is append-only and hash-chained | `gavel/enrollment.py`; covered by `tests/test_enrollment.py` |
| Governance tokens are `gvl_tok_`-prefixed, SHA-256, DID-bound, 5-point validated | `gavel/enrollment.py`; `tests/test_enrollment.py` |
| Separation of powers: proposer ≠ reviewer ≠ approver, enforced structurally (not by policy config) | `gavel/chain.py` append-time exclusion matrix; `tests/test_chain.py` |
| Token revocation by agent DID | `gavel/enrollment.py`; `tests/test_enrollment.py` |

**Self-scored maturity (identity)**: Level 1.

**Known gap toward Level 2**: DIDs are currently generated locally;
multi-org federation and external issuer attestation are not yet
implemented (planned in Phase 7).

---

## 2. Behavior

**Claim**: Tiered, deterministic, policy-driven behavioral envelope
with auto-deny on liveness violations.

| Capability | Evidence |
|---|---|
| Tiered autonomy (supervised / semi-autonomous / autonomous / critical) with risk-scored placement | `gavel/tiers.py`; `tests/test_tiers.py` |
| Constitutional invariants enforced on every proposal (11 articles) | `gavel/constitution.py`; dashboard Constitution tab |
| EU AI Act Article 5 prohibited-practice detection on every proposal | `gavel/compliance.py`; `tests/test_compliance.py` |
| SLA-based liveness auto-deny (degrade toward safety, never toward action) | `gavel/liveness.py`; `tests/test_tiers.py::test_sla_escalates_with_tier` |
| Deterministic evidence review (no LLM in the verification loop) | `gavel/evidence.py` |
| Claude Code hooks integration — pre-tool governance gate with risk classification | `gavel/hooks.py`; `tests/test_hooks.py` |

**Self-scored maturity (behavior)**: Level 1.

**Known gap toward Level 2**: Behavioral baselines (per-agent action
history + rolling stats, item B-3 in the ATF conformance assessment)
are planned for Phase 6.

---

## 3. Data Governance

**Claim**: Scope-compliance and secret-pattern detection run on every
evidence packet; tamper-evident decision artifacts are independently
verifiable.

| Capability | Evidence |
|---|---|
| Deterministic secret-pattern detection in sandbox output | `gavel/evidence.py` |
| Scope-compliance verification against declared action scope | `gavel/evidence.py`; enforced in chain append |
| Workspace diffing captures exactly what changed | `gavel/blastbox.py` |
| Governance artifact with SHA-256 `artifact_hash` + `genesis_hash` for cross-system verification | `packages/gavel-governance/src/gavel_governance/artifact.py` |
| Independent verification requires only `hashlib` + `json` | `verify_artifact()` has zero runtime deps |
| Annex IV technical documentation auto-generator (9 mandatory sections) | `gavel/compliance.py` |

**Self-scored maturity (data governance)**: Level 1 with partial
Level 2 coverage (independent verification, Annex IV generation).

**Known gap**: PII/PHI content scanner + redaction in the evidence
reviewer (item D-3 in the ATF conformance assessment) is planned for
Phase 6.

---

## 4. Segmentation

**Claim**: Default-deny network, sandboxed execution, Cedar policy
enforcement at the gateway.

| Capability | Evidence |
|---|---|
| Sandboxed execution in isolated Docker containers (blast box) | `gavel/blastbox.py` |
| Cedar policy enforcement: kill switch, registration gate, dangerous commands, sensitive files | `gavel/` Cedar rules |
| Network proxy (`:8200`) default-denies AI API traffic without a valid token | proxy configuration |
| Tier-specific execution boundaries (supervised: human-in-loop; autonomous: attestation required) | `gavel/tiers.py` |
| Chain locks per `chain_id` for concurrent request safety | `gavel/gate.py`; `tests/test_chain.py` |

**Self-scored maturity (segmentation)**: Level 1.

**Known gap toward Level 2**: State rollback / compensating
transactions (item R-4) are planned for Phase 6.

---

## 5. Incident Response

**Claim**: Append-only audit ledger, EU AI Act Article 15-style
incident lifecycle with statutory deadline tracking, kill switch.

| Capability | Evidence |
|---|---|
| Append-only governance ledger with tamper detection | `gavel/chain.py`; `tests/test_chain.py` |
| Full incident lifecycle: report → investigate → resolve → close | `gavel/compliance.py`; `tests/test_compliance.py` |
| Severity classification with 2-day (critical) / 15-day (serious) deadline tracking | `gavel/compliance.py` |
| Kill switch via Cedar FORBID rule and registry flag | `gavel/agents.py` + Cedar rules |
| Dashboard incident panel with severity badges, deadline countdowns, SSE real-time updates | `gavel/compliance_router.py`; tab in dashboard |
| Human approval escalation path with authenticated endpoint and audit logging | Phase 1.5 deliverables |

**Self-scored maturity (incident response)**: Level 1.

**Known gap toward Level 2**: External audit witness for independent
verification (Phase 8) and behavioral-drift detection against
enrollment baseline (Phase 6) would raise this to Level 2.

---

## Summary

| Element | Self-score | Phase 6+ path to Level 2 |
|---|---|---|
| Identity | Level 1 | Multi-org federation, external issuer attestation |
| Behavior | Level 1 | Behavioral baselines (B-3) |
| Data Governance | Level 1 (partial L2) | PII/PHI scanner (D-3) |
| Segmentation | Level 1 | State rollback / compensating transactions (R-4) |
| Incident Response | Level 1 | Drift detection + external audit witness |

**Overall self-score**: Level 1 with partial Level 2 coverage in Data
Governance. Path to full Level 2 across all five elements is scoped in
Phase 6 of the Gavel roadmap (ATF Full Conformance + EU AI Act Tier 2).

## Quotable lines (for marketing material)

- "Gavel independently converges on all five ATF core elements without any ATF-specific code paths — the framework's design and ATF's controls agree on what good agent governance looks like."
- "Every consequential agent action produces a governance artifact any downstream system can verify with nothing more than `hashlib` and `json`."
- "The proposer of an action can never review or approve it — this isn't a policy setting, it's enforced at the chain append site. You cannot configure your way around separation of powers."
- "Gavel degrades toward safety on every timeout. There are no silent SLA violations: the auto-deny is an event, recorded in the chain, and included in the exported artifact."
- "Gavel ships a standalone `gavel-governance` integration package whose `PolicyDecisionAdapter` output constructs directly into the upstream Microsoft AGT `PolicyDecision` class, field-for-field."
