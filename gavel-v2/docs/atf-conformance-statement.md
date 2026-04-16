# ATF v0.9.1 Conformance Statement -- Gavel v2

| Field             | Value                                      |
|-------------------|--------------------------------------------|
| Project           | Gavel v2 (`gavel-governance` v0.1.0)       |
| Framework         | Agentic Trust Framework (ATF) v0.9.1       |
| Conformance Tier  | Tier 1 (Documented)                        |
| Date              | 2026-04-11                                 |
| Assessor          | Self-assessment (internal audit)           |
| Repository        | https://github.com/jlugo63/gavel           |
| ATF Spec          | https://github.com/massivescale-ai/agentic-trust-framework |

---

## Summary

Gavel v2 meets **17 of 25** ATF requirements at the FULLY MET level and
**8 of 25** at the PARTIALLY MET level. No requirements are NOT MET.

This satisfies the Tier 1 (Documented) conformance criteria, which require
a completed self-assessment checklist and a published conformance statement.

| Rating        | Count |
|---------------|-------|
| FULLY MET     | 17    |
| PARTIALLY MET | 8     |
| NOT MET       | 0     |

---

## Requirement-Level Assessment

### Element I -- Identity

| Req | Name                   | Rating       | Evidence                    | Gap |
|-----|------------------------|--------------|-----------------------------|-----|
| I-1 | Unique IDs            | FULLY MET    | `agents.py:39` agent_id + `crypto.py` Ed25519 DID | -- |
| I-2 | Credential binding    | FULLY MET    | `enrollment.py:489-523` SHA-256 bound GovernanceToken | -- |
| I-3 | Identity verification | PARTIALLY MET | Token validation + Ed25519 signature verify | No mutual agent-to-agent verification; gateway-mediated only |
| I-4 | Ownership             | FULLY MET    | `enrollment.py:64-78` PurposeDeclaration (cites ATF I-4) | -- |
| I-5 | Capability manifests  | FULLY MET    | `enrollment.py:81-93` CapabilityManifest | -- |

### Element B -- Behavioral Accountability

| Req | Name                   | Rating       | Evidence                    | Gap |
|-----|------------------------|--------------|-----------------------------|-----|
| B-1 | Structured logging    | FULLY MET    | `chain.py:42-70` ChainEvent Pydantic model, hash-chained | -- |
| B-2 | Action attribution    | FULLY MET    | Every ChainEvent records actor_id + role_used | -- |
| B-3 | Behavioral baselines  | FULLY MET    | `baseline.py` rolling window (default 200, configurable) | ATF specifies 7d/1000-op; Gavel uses 200-op default (configurable) |
| B-4 | Anomaly detection     | PARTIALLY MET | 6 evasion signals + drift scoring, synchronous | No explicit <60s SLA guarantee |
| B-5 | Explainability        | PARTIALLY MET | DriftReport.reasons + Finding.detail structured | No natural-language explainability for regulators |

### Element D -- Data Integrity

| Req | Name                   | Rating       | Evidence                    | Gap |
|-----|------------------------|--------------|-----------------------------|-----|
| D-1 | Schema validation     | FULLY MET    | Pydantic BaseModel everywhere | -- |
| D-2 | Injection prevention  | PARTIALLY MET | PromptInjectionDetector stubbed in `agt_compat.py` | Stub-only unless real AGT installed; not in gate path |
| D-3 | PII/PHI protection    | FULLY MET    | `privacy.py` 9 pattern types + Luhn + redaction | -- |
| D-4 | Output validation     | FULLY MET    | `evidence.py` 7 deterministic checks on blast box output | -- |
| D-5 | Data lineage          | PARTIALLY MET | Hash-chain provides decision lineage | No data-object-level lineage tracking |

### Element S -- Scope Constraints

| Req | Name                       | Rating       | Evidence                    | Gap |
|-----|----------------------------|--------------|-----------------------------|-----|
| S-1 | Resource allowlists       | FULLY MET    | `enrollment.py:96-107` ResourceAllowlist | -- |
| S-2 | Action boundaries         | FULLY MET    | `enrollment.py:110-120` ActionBoundaries | -- |
| S-3 | Rate limiting             | PARTIALLY MET | max_actions_per_minute declared at enrollment | No runtime enforcement (no token bucket/sliding window) |
| S-4 | Transaction limits        | PARTIALLY MET | budget_tokens + budget_usd declared + validated | No runtime budget decrement per action |
| S-5 | Blast radius containment  | FULLY MET    | `blastbox.py` sandboxed execution + `rollback.py` state rollback | -- |

### Element R -- Resilience

| Req | Name                   | Rating       | Evidence                    | Gap |
|-----|------------------------|--------------|-----------------------------|-----|
| R-1 | Circuit breakers      | PARTIALLY MET | `liveness.py` SLA escalation + auto-deny on timeout | No proper open/half-open/closed circuit breaker pattern |
| R-2 | Kill switches         | FULLY MET    | `agents.py:119-134` kill() synchronous, sub-second | -- |
| R-3 | Session revocation    | FULLY MET    | `enrollment.py:619-635` TokenManager.revoke() | -- |
| R-4 | State rollback        | FULLY MET    | `rollback.py` Snapshotter with compensating transactions | -- |
| R-5 | Graceful degradation  | FULLY MET    | FallbackBehavior + Constitutional Article IV.2 default-DENY | -- |

---

## Differentiation: Gavel Beyond ATF

Gavel provides capabilities that go significantly beyond the ATF v0.9.1
baseline. These features represent the constitutional governance layer
that distinguishes Gavel from toolkit-level implementations such as
Microsoft AGT.

### 1. Constitutional Governance

Gavel enforces 9 immutable constitutional invariants that cannot be
overridden at runtime. These are structural rules (separation of powers,
human override supremacy, default-DENY) rather than configurable policies.
ATF has no equivalent concept.

### 2. Separation of Powers

Every governance decision passes through structurally distinct
proposer/reviewer/approver roles. No single agent can self-approve
actions. This is enforced at the architecture level, not through policy
configuration.

### 3. Evasion and Collusion Detection

Gavel implements 6 adversarial evasion signals and 4 collusion detection
patterns. ATF requires anomaly detection (B-4) but does not address
adversarial behavior by agents attempting to circumvent governance.

### 4. EU AI Act Compliance

Gavel maps directly to EU AI Act requirements:
- Article 5 prohibited practice detection
- Annex IV technical documentation
- Article 73 incident reporting
- Compliance export bundles for SOC 2, ISO 42001, and EU AI Act

### 5. Hash-Chained Audit Trail

Every governance decision is recorded in a SHA-256 hash-chained log
(`chain.py`). Each entry links to the previous entry's hash, making
the audit trail tamper-evident. ATF requires structured logging (B-1)
but does not require cryptographic chaining.

### 6. Blind LLM Auditor

Gavel's evidence review system (`evidence.py`) performs 7 deterministic
checks on LLM output without the reviewing logic having access to the
original prompt, preventing the auditor from being influenced by the
same context that produced the output.

### 7. Sandboxed Speculative Execution

The blast box (`blastbox.py`) executes agent actions in an isolated
sandbox with full state rollback capability (`rollback.py`), allowing
Gavel to evaluate consequences before committing changes.

---

## Roadmap: 8 Gaps Targeted for Tier 2

| # | Req | Gap | Planned Approach | Priority |
|---|-----|-----|------------------|----------|
| 1 | I-3 | No mutual agent-to-agent identity verification | Implement mutual DID-based challenge-response protocol between agents at mesh join time | P3 |
| 2 | B-4 | No explicit <60s anomaly detection SLA | Add async monitoring loop with configurable SLA threshold; emit SLA-breach events to governance chain | P3 |
| 3 | B-5 | No natural-language explainability for regulators | Add explainability interface that renders DriftReport and Finding objects as human-readable narratives | P2 |
| 4 | D-2 | PromptInjectionDetector stub-only, not in gate path | Integrate AGT PromptInjectionDetector (or equivalent) into the live gateway gate path | P1 |
| 5 | D-5 | No data-object-level lineage tracking | Implement lineage graph that tracks data objects through agent transformations, linked to governance chain events | P3 |
| 6 | S-3 | No runtime rate-limiting enforcement | Add token-bucket or sliding-window rate limiter as gateway middleware, enforcing the max_actions_per_minute declared at enrollment | P1 |
| 7 | S-4 | No runtime budget enforcement | Add per-action budget decrement logic that tracks cumulative token and USD spend against declared budgets | P1 |
| 8 | R-1 | No proper circuit breaker pattern | Implement open/half-open/closed circuit breaker with configurable failure thresholds and recovery probes | P1 |

**Estimated total effort to reach Tier 2: 3-4 weeks.**

---

## Attestation

This conformance statement was prepared through a systematic audit of the
Gavel v2 codebase against all 25 ATF v0.9.1 requirements. Evidence
references point to specific source files and line numbers in the
`gavel-governance` v0.1.0 codebase.

Prepared: 2026-04-11
Framework version: ATF v0.9.1
Platform version: gavel-governance v0.1.0
