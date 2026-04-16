# ATF v0.9.1 Self-Assessment Checklist -- Gavel v2

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Project          | Gavel v2 (`gavel-governance` v0.1.0)       |
| Framework        | ATF v0.9.1                                 |
| Date             | 2026-04-11                                 |
| Result           | 17/25 FULLY MET, 8/25 PARTIALLY MET        |

Legend: `[x]` = FULLY MET, `[~]` = PARTIALLY MET, `[ ]` = NOT MET

---

## Element I -- Identity

| Status | Req | Requirement           | Evidence                                              |
|--------|-----|-----------------------|-------------------------------------------------------|
| [x]    | I-1 | Unique IDs            | `agents.py:39` agent_id + `crypto.py` Ed25519 DID    |
| [x]    | I-2 | Credential binding    | `enrollment.py:489-523` SHA-256 bound GovernanceToken |
| [~]    | I-3 | Identity verification | Token validation + Ed25519 signature verify. Gap: no mutual agent-to-agent verification; gateway-mediated only |
| [x]    | I-4 | Ownership             | `enrollment.py:64-78` PurposeDeclaration (cites ATF I-4) |
| [x]    | I-5 | Capability manifests  | `enrollment.py:81-93` CapabilityManifest              |

## Element B -- Behavioral Accountability

| Status | Req | Requirement            | Evidence                                              |
|--------|-----|------------------------|-------------------------------------------------------|
| [x]    | B-1 | Structured logging     | `chain.py:42-70` ChainEvent Pydantic model, hash-chained |
| [x]    | B-2 | Action attribution     | Every ChainEvent records actor_id + role_used         |
| [x]    | B-3 | Behavioral baselines   | `baseline.py` rolling window (default 200, configurable) |
| [~]    | B-4 | Anomaly detection      | 6 evasion signals + drift scoring, synchronous. Gap: no explicit <60s SLA guarantee |
| [~]    | B-5 | Explainability         | DriftReport.reasons + Finding.detail structured. Gap: no natural-language explainability for regulators |

## Element D -- Data Integrity

| Status | Req | Requirement            | Evidence                                              |
|--------|-----|------------------------|-------------------------------------------------------|
| [x]    | D-1 | Schema validation      | Pydantic BaseModel everywhere                         |
| [~]    | D-2 | Injection prevention   | PromptInjectionDetector stubbed in `agt_compat.py`. Gap: stub-only unless real AGT installed; not in gate path |
| [x]    | D-3 | PII/PHI protection     | `privacy.py` 9 pattern types + Luhn + redaction       |
| [x]    | D-4 | Output validation      | `evidence.py` 7 deterministic checks on blast box output |
| [~]    | D-5 | Data lineage           | Hash-chain provides decision lineage. Gap: no data-object-level lineage tracking |

## Element S -- Scope Constraints

| Status | Req | Requirement                | Evidence                                              |
|--------|-----|----------------------------|-------------------------------------------------------|
| [x]    | S-1 | Resource allowlists        | `enrollment.py:96-107` ResourceAllowlist              |
| [x]    | S-2 | Action boundaries          | `enrollment.py:110-120` ActionBoundaries              |
| [~]    | S-3 | Rate limiting              | max_actions_per_minute declared at enrollment. Gap: no runtime enforcement (no token bucket/sliding window) |
| [~]    | S-4 | Transaction limits         | budget_tokens + budget_usd declared + validated. Gap: no runtime budget decrement per action |
| [x]    | S-5 | Blast radius containment   | `blastbox.py` sandboxed execution + `rollback.py` state rollback |

## Element R -- Resilience

| Status | Req | Requirement            | Evidence                                              |
|--------|-----|------------------------|-------------------------------------------------------|
| [~]    | R-1 | Circuit breakers       | `liveness.py` SLA escalation + auto-deny on timeout. Gap: no proper open/half-open/closed circuit breaker pattern |
| [x]    | R-2 | Kill switches          | `agents.py:119-134` kill() synchronous, sub-second    |
| [x]    | R-3 | Session revocation     | `enrollment.py:619-635` TokenManager.revoke()         |
| [x]    | R-4 | State rollback         | `rollback.py` Snapshotter with compensating transactions |
| [x]    | R-5 | Graceful degradation   | FallbackBehavior + Constitutional Article IV.2 default-DENY |

---

## Summary

```
FULLY MET:     17/25  (68%)
PARTIALLY MET:  8/25  (32%)
NOT MET:        0/25   (0%)
```

**Tier 1 (Documented): ACHIEVED**

All 25 requirements have been assessed with evidence citations pointing to
specific source files and line numbers. The 8 partially met requirements
have identified gaps with planned remediation approaches documented in the
conformance statement (`docs/atf-conformance-statement.md`).
