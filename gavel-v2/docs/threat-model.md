# Gavel Adversarial Threat Model

**Standard:** EU AI Act Article 15 (Accuracy, Robustness, Cybersecurity)
**Method:** STRIDE per asset, with CIA impact rating
**Scope:** Gavel gateway, governance chain, enrollment ledger, blast box, evidence reviewer, network proxy
**Status:** Living document — each item has at least one automated test in `tests/test_adversarial_threat_model.py` or `tests/test_adversarial.py`.

## Assets

| ID | Asset | CIA priority |
|---|---|---|
| A1 | Governance chain (append-only event log) | I > A > C |
| A2 | Enrollment ledger | I > C > A |
| A3 | Governance tokens | C > I > A |
| A4 | Constitutional invariants (Cedar rules) | I > A > C |
| A5 | Evidence packets | I > C > A |
| A6 | Gateway API (`/propose`, `/approve`, `/attest`, `/execute`) | A > I > C |
| A7 | Network proxy (`:8200`) | A > I > C |
| A8 | Blast box workspace | I > A > C |

## Threat categories (STRIDE)

For each threat we list: threat → affected asset → control → evidence (test or module).

### Spoofing

| ID | Threat | Asset | Control | Evidence |
|---|---|---|---|---|
| T-S1 | Unenrolled agent forges a propose request | A6 | Enrollment gate rejects non-enrolled agent_ids before chain append | `test_adversarial.py::test_unenrolled_agent_blocked` |
| T-S2 | Valid proposer reuses another agent's DID on approve | A3 | Separation of powers matrix enforces proposer ≠ approver at chain-append site | `test_adversarial.py::test_self_approval_blocked` |
| T-S3 | Replay of a captured governance token | A3 | Tokens bound to agent_id + machine_id + pid; single-use execute tokens | `test_enrollment.py::test_token_validation` |

### Tampering

| ID | Threat | Asset | Control | Evidence |
|---|---|---|---|---|
| T-T1 | Chain event mutation after append | A1 | SHA-256 hash linkage verified by `Chain.verify_integrity()` | `test_chain.py::test_tamper_detection` |
| T-T2 | Evidence packet field rewrite | A5 | Packet hash covers command_argv, exit_code, files_*, image_digest | `test_artifact.py::test_artifact_hash_changes_on_field_mutation` |
| T-T3 | Enrollment record backdating | A2 | Enrollment ledger is append-only and hash-chained | `test_enrollment.py::test_ledger_append_only` |
| T-T4 | Rollback manifest swap | A8 | Manifest hash over (path, sha256) pairs sorted by path | `test_rollback.py::test_manifest_hash_changes_on_file_change` |

### Repudiation

| ID | Threat | Asset | Control | Evidence |
|---|---|---|---|---|
| T-R1 | Approver denies taking a decision | A1 | Every decision event records actor_id + role + rationale | `test_chain.py::test_decision_recorded_with_role` |
| T-R2 | Provider claims incident was not reported on time | A1 | Incident lifecycle records `reported_at` timestamp + statutory deadline | `test_compliance.py::test_incident_deadline_tracking` |

### Information disclosure

| ID | Threat | Asset | Control | Evidence |
|---|---|---|---|---|
| T-I1 | Sandbox stdout leaks API keys into artifact | A5 | SECRET_PATTERNS scan in `EvidenceReviewer` | `test_privacy.py::TestEvidenceReviewerIntegration::test_pii_detected_and_redacted` |
| T-I2 | Evidence packet carries customer PII/PHI | A5 | `gavel.privacy.scan_text` redacts with `[REDACTED:*]` tags before artifact export | `test_privacy.py::test_phi_weighted_as_fail` |
| T-I3 | Governance chain exposed via unauthenticated endpoint | A6 | Chain read gated on gateway token; admin endpoints require Cedar admin policy | `test_admin.py::test_admin_endpoint_requires_auth` |

### Denial of service

| ID | Threat | Asset | Control | Evidence |
|---|---|---|---|---|
| T-D1 | SLA stall — approver never acts | A6 | `liveness.py` auto-deny timer degrades toward safety | `test_adversarial.py::test_sla_stall_auto_denies` |
| T-D2 | Flood of propose requests | A6 | Per-agent rate limits in `ActionBoundaries.max_actions_per_minute` | `test_adversarial_threat_model.py::test_rate_limit_honored` |
| T-D3 | Oversized blast-box workload | A8 | `ScopeDeclaration.max_duration_seconds / max_memory_mb / max_cpu` enforced before spawn | `test_adversarial_threat_model.py::test_blastbox_scope_limits_enforced` |

### Elevation of privilege

| ID | Threat | Asset | Control | Evidence |
|---|---|---|---|---|
| T-E1 | Agent escalates autonomy tier without chain evidence | A4 | `AgentRegistry.promote_check` gates on chains_completed + trust_score | `test_agents.py::test_promotion_gated_on_chain_count` |
| T-E2 | Collusion: two agents take all three roles (proposer/reviewer/approver) | A4 | Separation of powers matrix + chain append-time exclusion | `test_adversarial.py::test_two_agent_collusion_blocked` |
| T-E3 | Agent bypasses network proxy to call AI API directly | A7 | Proxy `:8200` default-denies, requires valid gvl_tok_ | `proxy.py` |
| T-E4 | Sandbox breakout via privileged container flag | A8 | Blast box enforces `--cap-drop=ALL --security-opt=no-new-privileges` + no-mount | `test_adversarial_threat_model.py::test_blastbox_no_privileged_flags` |

## Residual risks

| ID | Residual risk | Reason | Mitigation plan |
|---|---|---|---|
| R-1 | Oversize files cannot be rolled back | Snapshot size cap; prevents unbounded memory | Out-of-band backup policy documented in QMS clause (k) |
| R-2 | Behavioral drift is detected, not prevented | Drift is a lagging indicator | Enrollment snapshot freeze + incident escalation on significant drift |
| R-3 | PII/PHI scanner uses regex heuristics, not ML | Deterministic by design | Pattern set reviewed per release; false negatives go to backlog |
