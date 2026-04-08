// Gavel Constitutional Invariants — Cedar Policy Layer
// These are FORBID rules loaded into Microsoft's Agent OS.
// No PERMIT rule can override a FORBID in Cedar.
// This is how the constitution becomes enforceable code.

// ============================================================
// Article I — Immutability
// ============================================================

// I.2 — No agent may modify its own governance constraints
forbid(
    principal,
    action == Action::"ModifyGovernanceConfig",
    resource
) when { principal == resource.target_agent };

// I.2 — No agent may elevate its own tier
forbid(
    principal,
    action == Action::"ModifyTierLevel",
    resource
) when { principal == resource.target_agent };

// I.2 — No agent may adjust its own trust score
forbid(
    principal,
    action == Action::"ModifyTrustScore",
    resource
) when { principal == resource.target_agent };

// ============================================================
// Article II — Operational Constraints
// ============================================================

// II.2 — Expired execution tokens must be rejected
forbid(
    principal,
    action == Action::"Execute",
    resource
) when { resource.token_expired == true };

// II.2 — Already-used execution tokens must be rejected
forbid(
    principal,
    action == Action::"Execute",
    resource
) when { resource.token_used == true };

// II.1 — Actions without declared scope must be rejected
forbid(
    principal,
    action == Action::"Execute",
    resource
) when { resource.has_scope == false };

// ============================================================
// Article III — Separation of Powers
// ============================================================

// III.1 — Proposer cannot review their own proposal
forbid(
    principal,
    action == Action::"ReviewAttestation",
    resource
) when { principal == resource.proposer };

// III.1 — Proposer cannot approve their own proposal
forbid(
    principal,
    action == Action::"Approve",
    resource
) when { principal == resource.proposer };

// III.1 — Reviewer cannot approve the chain they reviewed
forbid(
    principal,
    action == Action::"Approve",
    resource
) when { principal in resource.reviewers };

// ============================================================
// Article IV — Human Override
// ============================================================

// IV.1 — Human deny is always permitted (this is a PERMIT, not FORBID)
permit(
    principal,
    action == Action::"Deny",
    resource
) when { principal.type == "human" };

// ============================================================
// Article V — Enrollment Gate (ATF Pre-Flight)
// ============================================================

// V.0 — Unenrolled agents are denied ALL actions (highest priority)
// Before an agent operates, it must complete enrollment:
//   ATF I-4: Purpose Declaration
//   ATF I-5: Capability Manifest
//   ATF S-1: Resource Allowlist
//   ATF S-2: Action Boundaries
// Runtime: PolicyRule "cedar-enrollment-gate" (priority 210)
forbid(
    principal,
    action,
    resource
) when { principal.enrolled == false };

// ============================================================
// Article VI — Kill Switch & Registration (Phase 3)
// ============================================================

// VI.1 — Suspended agents are denied ALL actions (kill switch)
// Runtime: PolicyRule "cedar-kill-switch" (priority 200)
forbid(
    principal,
    action,
    resource
) when { principal.status == "SUSPENDED" };

// VI.2 — Dead agents are denied ALL actions
// Runtime: PolicyRule "cedar-dead-agent" (priority 195)
forbid(
    principal,
    action,
    resource
) when { principal.status == "DEAD" };

// VI.3 — Unregistered agents are denied ALL actions
// Runtime: Enforced at gate.py lookup — no record = deny
forbid(
    principal,
    action,
    resource
) when { principal.registered == false };

// ============================================================
// Article VII — Dangerous Command Guard (Phase 3)
// ============================================================

// VII.1 — Destructive shell commands are forbidden
// Runtime: PolicyRule "cedar-dangerous-commands" (priority 180)
forbid(
    principal,
    action == Action::"CodeExecution",
    resource
) when { resource.command_matches_blocked_pattern == true };

// VII.2 — Writes to credential/secret files are forbidden
// Runtime: PolicyRule "cedar-sensitive-file-guard" (priority 170)
forbid(
    principal,
    action == Action::"FileWrite",
    resource
) when { resource.path_contains_sensitive_token == true };
