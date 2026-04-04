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
