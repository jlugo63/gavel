# Gavel Roadmap

## Phase 1: Constitutional Core -- Complete

- Append-only audit ledger with tamper detection
- Deterministic policy engine evaluating proposals against a written constitution
- Governance gateway with propose and health endpoints
- Read-only admin dashboard with live integrity status

## Phase 1.5: Human Approval Flow -- Complete

- Escalation path for proposals that require human judgment
- Authenticated approval endpoint with audit logging
- Dashboard integration for reviewing and approving escalated actions

## Phase 2: Controlled Autonomy -- In Progress

- Tiered autonomy levels (propose-only, sandboxed, canary, production)
- Isolated execution environment for agent actions
- Captured evidence of what changed during execution
- Agent framework integrations and Python SDK

## Phase 3: Separation of Powers

- Multi-agent review workflow (proposer cannot approve their own work)
- Attestation-based sign-off before high-risk execution
- Scoped credentials per agent role

## Phase 4: Risk Classification

- Structured risk model with explainable decisions
- Governance reporting (why allowed, who approved, what changed)
- Versioned policy logic with full audit trail

## Phase 5: Execution Tokens

- Scoped, expiring permissions tied to approved proposals
- Environment-level enforcement of token validity
- Automatic revocation on chain integrity failure

## Phase 6: Reversibility

- Rollback orchestration for failed or flagged changes
- Kill switch to freeze all active execution tokens
- Post-deploy health validation

## Phase 7: Scale + Compliance

- Role-based and attribute-based access control
- Multi-tenant isolation
- Compliance export bundles for common frameworks
- External audit witness for independent verification
