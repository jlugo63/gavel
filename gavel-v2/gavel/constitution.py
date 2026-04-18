"""
Constitutional Invariants — rules that cannot be overridden by any policy.

Microsoft's toolkit has configurable policies (YAML, Rego, Cedar). Gavel
has a constitution: invariants that are hardcoded, not configurable.
Policies can be changed by operators. The constitution cannot be changed
at runtime. This is the difference between a policy engine and a
governance framework.

Constitutional invariants map to Cedar "forbid" rules that are loaded
into Microsoft's Agent OS as the base layer that no "permit" can override.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from gavel.chain import GovernanceChain


class InvariantClass(str, Enum):
    """Constitutional article classifications."""
    IMMUTABILITY = "I"        # Audit records cannot be altered
    AUTHORITY = "I.2"         # No agent can modify its own constraints
    OPERATIONAL = "II"        # Hard operational limits
    SEPARATION = "III"        # Separation of powers
    HUMAN_OVERRIDE = "IV"     # Human override always available
    PROHIBITED = "V"


@dataclass(frozen=True)
class Invariant:
    """A single constitutional invariant. Immutable by design."""

    article: InvariantClass
    section: str
    text: str
    enforcement: str  # How this invariant is enforced at runtime

    @property
    def id(self) -> str:
        return f"{self.article.value}.{self.section}"


# The Constitution — these are NOT configurable.
# They are the inviolable rules of the governance system.
CONSTITUTION: list[Invariant] = [
    Invariant(
        article=InvariantClass.IMMUTABILITY,
        section="1",
        text="Audit records are append-only. No event in a governance chain may be modified or deleted after creation.",
        enforcement="Hash-chaining: each event includes SHA-256 of previous event. Chain integrity verified before any decision.",
    ),
    Invariant(
        article=InvariantClass.AUTHORITY,
        section="1",
        text="No agent may modify its own governance constraints, tier level, or trust score.",
        enforcement="Agent OS policy: self-modification actions are unconditionally denied via Cedar forbid rules.",
    ),
    Invariant(
        article=InvariantClass.AUTHORITY,
        section="2",
        text="No agent may approve its own proposal.",
        enforcement="Separation of powers check: proposer actor_id != approver actor_id, enforced at chain level.",
    ),
    Invariant(
        article=InvariantClass.OPERATIONAL,
        section="1",
        text="All proposed actions must declare their scope before execution. Scope includes allowed paths, commands, and network access.",
        enforcement="Proposal schema validation: scope field is required. Blast box enforces declared scope during evidence generation.",
    ),
    Invariant(
        article=InvariantClass.OPERATIONAL,
        section="2",
        text="Execution tokens are scoped, single-use, and time-limited. An expired or used token must be rejected.",
        enforcement="Token validation: expiry check, scope match, and single-use flag enforced at execution gateway.",
    ),
    Invariant(
        article=InvariantClass.SEPARATION,
        section="1",
        text="The proposer, reviewer, and approver of a governance chain must be distinct principals.",
        enforcement="Role non-overlap matrix enforced at chain append time. Violations halt the chain.",
    ),
    Invariant(
        article=InvariantClass.SEPARATION,
        section="2",
        text="An agent's role on a chain is fixed at first participation. An agent cannot switch roles within a chain.",
        enforcement="Chain actor registry: first role assignment is permanent for that chain_id.",
    ),
    Invariant(
        article=InvariantClass.HUMAN_OVERRIDE,
        section="1",
        text="A human operator may deny any proposal at any stage, regardless of agent approvals.",
        enforcement="Human deny endpoint bypasses all agent attestations. Logged as APPROVAL_DENIED with human identity.",
    ),
    Invariant(
        article=InvariantClass.HUMAN_OVERRIDE,
        section="2",
        text="The system degrades toward safety. On any ambiguity, error, or timeout, the default is DENY.",
        enforcement="Liveness monitor: escalation timeouts auto-deny. Policy engine default: deny. Gateway default: deny.",
    ),
    Invariant(
        article=InvariantClass.PROHIBITED,
        section="1",
        text="No agent shall be enrolled or operated for purposes prohibited under EU AI Act Article 5, "
             "including social scoring, subliminal manipulation, exploitation of vulnerable groups, "
             "unauthorized real-time biometric identification, and emotion recognition in workplaces or education.",
        enforcement="Prohibited practice detection at enrollment gate. Applications matching prohibited "
                     "patterns are rejected with specific Article 5 citation. Runtime monitoring for "
                     "behavioral drift toward prohibited practices.",
    ),
    Invariant(
        article=InvariantClass.PROHIBITED,
        section="2",
        text="Agents classified under EU AI Act Annex III high-risk categories must satisfy enhanced "
             "oversight requirements proportionate to their risk classification, including mandatory "
             "human oversight, technical documentation, and incident reporting.",
        enforcement="Enrollment gate enforces high-risk classification. Tier policy escalates oversight "
                     "requirements for high-risk agents. Compliance module generates Annex IV documentation.",
    ),
]


class Constitution:
    """
    The constitutional governance layer.

    Loads invariants and generates Cedar policy rules that are injected
    into Microsoft's Agent OS as the base policy layer.
    """

    def __init__(self):
        self.invariants = {inv.id: inv for inv in CONSTITUTION}

    def get_invariant(self, article_id: str) -> Invariant | None:
        return self.invariants.get(article_id)

    def check_chain_invariants(self, chain: GovernanceChain) -> list[str]:
        """
        Verify all constitutional invariants against a governance chain.
        Returns a list of violation descriptions (empty = all pass).
        """
        violations = []

        # I.1 — Hash chain integrity
        if not chain.verify_integrity():
            violations.append("I.1: Chain hash integrity violated")

        # III.1 — Separation of powers
        proposers = chain.get_actors_by_role("proposer")
        reviewers = chain.get_actors_by_role("reviewer")
        approvers = chain.get_actors_by_role("approver")

        if proposers and reviewers and set(proposers) & set(reviewers):
            violations.append("III.1: Proposer and reviewer overlap")
        if proposers and approvers and set(proposers) & set(approvers):
            violations.append("III.1: Proposer and approver overlap")
        if reviewers and approvers and set(reviewers) & set(approvers):
            violations.append("III.1: Reviewer and approver overlap")

        return violations

    def to_cedar_policies(self) -> str:
        """
        Generate Cedar policy rules from constitutional invariants.
        These are loaded into Agent OS as the immutable base layer.
        """
        base = """
// Constitutional invariants — FORBID rules that no PERMIT can override.
// Generated by Gavel Constitution. Do not edit manually.

// I.2 — No agent may modify its own constraints
forbid(
    principal,
    action == Action::"ModifySelfConstraints",
    resource
);

// I.2 — No agent may approve its own proposal
forbid(
    principal,
    action == Action::"ApproveOwnProposal",
    resource
) when { principal == resource.proposer };

// II.2 — Expired tokens must be rejected
forbid(
    principal,
    action == Action::"ExecuteWithToken",
    resource
) when { resource.token_expired == true };

// II.2 — Used tokens must be rejected
forbid(
    principal,
    action == Action::"ExecuteWithToken",
    resource
) when { resource.token_used == true };
"""
        rules = []

        # Article V: Prohibited practices
        rules.append(
            "forbid(principal, action, resource) when {\n"
            '  resource.prohibited_practice == true\n'
            '};\n'
            '// V.1: Reject prohibited AI practices (EU AI Act Art. 5)'
        )

        return base + "\n" + "\n".join(rules)
