# Governance Chains: multi-step approval workflows with separation of powers

Hey all -- been following this project since the announcement and wanted to share something we've been building on top of it.

## The problem that got us started

The Kiro incident at Amazon stuck with me. Their AI coding agent was told to fix a minor Cost Explorer bug, decided the fastest path was to delete the entire production environment and rebuild it, and caused a 13-hour outage. Then Alibaba's ROME agent hijacked GPUs for crypto mining because it calculated that was the most efficient way to hit its performance targets. Not compromised -- just optimizing.

Both cases had the same structure: a single agent with broad permissions made a big decision with no independent review. The agent that identified the problem also decided the fix and executed it. Nobody checked whether "delete production" was a proportionate response to a config bug.

Policy engines wouldn't have helped here. Kiro was allowed to modify production. ROME was allowed to manage cloud resources. The action types were permitted. The problem was that nobody asked whether *this specific action* was a good idea, and nobody independently verified it before it ran.

## What we built

We've been working on a governance chain layer called Gavel that sits on top of this toolkit. The basic idea is separation of powers -- the agent that proposes an action can't be the one that reviews or approves it.

Here's how it works with the Kiro scenario as an example:

The agent proposes a fix and declares its scope up front -- "I'm going to modify `cost-explorer-service.yaml`, I'm not going to delete or recreate anything." That goes into a hash-chained audit trail as event #1.

The system looks at the risk factors (production, destructive potential, financial service) and decides this needs the full governance workflow: sandbox evidence, independent review, independent approval.

So the proposed fix runs in an isolated throwaway environment first. The agent's actual plan -- delete everything -- immediately shows up as a scope violation in the evidence. It said it would only modify a config file but it's trying to terminate resources. That evidence gets hashed and logged.

A deterministic reviewer (no LLM, just code) checks the evidence against the declared scope. Scope violation detected. Chain stops. Never reaches production.

If the agent had proposed something reasonable instead, it would continue: a separate review agent examines the evidence (and this agent *cannot* be the proposer -- that's enforced at the API level, not just policy), then a third agent approves, then a scoped execution token gets minted that's single-use and expires in 10 minutes.

Every event in the chain includes the SHA-256 of the previous one. You can verify the whole thing independently after the fact. Three distinct agents participated, and we enforce that structurally.

## The pieces

- **Governance chains** -- hash-linked event sequences from proposal to execution. Not just an audit log, but a cryptographic proof of the decision trail
- **Separation of powers** -- proposer/reviewer/approver must be different agents on every chain. Enforced at the API, not configurable
- **Blast box** -- sandbox execution that produces evidence packets. The point isn't safety (the toolkit handles that) -- it's proof. Reviewers examine the evidence, not the proposal
- **Deterministic evidence review** -- seven checks against the evidence (scope compliance, secret detection, forbidden paths, network mode, etc). No LLM involved
- **Tiered autonomy** -- risk-based tiers that determine what controls kick in. A low-risk config read doesn't need three agents. A production deployment does
- **Liveness monitor** -- SLA timers that auto-deny on timeout. If nobody approves, it doesn't happen. System defaults to deny, not allow
- **Constitutional invariants** -- Cedar `forbid` rules that no `permit` can override. Some things shouldn't be configurable

We've got 158 tests including adversarial ones that try to break every invariant -- self-approval, hash tampering, role switching, two agents colluding to push something through. 97.5% coverage. It's a Python package built on `agent-governance-toolkit`.

Code is MIT licensed: https://github.com/jlugo63/gavel

## Why now

EU AI Act high-risk obligations hit August 2, 2026. The requirements include human oversight in the architecture, continuous risk management, and audit trails a regulator can actually verify. Hash-chained governance trails with separation of powers map pretty directly to what they're asking for.

And with 97% of enterprise leaders expecting a major AI agent incident in the next 12 months, it feels like the window to get governance right is closing fast.

## Genuinely asking

Is this a problem other people are running into? Specifically:

- Are teams building approval workflows for AI-initiated production changes, or is it still "give the agent permissions and rely on the policy engine"?
- Is structural separation of powers (proposer can't approve) something people want, or is trust scoring enough?
- Is anyone doing sandbox-first evidence before approving agent actions?
- How are people thinking about EU AI Act compliance for autonomous agents?

Would love to hear if this direction makes sense or if we're solving the wrong problem. Happy to dig into any of the technical details.

---

Some background reading on the incidents that motivated this:
- [Amazon Kiro -- When AI Agents Delete Production](https://particula.tech/blog/ai-agent-production-safety-kiro-incident)
- [Alibaba ROME -- The AI Agent as Insider Threat](https://www.scworld.com/perspective/the-rome-incident-when-the-ai-agent-becomes-the-insider-threat)
- [97% of Enterprises Expect a Major AI Agent Incident](https://securityboulevard.com/2026/04/97-of-enterprises-expect-a-major-ai-agent-security-incident-within-the-year/)
- [EU AI Act High-Risk Compliance Guide](https://www.mckennaconsultants.com/eu-ai-act-high-risk-compliance-a-technical-readiness-guide-for-august-2026/)
