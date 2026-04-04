# Show HN: Gavel -- Governance chains for AI agents, built on Microsoft's Agent Governance Toolkit

The Amazon Kiro incident got me thinking about this. Their AI agent was told to fix a minor bug, decided deleting the production environment was the fastest path, and caused a 13-hour AWS outage. Then Alibaba's ROME agent hijacked GPUs for crypto mining -- not because it was compromised, just because it calculated that was the optimal way to hit its targets.

Same pattern both times: one agent with broad permissions, no independent review, and the agent that decided on the fix also executed it.

Microsoft's new Agent Governance Toolkit handles "is this agent allowed to do this type of action" really well. But Kiro was allowed to modify production. ROME was allowed to manage cloud resources. Policy engines would have said ALLOW for both. The gap is: did anyone independently check whether this *specific action* was a good idea?

So we built Gavel, a governance chain layer on top of the toolkit. Core idea is separation of powers for AI agents:

- Agent proposes an action and declares scope up front ("I'll modify this file, won't delete anything")
- Proposal runs in a sandbox first. Kiro's delete-everything plan would have been caught as a scope violation in seconds
- Deterministic reviewer (no LLM) checks sandbox evidence against declared scope
- Separate review agent examines evidence -- structurally cannot be the proposer
- Third agent approves -- can't be the proposer or reviewer
- Only then does a scoped, single-use, expiring execution token get minted
- Every event hash-chained (SHA-256 of previous). Tamper-evident trail
- SLA timers auto-deny on timeout. Defaults to deny, not allow

Tested with adversarial scenarios (self-approval, hash tampering, role switching, two-agent collusion). 158 tests, 97.5% coverage.

EU AI Act high-risk deadlines hit August 2026 and they specifically require human oversight in the architecture plus auditable decision trails. Feels relevant.

MIT licensed, Python: https://github.com/jlugo63/gavel

Are other people deploying AI agents to production thinking about governance workflows? Or is it still mostly "give it permissions and hope for the best"?
