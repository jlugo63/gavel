# Gavel

Constitutional governance for autonomous AI agents.

Built on [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit). Adds governance chains, separation of powers, blast box execution, evidence review, and tiered autonomy with escalation.

## Install

```bash
pip install gavel-governance
```

## Quick Start

```python
from gavel import GovernanceChain, Constitution, SeparationOfPowers

chain = GovernanceChain()
constitution = Constitution()
separation = SeparationOfPowers()
```

## What Gavel Adds

Microsoft's toolkit answers: *"Is this agent allowed to do this?"*

Gavel answers: *"Should this specific action happen, and can we prove it?"*

| Concept | What It Does |
|---------|-------------|
| Governance Chains | Hash-linked decision trails from proposal to execution |
| Separation of Powers | Proposer, reviewer, and approver must be distinct principals |
| Blast Box | Sandboxed execution that produces cryptographic evidence |
| Evidence Review | Deterministic, non-LLM review of blast box output |
| Tiered Autonomy | Risk-based governance tiers (0-3) with escalation |
| Liveness Monitor | SLA timers that auto-deny on timeout |
| Constitution | Inviolable invariants that no policy can override |

## License

MIT
