"""
SCENARIO A: Standalone Microsoft Agent Governance Toolkit
=========================================================

The setting: Same fintech company, same 2:14 AM incident.
The monitoring agent detects payments-service memory pressure.

This scenario shows what happens with ONLY Microsoft's toolkit.
It handles policy evaluation and identity well — but watch what's MISSING.
"""

# === What Microsoft's toolkit gives you ===

from agent_os import PolicyEngine, CapabilityModel
from agentmesh import AgentMeshClient

# 1. Define agent capabilities
monitor_caps = CapabilityModel(
    allowed_tools=["observe", "propose_scale"],
    denied_tools=["kubectl", "shell_exec", "secret_access"],
    max_tokens_per_call=4096,
)

# 2. Create policy engine
engine = PolicyEngine(capabilities=monitor_caps)

# 3. Agent wants to scale payments-service
decision = engine.evaluate(
    agent_id="did:mesh:ops-monitor",
    action="tool_call",
    tool="propose_scale",
)

print(f"Policy decision: {'ALLOW' if decision.allowed else 'DENY'}")
print(f"Latency: <0.1ms")
# >>> Policy decision: ALLOW
# >>> Latency: <0.1ms

# 4. Check agent trust score
mesh = AgentMeshClient("ops-monitor")
trust = mesh.get_trust_score()  # 0-1000 scale
print(f"Agent trust score: {trust}")
# >>> Agent trust score: 847

# 5. The action is ALLOWED. Agent proceeds to scale.
#    The toolkit logs the decision.
print("Action logged to audit trail.")
print("Agent executes: kubectl scale deployment payments-service --replicas=6")
print("")

# ============================================================
# HERE'S WHAT'S MISSING
# ============================================================

print("=" * 60)
print("WHAT MICROSOFT'S TOOLKIT HANDLED:")
print("=" * 60)
print("[OK] Policy evaluation: is this action type allowed for this agent?")
print("[OK] Identity: cryptographic DID verification")
print("[OK] Trust scoring: agent has earned 847/1000 trust")
print("[OK] Audit log: decision was recorded")
print("[OK] Latency: sub-millisecond evaluation")
print("")

print("=" * 60)
print("WHAT'S MISSING (the governance gap):")
print("=" * 60)
print("")
print("[--] WHO ELSE REVIEWED THIS?")
print("     The monitoring agent proposed AND the system approved.")
print("     No independent reviewer verified the proposal was sound.")
print("     No separation of powers.")
print("")
print("[--] WAS IT TESTED FIRST?")
print("     The action went straight to production.")
print("     No sandboxed execution. No evidence packet.")
print("     No proof that scaling from 3->6 replicas is safe.")
print("")
print("[--] IS THE EVIDENCE TAMPER-PROOF?")
print("     The audit log is append-only, but decisions aren't")
print("     hash-chained. You can prove an entry exists, but you")
print("     can't prove nothing was inserted between entries.")
print("")
print("[--] WHAT IF NOBODY'S AWAKE?")
print("     It's 2:14 AM. The toolkit has no escalation model.")
print("     No SLA timer. No auto-deny on timeout.")
print("     If the action needed human approval, it would just... wait.")
print("")
print("[--] CAN THE SAME AGENT GAME THE SYSTEM?")
print("     With trust score 847, ops-monitor could propose an action")
print("     and the system would allow it. Nothing prevents a compromised")
print("     agent from self-approving through high trust alone.")
print("")
print("[--] WHERE'S THE DECISION CHAIN?")
print("     If something goes wrong at 7:30 AM, the engineer sees:")
print("     'agent:ops-monitor called propose_scale -> ALLOW'")
print("     That's it. No proposal envelope. No evidence. No reviewer")
print("     rationale. No timeline of who decided what and when.")
print("")

print("=" * 60)
print("THE 7:30 AM INCIDENT REVIEW")
print("=" * 60)
print("")
print("Engineer opens the dashboard and sees:")
print("  - ops-monitor made a tool call: propose_scale")
print("  - Policy engine said: ALLOW")
print("  - Trust score: 847")
print("  - Action executed: kubectl scale --replicas=6")
print("")
print("Engineer asks: 'Why 6? Why not 5? Who verified this was")
print("proportionate? Did anyone check the diff? Was it tested?'")
print("")
print("Answer: Nobody. The policy said the action TYPE was allowed.")
print("It didn't evaluate whether THIS SPECIFIC action was WISE.")
print("")
print("Microsoft's toolkit answers: 'Is this agent allowed to do this?'")
print("It does NOT answer: 'Should this specific action happen, and can we prove it?'")
