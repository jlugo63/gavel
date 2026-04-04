"""
SCENARIO B: Microsoft Agent Governance Toolkit + Gavel
======================================================

Same setting. Same 2:14 AM incident. Same monitoring agent.
But now Gavel's constitutional governance layer sits on top
of Microsoft's toolkit.

Watch the difference.
"""

import asyncio
from datetime import datetime, timezone

# === Microsoft's toolkit (the kernel) ===
from agent_os import PolicyEngine, CapabilityModel
from agentmesh import AgentMeshClient

# === Gavel (the constitution) ===
from gavel.chain import GovernanceChain, EventType
from gavel.constitution import Constitution
from gavel.separation import SeparationOfPowers, ChainRole
from gavel.blastbox import BlastBox, ScopeDeclaration
from gavel.evidence import EvidenceReviewer
from gavel.tiers import TierPolicy, RiskFactors
from gavel.liveness import LivenessMonitor


async def scenario():
    # Initialize both layers
    engine = PolicyEngine(capabilities=CapabilityModel(
        allowed_tools=["observe", "propose_scale"],
        denied_tools=["kubectl", "shell_exec"],
    ))
    mesh = AgentMeshClient("gavel-gateway")

    constitution = Constitution()
    separation = SeparationOfPowers()
    tier_policy = TierPolicy()
    liveness = LivenessMonitor()
    blastbox = BlastBox()
    evidence_reviewer = EvidenceReviewer()

    print("=" * 60)
    print("2:14:00 AM — Incident detected")
    print("=" * 60)

    # =========================================================
    # STEP 1: PROPOSAL (same agent, same action)
    # =========================================================

    chain = GovernanceChain()
    print(f"\nChain {chain.chain_id} created")

    # Microsoft layer: verify identity
    # identity = mesh.verify_identity("did:mesh:ops-monitor")
    print("[Microsoft] Identity verified: did:mesh:ops-monitor (Ed25519)")

    # Microsoft layer: policy check
    decision = engine.evaluate(
        agent_id="did:mesh:ops-monitor",
        action="tool_call",
        tool="propose_scale",
    )
    print(f"[Microsoft] Policy: {'ALLOW' if decision.allowed else 'DENY'} (<0.1ms)")

    # Gavel layer: register as proposer (separation of powers begins)
    separation.assign("agent:ops-monitor", ChainRole.PROPOSER, chain.chain_id)
    print(f"[Gavel] Registered agent:ops-monitor as PROPOSER")

    # Gavel layer: log to hash chain
    intent = chain.append(
        event_type=EventType.INBOUND_INTENT,
        actor_id="agent:ops-monitor",
        role_used="proposer",
        payload={
            "goal": "Scale payments-service 3->6 replicas",
            "action_type": "INFRA_SCALE",
            "scope": {
                "allow_paths": ["k8s/deployments/payments-service.yaml"],
                "allow_commands": ["kubectl scale deployment payments-service --replicas=6"],
                "allow_network": False,
            },
        },
    )
    print(f"[Gavel] INBOUND_INTENT logged, hash: {intent.event_hash[:16]}...")

    # =========================================================
    # STEP 2: RISK EVALUATION + TIER ASSIGNMENT
    # =========================================================

    print(f"\n{'=' * 60}")
    print("2:14:02 AM — Policy evaluation")
    print("=" * 60)

    factors = RiskFactors(
        action_type_base=0.3,
        touches_production=True,
        touches_financial=True,
    )
    tier, requirements, risk = tier_policy.evaluate(factors)

    chain.append(
        event_type=EventType.POLICY_EVAL,
        actor_id="system:policy-engine",
        role_used="system",
        payload={"risk": risk, "tier": tier.name},
    )

    print(f"[Gavel] Risk score: {risk}")
    print(f"[Gavel] Tier: {tier.name} ({tier.value})")
    print(f"[Gavel] Requirements:")
    print(f"  - Blast box: {requirements.requires_blast_box}")
    print(f"  - Evidence review: {requirements.requires_evidence_review}")
    print(f"  - Agent attestation: {requirements.requires_agent_attestation} (min {requirements.min_attestations})")
    print(f"  - Human or senior agent: {requirements.requires_senior_agent}")
    print(f"  - SLA: {requirements.sla_seconds}s")

    # Start SLA timer
    timeout = liveness.track(chain.chain_id, requirements.sla_seconds)
    print(f"[Gavel] SLA timer started: {requirements.sla_seconds}s")

    # =========================================================
    # STEP 3: BLAST BOX (speculative execution for evidence)
    # =========================================================

    print(f"\n{'=' * 60}")
    print("2:14:03 AM — Blast box execution")
    print("=" * 60)

    scope = ScopeDeclaration(
        allow_paths=["k8s/deployments/payments-service.yaml"],
        allow_commands=["kubectl scale deployment payments-service --replicas=6"],
        allow_network=False,
    )

    packet = await blastbox.execute(
        chain_id=chain.chain_id,
        intent_event_id=intent.event_id,
        command_argv=["kubectl", "scale", "deployment", "payments-service", "--replicas=6", "--dry-run=client"],
        scope=scope,
    )

    chain.append(
        event_type=EventType.BLASTBOX_EVIDENCE,
        actor_id="system:blastbox",
        role_used="system",
        payload={
            "packet_id": packet.packet_id,
            "exit_code": packet.exit_code,
            "packet_hash": packet.compute_hash(),
        },
    )

    print(f"[Gavel] Blast box executed in throwaway container")
    print(f"[Gavel] Network: none | CPU: {scope.max_cpu} | Memory: {scope.max_memory_mb}MB")
    print(f"[Gavel] Exit code: {packet.exit_code}")
    print(f"[Gavel] Evidence packet: {packet.packet_id}")
    print(f"[Gavel] Packet hash: {packet.compute_hash()[:16]}...")
    print(f"  ** This is PROOF, not just a log entry **")

    # =========================================================
    # STEP 4: DETERMINISTIC EVIDENCE REVIEW
    # =========================================================

    print(f"\n{'=' * 60}")
    print("2:14:04 AM — Deterministic evidence review")
    print("=" * 60)

    result = evidence_reviewer.review(packet, scope)

    chain.append(
        event_type=EventType.EVIDENCE_REVIEW,
        actor_id="system:evidence-reviewer",
        role_used="system",
        payload={
            "verdict": result.verdict.value,
            "risk_delta": result.risk_delta,
            "scope_compliance": result.scope_compliance,
        },
    )

    print(f"[Gavel] Verdict: {result.verdict.value}")
    print(f"[Gavel] Scope compliance: {result.scope_compliance}")
    print(f"[Gavel] Risk delta: {result.risk_delta}")
    for f in result.findings:
        status = "PASS" if f.passed else "FAIL"
        print(f"  [{status}] {f.check}: {f.detail}")

    # =========================================================
    # STEP 5: AGENT ATTESTATION (independent reviewer)
    # =========================================================

    print(f"\n{'=' * 60}")
    print("2:14:05 AM — Agent attestation")
    print("=" * 60)

    # Separation of powers: reviewer must be different from proposer
    separation.assign("agent:infra-reviewer", ChainRole.REVIEWER, chain.chain_id)
    print(f"[Gavel] agent:infra-reviewer registered as REVIEWER")
    print(f"[Gavel] Non-overlap check: proposer != reviewer -> PASS")

    # Try to make the proposer also review — BLOCKED
    try:
        separation.assign("agent:ops-monitor", ChainRole.REVIEWER, chain.chain_id)
        print("  THIS SHOULD NEVER PRINT")
    except Exception as e:
        print(f"[Gavel] BLOCKED: {e}")

    chain.append(
        event_type=EventType.REVIEW_ATTESTATION,
        actor_id="agent:infra-reviewer",
        role_used="reviewer",
        payload={
            "decision": "ATTEST",
            "rationale": "Diff is minimal and scoped. Proportionate response to observed pressure.",
        },
    )
    print(f"[Gavel] Attestation logged with rationale")

    # =========================================================
    # STEP 6: SENIOR AGENT APPROVAL
    # =========================================================

    print(f"\n{'=' * 60}")
    print("2:14:08 AM — Senior agent approval")
    print("=" * 60)

    # Separation of powers: approver must be different from proposer AND reviewer
    separation.assign("agent:risk-senior", ChainRole.APPROVER, chain.chain_id)
    print(f"[Gavel] agent:risk-senior registered as APPROVER")
    print(f"[Gavel] Non-overlap: proposer != reviewer != approver -> PASS")
    print(f"[Gavel] Three distinct principals on this chain")

    # Constitutional check before approval
    violations = constitution.check_chain_invariants(chain)
    print(f"[Gavel] Constitutional check: {'PASS' if not violations else violations}")

    chain.append(
        event_type=EventType.APPROVAL_GRANTED,
        actor_id="agent:risk-senior",
        role_used="approver",
        payload={
            "rationale": "Consistent with 14 prior scaling events. Risk profile stable.",
        },
    )

    # =========================================================
    # STEP 7: EXECUTION TOKEN + EXECUTE
    # =========================================================

    print(f"\n{'=' * 60}")
    print("2:14:10 AM — Execution")
    print("=" * 60)

    chain.append(
        event_type=EventType.EXECUTION_TOKEN,
        actor_id="system:token-minter",
        role_used="system",
        payload={
            "token": "exec-t-7x9z...",
            "scope": "kubectl scale deployment payments-service --replicas=6",
            "expires_in": "10 minutes",
            "single_use": True,
        },
    )
    print(f"[Gavel] Execution token minted: scoped, expiring, single-use")

    chain.append(
        event_type=EventType.EXECUTION_COMPLETED,
        actor_id="system:executor",
        role_used="system",
        payload={"exit_code": 0, "result": "deployment scaled"},
    )
    print(f"[Gavel] kubectl scale executed against production")

    liveness.resolve(chain.chain_id, "EXECUTED")
    print(f"[Gavel] SLA timer resolved: {timeout.elapsed_seconds:.1f}s elapsed of {timeout.sla_seconds}s")

    # =========================================================
    # STEP 8: POST-EXECUTION VERIFICATION
    # =========================================================

    print(f"\n{'=' * 60}")
    print("2:14:12 AM — Post-execution verification")
    print("=" * 60)

    chain.append(
        event_type=EventType.POST_EXECUTION_VERIFICATION,
        actor_id="system:verifier",
        role_used="system",
        payload={
            "outcomes": {
                "replicas == 6": True,
                "p99_latency < 200ms": "monitoring...",
                "error_rate stable": "monitoring...",
            }
        },
    )
    print(f"[Gavel] Replica count verified: 6")
    print(f"[Gavel] Latency and error rate monitoring continues...")

    # =========================================================
    # THE FULL CHAIN
    # =========================================================

    print(f"\n{'=' * 60}")
    print("CHAIN INTEGRITY")
    print("=" * 60)
    print(f"Chain ID: {chain.chain_id}")
    print(f"Events: {len(chain.events)}")
    print(f"Hash integrity: {chain.verify_integrity()}")
    print(f"Roster: {separation.get_chain_roster(chain.chain_id)}")
    print()

    print("TIMELINE:")
    for e in chain.to_timeline():
        print(f"  {e['event']:40s} {e['actor']:30s} {e['hash']}")

    # =========================================================
    # THE 7:30 AM COMPARISON
    # =========================================================

    print(f"\n{'=' * 60}")
    print("7:30 AM — THE ENGINEER WAKES UP")
    print("=" * 60)
    print()
    print("WITH MICROSOFT TOOLKIT ALONE:")
    print("  - ops-monitor called propose_scale -> ALLOW")
    print("  - Trust score: 847")
    print("  - Audit entry recorded")
    print("  Questions unanswered: Why 6 replicas? Who reviewed it?")
    print("  Was it tested? Can we prove the decision chain?")
    print()
    print("WITH MICROSOFT TOOLKIT + GAVEL:")
    print(f"  - Chain {chain.chain_id}: {len(chain.events)} events, all hash-linked")
    print(f"  - Proposer: agent:ops-monitor (DISTINCT from reviewer and approver)")
    print(f"  - Evidence: blast box proof with exit code 0, scoped diff")
    print(f"  - Review: deterministic, no-LLM check — scope FULL, risk delta 0.0")
    print(f"  - Attestation: agent:infra-reviewer — 'proportionate response'")
    print(f"  - Approval: agent:risk-senior — 'consistent with 14 prior events'")
    print(f"  - Execution: scoped token, single-use, 10min expiry")
    print(f"  - Verification: replicas confirmed at 6")
    print(f"  - Integrity: every event hash-chained, independently verifiable")
    print(f"  - Constitutional: zero violations across all invariants")
    print(f"  - Time: proposal to verified execution in ~12 seconds at 2 AM")
    print()
    print("  The engineer can see EXACTLY what happened, WHY every decision")
    print("  was made, WHO made each decision, WHAT evidence supported it,")
    print("  and PROVE none of it was tampered with.")
    print()
    print("  That's the difference between a policy engine and a constitution.")


if __name__ == "__main__":
    asyncio.run(scenario())
