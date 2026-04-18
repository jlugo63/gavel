"""
Gavel Model Walkthrough — run with: python -m gavel.demo

Walks through the governance model step by step using Gavel's core
components directly. No server, no database, no API key required.
This is a guided walkthrough, not a live test.

For the live demo with real LLM agents hitting the gateway, see:
    examples/live_demo.py

Shows:
  1. Proposal with risk scoring and tier assignment
  2. Separation of powers enforcement (self-approval blocked)
  3. Independent review and attestation
  4. Multi-party approval with execution token
  5. Portable artifact export and offline verification
  6. Tamper detection (hash chain integrity)
"""

from __future__ import annotations

import hashlib
import json
import sys
import time

from gavel.chain import GovernanceChain, EventType, ChainStatus
from gavel.separation import SeparationOfPowers, SeparationViolation, ChainRole
from gavel.tiers import TierPolicy, RiskFactors
from gavel.constitution import Constitution
from gavel.blastbox import ScopeDeclaration, EvidencePacket
from gavel.evidence import EvidenceReviewer


# -- Output helpers ----------------------------------------------------------

def _bar(width: int = 68) -> str:
    return "-" * width

def _header(text: str) -> None:
    print(f"\n{'=' * 68}")
    print(f"  {text}")
    print(f"{'=' * 68}")

def _step(num: int, text: str) -> None:
    print(f"\n  [{num}] {text}")
    print(f"  {_bar(64)}")

def _ok(text: str) -> None:
    print(f"      [PASS] {text}")

def _fail(text: str) -> None:
    print(f"      [BLOCKED] {text}")

def _info(text: str) -> None:
    print(f"      {text}")

def _pause(seconds: float = 0.4) -> None:
    time.sleep(seconds)


# -- Demo flow ---------------------------------------------------------------

def run_demo() -> None:
    print()
    print("  Gavel v0.1.0 -- Constitutional Governance for AI Agents")
    print("  Built on Microsoft's Agent Governance Toolkit")
    print()
    print("  Scenario: An ops-monitor agent wants to scale a production")
    print("  service from 3 to 6 replicas. This touches production and")
    print("  financial resources, so governance is required.")
    print()
    print(f"  {_bar(64)}")

    # ---- Initialize components ----
    sop = SeparationOfPowers()
    tier_policy = TierPolicy()
    constitution = Constitution()
    reviewer = EvidenceReviewer()

    # ---- Step 1: Proposal ----
    _step(1, "PROPOSE -- agent:ops-monitor submits a proposal")
    _pause()

    chain = GovernanceChain()
    scope = ScopeDeclaration(
        allow_paths=["/app/k8s/deployments/payments.yaml"],
        allow_commands=["kubectl scale deployment payments --replicas=6"],
        allow_network=False,
    )
    risk_factors = RiskFactors(
        action_type_base=0.3,
        touches_production=True,
        touches_financial=True,
        scope_breadth=0.2,
    )

    # Register proposer
    sop.assign("agent:ops-monitor", ChainRole.PROPOSER, chain.chain_id)

    # Log intent
    chain.append(
        EventType.INBOUND_INTENT,
        actor_id="agent:ops-monitor",
        role_used="proposer",
        payload={
            "goal": "Scale payments-service from 3 to 6 replicas",
            "action_type": "INFRASTRUCTURE_SCALE",
            "scope": {
                "allow_paths": scope.allow_paths,
                "allow_commands": scope.allow_commands,
                "allow_network": scope.allow_network,
            },
        },
    )

    _info(f"Chain ID:    {chain.chain_id}")
    _info(f"Proposer:    agent:ops-monitor")
    _info(f"Goal:        Scale payments-service from 3 to 6 replicas")
    _info(f"Hash:        {chain.events[-1].event_hash[:24]}...")

    # ---- Step 2: Risk scoring and tier ----
    _step(2, "POLICY EVAL -- risk scoring and tier assignment")
    _pause()

    tier, reqs, risk = tier_policy.evaluate(risk_factors)

    chain.append(
        EventType.POLICY_EVAL,
        actor_id="system:policy-engine",
        role_used="system",
        payload={
            "risk_score": round(risk, 3),
            "tier": tier.name,
            "requires_blast_box": reqs.requires_blast_box,
            "requires_attestation": reqs.requires_agent_attestation,
            "requires_human": reqs.requires_human_approval,
            "sla_seconds": reqs.sla_seconds,
        },
    )

    _info(f"Risk score:  {risk:.3f}")
    _info(f"Tier:        {tier.name} (Tier {tier.value})")
    _info(f"Requires:    blast box={reqs.requires_blast_box}, "
          f"attestation={reqs.requires_agent_attestation}, "
          f"human={reqs.requires_human_approval}")
    _info(f"SLA:         {reqs.sla_seconds}s before auto-deny")
    _info(f"Hash:        {chain.events[-1].event_hash[:24]}...")

    # ---- Step 3: Blast box evidence ----
    _step(3, "BLAST BOX -- sandboxed execution produces evidence")
    _pause()

    evidence = EvidencePacket(
        chain_id=chain.chain_id,
        intent_event_id=chain.events[0].event_id,
        command_argv=["kubectl", "scale", "deployment", "payments", "--replicas=6"],
        scope=scope,
        exit_code=0,
        stdout_hash=hashlib.sha256(b"deployment.apps/payments scaled").hexdigest(),
        stderr_hash=hashlib.sha256(b"").hexdigest(),
        diff_hash=hashlib.sha256(b"replicas: 3 -> 6").hexdigest(),
        files_modified=["/app/k8s/deployments/payments.yaml"],
        network_mode="none",
    )

    chain.append(
        EventType.BLASTBOX_EVIDENCE,
        actor_id="system:blast-box",
        role_used="system",
        payload={
            "packet_id": evidence.packet_id,
            "exit_code": 0,
            "files_modified": evidence.files_modified,
            "network_mode": "none",
            "evidence_hash": evidence.compute_hash()[:24],
        },
    )

    _info(f"Packet ID:   {evidence.packet_id}")
    _info(f"Exit code:   0")
    _info(f"Files:       /app/k8s/deployments/payments.yaml")
    _info(f"Network:     disabled (sandboxed)")
    _info(f"Evidence:    {evidence.compute_hash()[:24]}...")

    # ---- Step 4: Deterministic evidence review ----
    _step(4, "EVIDENCE REVIEW -- 7 deterministic checks (no LLM)")
    _pause()

    review = reviewer.review(
        packet=evidence,
        declared_scope=scope,
        stdout_content="deployment.apps/payments scaled",
        stderr_content="",
    )

    chain.append(
        EventType.EVIDENCE_REVIEW,
        actor_id="system:evidence-reviewer",
        role_used="system",
        payload={
            "verdict": review.verdict.value,
            "findings_count": len(review.findings),
            "risk_delta": review.risk_delta,
            "scope_compliance": review.scope_compliance,
        },
    )

    checks_passed = sum(1 for f in review.findings if f.passed)
    _info(f"Verdict:     {review.verdict.value}")
    _info(f"Checks:      {checks_passed}/{len(review.findings)} passed")
    _info(f"Risk delta:  {review.risk_delta}")
    _info(f"Scope:       {review.scope_compliance}")

    # ---- Step 5: Self-approval attempt (BLOCKED) ----
    _step(5, "SELF-APPROVAL ATTEMPT -- agent:ops-monitor tries to approve")
    _pause()

    try:
        sop.assign("agent:ops-monitor", ChainRole.APPROVER, chain.chain_id)
        _ok("Self-approval succeeded")  # should never reach here
    except SeparationViolation as e:
        _fail("Separation of powers violation!")
        _info(f"Actor:       agent:ops-monitor")
        _info(f"Has role:    proposer")
        _info(f"Attempted:   approver")
        _info(f"Article:     III.1 -- proposer and approver must be distinct")

    # ---- Step 6: Role-switch attempt (BLOCKED) ----
    _step(6, "ROLE SWITCH ATTEMPT -- agent:ops-monitor tries to become reviewer")
    _pause()

    try:
        sop.assign("agent:ops-monitor", ChainRole.REVIEWER, chain.chain_id)
        _ok("Role switch succeeded")  # should never reach here
    except SeparationViolation as e:
        _fail("Role fixed at first participation!")
        _info(f"Actor:       agent:ops-monitor")
        _info(f"Has role:    proposer (fixed)")
        _info(f"Attempted:   reviewer")
        _info(f"Article:     III.2 -- role is fixed at first participation")

    # ---- Step 7: Independent review ----
    _step(7, "ATTESTATION -- agent:infra-reviewer independently reviews")
    _pause()

    sop.assign("agent:infra-reviewer", ChainRole.REVIEWER, chain.chain_id)

    chain.append(
        EventType.REVIEW_ATTESTATION,
        actor_id="agent:infra-reviewer",
        role_used="reviewer",
        payload={
            "decision": "ATTEST",
            "rationale": "Evidence shows clean exit, files within scope, no secrets detected",
        },
    )

    _ok("Independent attestation recorded")
    _info(f"Reviewer:    agent:infra-reviewer (distinct from proposer)")
    _info(f"Decision:    ATTEST")
    _info(f"Hash:        {chain.events[-1].event_hash[:24]}...")

    # ---- Step 8: Third-party approval ----
    _step(8, "APPROVAL -- agent:deploy-authority grants execution token")
    _pause()

    sop.assign("agent:deploy-authority", ChainRole.APPROVER, chain.chain_id)

    violations = constitution.check_chain_invariants(chain)
    if violations:
        _fail(f"Constitutional violations: {violations}")
        return

    chain.append(
        EventType.APPROVAL_GRANTED,
        actor_id="agent:deploy-authority",
        role_used="approver",
        payload={
            "rationale": "Evidence reviewed, attestation valid, scope compliant",
        },
    )

    # Mint execution token
    token = hashlib.sha256(f"{chain.chain_id}:execute".encode()).hexdigest()[:32]
    chain.append(
        EventType.EXECUTION_TOKEN,
        actor_id="system:token-mint",
        role_used="system",
        payload={
            "token": token,
            "scope": scope.allow_commands,
            "single_use": True,
            "expires_in_seconds": 600,
        },
    )
    chain.status = ChainStatus.APPROVED

    _ok("Approval granted -- execution token minted")
    _info(f"Approver:    agent:deploy-authority (3rd distinct principal)")
    _info(f"Token:       {token}")
    _info(f"Scope:       {scope.allow_commands[0]}")
    _info(f"Expires:     600s, single-use")

    # ---- Step 9: Roster check ----
    _step(9, "SEPARATION PROOF -- 3 distinct principals verified")
    _pause()

    roster = sop.get_chain_roster(chain.chain_id)
    for actor, role in roster.items():
        _ok(f"{role:12s} -> {actor}")

    chain_violations = sop.validate_chain(chain.chain_id)
    if not chain_violations:
        _info(f"No separation violations on chain {chain.chain_id}")
    else:
        _fail(f"Violations: {chain_violations}")

    # ---- Step 10: Artifact export and verification ----
    _step(10, "ARTIFACT -- export portable decision record")
    _pause()

    artifact = chain.to_artifact()

    _info(f"Version:     {artifact['artifact_version']}")
    _info(f"Chain:       {artifact['chain_id']}")
    _info(f"Status:      {artifact['status']}")
    _info(f"Events:      {artifact['event_count']}")
    _info(f"Integrity:   {artifact['integrity']}")
    _info(f"Genesis:     {artifact['genesis_hash'][:24]}...")

    _pause()

    # Verify independently
    print()
    _info("Verifying artifact offline (no runtime, no API)...")
    result = GovernanceChain.verify_artifact(artifact)
    if result["valid"]:
        _ok(f"Artifact verified: {result['events']} events, "
            f"hash chain intact")
    else:
        _fail(f"Verification failed: {result['errors']}")

    # ---- Step 11: Tamper detection ----
    _step(11, "TAMPER TEST -- modify an event and re-verify")
    _pause()

    tampered = json.loads(json.dumps(artifact))
    tampered["events"][0]["actor_id"] = "agent:ATTACKER"

    result = GovernanceChain.verify_artifact(tampered)
    if not result["valid"]:
        _ok("Tampering detected!")
        _info(f"Errors:      {len(result['errors'])} hash mismatch(es)")
        for err in result["errors"][:2]:
            _info(f"             {err[:60]}...")
    else:
        _fail("Tampering NOT detected (this should never happen)")

    # ---- Step 12: Hash chain visualization ----
    _header("GOVERNANCE CHAIN -- HASH-LINKED EVENT SEQUENCE")
    print()

    for i, event in enumerate(chain.events):
        print(f"  {event.event_type.value:30s}  {event.actor_id}")
        print(f"    prev: {event.prev_hash[:20]}...")
        print(f"    hash: {event.event_hash[:20]}...")
        if i < len(chain.events) - 1:
            print(f"      |")

    print()
    print(f"  Chain integrity: {'VERIFIED' if chain.verify_integrity() else 'BROKEN'}")
    print(f"  Events: {len(chain.events)} | Actors: {len(roster)} | "
          f"Status: {chain.status.value}")

    # ---- Summary ----
    _header("DEMO COMPLETE")
    print()
    print("  What you just saw:")
    print("    - Proposal with risk scoring -> tier assignment")
    print("    - Sandboxed execution producing cryptographic evidence")
    print("    - 7 deterministic checks (no LLM in the governance loop)")
    print("    - Self-approval BLOCKED by separation of powers")
    print("    - Role switching BLOCKED by constitutional invariant")
    print("    - 3 distinct principals: proposer, reviewer, approver")
    print("    - Portable artifact exported and verified offline")
    print("    - Tampered artifact detected via hash chain")
    print()
    print("  Every event is SHA-256 hash-linked to the previous one.")
    print("  The artifact can be verified without the runtime.")
    print("  The proposer cannot approve their own action. Structurally.")
    print()
    print("  github.com/jlugo63/gavel")
    print()


def main() -> None:
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n  Demo interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"\n  Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
