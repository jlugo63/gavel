"""Governance chain endpoints — propose, attest, approve, execute, chain queries.

Extracted from gateway.py as part of the router decomposition.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from gavel.blastbox import BlastBox, ScopeDeclaration
from gavel.chain import GovernanceChain, ChainStatus, EventType
from gavel.constitution import Constitution
from gavel.dependencies import (
    ChainLockManager,
    get_blastbox,
    get_chain_lock_manager,
    get_chain_repo,
    get_constitution,
    get_event_bus,
    get_evidence_repo,
    get_evidence_reviewer,
    get_execution_token_repo,
    get_liveness,
    get_mesh_client_factory,
    get_review_repo,
    get_separation,
    get_tier_policy,
    require_gavel_token,
)
from gavel.db.repositories import (
    ChainRepository,
    EvidenceRepository,
    ExecutionTokenRepository,
    ReviewRepository,
)
from gavel.evidence import EvidenceReviewer, ReviewResult
from gavel.liveness import LivenessMonitor
from gavel.separation import SeparationOfPowers, ChainRole, SeparationViolation
from gavel.tiers import TierPolicy, RiskFactors, AutonomyTier
from gavel.events import EventBus, DashboardEvent
from gavel.enrollment import GovernanceToken


# Constant — destructive command patterns blocked at /propose. Mirrors the
# gateway-level BLOCKED_PATTERNS constant; kept here so this router is
# self-contained.
BLOCKED_PATTERNS = ["rm -rf", "drop table", "delete from", "format c:", "truncate", "shutdown"]


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class ProposalRequest(BaseModel):
    actor_id: str
    role: str = "proposer"
    goal: str
    action_type: str
    action_content: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)
    expected_outcomes: list[str] = Field(default_factory=list)
    risk_factors: dict[str, Any] = Field(default_factory=dict)


class AttestationRequest(BaseModel):
    chain_id: str
    actor_id: str
    role: str = "reviewer"
    decision: str  # "ATTEST" or "REJECT"
    rationale: str


class ApprovalRequest(BaseModel):
    chain_id: str
    actor_id: str
    role: str = "approver"
    decision: str  # "APPROVED" or "DENIED"
    rationale: str


class ExecuteRequest(BaseModel):
    chain_id: str
    execution_token: str  # The exec-t-* token string returned by /approve


class ExecuteResponse(BaseModel):
    chain_id: str
    status: str
    execution_id: str
    token_revoked: bool
    result: dict[str, Any] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
governance_router = APIRouter(tags=["governance"])


@governance_router.post("/propose")
async def propose(
    req: ProposalRequest,
    token: GovernanceToken = Depends(require_gavel_token),
    chain_repo: ChainRepository = Depends(get_chain_repo),
    evidence_repo: EvidenceRepository = Depends(get_evidence_repo),
    review_repo: ReviewRepository = Depends(get_review_repo),
    chain_locks: ChainLockManager = Depends(get_chain_lock_manager),
    separation: SeparationOfPowers = Depends(get_separation),
    tier_policy: TierPolicy = Depends(get_tier_policy),
    liveness: LivenessMonitor = Depends(get_liveness),
    blastbox: BlastBox = Depends(get_blastbox),
    evidence_reviewer: EvidenceReviewer = Depends(get_evidence_reviewer),
    event_bus: EventBus = Depends(get_event_bus),
    mesh_client_factory=Depends(get_mesh_client_factory),
):
    """Submit a governance proposal. This starts a new chain."""
    chain = GovernanceChain()

    # --- Microsoft Layer: Identity verification via Agent Mesh ---
    mesh_client = mesh_client_factory(req.actor_id)
    agent_identity = mesh_client.identity
    agent_trust = mesh_client.trust_score

    # --- Microsoft Layer: Policy violation check via Agent OS ---
    for cmd in req.scope.get("allow_commands", []):
        for pattern in BLOCKED_PATTERNS:
            if pattern in cmd.lower():
                raise HTTPException(
                    status_code=403,
                    detail=f"Agent OS policy violation: command '{cmd}' matches blocked pattern '{pattern}'",
                )

    # --- Gavel Layer: Separation of powers ---
    try:
        separation.assign(req.actor_id, ChainRole.PROPOSER, chain.chain_id)
    except SeparationViolation as e:
        raise HTTPException(status_code=403, detail=str(e))

    async with chain_locks.lock(chain.chain_id):
        intent_event = chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id=req.actor_id,
            role_used="proposer",
            payload={
                "goal": req.goal,
                "action_type": req.action_type,
                "action_content": req.action_content,
                "scope": req.scope,
                "expected_outcomes": req.expected_outcomes,
                "agent_did": str(agent_identity.did),
                "trust_score": agent_trust.total_score,
                "trust_tier": agent_trust.tier,
            },
        )

        factors = RiskFactors(
            action_type_base=req.risk_factors.get("base_risk", 0.3),
            touches_production=req.risk_factors.get("production", False),
            touches_financial=req.risk_factors.get("financial", False),
            touches_pii=req.risk_factors.get("pii", False),
        )

        tier, requirements, risk = tier_policy.evaluate(factors)

        policy_event = chain.append(
            event_type=EventType.POLICY_EVAL,
            actor_id="system:policy-engine",
            role_used="system",
            payload={
                "risk_score": risk,
                "tier": tier.value,
                "tier_name": tier.name,
                "requirements": {
                    "blast_box": requirements.requires_blast_box,
                    "evidence_review": requirements.requires_evidence_review,
                    "agent_attestation": requirements.requires_agent_attestation,
                    "min_attestations": requirements.min_attestations,
                    "human_approval": requirements.requires_human_approval,
                    "senior_agent": requirements.requires_senior_agent,
                    "sla_seconds": requirements.sla_seconds,
                },
            },
        )

        sla_timeout = liveness.track(chain.chain_id, requirements.sla_seconds)

        if requirements.requires_blast_box:
            scope = ScopeDeclaration(
                allow_paths=req.scope.get("allow_paths", []),
                allow_commands=req.scope.get("allow_commands", []),
                allow_network=req.scope.get("allow_network", False),
            )

            packet = await blastbox.execute(
                chain_id=chain.chain_id,
                intent_event_id=intent_event.event_id,
                command_argv=req.scope.get("allow_commands", []),
                scope=scope,
            )
            await evidence_repo.save(chain.chain_id, packet)

            chain.append(
                event_type=EventType.BLASTBOX_EVIDENCE,
                actor_id="system:blastbox",
                role_used="system",
                payload={
                    "packet_id": packet.packet_id,
                    "exit_code": packet.exit_code,
                    "stdout_hash": packet.stdout_hash,
                    "packet_hash": packet.compute_hash(),
                },
            )

            if requirements.requires_evidence_review:
                result = evidence_reviewer.review(packet, scope)
                await review_repo.save(chain.chain_id, result)

                chain.append(
                    event_type=EventType.EVIDENCE_REVIEW,
                    actor_id="system:evidence-reviewer",
                    role_used="system",
                    payload={
                        "verdict": result.verdict.value,
                        "risk_delta": result.risk_delta,
                        "scope_compliance": result.scope_compliance,
                        "findings_count": len(result.findings),
                    },
                )

        current_review = await review_repo.get(chain.chain_id) or ReviewResult()
        if tier == AutonomyTier.SEMI_AUTONOMOUS and current_review.passed:
            chain.status = ChainStatus.APPROVED
            chain.append(
                event_type=EventType.APPROVAL_GRANTED,
                actor_id="system:auto-approve",
                role_used="system",
                payload={"reason": "Tier 1 auto-approve: evidence review passed, risk below threshold"},
            )
            liveness.resolve(chain.chain_id, "AUTO_APPROVED")
        else:
            chain.status = ChainStatus.ESCALATED
            chain.append(
                event_type=EventType.ESCALATED,
                actor_id="system:policy-engine",
                role_used="system",
                payload={
                    "reason": f"Tier {tier.value} requires additional approval",
                    "needed": {
                        "attestations": requirements.min_attestations,
                        "human": requirements.requires_human_approval,
                        "senior": requirements.requires_senior_agent,
                    },
                },
            )

        await chain_repo.save(chain)

    await event_bus.publish(DashboardEvent(
        event_type="chain_event",
        agent_id=req.actor_id,
        chain_id=chain.chain_id,
        payload={"status": chain.status.value, "risk": risk, "tier": tier.name},
    ))

    return {
        "chain_id": chain.chain_id,
        "status": chain.status.value,
        "risk": risk,
        "tier": tier.name,
        "sla_remaining": sla_timeout.remaining_seconds,
        "timeline": chain.to_timeline(),
    }


@governance_router.post("/attest")
async def attest(
    req: AttestationRequest,
    token: GovernanceToken = Depends(require_gavel_token),
    chain_repo: ChainRepository = Depends(get_chain_repo),
    chain_locks: ChainLockManager = Depends(get_chain_lock_manager),
    separation: SeparationOfPowers = Depends(get_separation),
):
    """Submit an agent attestation for a chain."""
    chain = await chain_repo.get(req.chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    try:
        separation.assign(req.actor_id, ChainRole.REVIEWER, req.chain_id)
    except SeparationViolation as e:
        raise HTTPException(status_code=403, detail=str(e))

    async with chain_locks.lock(req.chain_id):
        chain.append(
            event_type=EventType.REVIEW_ATTESTATION,
            actor_id=req.actor_id,
            role_used="reviewer",
            payload={
                "decision": req.decision,
                "rationale": req.rationale,
            },
        )
        await chain_repo.save(chain)

    return {
        "chain_id": req.chain_id,
        "status": chain.status.value,
        "roster": separation.get_chain_roster(req.chain_id),
        "timeline": chain.to_timeline(),
    }


@governance_router.post("/approve")
async def approve(
    req: ApprovalRequest,
    token: GovernanceToken = Depends(require_gavel_token),
    chain_repo: ChainRepository = Depends(get_chain_repo),
    execution_token_repo: ExecutionTokenRepository = Depends(get_execution_token_repo),
    chain_locks: ChainLockManager = Depends(get_chain_lock_manager),
    separation: SeparationOfPowers = Depends(get_separation),
    constitution: Constitution = Depends(get_constitution),
    liveness: LivenessMonitor = Depends(get_liveness),
):
    """Submit an approval or denial for a chain."""
    chain = await chain_repo.get(req.chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    try:
        separation.assign(req.actor_id, ChainRole.APPROVER, req.chain_id)
    except SeparationViolation as e:
        raise HTTPException(status_code=403, detail=str(e))

    violations = constitution.check_chain_invariants(chain)
    if violations:
        raise HTTPException(
            status_code=403,
            detail={"constitutional_violations": violations},
        )

    async with chain_locks.lock(req.chain_id):
        if req.decision == "APPROVED":
            chain.status = ChainStatus.APPROVED
            chain.append(
                event_type=EventType.APPROVAL_GRANTED,
                actor_id=req.actor_id,
                role_used="approver",
                payload={"rationale": req.rationale},
            )
            liveness.resolve(req.chain_id, "APPROVED")

            token_id = f"exec-t-{uuid.uuid4().hex[:8]}"
            exec_token = {
                "token_id": token_id,
                "chain_id": req.chain_id,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                "used": False,
            }
            await execution_token_repo.save(token_id, exec_token)

            chain.append(
                event_type=EventType.EXECUTION_TOKEN,
                actor_id="system:token-minter",
                role_used="system",
                payload=exec_token,
            )
            await chain_repo.save(chain)

            return {
                "chain_id": req.chain_id,
                "status": "APPROVED",
                "execution_token": token_id,
                "roster": separation.get_chain_roster(req.chain_id),
                "timeline": chain.to_timeline(),
            }
        else:
            chain.status = ChainStatus.DENIED
            chain.append(
                event_type=EventType.APPROVAL_DENIED,
                actor_id=req.actor_id,
                role_used="approver",
                payload={"rationale": req.rationale},
            )
            liveness.resolve(req.chain_id, "DENIED")
            await chain_repo.save(chain)

            return {
                "chain_id": req.chain_id,
                "status": "DENIED",
                "rationale": req.rationale,
                "timeline": chain.to_timeline(),
            }


@governance_router.post("/execute", response_model=ExecuteResponse)
async def execute(
    req: ExecuteRequest,
    chain_repo: ChainRepository = Depends(get_chain_repo),
    execution_token_repo: ExecutionTokenRepository = Depends(get_execution_token_repo),
    chain_locks: ChainLockManager = Depends(get_chain_lock_manager),
    constitution: Constitution = Depends(get_constitution),
    blastbox: BlastBox = Depends(get_blastbox),
    event_bus: EventBus = Depends(get_event_bus),
):
    """Execute an approved governance action -- closing the propose->approve->execute loop."""
    token_record = await execution_token_repo.get(req.execution_token)
    if token_record is None:
        raise HTTPException(
            status_code=403,
            detail={"error": "token_not_found", "detail": "Execution token not recognized"},
        )

    if token_record.get("used", False):
        raise HTTPException(
            status_code=403,
            detail={"error": "token_already_used", "detail": "Execution token has already been consumed (Article II.2: single-use)"},
        )

    expires_at = datetime.fromisoformat(token_record["expires_at"])
    if datetime.now(timezone.utc) >= expires_at:
        raise HTTPException(
            status_code=403,
            detail={"error": "token_expired", "detail": "Execution token has expired"},
        )

    if token_record["chain_id"] != req.chain_id:
        raise HTTPException(
            status_code=403,
            detail={"error": "token_chain_mismatch", "detail": "Execution token does not belong to this chain"},
        )

    chain = await chain_repo.get(req.chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail="Chain not found")

    if chain.status != ChainStatus.APPROVED:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "chain_not_approved",
                "detail": f"Chain status is {chain.status.value}, expected APPROVED",
            },
        )

    if not chain.verify_integrity():
        raise HTTPException(
            status_code=403,
            detail={"error": "integrity_violation", "detail": "Chain hash integrity check failed -- possible tampering"},
        )

    violations = constitution.check_chain_invariants(chain)
    if violations:
        raise HTTPException(
            status_code=403,
            detail={"error": "constitutional_violation", "detail": violations},
        )

    async with chain_locks.lock(req.chain_id):
        execution_id = f"exec-{uuid.uuid4().hex[:8]}"
        chain.status = ChainStatus.EXECUTING

        chain.append(
            event_type=EventType.EXECUTION_STARTED,
            actor_id="system:executor",
            role_used="executor",
            payload={
                "execution_id": execution_id,
                "execution_token": req.execution_token,
                "started_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        intent_event = chain.get_event(EventType.INBOUND_INTENT)
        action_content = intent_event.payload if intent_event else {}

        try:
            scope_data = action_content.get("scope", {})
            commands = scope_data.get("allow_commands", [])

            if commands:
                scope = ScopeDeclaration(
                    allow_paths=scope_data.get("allow_paths", []),
                    allow_commands=commands,
                    allow_network=scope_data.get("allow_network", False),
                )
                packet = await blastbox.execute(
                    chain_id=req.chain_id,
                    intent_event_id=intent_event.event_id if intent_event else "",
                    command_argv=commands,
                    scope=scope,
                )
                exec_result = {
                    "method": "blastbox",
                    "exit_code": packet.exit_code,
                    "stdout_hash": packet.stdout_hash,
                    "packet_id": packet.packet_id,
                    "success": packet.exit_code == 0,
                }
            else:
                exec_result = {
                    "method": "governed_passthrough",
                    "action_type": action_content.get("action_type", "unknown"),
                    "goal": action_content.get("goal", ""),
                    "success": True,
                }
        except Exception as e:
            exec_result = {
                "method": "failed",
                "error": str(e),
                "success": False,
            }

        chain.append(
            event_type=EventType.EXECUTION_COMPLETED,
            actor_id="system:executor",
            role_used="executor",
            payload={
                "execution_id": execution_id,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "result": exec_result,
            },
        )

        token_flipped = await execution_token_repo.mark_used(req.execution_token)
        if not token_flipped:
            raise HTTPException(
                status_code=403,
                detail={"error": "token_already_used", "detail": "Execution token was consumed concurrently"},
            )

        chain.status = ChainStatus.COMPLETED
        await chain_repo.save(chain)

    await event_bus.publish(DashboardEvent(
        event_type="execution_completed",
        agent_id="system:executor",
        chain_id=req.chain_id,
        payload={
            "execution_id": execution_id,
            "success": exec_result.get("success", False),
            "method": exec_result.get("method", "unknown"),
        },
    ))

    return ExecuteResponse(
        chain_id=req.chain_id,
        status=chain.status.value,
        execution_id=execution_id,
        token_revoked=True,
        result=exec_result,
        timeline=chain.to_timeline(),
    )


@governance_router.get("/chains")
async def list_chains(
    chain_repo: ChainRepository = Depends(get_chain_repo),
    separation: SeparationOfPowers = Depends(get_separation),
):
    """List all governance chains with summary data."""
    chains = await chain_repo.list_all()
    return [
        {
            "chain_id": c.chain_id,
            "status": c.status.value,
            "roster": separation.get_chain_roster(c.chain_id),
            "timeline": c.to_timeline(),
            "event_count": len(c.events),
        }
        for c in chains
    ]


@governance_router.get("/chain/{chain_id}")
async def get_chain(
    chain_id: str,
    chain_repo: ChainRepository = Depends(get_chain_repo),
    evidence_repo: EvidenceRepository = Depends(get_evidence_repo),
    review_repo: ReviewRepository = Depends(get_review_repo),
    separation: SeparationOfPowers = Depends(get_separation),
):
    """Get the full governance chain -- the complete decision trail."""
    chain = await chain_repo.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    evidence = await evidence_repo.get(chain_id)
    review = await review_repo.get(chain_id)

    return {
        "chain_id": chain.chain_id,
        "status": chain.status.value,
        "integrity": chain.verify_integrity(),
        "roster": separation.get_chain_roster(chain_id),
        "evidence": evidence,
        "review": review,
        "timeline": chain.to_timeline(),
        "events": [
            {
                "event_id": e.event_id,
                "type": e.event_type.value,
                "actor": e.actor_id,
                "role": e.role_used,
                "timestamp": e.timestamp.isoformat(),
                "hash": e.event_hash,
                "payload": e.payload,
            }
            for e in chain.events
        ],
    }


@governance_router.get("/chain/{chain_id}/artifact")
async def get_chain_artifact(
    chain_id: str,
    chain_repo: ChainRepository = Depends(get_chain_repo),
):
    """Export a governance chain as a portable decision artifact."""
    chain = await chain_repo.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    return chain.to_artifact()


@governance_router.post("/verify-artifact")
async def verify_artifact(request: Request):
    """Verify a decision artifact's integrity without the runtime."""
    artifact = await request.json()
    result = GovernanceChain.verify_artifact(artifact)
    return result


@governance_router.get("/constitution")
async def get_constitution_endpoint(
    constitution: Constitution = Depends(get_constitution),
):
    """Return the constitutional invariants."""
    return {
        "invariants": [
            {
                "id": inv.id,
                "article": inv.article.value,
                "section": inv.section,
                "text": inv.text,
                "enforcement": inv.enforcement,
            }
            for inv in constitution.invariants.values()
        ]
    }
