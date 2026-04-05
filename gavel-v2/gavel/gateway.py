"""
Gavel Gateway — the FastAPI application that orchestrates governance chains.

This is where Microsoft's toolkit and Gavel's constitutional layer meet.
Incoming proposals hit Agent OS for policy evaluation, then flow through
Gavel's chain/separation/blastbox/evidence/tier pipeline.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# Microsoft Agent Governance Toolkit
from agent_os import PolicyEngine as AgentOSEngine
from agentmesh import AgentMeshClient

from gavel.blastbox import BlastBox, ScopeDeclaration, EvidencePacket
from gavel.chain import GovernanceChain, ChainEvent, ChainStatus, EventType
from gavel.constitution import Constitution
from gavel.evidence import EvidenceReviewer, ReviewResult
from gavel.liveness import LivenessMonitor, EscalationLevel
from gavel.separation import SeparationOfPowers, ChainRole, SeparationViolation
from gavel.tiers import TierPolicy, RiskFactors, AutonomyTier

app = FastAPI(
    title="Gavel Governance Gateway",
    description="Constitutional governance for autonomous AI agents, built on Microsoft's Agent Governance Toolkit",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/demo", response_class=HTMLResponse)
async def demo_page():
    """Serve the visual governance chain demo."""
    html_path = Path(__file__).parent / "demo.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Demo page not available in this deployment")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


# --- Microsoft Agent Governance Toolkit layer ---
agent_os = AgentOSEngine()
BLOCKED_PATTERNS = ["rm -rf", "drop table", "delete from", "format c:", "truncate", "shutdown"]
_mesh_clients: dict[str, AgentMeshClient] = {}


def get_mesh_client(actor_id: str) -> AgentMeshClient:
    """Get or create an AgentMesh client for identity + trust scoring."""
    if actor_id not in _mesh_clients:
        _mesh_clients[actor_id] = AgentMeshClient(agent_id=actor_id)
    return _mesh_clients[actor_id]


# --- Gavel constitutional layer ---
constitution = Constitution()
separation = SeparationOfPowers()
tier_policy = TierPolicy()
liveness = LivenessMonitor()
blastbox = BlastBox()
evidence_reviewer = EvidenceReviewer()

# --- In-memory stores (swap for DB in production) ---
chains: dict[str, GovernanceChain] = {}
evidence_packets: dict[str, EvidencePacket] = {}
review_results: dict[str, ReviewResult] = {}
execution_tokens: dict[str, dict] = {}


# --- Request/Response models ---

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


# --- Endpoints ---

@app.post("/propose")
async def propose(req: ProposalRequest):
    """
    Submit a governance proposal. This starts a new chain.

    Flow:
    1. Verify actor identity (Agent Mesh in production)
    2. Register actor as proposer (separation of powers)
    3. Evaluate policy (Agent OS in production)
    4. Compute risk and determine tier
    5. Start blast box if required
    6. Start SLA timer
    """
    chain = GovernanceChain()

    # --- Microsoft Layer: Identity verification via Agent Mesh ---
    mesh_client = get_mesh_client(req.actor_id)
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

    # --- Log INBOUND_INTENT with real identity ---
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

    # --- Gavel Layer: Risk evaluation and tier assignment ---

    factors = RiskFactors(
        action_type_base=req.risk_factors.get("base_risk", 0.3),
        touches_production=req.risk_factors.get("production", False),
        touches_financial=req.risk_factors.get("financial", False),
        touches_pii=req.risk_factors.get("pii", False),
    )

    tier, requirements, risk = tier_policy.evaluate(factors)

    # --- Log POLICY_EVAL ---
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

    # --- Gavel Layer: Start SLA timer ---
    sla_timeout = liveness.track(chain.chain_id, requirements.sla_seconds)

    # --- Gavel Layer: Blast box (speculative execution) ---
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
        evidence_packets[chain.chain_id] = packet

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

        # --- Gavel Layer: Deterministic evidence review ---
        if requirements.requires_evidence_review:
            result = evidence_reviewer.review(packet, scope)
            review_results[chain.chain_id] = result

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

    # --- Determine chain status ---
    if tier == AutonomyTier.SEMI_AUTONOMOUS and review_results.get(chain.chain_id, ReviewResult()).passed:
        # Tier 1 auto-approve: evidence passed, low risk
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

    chains[chain.chain_id] = chain

    return {
        "chain_id": chain.chain_id,
        "status": chain.status.value,
        "risk": risk,
        "tier": tier.name,
        "sla_remaining": sla_timeout.remaining_seconds,
        "timeline": chain.to_timeline(),
    }


@app.post("/attest")
async def attest(req: AttestationRequest):
    """Submit an agent attestation for a chain."""
    chain = chains.get(req.chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    # Separation of powers check
    try:
        separation.assign(req.actor_id, ChainRole.REVIEWER, req.chain_id)
    except SeparationViolation as e:
        raise HTTPException(status_code=403, detail=str(e))

    event_type = EventType.REVIEW_ATTESTATION
    chain.append(
        event_type=event_type,
        actor_id=req.actor_id,
        role_used="reviewer",
        payload={
            "decision": req.decision,
            "rationale": req.rationale,
        },
    )

    return {
        "chain_id": req.chain_id,
        "status": chain.status.value,
        "roster": separation.get_chain_roster(req.chain_id),
        "timeline": chain.to_timeline(),
    }


@app.post("/approve")
async def approve(req: ApprovalRequest):
    """Submit an approval or denial for a chain."""
    chain = chains.get(req.chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    # Separation of powers check
    try:
        separation.assign(req.actor_id, ChainRole.APPROVER, req.chain_id)
    except SeparationViolation as e:
        raise HTTPException(status_code=403, detail=str(e))

    # Constitutional check before approval
    violations = constitution.check_chain_invariants(chain)
    if violations:
        raise HTTPException(
            status_code=403,
            detail={"constitutional_violations": violations},
        )

    if req.decision == "APPROVED":
        chain.status = ChainStatus.APPROVED
        chain.append(
            event_type=EventType.APPROVAL_GRANTED,
            actor_id=req.actor_id,
            role_used="approver",
            payload={"rationale": req.rationale},
        )
        liveness.resolve(req.chain_id, "APPROVED")

        # Mint execution token
        token_id = f"exec-t-{uuid.uuid4().hex[:8]}"
        token = {
            "token_id": token_id,
            "chain_id": req.chain_id,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            "used": False,
        }
        execution_tokens[token_id] = token

        chain.append(
            event_type=EventType.EXECUTION_TOKEN,
            actor_id="system:token-minter",
            role_used="system",
            payload=token,
        )

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

        return {
            "chain_id": req.chain_id,
            "status": "DENIED",
            "rationale": req.rationale,
            "timeline": chain.to_timeline(),
        }


@app.get("/chain/{chain_id}")
async def get_chain(chain_id: str):
    """Get the full governance chain — the complete decision trail."""
    chain = chains.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    return {
        "chain_id": chain.chain_id,
        "status": chain.status.value,
        "integrity": chain.verify_integrity(),
        "roster": separation.get_chain_roster(chain_id),
        "evidence": evidence_packets.get(chain_id, None),
        "review": review_results.get(chain_id, None),
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


@app.get("/liveness")
async def get_liveness():
    """Dashboard: SLA status of all active chains."""
    expired = liveness.get_expired()

    # Auto-deny expired chains (Constitutional Article IV.2)
    for timeout in expired:
        chain = chains.get(timeout.chain_id)
        if chain and chain.status == ChainStatus.ESCALATED:
            chain.status = ChainStatus.TIMED_OUT
            chain.append(
                event_type=EventType.AUTO_DENIED,
                actor_id="system:liveness",
                role_used="system",
                payload={"reason": "SLA timeout — Constitutional Article IV.2: system degrades toward safety"},
            )
            liveness.resolve(timeout.chain_id, "AUTO_DENIED")

    return liveness.status_summary()


@app.get("/chain/{chain_id}/artifact")
async def get_chain_artifact(chain_id: str):
    """Export a governance chain as a portable decision artifact."""
    chain = chains.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    return chain.to_artifact()


@app.post("/verify-artifact")
async def verify_artifact(request: Request):
    """Verify a decision artifact's integrity without the runtime."""
    artifact = await request.json()
    result = GovernanceChain.verify_artifact(artifact)
    return result


@app.get("/constitution")
async def get_constitution():
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
