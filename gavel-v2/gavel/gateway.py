"""
Gavel Gateway — the FastAPI application that orchestrates governance chains.

This is where Microsoft's toolkit and Gavel's constitutional layer meet.
Incoming proposals hit Agent OS for policy evaluation, then flow through
Gavel's chain/separation/blastbox/evidence/tier pipeline.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from starlette.responses import StreamingResponse
from pydantic import BaseModel, Field

# Microsoft Agent Governance Toolkit (graceful fallback if not installed)
from gavel.agt_compat import AgentOSEngine, AgentMeshClient

from gavel.blastbox import BlastBox, ScopeDeclaration, EvidencePacket
from gavel.chain import GovernanceChain, ChainEvent, ChainStatus, EventType
from gavel.constitution import Constitution
from gavel.evidence import EvidenceReviewer, ReviewResult
from gavel.liveness import LivenessMonitor, EscalationLevel
from gavel.separation import SeparationOfPowers, ChainRole, SeparationViolation
from gavel.tiers import TierPolicy, RiskFactors, AutonomyTier
from gavel.events import EventBus, DashboardEvent
from gavel.agents import AgentRegistry, AgentStatus
from gavel.supervisor import Supervisor
from gavel.hooks import classify_risk, should_govern, format_action_log
from .gate import router as gate_router, init_gate
from gavel.compliance import IncidentRegistry
from gavel.compliance_router import router as compliance_router, init_compliance_router

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

# --- Monitoring infrastructure ---
event_bus = EventBus()
agent_registry = AgentRegistry(event_bus)

# --- Enrollment gate (ATF I-4, I-5, S-1, S-2) ---
from gavel.enrollment import EnrollmentRegistry, EnrollmentApplication, EnrollmentStatus, TokenManager, GovernanceToken
enrollment_registry = EnrollmentRegistry()
token_manager = TokenManager()
incident_registry = IncidentRegistry()


async def require_gavel_token(
    x_gavel_token: Optional[str] = Header(default=None),
) -> GovernanceToken:
    """FastAPI dependency that validates the X-Gavel-Token header.

    Use as a dependency on any endpoint that requires a valid governance token:

        @app.get("/protected")
        async def protected(token: GovernanceToken = Depends(require_gavel_token)):
            ...

    Raises 401 if the header is missing, 403 if the token is invalid/expired/revoked.
    """
    if x_gavel_token is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_token", "detail": "X-Gavel-Token header is required"},
        )

    valid, reason, gov_token = token_manager.validate(x_gavel_token)
    if not valid:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "token_invalid",
                "detail": reason,
                "agent_did": gov_token.agent_did if gov_token else None,
            },
        )

    return gov_token


def _load_cedar_rules(engine) -> None:
    """Load Gavel constitutional rules into AGT PolicyEngine as custom rules.

    Maps Cedar FORBID semantics to PolicyRule validators. The .cedar file
    remains the source-of-truth documentation; this function is the runtime
    enforcement equivalent.
    """
    import re
    from gavel.agt_compat import PolicyRule, ActionType

    all_types = list(ActionType)

    # Rule 1: Kill switch — suspended agents are denied everything
    def block_suspended(req):
        return req.agent_context.metadata.get("status") != "SUSPENDED"

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-kill-switch",
        name="Constitutional Kill Switch",
        description="Art. IV: Suspended agents are denied all actions",
        action_types=all_types,
        validator=block_suspended,
        priority=200,
    ))

    # Rule 2: Dead agents denied
    def block_dead(req):
        return req.agent_context.metadata.get("status") != "DEAD"

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-dead-agent",
        name="Dead Agent Block",
        description="Dead agents cannot perform actions",
        action_types=all_types,
        validator=block_dead,
        priority=195,
    ))

    # Rule 3: Dangerous command patterns — Art. II operational constraints
    def block_dangerous_commands(req):
        cmd = req.parameters.get("command", "")
        if not cmd:
            return True
        for pat in BLOCKED_PATTERNS:
            if pat in cmd.lower():
                return False
        # Also check regex patterns from hooks.py
        from .hooks import HIGH_RISK_PATTERNS
        for pat in HIGH_RISK_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                return False
        return True

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-dangerous-commands",
        name="Dangerous Command Block",
        description="Art. II: Block destructive shell commands via Cedar policy",
        action_types=[ActionType.CODE_EXECUTION],
        validator=block_dangerous_commands,
        priority=180,
    ))

    # Rule 4: Sensitive file writes — Art. II scope constraints
    def block_sensitive_writes(req):
        path = req.parameters.get("file_path", "").lower()
        if not path:
            return True
        sensitive = [".env", "credentials", "secret", "password", ".key", "token"]
        return not any(s in path for s in sensitive)

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-sensitive-file-guard",
        name="Sensitive File Guard",
        description="Art. II: Block writes to credential/secret files",
        action_types=[ActionType.FILE_WRITE],
        validator=block_sensitive_writes,
        priority=170,
    ))

    # Rule 5: Enrollment gate — ATF I-4, I-5, S-1, S-2
    def block_unenrolled(req):
        agent_id = req.agent_context.agent_id
        return enrollment_registry.is_enrolled(agent_id)

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-enrollment-gate",
        name="Enrollment Gate (ATF I-4/I-5/S-1/S-2)",
        description="Agents must complete enrollment before operating",
        action_types=all_types,
        validator=block_unenrolled,
        priority=210,  # Highest priority — checked before kill-switch
    ))

    import logging
    log = logging.getLogger("gavel.cedar")
    log.info(
        "Cedar enforcement active: %d rules loaded",
        len(engine.custom_rules),
    )


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """Start supervisor on startup, stop on shutdown."""
    # Load Cedar constitutional rules into AGT PolicyEngine
    _load_cedar_rules(agent_os)

    # Wire gate module into registry, event bus, chains, liveness, AND Cedar engine
    init_gate(
        registry=agent_registry,
        bus=event_bus,
        chain_store=chains,
        liveness_monitor=liveness,
        cedar_engine=agent_os,
        tokens=token_manager,
        lock_manager=chain_locks,
    )

    init_compliance_router(
        incidents=incident_registry,
        enrollments=enrollment_registry,
        chains=chains,
        review_results=review_results,
        constitution=constitution,
        tier_policy=tier_policy,
        event_bus=event_bus,
    )

    sup = Supervisor(event_bus, agent_registry, liveness)
    await sup.start()
    yield
    await sup.stop()


app = FastAPI(
    title="Gavel Governance Gateway",
    description="Constitutional governance for autonomous AI agents, built on Microsoft's Agent Governance Toolkit",
    version="0.2.0",
    lifespan=lifespan,
)

app.include_router(gate_router)
app.include_router(compliance_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- In-memory stores (swap for DB in production) ---
chains: dict[str, GovernanceChain] = {}
evidence_packets: dict[str, EvidencePacket] = {}
review_results: dict[str, ReviewResult] = {}
execution_tokens: dict[str, dict] = {}


# --- Per-chain concurrency control ---

class ChainLockManager:
    """Manages per-chain asyncio locks to prevent concurrent chain mutations.

    Two concurrent requests on the same chain_id can interleave appends and
    corrupt the hash chain. This manager provides a lazy-created asyncio.Lock
    per chain_id, so callers serialize mutations with:

        async with chain_locks.lock(chain_id):
            chain.append(...)
    """

    def __init__(self):
        self._locks: dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def lock(self, chain_id: str):
        """Acquire the lock for *chain_id*, creating it lazily if needed."""
        if chain_id not in self._locks:
            self._locks[chain_id] = asyncio.Lock()
        async with self._locks[chain_id]:
            yield

    def discard(self, chain_id: str) -> None:
        """Remove the lock for a completed/expired chain to reclaim memory."""
        self._locks.pop(chain_id, None)


chain_locks = ChainLockManager()


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


# --- Endpoints ---

@app.post("/propose")
async def propose(req: ProposalRequest, token: GovernanceToken = Depends(require_gavel_token)):
    """
    Submit a governance proposal. This starts a new chain.

    Requires a valid X-Gavel-Token header (issued at enrollment).

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

    # Lock the chain for the duration of all mutations
    async with chain_locks.lock(chain.chain_id):
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

    # Publish to dashboard
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


@app.post("/attest")
async def attest(req: AttestationRequest, token: GovernanceToken = Depends(require_gavel_token)):
    """Submit an agent attestation for a chain. Requires a valid X-Gavel-Token."""
    chain = chains.get(req.chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    # Separation of powers check
    try:
        separation.assign(req.actor_id, ChainRole.REVIEWER, req.chain_id)
    except SeparationViolation as e:
        raise HTTPException(status_code=403, detail=str(e))

    async with chain_locks.lock(req.chain_id):
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
async def approve(req: ApprovalRequest, token: GovernanceToken = Depends(require_gavel_token)):
    """Submit an approval or denial for a chain. Requires a valid X-Gavel-Token."""
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

            # Mint execution token
            token_id = f"exec-t-{uuid.uuid4().hex[:8]}"
            exec_token = {
                "token_id": token_id,
                "chain_id": req.chain_id,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                "used": False,
            }
            execution_tokens[token_id] = exec_token

            chain.append(
                event_type=EventType.EXECUTION_TOKEN,
                actor_id="system:token-minter",
                role_used="system",
                payload=exec_token,
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


@app.post("/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest):
    """
    Execute an approved governance action -- closing the propose->approve->execute loop.

    Constitutional enforcement:
    - Article II.2: Tokens are single-use (revoked after execution)
    - Fail-closed: any validation failure = deny

    Flow:
    1. Validate execution token (exists, not used, not expired)
    2. Verify chain exists and is APPROVED
    3. Verify chain hash integrity (constitutional invariant)
    4. Record EXECUTION_STARTED
    5. Run the action (simulated via BlastBox)
    6. Record EXECUTION_COMPLETED with results
    7. Revoke token (single-use)
    8. Update chain status to COMPLETED
    """
    # --- Step 1: Validate execution token ---
    token_record = execution_tokens.get(req.execution_token)
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

    # Check expiry
    expires_at = datetime.fromisoformat(token_record["expires_at"])
    if datetime.now(timezone.utc) >= expires_at:
        raise HTTPException(
            status_code=403,
            detail={"error": "token_expired", "detail": "Execution token has expired"},
        )

    # Token must belong to the requested chain
    if token_record["chain_id"] != req.chain_id:
        raise HTTPException(
            status_code=403,
            detail={"error": "token_chain_mismatch", "detail": "Execution token does not belong to this chain"},
        )

    # --- Step 2: Verify chain exists and is APPROVED ---
    chain = chains.get(req.chain_id)
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

    # --- Step 3: Verify constitutional invariants (hash integrity) ---
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
        # --- Step 4: Record EXECUTION_STARTED ---
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

        # --- Step 5: Run the action (simulated) ---
        # Extract the original intent from the chain to know what to execute
        intent_event = chain.get_event(EventType.INBOUND_INTENT)
        action_content = intent_event.payload if intent_event else {}

        try:
            # Simulate execution via BlastBox if there are commands in scope
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
                # No commands -- record as a governed action completion
                exec_result = {
                    "method": "governed_passthrough",
                    "action_type": action_content.get("action_type", "unknown"),
                    "goal": action_content.get("goal", ""),
                    "success": True,
                }
        except Exception as e:
            # Fail-closed: record failure, still revoke token, mark chain
            exec_result = {
                "method": "failed",
                "error": str(e),
                "success": False,
            }

        # --- Step 6: Record EXECUTION_COMPLETED ---
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

        # --- Step 7: Revoke token (Article II.2 -- single-use) ---
        token_record["used"] = True

        # --- Step 8: Update chain status to COMPLETED ---
        chain.status = ChainStatus.COMPLETED

    # --- Publish to dashboard ---
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
            async with chain_locks.lock(timeout.chain_id):
                chain.status = ChainStatus.TIMED_OUT
                chain.append(
                    event_type=EventType.AUTO_DENIED,
                    actor_id="system:liveness",
                    role_used="system",
                    payload={"reason": "SLA timeout — Constitutional Article IV.2: system degrades toward safety"},
                )
            liveness.resolve(timeout.chain_id, "AUTO_DENIED")
            chain_locks.discard(timeout.chain_id)

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


# ═══════════════════════════════════════════════════════════════
# Agent Monitoring & Dashboard Endpoints
# ═══════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    agent_id: str
    display_name: str
    agent_type: str = "llm"
    capabilities: list[str] = Field(default_factory=list)


class ActionRequest(BaseModel):
    tool: str
    phase: str = "pre"  # "pre" or "post"
    args: dict[str, Any] = Field(default_factory=dict)
    result: str = ""


class KillRequest(BaseModel):
    reason: str = "Manual kill switch"


class ActionReport(BaseModel):
    tool: str
    tool_input_summary: str = ""
    success: bool = True
    chain_id: Optional[str] = None


@app.post("/agents/{agent_id}/report")
async def report_action(agent_id: str, report: ActionReport):
    """Post-execution report — called by PostToolUse hook after a tool executes."""
    record = agent_registry.get(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")

    # Update trust score based on outcome
    agent_registry.update_trust_from_outcome(agent_id, report.tool, report.success)

    # Record chain completion if chain_id provided
    if report.chain_id and report.chain_id in chains:
        chain = chains[report.chain_id]
        async with chain_locks.lock(report.chain_id):
            chain.append(
                event_type=EventType.EXECUTION_TOKEN,
                actor_id=agent_id,
                role_used="executor",
                payload={
                    "tool": report.tool,
                    "success": report.success,
                    "tool_input_summary": report.tool_input_summary,
                    "phase": "completion",
                },
            )

    # Publish action_reported event
    await event_bus.publish(DashboardEvent(
        event_type="action_reported",
        agent_id=agent_id,
        chain_id=report.chain_id,
        payload={
            "tool": report.tool,
            "tool_input_summary": report.tool_input_summary,
            "success": report.success,
            "chain_id": report.chain_id,
        },
    ))

    # Re-fetch record after trust update
    record = agent_registry.get(agent_id)
    return {
        "recorded": True,
        "trust_score": record.trust_score,
        "autonomy_tier": record.autonomy_tier,
    }


@app.post("/agents/register")
async def register_agent(req: RegisterRequest):
    """Register a new agent under Gavel governance.

    Legacy endpoint — creates the agent record. If enrollment is required
    but not completed, the agent will be blocked at the gate until it
    enrolls via POST /agents/enroll.
    """
    existing = agent_registry.get(req.agent_id)
    if existing:
        return existing.model_dump(mode="json")

    record = await agent_registry.register(
        agent_id=req.agent_id,
        display_name=req.display_name,
        agent_type=req.agent_type,
        capabilities=req.capabilities,
    )

    # Check enrollment status
    enrollment = enrollment_registry.get(req.agent_id)
    enrolled = enrollment is not None and enrollment.status == EnrollmentStatus.ENROLLED

    result = record.model_dump(mode="json")
    result["enrolled"] = enrolled
    if not enrolled:
        result["enrollment_required"] = True
        result["enroll_url"] = "/agents/enroll"
    return result


@app.post("/agents/enroll")
async def enroll_agent(app_data: EnrollmentApplication):
    """Enroll an agent — ATF pre-flight checks before the agent can operate.

    Validates:
      I-4  Purpose Declaration
      I-5  Capability Manifest
      S-1  Resource Allowlist
      S-2  Action Boundaries
      +    Owner, budget, fallback behavior

    If validation passes, the agent is marked ENROLLED and can proceed to
    /agents/register (or is automatically activated if already registered).
    If validation fails, returns the specific violations to fix.
    """
    record = enrollment_registry.submit(app_data)

    # If already registered in agent_registry, sync enrollment status
    agent = agent_registry.get(app_data.agent_id)
    if not agent and record.status == EnrollmentStatus.ENROLLED:
        # Auto-register enrolled agents
        agent = await agent_registry.register(
            agent_id=app_data.agent_id,
            display_name=app_data.display_name,
            agent_type=app_data.agent_type,
            capabilities=app_data.capabilities.tools,
        )

    # Publish enrollment event
    await event_bus.publish(DashboardEvent(
        event_type="agent_enrolled" if record.status == EnrollmentStatus.ENROLLED else "enrollment_failed",
        agent_id=app_data.agent_id,
        payload={
            "status": record.status.value,
            "owner": app_data.owner,
            "purpose": app_data.purpose.summary,
            "risk_tier": app_data.purpose.risk_tier,
            "tools": app_data.capabilities.tools,
            "violations": record.violations,
        },
    ))

    result = {
        "agent_id": app_data.agent_id,
        "enrollment_status": record.status.value,
        "enrolled": record.status == EnrollmentStatus.ENROLLED,
        "enrolled_at": record.enrolled_at.isoformat() if record.enrolled_at else None,
        "violations": record.violations,
        "owner": app_data.owner,
        "purpose": app_data.purpose.summary,
    }

    # Issue a governance token when enrollment succeeds
    if record.status == EnrollmentStatus.ENROLLED:
        gov_token = token_manager.issue(
            agent_id=app_data.agent_id,
            scope={
                "tools": app_data.capabilities.tools,
                "allowed_actions": app_data.boundaries.allowed_actions,
            },
        )
        result["governance_token"] = {
            "token": gov_token.token,
            "agent_did": gov_token.agent_did,
            "issued_at": gov_token.issued_at.isoformat(),
            "expires_at": gov_token.expires_at.isoformat(),
            "ttl_seconds": gov_token.ttl_seconds,
        }

    return result


@app.get("/agents/enrollments")
async def list_enrollments():
    """List all enrollment records."""
    return [
        {
            "agent_id": r.agent_id,
            "status": r.status.value,
            "owner": r.application.owner,
            "purpose": r.application.purpose.summary,
            "risk_tier": r.application.purpose.risk_tier,
            "violations": r.violations,
            "enrolled_at": r.enrolled_at.isoformat() if r.enrolled_at else None,
        }
        for r in enrollment_registry.get_all()
    ]


@app.post("/agents/{agent_id}/enrollment/approve")
async def approve_enrollment(agent_id: str, request: Request):
    """Manually approve an incomplete enrollment (human override)."""
    body = await request.json()
    reviewed_by = body.get("reviewed_by", "unknown")
    record = enrollment_registry.approve_manual(agent_id, reviewed_by)
    if not record:
        raise HTTPException(status_code=404, detail="No enrollment found")

    await event_bus.publish(DashboardEvent(
        event_type="agent_enrolled",
        agent_id=agent_id,
        payload={"status": "ENROLLED", "reviewed_by": reviewed_by, "manual_override": True},
    ))

    return {"agent_id": agent_id, "status": record.status.value, "reviewed_by": reviewed_by}


@app.get("/agents")
async def list_agents():
    """List all registered agents with current status."""
    return [a.model_dump(mode="json") for a in agent_registry.get_all()]


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get details for a single agent."""
    record = agent_registry.get(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")
    return record.model_dump(mode="json")


@app.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, request: Request):
    """Agent heartbeat — proof of life + optional status payload."""
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    record = await agent_registry.heartbeat(agent_id, body)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")
    return {"status": record.status.value, "trust_score": record.trust_score}


@app.post("/agents/{agent_id}/kill")
async def kill_agent(agent_id: str, req: KillRequest):
    """Kill switch — immediately suspend agent and drop to SUPERVISED tier."""
    record = await agent_registry.kill(agent_id, req.reason)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")
    return {
        "agent_id": agent_id,
        "status": record.status.value,
        "reason": req.reason,
        "autonomy_tier": record.autonomy_tier,
    }


@app.post("/agents/{agent_id}/revive")
async def revive_agent(agent_id: str):
    """Reactivate a suspended agent (stays at SUPERVISED tier)."""
    record = await agent_registry.revive(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")
    return record.model_dump(mode="json")


@app.post("/agents/{agent_id}/action")
async def agent_action(agent_id: str, req: ActionRequest):
    """Handle a tool action from Claude Code hooks or other agents.

    Low-risk tools are auto-logged. High-risk tools can trigger governance.
    """
    record = agent_registry.get(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")

    if record.status == AgentStatus.SUSPENDED:
        raise HTTPException(status_code=403, detail="Agent is SUSPENDED — action blocked")

    # Update heartbeat
    await agent_registry.heartbeat(agent_id, {"activity": f"{req.phase}: {req.tool}"})

    risk = classify_risk(req.tool, req.args)
    governed = should_govern(risk)

    log_entry = format_action_log(agent_id, req.tool, req.phase, risk, req.args)

    await event_bus.publish(DashboardEvent(
        event_type="action",
        agent_id=agent_id,
        payload=log_entry,
    ))

    return {
        "allowed": True,
        "risk": round(risk, 2),
        "governed": governed,
        "agent_status": record.status.value,
    }


@app.get("/events/stream")
async def event_stream():
    """SSE endpoint — streams all dashboard events to connected clients."""
    async def generate():
        async for event in event_bus.subscribe():
            yield event.to_sse()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """Serve the agent monitoring dashboard."""
    html_path = Path(__file__).parent / "dashboard.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard not available")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/status")
async def system_status():
    """System-wide status: agents, chains, liveness, event bus."""
    return {
        "agents": len(agent_registry.get_all()),
        "active_agents": sum(1 for a in agent_registry.get_all() if a.status == AgentStatus.ACTIVE),
        "chains": len(chains),
        "active_chains": sum(1 for c in chains.values() if c.status in (ChainStatus.PENDING, ChainStatus.ESCALATED, ChainStatus.EVALUATING)),
        "liveness": liveness.status_summary(),
        "dashboard_subscribers": event_bus.subscriber_count,
    }


# ═══════════════════════════════════════════════════════════════
# Governance Token Endpoints
# ═══════════════════════════════════════════════════════════════


class TokenValidateRequest(BaseModel):
    token: str
    required_scope: Optional[str] = None


@app.post("/api/v1/tokens/validate")
async def validate_token(req: TokenValidateRequest):
    """Validate a governance token.

    Called by the proxy layer to verify that an inbound request carries
    a valid, non-expired, non-revoked governance token. Optionally checks
    that the token's scope includes a required key.
    """
    valid, reason, gov_token = token_manager.validate(req.token, req.required_scope)
    result: dict[str, Any] = {
        "valid": valid,
        "reason": reason,
    }
    if gov_token:
        result["agent_did"] = gov_token.agent_did
        result["agent_id"] = gov_token.agent_id
        result["expires_at"] = gov_token.expires_at.isoformat()
        result["revoked"] = gov_token.revoked
        result["scope"] = gov_token.scope
    return result


@app.delete("/api/v1/agents/{agent_did}/token/revoke")
async def revoke_governance_token(agent_did: str):
    """Revoke a governance token by agent DID.

    Immediately invalidates the token so subsequent validate calls
    return revoked. This is the governance kill-switch for token-based
    access control.
    """
    gov_token = token_manager.revoke(agent_did)
    if gov_token is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "detail": f"No token found for DID: {agent_did}"},
        )

    # Publish revocation event
    await event_bus.publish(DashboardEvent(
        event_type="token_revoked",
        agent_id=gov_token.agent_id,
        payload={
            "agent_did": agent_did,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
        },
    ))

    return {
        "status": "revoked",
        "agent_did": agent_did,
        "agent_id": gov_token.agent_id,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
    }
