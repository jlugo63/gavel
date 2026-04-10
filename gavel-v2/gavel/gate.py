"""
Gavel Gate — central enforcement endpoint for Claude Code tool calls.

Every tool invocation from a governed agent passes through /gate before
execution. The gate classifies risk, checks agent status, and either
allows the action immediately or creates a governance chain for review.

This is the fast path. Low-risk actions get a sub-millisecond allow.
High-risk actions get a chain_id and a poll URL so the caller can
wait for governance approval without blocking.

Phase 3: Cedar enforcement is active — the AGT PolicyEngine evaluates
constitutional rules (kill-switch, registration, dangerous commands)
before the gate's own risk/tier logic runs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from .agents import AgentRegistry, AgentStatus
from .enrollment import TokenManager, GovernanceToken
from .chain import GovernanceChain, ChainStatus, EventType
from .events import EventBus, DashboardEvent
from .hooks import classify_risk, should_govern
from .tiers import TierPolicy, AutonomyTier, TIER_TABLE

log = logging.getLogger("gavel.gate")

# ---------------------------------------------------------------------------
# Shared state — set by gateway.py at startup via init_gate()
# ---------------------------------------------------------------------------
agent_registry: Optional[AgentRegistry] = None
event_bus: Optional[EventBus] = None
chains: Optional[dict[str, GovernanceChain]] = None
liveness: Optional[Any] = None
tier_policy: Optional[TierPolicy] = None
policy_engine: Optional[Any] = None  # AGT PolicyEngine instance
token_manager: Optional[TokenManager] = None
chain_locks: Optional[Any] = None  # ChainLockManager from gateway.py


def init_gate(
    registry: AgentRegistry,
    bus: EventBus,
    chain_store: dict[str, GovernanceChain],
    liveness_monitor: Any,
    policy: TierPolicy | None = None,
    cedar_engine: Any | None = None,
    tokens: TokenManager | None = None,
    lock_manager: Any | None = None,
) -> None:
    """Wire shared state from gateway.py into this module."""
    global agent_registry, event_bus, chains, liveness, tier_policy, policy_engine, token_manager, chain_locks
    agent_registry = registry
    event_bus = bus
    chains = chain_store
    liveness = liveness_monitor
    tier_policy = policy or TierPolicy()
    policy_engine = cedar_engine
    token_manager = tokens
    chain_locks = lock_manager


async def require_gavel_token(
    x_gavel_token: Optional[str] = Header(default=None),
) -> GovernanceToken:
    """FastAPI dependency that validates the X-Gavel-Token header.

    Raises 401 if the header is missing, 403 if the token is invalid/expired/revoked.
    """
    if x_gavel_token is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_token", "detail": "X-Gavel-Token header is required"},
        )

    if token_manager is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "not_initialized", "detail": "Token manager not available"},
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


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class GateRequest(BaseModel):
    agent_id: str
    tool_name: str
    tool_input: dict = {}
    session_id: str = ""


class GateResponse(BaseModel):
    decision: str  # "allow", "deny", "govern"
    risk: float = 0.0
    tier: str = "SUPERVISED"
    reason: str = ""
    chain_id: Optional[str] = None
    poll_url: Optional[str] = None
    sla_seconds: Optional[int] = None


class GatePollResponse(BaseModel):
    chain_id: str
    status: str
    decision: str  # "pending", "allow", "deny"
    reason: str = ""
    sla_remaining: Optional[float] = None


# ---------------------------------------------------------------------------
# Cedar enforcement helpers
# ---------------------------------------------------------------------------

# ActionType mapping for AGT PolicyEngine (values are lowercase enum values)
_TOOL_ACTION_TYPE: dict[str, str] = {
    "Read": "file_read",
    "Glob": "file_read",
    "Grep": "file_read",
    "Write": "file_write",
    "Edit": "file_write",
    "NotebookEdit": "file_write",
    "Bash": "code_execution",
    "Agent": "workflow_trigger",
    "WebFetch": "api_call",
    "WebSearch": "api_call",
}


async def _evaluate_cedar(req: GateRequest, record) -> GateResponse | None:
    """Run the AGT PolicyEngine against constitutional rules.

    Returns a GateResponse (deny) if the policy rejects the request,
    or None if the request passes all Cedar rules and should continue
    to risk/tier evaluation.
    """
    try:
        from gavel.agt_compat import (
            ActionType,
            AgentContext,
            ExecutionRequest,
            PermissionLevel,
        )

        # Map tool to AGT ActionType
        at_name = _TOOL_ACTION_TYPE.get(req.tool_name, "CODE_EXECUTION")
        action_type = ActionType(at_name)

        # Build agent context with live status from registry
        ctx = AgentContext(
            agent_id=req.agent_id,
            session_id=req.session_id or "",
            created_at=record.registered_at,
            permissions={at: PermissionLevel.ADMIN for at in ActionType},
            metadata={
                "registered": True,
                "status": record.status.value,
                "trust_score": record.trust_score,
                "autonomy_tier": record.autonomy_tier,
            },
        )

        # Build execution request
        exec_req = ExecutionRequest(
            request_id=f"gate-{req.agent_id}-{req.tool_name}-{uuid4().hex[:8]}",
            agent_context=ctx,
            action_type=action_type,
            parameters={
                "tool": req.tool_name,
                **req.tool_input,
            },
            timestamp=datetime.now(timezone.utc),
            risk_score=classify_risk(req.tool_name, req.tool_input),
        )

        # Evaluate against all loaded constitutional rules
        allowed, reason = policy_engine.validate_request(exec_req)

        if not allowed:
            log.warning(
                "Cedar DENY: agent=%s tool=%s reason=%s",
                req.agent_id, req.tool_name, reason,
            )
            # Publish Cedar denial to dashboard
            if event_bus:
                await event_bus.publish(DashboardEvent(
                    event_type="gate_check",
                    agent_id=req.agent_id,
                    payload={
                        "tool": req.tool_name,
                        "risk": round(exec_req.risk_score, 3),
                        "decision": "deny",
                        "reason": f"Cedar: {reason}",
                        "cedar": True,
                        "session_id": req.session_id,
                    },
                ))
            return GateResponse(
                decision="deny",
                reason=f"Cedar policy: {reason}",
            )

        # Passed all Cedar rules — continue to risk/tier logic
        return None

    except Exception as e:
        # Fail-closed: if Cedar evaluation crashes, deny the request
        log.error("Cedar evaluation error: %s", e, exc_info=True)
        return GateResponse(
            decision="deny",
            reason=f"Cedar evaluation error (fail-closed): {e}",
        )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
router = APIRouter(tags=["gate"])


@router.post("/gate", response_model=GateResponse)
async def gate(req: GateRequest, token: GovernanceToken = Depends(require_gavel_token)) -> GateResponse:
    """Central enforcement gate for every tool invocation.

    Requires a valid X-Gavel-Token header (issued at enrollment).

    Fast path: low-risk actions are allowed immediately.
    Slow path: high-risk actions create a governance chain and return
    a poll URL so the caller can await approval.
    """
    # 1. Agent lookup
    record = agent_registry.get(req.agent_id)
    if not record:
        return GateResponse(decision="deny", reason="Agent not registered")

    # 2. Cedar policy evaluation via AGT PolicyEngine
    #    Enforces constitutional rules: kill-switch, registration,
    #    dangerous commands — all as PolicyRule validators.
    if policy_engine:
        cedar_decision = await _evaluate_cedar(req, record)
        if cedar_decision is not None:
            return cedar_decision

    # 3. Status checks — kill switch and dead agents (fallback if no Cedar)
    if record.status == AgentStatus.SUSPENDED:
        return GateResponse(
            decision="deny",
            reason="Agent SUSPENDED \u2014 kill switch active",
        )
    if record.status == AgentStatus.DEAD:
        return GateResponse(decision="deny", reason="Agent marked dead")

    # 4. Risk classification
    risk = classify_risk(req.tool_name, req.tool_input)

    # 5. Determine governance tier from agent record
    agent_tier = AutonomyTier(record.autonomy_tier)
    tier_reqs = TIER_TABLE[agent_tier]

    # 6. Heartbeat — agent is alive if it is calling /gate
    await agent_registry.heartbeat(
        req.agent_id,
        {"activity": f"gate: {req.tool_name}"},
    )

    # 7. Decision — allow or govern
    governed = should_govern(risk)

    # 8. Publish gate_check event to dashboard (with decision)
    await event_bus.publish(DashboardEvent(
        event_type="gate_check",
        agent_id=req.agent_id,
        payload={
            "tool": req.tool_name,
            "risk": round(risk, 3),
            "tier": agent_tier.name,
            "decision": "govern" if governed else "allow",
            "session_id": req.session_id,
        },
    ))

    if not governed:
        return GateResponse(
            decision="allow",
            risk=round(risk, 3),
            tier=agent_tier.name,
            reason="Risk below governance threshold",
        )

    # 9. High risk — create governance chain
    chain = GovernanceChain()
    async with chain_locks.lock(chain.chain_id):
        chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id=req.agent_id,
            role_used="proposer",
            payload={
                "tool_name": req.tool_name,
                "tool_input": req.tool_input,
                "risk": round(risk, 3),
                "session_id": req.session_id,
            },
        )
        chain.status = ChainStatus.ESCALATED
        chains[chain.chain_id] = chain

    # Start SLA timer if liveness monitor is available
    sla_seconds = tier_reqs.sla_seconds
    if liveness:
        liveness.track(chain.chain_id, sla_seconds)

    await event_bus.publish(DashboardEvent(
        event_type="chain_event",
        agent_id=req.agent_id,
        chain_id=chain.chain_id,
        payload={
            "status": chain.status.value,
            "risk": round(risk, 3),
            "tier": agent_tier.name,
            "tool": req.tool_name,
        },
    ))

    return GateResponse(
        decision="govern",
        risk=round(risk, 3),
        tier=agent_tier.name,
        reason=f"Risk {risk:.2f} >= 0.5 — governance chain created",
        chain_id=chain.chain_id,
        poll_url=f"/gate/poll/{chain.chain_id}",
        sla_seconds=sla_seconds,
    )


@router.get("/gate/poll/{chain_id}", response_model=GatePollResponse)
async def gate_poll(chain_id: str) -> GatePollResponse:
    """Poll a governance chain for its current decision status."""
    chain = chains.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    # Map chain status to a gate decision
    if chain.status in (ChainStatus.APPROVED, ChainStatus.COMPLETED):
        decision = "allow"
        reason = "Governance chain approved"
    elif chain.status in (ChainStatus.DENIED, ChainStatus.ROLLED_BACK, ChainStatus.TIMED_OUT):
        decision = "deny"
        reason = f"Governance chain {chain.status.value.lower()}"
    else:
        decision = "pending"
        reason = f"Chain status: {chain.status.value}"

    # SLA remaining
    sla_remaining = None
    if liveness:
        summary = liveness.status_summary()
        chains_info = summary.get("chains", {})
        if chain_id in chains_info:
            sla_remaining = chains_info[chain_id].get("remaining_seconds")

    return GatePollResponse(
        chain_id=chain_id,
        status=chain.status.value,
        decision=decision,
        reason=reason,
        sla_remaining=sla_remaining,
    )
