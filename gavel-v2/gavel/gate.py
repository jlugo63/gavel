"""
Gavel Gate — central enforcement endpoint for Claude Code tool calls.

Every tool invocation from a governed agent passes through /gate before
execution. The gate classifies risk, checks agent status, and either
allows the action immediately or creates a governance chain for review.

This is the fast path. Low-risk actions get a sub-millisecond allow.
High-risk actions get a chain_id and a poll URL so the caller can
wait for governance approval without blocking.

The AGT PolicyEngine evaluates constitutional rules (kill-switch,
registration, dangerous commands) before the gate's own risk/tier
logic runs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .agents import AgentRegistry, AgentStatus
from .agt_compat import AgentOSEngine
from .enrollment import GovernanceToken
from .liveness import LivenessMonitor
from .chain import GovernanceChain, ChainStatus, EventType
from .events import EventBus, DashboardEvent
from .hooks import classify_risk, should_govern
from .prompt_injection import PromptInjectionDetector as _PIDetector, DetectionResult
from .rate_limit import RateLimiter, BudgetTracker
from .tiers import TierPolicy, AutonomyTier, TIER_TABLE
from .dependencies import (
    ChainLockManager,
    get_agent_os,
    get_agent_registry,
    get_budget_tracker,
    get_chain_lock_manager,
    get_chain_repo,
    get_event_bus,
    get_liveness,
    get_rate_limiter,
    get_tier_policy,
    require_gavel_token,
)
from gavel.db.repositories import ChainRepository

log = logging.getLogger("gavel.gate")

# Module-level detector instance (no external dependencies)
_injection_detector = _PIDetector()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class GateRequest(BaseModel):
    agent_id: str
    tool_name: str
    tool_input: dict[str, Any] = {}
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


async def _evaluate_cedar(
    req: GateRequest,
    record,
    policy_engine,
    event_bus: EventBus,
) -> GateResponse | None:
    """Run the AGT PolicyEngine against constitutional rules."""
    try:
        from gavel.agt_compat import (
            ActionType,
            AgentContext,
            ExecutionRequest,
            PermissionLevel,
        )

        at_name = _TOOL_ACTION_TYPE.get(req.tool_name, "CODE_EXECUTION")
        action_type = ActionType(at_name)

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

        allowed, reason = policy_engine.validate_request(exec_req)

        if not allowed:
            log.warning(
                "Cedar DENY: agent=%s tool=%s reason=%s",
                req.agent_id, req.tool_name, reason,
            )
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

        return None

    except Exception as e:
        log.error("Cedar evaluation error: %s", e, exc_info=True)
        return GateResponse(
            decision="deny",
            reason=f"Cedar evaluation error (fail-closed): {e}",
        )


# ---------------------------------------------------------------------------
# Prompt injection scanning helper (ATF D-2)
# ---------------------------------------------------------------------------

def _scan_for_injection(req: GateRequest) -> DetectionResult:
    """Extract scannable text fields from a gate request and run detection."""
    fields: dict[str, str] = {}
    for key, value in req.tool_input.items():
        if isinstance(value, str):
            fields[key] = value
    fields["_tool_name"] = req.tool_name
    if fields:
        return _injection_detector.scan_fields(fields)
    return DetectionResult(summary="No scannable fields")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
router = APIRouter(tags=["gate"])


@router.post("/gate", response_model=GateResponse)
async def gate(
    req: GateRequest,
    token: GovernanceToken = Depends(require_gavel_token),
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    event_bus: EventBus = Depends(get_event_bus),
    chain_repo: ChainRepository = Depends(get_chain_repo),
    chain_locks: ChainLockManager = Depends(get_chain_lock_manager),
    liveness: LivenessMonitor = Depends(get_liveness),
    tier_policy: TierPolicy = Depends(get_tier_policy),
    policy_engine: AgentOSEngine = Depends(get_agent_os),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    budget_tracker: BudgetTracker = Depends(get_budget_tracker),
) -> GateResponse:
    """Central enforcement gate for every tool invocation."""
    # 1. Agent lookup
    record = await agent_registry.get(req.agent_id)
    if not record:
        return GateResponse(decision="deny", reason="Agent not registered")

    # 2. Cedar policy evaluation via AGT PolicyEngine
    if policy_engine:
        cedar_decision = await _evaluate_cedar(req, record, policy_engine, event_bus)
        if cedar_decision is not None:
            return cedar_decision

    # 2b. Prompt injection detection (ATF D-2)
    pi_result = _scan_for_injection(req)
    if pi_result.is_injection:
        log.warning(
            "Prompt injection detected: agent=%s tool=%s confidence=%.2f vectors=%s",
            req.agent_id, req.tool_name, pi_result.confidence,
            [v.value for v in pi_result.vectors_found],
        )
        if event_bus:
            await event_bus.publish(DashboardEvent(
                event_type="prompt_injection",
                agent_id=req.agent_id,
                payload={
                    "tool": req.tool_name,
                    "session_id": req.session_id,
                    **pi_result.to_gate_dict(),
                },
            ))
        if pi_result.should_deny:
            return GateResponse(
                decision="deny",
                reason=f"Prompt injection detected (confidence {pi_result.confidence:.2f}): {pi_result.summary}",
            )

    # 3. Status checks — kill switch and dead agents (fallback if no Cedar)
    if record.status == AgentStatus.SUSPENDED:
        return GateResponse(
            decision="deny",
            reason="Agent SUSPENDED \u2014 kill switch active",
        )
    if record.status == AgentStatus.DEAD:
        return GateResponse(decision="deny", reason="Agent marked dead")

    # 3b. ATF S-3: Rate limiting enforcement
    rl_result = await rate_limiter.check_and_record(req.agent_id)
    if not rl_result.allowed:
        log.warning("S-3 rate limit deny: agent=%s", req.agent_id)
        if event_bus:
            await event_bus.publish(DashboardEvent(
                event_type="gate_check",
                agent_id=req.agent_id,
                payload={
                    "tool": req.tool_name,
                    "decision": "deny",
                    "reason": rl_result.reason,
                    "rate_limit": True,
                    "retry_after_seconds": rl_result.retry_after_seconds,
                },
            ))
        return GateResponse(
            decision="deny",
            reason=f"ATF S-3: {rl_result.reason}",
        )

    # 3c. ATF S-4: Budget enforcement
    token_cost = req.tool_input.get("token_cost", 0)
    usd_cost = req.tool_input.get("usd_cost", 0.0)
    budget_result = await budget_tracker.check_and_decrement(
        req.agent_id,
        token_cost=int(token_cost),
        usd_cost=float(usd_cost),
    )
    if not budget_result.allowed:
        log.warning("S-4 budget deny: agent=%s", req.agent_id)
        if event_bus:
            await event_bus.publish(DashboardEvent(
                event_type="gate_check",
                agent_id=req.agent_id,
                payload={
                    "tool": req.tool_name,
                    "decision": "deny",
                    "reason": budget_result.reason,
                    "budget_exceeded": True,
                },
            ))
        return GateResponse(
            decision="deny",
            reason=f"ATF S-4: {budget_result.reason}",
        )

    # 4. Risk classification
    risk = classify_risk(req.tool_name, req.tool_input)
    if pi_result.should_flag:
        risk = min(risk + 0.3 + pi_result.confidence * 0.2, 1.0)

    # 5. Determine governance tier from agent record
    agent_tier = AutonomyTier(record.autonomy_tier)
    tier_reqs = TIER_TABLE[agent_tier]

    # 6. Heartbeat
    await agent_registry.heartbeat(
        req.agent_id,
        {"activity": f"gate: {req.tool_name}"},
    )

    # 7. Decision — allow or govern
    governed = should_govern(risk)

    # 8. Publish gate_check event to dashboard
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
        await chain_repo.save(chain)

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
        poll_url=f"/v1/gate/poll/{chain.chain_id}",
        sla_seconds=sla_seconds,
    )


@router.get("/gate/poll/{chain_id}", response_model=GatePollResponse)
async def gate_poll(
    chain_id: str,
    chain_repo: ChainRepository = Depends(get_chain_repo),
    liveness: LivenessMonitor = Depends(get_liveness),
) -> GatePollResponse:
    """Poll a governance chain for its current decision status."""
    chain = await chain_repo.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")

    if chain.status in (ChainStatus.APPROVED, ChainStatus.COMPLETED):
        decision = "allow"
        reason = "Governance chain approved"
    elif chain.status in (ChainStatus.DENIED, ChainStatus.ROLLED_BACK, ChainStatus.TIMED_OUT):
        decision = "deny"
        reason = f"Governance chain {chain.status.value.lower()}"
    else:
        decision = "pending"
        reason = f"Chain status: {chain.status.value}"

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
