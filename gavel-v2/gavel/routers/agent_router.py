"""Agent management endpoints — register, enroll, heartbeat, kill, revive, action, report.

Extracted from gateway.py as part of the router decomposition.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from gavel.agents import AgentRegistry, AgentStatus
from gavel.chain import EventType
from gavel.dependencies import (
    ChainLockManager,
    get_agent_registry,
    get_budget_tracker,
    get_chain_lock_manager,
    get_chain_repo,
    get_enrollment_registry,
    get_event_bus,
    get_rate_limiter,
    get_token_manager,
)
from gavel.db.repositories import ChainRepository
from gavel.enrollment import (
    EnrollmentRegistry,
    EnrollmentApplication,
    EnrollmentStatus,
    TokenManager,
)
from gavel.events import EventBus, DashboardEvent
from gavel.hooks import classify_risk, should_govern, format_action_log
from gavel.rate_limit import RateLimiter, BudgetTracker


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
agent_router = APIRouter(tags=["agents"])


@agent_router.post("/agents/register")
async def register_agent(
    req: RegisterRequest,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    enrollment_registry: EnrollmentRegistry = Depends(get_enrollment_registry),
):
    """Register a new agent under Gavel governance."""
    existing = await agent_registry.get(req.agent_id)
    if existing:
        return existing.model_dump(mode="json")

    record = await agent_registry.register(
        agent_id=req.agent_id,
        display_name=req.display_name,
        agent_type=req.agent_type,
        capabilities=req.capabilities,
    )

    enrollment = await enrollment_registry.get(req.agent_id)
    enrolled = enrollment is not None and enrollment.status == EnrollmentStatus.ENROLLED

    result = record.model_dump(mode="json")
    result["enrolled"] = enrolled
    if not enrolled:
        result["enrollment_required"] = True
        result["enroll_url"] = "/v1/agents/enroll"
    return result


@agent_router.post("/agents/enroll")
async def enroll_agent(
    app_data: EnrollmentApplication,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    enrollment_registry: EnrollmentRegistry = Depends(get_enrollment_registry),
    event_bus: EventBus = Depends(get_event_bus),
    token_manager: TokenManager = Depends(get_token_manager),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    budget_tracker: BudgetTracker = Depends(get_budget_tracker),
):
    """Enroll an agent — ATF pre-flight checks before the agent can operate."""
    record = await enrollment_registry.submit(app_data)

    agent = await agent_registry.get(app_data.agent_id)
    if not agent and record.status == EnrollmentStatus.ENROLLED:
        agent = await agent_registry.register(
            agent_id=app_data.agent_id,
            display_name=app_data.display_name,
            agent_type=app_data.agent_type,
            capabilities=app_data.capabilities.tools,
        )

    is_prohibited = any("Art. 5" in v or "prohibited" in v.lower() for v in record.violations)

    if record.status != EnrollmentStatus.ENROLLED and is_prohibited and agent:
        await agent_registry.kill(app_data.agent_id, reason="EU AI Act Art. 5: prohibited practice")

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

    if record.status == EnrollmentStatus.ENROLLED:
        gov_token = await token_manager.issue(
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

        await rate_limiter.configure(
            app_data.agent_id,
            app_data.boundaries.max_actions_per_minute,
        )

        await budget_tracker.configure(
            app_data.agent_id,
            budget_tokens=app_data.budget_tokens,
            budget_usd=app_data.budget_usd,
        )

    return result


@agent_router.get("/agents/enrollments")
async def list_enrollments(
    enrollment_registry: EnrollmentRegistry = Depends(get_enrollment_registry),
):
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
        for r in await enrollment_registry.get_all()
    ]


@agent_router.post("/agents/{agent_id}/enrollment/approve")
async def approve_enrollment(
    agent_id: str,
    request: Request,
    enrollment_registry: EnrollmentRegistry = Depends(get_enrollment_registry),
    event_bus: EventBus = Depends(get_event_bus),
):
    """Manually approve an incomplete enrollment (human override)."""
    body = await request.json()
    reviewed_by = body.get("reviewed_by", "unknown")
    record = await enrollment_registry.approve_manual(agent_id, reviewed_by)
    if not record:
        raise HTTPException(status_code=404, detail="No enrollment found")

    await event_bus.publish(DashboardEvent(
        event_type="agent_enrolled",
        agent_id=agent_id,
        payload={"status": "ENROLLED", "reviewed_by": reviewed_by, "manual_override": True},
    ))

    return {"agent_id": agent_id, "status": record.status.value, "reviewed_by": reviewed_by}


@agent_router.get("/agents")
async def list_agents(
    agent_registry: AgentRegistry = Depends(get_agent_registry),
):
    """List all registered agents with current status."""
    return [a.model_dump(mode="json") for a in await agent_registry.get_all()]


@agent_router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
):
    """Get details for a single agent."""
    record = await agent_registry.get(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")
    return record.model_dump(mode="json")


@agent_router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    request: Request,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
):
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


@agent_router.post("/agents/{agent_id}/kill")
async def kill_agent(
    agent_id: str,
    req: KillRequest,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
):
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


@agent_router.post("/agents/{agent_id}/revive")
async def revive_agent(
    agent_id: str,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
):
    """Reactivate a suspended agent (stays at SUPERVISED tier)."""
    record = await agent_registry.revive(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")
    return record.model_dump(mode="json")


@agent_router.post("/agents/{agent_id}/action")
async def agent_action(
    agent_id: str,
    req: ActionRequest,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    event_bus: EventBus = Depends(get_event_bus),
):
    """Handle a tool action from Claude Code hooks or other agents."""
    record = await agent_registry.get(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")

    if record.status == AgentStatus.SUSPENDED:
        raise HTTPException(status_code=403, detail="Agent is SUSPENDED — action blocked")

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


@agent_router.post("/agents/{agent_id}/report")
async def report_action(
    agent_id: str,
    report: ActionReport,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    event_bus: EventBus = Depends(get_event_bus),
    chain_repo: ChainRepository = Depends(get_chain_repo),
    chain_locks: ChainLockManager = Depends(get_chain_lock_manager),
):
    """Post-execution report — called by PostToolUse hook after a tool executes."""
    record = await agent_registry.get(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail="Agent not registered")

    await agent_registry.update_trust_from_outcome(agent_id, report.tool, report.success)

    if report.chain_id:
        chain = await chain_repo.get(report.chain_id)
        if chain is not None:
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
                await chain_repo.save(chain)

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

    record = await agent_registry.get(agent_id)
    return {
        "recorded": True,
        "trust_score": record.trust_score,
        "autonomy_tier": record.autonomy_tier,
    }
