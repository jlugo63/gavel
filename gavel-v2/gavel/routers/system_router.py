"""System endpoints — SSE events, dashboard, status, liveness, token management.

Extracted from gateway.py as part of the router decomposition.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from starlette.responses import StreamingResponse
from pydantic import BaseModel

from gavel.agents import AgentRegistry, AgentStatus
from gavel.chain import GovernanceChain, ChainStatus, EventType
from gavel.dependencies import (
    ChainLockManager,
    get_agent_registry,
    get_chain_lock_manager,
    get_chain_repo,
    get_event_bus,
    get_liveness,
    get_token_manager,
)
from gavel.db.repositories import ChainRepository
from gavel.enrollment import TokenManager
from gavel.events import EventBus, DashboardEvent
from gavel.liveness import LivenessMonitor


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TokenValidateRequest(BaseModel):
    token: str
    required_scope: Optional[str] = None


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
system_router = APIRouter(tags=["system"])


@system_router.get("/events/stream")
async def event_stream(
    event_bus: EventBus = Depends(get_event_bus),
):
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


@system_router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """Serve the agent monitoring dashboard."""
    # Prefer the new static/ layout; fall back to legacy single-file dashboard
    static_path = Path(__file__).parent.parent / "static" / "dashboard.html"
    if static_path.exists():
        return HTMLResponse(static_path.read_text(encoding="utf-8"))
    legacy_path = Path(__file__).parent.parent / "dashboard.html"
    if legacy_path.exists():
        return HTMLResponse(legacy_path.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="Dashboard not available")


@system_router.get("/status")
async def system_status(
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    event_bus: EventBus = Depends(get_event_bus),
    chain_repo: ChainRepository = Depends(get_chain_repo),
    liveness: LivenessMonitor = Depends(get_liveness),
):
    """System-wide status: agents, chains, liveness, event bus."""
    all_agents = await agent_registry.get_all()
    all_chains = await chain_repo.list_all()
    return {
        "agents": len(all_agents),
        "active_agents": sum(1 for a in all_agents if a.status == AgentStatus.ACTIVE),
        "chains": len(all_chains),
        "active_chains": sum(1 for c in all_chains if c.status in (ChainStatus.PENDING, ChainStatus.ESCALATED, ChainStatus.EVALUATING)),
        "liveness": liveness.status_summary(),
        "dashboard_subscribers": event_bus.subscriber_count,
    }


@system_router.get("/liveness")
async def get_liveness_endpoint(
    chain_repo: ChainRepository = Depends(get_chain_repo),
    chain_locks: ChainLockManager = Depends(get_chain_lock_manager),
    liveness: LivenessMonitor = Depends(get_liveness),
):
    """Dashboard: SLA status of all active chains."""
    expired = liveness.get_expired()

    for timeout in expired:
        chain = await chain_repo.get(timeout.chain_id)
        if chain and chain.status == ChainStatus.ESCALATED:
            async with chain_locks.lock(timeout.chain_id):
                chain.status = ChainStatus.TIMED_OUT
                chain.append(
                    event_type=EventType.AUTO_DENIED,
                    actor_id="system:liveness",
                    role_used="system",
                    payload={"reason": "SLA timeout — Constitutional Article IV.2: system degrades toward safety"},
                )
                await chain_repo.save(chain)
            liveness.resolve(timeout.chain_id, "AUTO_DENIED")
            chain_locks.discard(timeout.chain_id)

    return liveness.status_summary()


@system_router.post("/tokens/validate")
async def validate_token(
    req: TokenValidateRequest,
    token_manager: TokenManager = Depends(get_token_manager),
):
    """Validate a governance token."""
    valid, reason, gov_token = await token_manager.validate(req.token, req.required_scope)
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


@system_router.delete("/agents/{agent_did}/token/revoke")
async def revoke_governance_token(
    agent_did: str,
    token_manager: TokenManager = Depends(get_token_manager),
    event_bus: EventBus = Depends(get_event_bus),
):
    """Revoke a governance token by agent DID."""
    gov_token = await token_manager.revoke(agent_did)
    if gov_token is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "detail": f"No token found for DID: {agent_did}"},
        )

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
