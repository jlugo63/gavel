"""
Governance Gateway (MVP)
Constitutional Reference: §II — All external API calls must be proxied
through the Governance Gateway for intent-logging.

Single point of entry for agent proposals. Every inbound intent is logged
to the Audit Spine BEFORE policy evaluation, ensuring a complete record
of what was attempted regardless of the outcome.
"""

from __future__ import annotations

from typing import Any, Union

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from governance.audit import AuditSpineManager
from governance.policy_engine import Decision, PolicyEngine

# ---------------------------------------------------------------------------
# App + shared services
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Constitutional AI Governance Gateway",
    version="1.0.0",
)

audit = AuditSpineManager()
engine = PolicyEngine(audit=audit)

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class Proposal(BaseModel):
    actor_id: str
    action_type: str
    content: Union[str, dict[str, Any]]


class ProposalResponse(BaseModel):
    decision: str
    risk_score: float
    intent_event_id: str
    policy_event_id: str
    violations: list[dict[str, str]]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "operational", "service": "governance-gateway"}


@app.post("/propose")
def propose(proposal: Proposal):
    """
    Submit a proposed action for constitutional review.

    Flow:
      1. Log the raw inbound intent to the Audit Spine (pre-evaluation).
      2. Run the PolicyEngine against all constitutional invariants.
      3. Return the decision with appropriate HTTP status.
    """

    # Normalise content to string for the policy engine
    content_str = (
        proposal.content if isinstance(proposal.content, str)
        else str(proposal.content)
    )

    proposal_dict = {
        "actor_id": proposal.actor_id,
        "action_type": proposal.action_type,
        "content": content_str,
    }

    # --- Step 1: Log raw inbound intent BEFORE evaluation ---
    intent_event_id = audit.log_event(
        actor_id=proposal.actor_id,
        action_type="INBOUND_INTENT",
        intent_payload={
            "action_type": proposal.action_type,
            "content": proposal.content if isinstance(proposal.content, str)
                       else proposal.content,
        },
    )

    # --- Step 2: Evaluate against constitutional invariants ---
    result, policy_event_id = engine.evaluate_proposal(proposal_dict)

    violations = [
        {"rule": v.rule, "description": v.description}
        for v in result.violations
    ]

    response_body = ProposalResponse(
        decision=result.decision.value,
        risk_score=result.risk_score,
        intent_event_id=intent_event_id,
        policy_event_id=policy_event_id,
        violations=violations,
    )

    # --- Step 3: Return decision with appropriate HTTP status ---
    if result.decision == Decision.DENIED:
        return JSONResponse(
            status_code=403,
            content={
                **response_body.model_dump(),
                "error": "CONSTITUTIONAL VIOLATION — proposal denied.",
            },
        )

    if result.decision == Decision.ESCALATED:
        return JSONResponse(
            status_code=202,
            content={
                **response_body.model_dump(),
                "message": "Proposal requires human approval before execution.",
            },
        )

    # APPROVED
    return JSONResponse(
        status_code=200,
        content={
            **response_body.model_dump(),
            "message": "Proposal approved. Cleared for execution.",
        },
    )
