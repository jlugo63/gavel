"""
Governance Gateway (MVP)
Constitutional Reference: §II — All external API calls must be proxied
through the Governance Gateway for intent-logging.

Single point of entry for agent proposals. Every inbound intent is logged
to the Audit Spine BEFORE policy evaluation, ensuring a complete record
of what was attempted regardless of the outcome.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Union

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from governance.audit import AuditSpineManager
from governance.policy_engine import Decision, PolicyEngine, PolicyResult

HUMAN_API_KEY = os.environ.get("HUMAN_API_KEY", "")
APPROVAL_TTL_SECONDS = int(os.environ.get("APPROVAL_TTL_SECONDS", "3600"))

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
    approval_consumed_event_id: str | None = None


class ApprovalRequest(BaseModel):
    intent_event_id: str
    policy_event_id: str


class DenialRequest(BaseModel):
    intent_event_id: str
    policy_event_id: str
    reason: str = ""


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
            "content": content_str,
        },
    )

    # --- Step 2: Evaluate against constitutional invariants ---
    result, policy_event_id = engine.evaluate_proposal(proposal_dict)

    violations = [
        {"rule": v.rule, "description": v.description}
        for v in result.violations
    ]

    # --- Step 2b: Check for prior human approval if ESCALATED ---
    approval_consumed_event_id = None
    if result.decision == Decision.ESCALATED:
        prior_approval = audit.find_valid_approval(
            actor_id=proposal.actor_id,
            action_type=proposal.action_type,
            content=content_str,
            ttl_seconds=APPROVAL_TTL_SECONDS,
        )
        if prior_approval is not None:
            # Parse the original approval payload to get the intent linkage
            approval_payload = prior_approval["intent_payload"]
            if isinstance(approval_payload, str):
                import json
                approval_payload = json.loads(approval_payload)

            # Log APPROVAL_CONSUMED to the audit spine
            approval_consumed_event_id = audit.log_event(
                actor_id=proposal.actor_id,
                action_type="APPROVAL_CONSUMED",
                intent_payload={
                    "approval_event_id": prior_approval["id"],
                    "original_intent_id": approval_payload.get("intent_event_id", ""),
                    "current_intent_event_id": intent_event_id,
                    "current_policy_event_id": policy_event_id,
                    "consumed_at": datetime.now(timezone.utc).isoformat(),
                },
            )

            # Override the decision to APPROVED
            result = PolicyResult(
                decision=Decision.APPROVED,
                risk_score=result.risk_score,
                violations=result.violations,
                proposal=result.proposal,
            )

    response_body = ProposalResponse(
        decision=result.decision.value,
        risk_score=result.risk_score,
        intent_event_id=intent_event_id,
        policy_event_id=policy_event_id,
        violations=violations,
        approval_consumed_event_id=approval_consumed_event_id,
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


@app.post("/approve")
def approve(
    request: ApprovalRequest,
    authorization: str = Header(...),
):
    """
    Human approval for an ESCALATED proposal.
    Constitutional Reference: §I.3 — Tiered Autonomy.

    Flow:
      1. Authenticate the human via Bearer token.
      2. Validate that the referenced events exist and are ESCALATED.
      3. Log HUMAN_APPROVAL_GRANTED to the Audit Spine.
    """

    # --- Step 1: Authenticate ---
    if not HUMAN_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="HUMAN_API_KEY environment variable is not configured.",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")

    token = authorization[len("Bearer "):]
    if token != HUMAN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    # --- Step 2: Validate referenced events ---
    intent_event = audit.get_event(request.intent_event_id)
    if intent_event is None:
        raise HTTPException(
            status_code=404,
            detail=f"Intent event {request.intent_event_id} not found.",
        )
    if intent_event["action_type"] != "INBOUND_INTENT":
        raise HTTPException(
            status_code=422,
            detail=f"Event {request.intent_event_id} is not an INBOUND_INTENT "
                   f"(got '{intent_event['action_type']}').",
        )

    policy_event = audit.get_event(request.policy_event_id)
    if policy_event is None:
        raise HTTPException(
            status_code=404,
            detail=f"Policy event {request.policy_event_id} not found.",
        )
    if not policy_event["action_type"].startswith("POLICY_EVAL:"):
        raise HTTPException(
            status_code=422,
            detail=f"Event {request.policy_event_id} is not a POLICY_EVAL "
                   f"(got '{policy_event['action_type']}').",
        )

    # Verify the policy decision was ESCALATED
    policy_payload = policy_event["intent_payload"]
    if isinstance(policy_payload, str):
        import json
        policy_payload = json.loads(policy_payload)

    if policy_payload.get("decision") != "ESCALATED":
        raise HTTPException(
            status_code=422,
            detail=f"Policy decision is '{policy_payload.get('decision')}', "
                   f"not ESCALATED. Only ESCALATED proposals can be approved.",
        )

    # Sanity check: actor_id should match between intent and policy events
    if intent_event["actor_id"] != policy_event["actor_id"]:
        raise HTTPException(
            status_code=422,
            detail="Actor mismatch between intent and policy events.",
        )

    # --- Step 3: Log approval to Audit Spine ---
    approval_event_id = audit.log_event(
        actor_id="human:admin",
        action_type="HUMAN_APPROVAL_GRANTED",
        intent_payload={
            "intent_event_id": request.intent_event_id,
            "policy_event_id": request.policy_event_id,
            "approved_scope": "allow_execute_once",
            "approved_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return JSONResponse(
        status_code=200,
        content={
            "approval_event_id": approval_event_id,
            "intent_event_id": request.intent_event_id,
            "policy_event_id": request.policy_event_id,
            "status": "HUMAN_APPROVAL_GRANTED",
            "scope": "allow_execute_once",
            "message": "Proposal approved by human operator.",
        },
    )


@app.post("/deny")
def deny(
    request: DenialRequest,
    authorization: str = Header(...),
):
    """
    Human denial for an ESCALATED proposal.
    Constitutional Reference: §I.3 — Tiered Autonomy.

    Flow:
      1. Authenticate the human via Bearer token.
      2. Validate that the referenced events exist and are ESCALATED.
      3. Log HUMAN_DENIAL to the Audit Spine.
    """

    # --- Step 1: Authenticate ---
    if not HUMAN_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="HUMAN_API_KEY environment variable is not configured.",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")

    token = authorization[len("Bearer "):]
    if token != HUMAN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    # --- Step 2: Validate referenced events ---
    intent_event = audit.get_event(request.intent_event_id)
    if intent_event is None:
        raise HTTPException(
            status_code=404,
            detail=f"Intent event {request.intent_event_id} not found.",
        )
    if intent_event["action_type"] != "INBOUND_INTENT":
        raise HTTPException(
            status_code=422,
            detail=f"Event {request.intent_event_id} is not an INBOUND_INTENT "
                   f"(got '{intent_event['action_type']}').",
        )

    policy_event = audit.get_event(request.policy_event_id)
    if policy_event is None:
        raise HTTPException(
            status_code=404,
            detail=f"Policy event {request.policy_event_id} not found.",
        )
    if not policy_event["action_type"].startswith("POLICY_EVAL:"):
        raise HTTPException(
            status_code=422,
            detail=f"Event {request.policy_event_id} is not a POLICY_EVAL "
                   f"(got '{policy_event['action_type']}').",
        )

    # Verify the policy decision was ESCALATED
    policy_payload = policy_event["intent_payload"]
    if isinstance(policy_payload, str):
        import json
        policy_payload = json.loads(policy_payload)

    if policy_payload.get("decision") != "ESCALATED":
        raise HTTPException(
            status_code=422,
            detail=f"Policy decision is '{policy_payload.get('decision')}', "
                   f"not ESCALATED. Only ESCALATED proposals can be denied.",
        )

    if intent_event["actor_id"] != policy_event["actor_id"]:
        raise HTTPException(
            status_code=422,
            detail="Actor mismatch between intent and policy events.",
        )

    # --- Step 3: Log denial to Audit Spine ---
    denial_event_id = audit.log_event(
        actor_id="human:admin",
        action_type="HUMAN_DENIAL",
        intent_payload={
            "intent_event_id": request.intent_event_id,
            "policy_event_id": request.policy_event_id,
            "reason": request.reason,
            "denied_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return JSONResponse(
        status_code=200,
        content={
            "denial_event_id": denial_event_id,
            "intent_event_id": request.intent_event_id,
            "policy_event_id": request.policy_event_id,
            "status": "HUMAN_DENIAL",
            "reason": request.reason,
            "message": "Proposal denied by human operator.",
        },
    )
