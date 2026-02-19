"""
Governance Gateway (MVP)
Constitutional Reference: §II — All external API calls must be proxied
through the Governance Gateway for intent-logging.

Single point of entry for agent proposals. Every inbound intent is logged
to the Audit Spine BEFORE policy evaluation, ensuring a complete record
of what was attempted regardless of the outcome.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Union
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from governance.audit import AuditSpineManager
from governance.blastbox import BlastBoxConfig, check_docker_available, run_in_blastbox
from governance.evidence import create_evidence_packet, log_evidence_to_spine
from governance.identity import authenticate_human, validate_actor
from governance.policy_engine import Decision, PolicyEngine, PolicyResult

APPROVAL_TTL_SECONDS = int(os.environ.get("APPROVAL_TTL_SECONDS", "3600"))

# ---------------------------------------------------------------------------
# App + shared services
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Gavel Governance Gateway",
    version="1.0.0",
)

audit = AuditSpineManager()
engine = PolicyEngine(audit=audit)

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class Proposal(BaseModel):
    """Legacy proposal format (kept for backward compatibility)."""
    actor_id: str
    action_type: str
    content: Union[str, dict[str, Any]]


class Scope(BaseModel):
    allow_paths: list[str] = []
    allow_commands: list[str] = []
    allow_network: bool = False


class Action(BaseModel):
    action_type: str
    content: Union[str, dict[str, Any]] = ""


class ProposalEnvelope(BaseModel):
    actor_id: str
    role: str = "unknown"
    tier_request: int = 0
    goal: str = ""
    scope: Scope = Scope()
    expected_outcomes: list[str] = []
    action: Action
    chain_id: str | None = None  # provide to continue an existing chain


class ProposalResponse(BaseModel):
    chain_id: str
    decision: str
    risk_score: float
    intent_event_id: str
    policy_event_id: str
    violations: list[dict[str, str]]
    rationale: list[str] = []
    matched_rules: list[str] = []
    signals: list[str] = []
    approval_consumed_event_id: str | None = None


class ApprovalRequest(BaseModel):
    intent_event_id: str
    policy_event_id: str


class DenialRequest(BaseModel):
    intent_event_id: str
    policy_event_id: str
    reason: str = ""


class ExecuteRequest(BaseModel):
    proposal_id: str  # intent_event_id from /propose


# ---------------------------------------------------------------------------
# Human authentication helper
# ---------------------------------------------------------------------------

def _authenticate_human_request(authorization: str):
    """Extract Bearer token and resolve to a human Identity.

    Raises HTTPException on auth failure.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")

    token = authorization[len("Bearer "):]
    try:
        return authenticate_human(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "operational", "service": "governance-gateway"}


def _parse_proposal(body: dict[str, Any]) -> ProposalEnvelope:
    """Convert raw JSON body to ProposalEnvelope.

    Detects legacy format (top-level action_type, no nested action field)
    and converts it to the envelope format automatically.
    """
    if "action" not in body and "action_type" in body:
        # Legacy Proposal format -> convert to envelope
        return ProposalEnvelope(
            actor_id=body["actor_id"],
            role=body.get("role", "unknown"),
            tier_request=body.get("tier_request", 0),
            goal=body.get("goal", ""),
            scope=Scope(**body["scope"]) if "scope" in body else Scope(),
            expected_outcomes=body.get("expected_outcomes", []),
            action=Action(
                action_type=body["action_type"],
                content=body.get("content", ""),
            ),
        )
    # New envelope format
    return ProposalEnvelope(**body)


@app.post("/propose")
async def propose(request: Request):
    """
    Submit a proposed action for constitutional review.

    Accepts both legacy Proposal format and new ProposalEnvelope format.

    Flow:
      1. Log the raw inbound intent to the Audit Spine (pre-evaluation).
      2. Run the PolicyEngine against all constitutional invariants.
      3. Return the decision with appropriate HTTP status.
    """
    body = await request.json()
    envelope = _parse_proposal(body)

    # --- Step 0: Identity validation — reject unknown actors BEFORE audit ---
    try:
        identity = validate_actor(envelope.actor_id)
    except ValueError as exc:
        return JSONResponse(
            status_code=403,
            content={"error": str(exc), "actor_id": envelope.actor_id},
        )

    # Fill role from identity if not provided in envelope
    if envelope.role == "unknown":
        envelope = envelope.model_copy(update={"role": identity.role})

    # Use provided chain_id (continuing a chain) or generate a new one
    chain_id = envelope.chain_id or str(uuid4())

    # --- Step 0b: Role-lock — actor cannot switch roles mid-chain ---
    if envelope.chain_id is not None:
        prior_role = audit.get_chain_role(chain_id, envelope.actor_id)
        if prior_role is not None and prior_role != envelope.role:
            return JSONResponse(
                status_code=409,
                content={
                    "error": (
                        f"Role-lock violation: actor {envelope.actor_id} used "
                        f"role '{prior_role}' on chain {chain_id}, cannot "
                        f"switch to '{envelope.role}'"
                    ),
                    "chain_id": chain_id,
                    "prior_role": prior_role,
                    "requested_role": envelope.role,
                },
            )

    # Normalise content to string for the policy engine
    content_str = (
        envelope.action.content if isinstance(envelope.action.content, str)
        else str(envelope.action.content)
    )

    proposal_dict = {
        "actor_id": envelope.actor_id,
        "action_type": envelope.action.action_type,
        "content": content_str,
    }

    # --- Step 1: Log raw inbound intent BEFORE evaluation ---
    intent_event_id = audit.log_event(
        actor_id=envelope.actor_id,
        action_type="INBOUND_INTENT",
        intent_payload={
            "chain_id": chain_id,
            "role": envelope.role,
            "tier_request": envelope.tier_request,
            "goal": envelope.goal,
            "scope": envelope.scope.model_dump(),
            "expected_outcomes": envelope.expected_outcomes,
            "action_type": envelope.action.action_type,
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
            actor_id=envelope.actor_id,
            action_type=envelope.action.action_type,
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
                actor_id=envelope.actor_id,
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
                rationale=result.rationale,
                matched_rules=result.matched_rules,
                signals=result.signals,
            )

    response_body = ProposalResponse(
        chain_id=chain_id,
        decision=result.decision.value,
        risk_score=result.risk_score,
        intent_event_id=intent_event_id,
        policy_event_id=policy_event_id,
        violations=violations,
        rationale=result.rationale,
        matched_rules=result.matched_rules,
        signals=result.signals,
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
    human_identity = _authenticate_human_request(authorization)

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
        actor_id=human_identity.actor_id,
        action_type="HUMAN_APPROVAL_GRANTED",
        intent_payload={
            "intent_event_id": request.intent_event_id,
            "policy_event_id": request.policy_event_id,
            "approved_scope": "allow_execute_once",
            "approved_by": human_identity.actor_id,
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
            "approved_by": human_identity.actor_id,
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
    human_identity = _authenticate_human_request(authorization)

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
        actor_id=human_identity.actor_id,
        action_type="HUMAN_DENIAL",
        intent_payload={
            "intent_event_id": request.intent_event_id,
            "policy_event_id": request.policy_event_id,
            "reason": request.reason,
            "denied_by": human_identity.actor_id,
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
            "denied_by": human_identity.actor_id,
            "message": "Proposal denied by human operator.",
        },
    )


@app.post("/execute")
def execute(request: ExecuteRequest):
    """
    Execute an approved proposal inside a Blast Box sandbox.
    Constitutional Reference: SS II -- Blast Box sandbox execution.

    Flow:
      1. Validate the proposal exists and has been approved (or escalated+approved).
      2. Run the command in a Docker sandbox.
      3. Build an evidence packet and log it to the Audit Spine.
    """

    # --- Step 1: Look up the INBOUND_INTENT event ---
    intent_event = audit.get_event(request.proposal_id)
    if intent_event is None:
        return JSONResponse(
            status_code=404,
            content={"error": f"Proposal {request.proposal_id} not found."},
        )
    if intent_event["action_type"] != "INBOUND_INTENT":
        return JSONResponse(
            status_code=422,
            content={
                "error": (
                    f"Event {request.proposal_id} is not an INBOUND_INTENT "
                    f"(got '{intent_event['action_type']}')."
                ),
            },
        )

    # --- Step 2: Find the corresponding POLICY_EVAL ---
    policy_event = audit.find_policy_eval_for_intent(request.proposal_id)
    if policy_event is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": f"No policy evaluation found for proposal {request.proposal_id}.",
            },
        )

    # --- Step 3: Parse policy decision ---
    policy_payload = policy_event["intent_payload"]
    if isinstance(policy_payload, str):
        policy_payload = json.loads(policy_payload)
    decision = policy_payload.get("decision")

    # --- Step 4: Determine effective decision ---
    if decision == "DENIED":
        return JSONResponse(
            status_code=403,
            content={"error": "Proposal was denied by policy. Cannot execute."},
        )

    if decision == "ESCALATED":
        # Check for human approval in the audit spine
        conn = audit._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id FROM audit_events
                WHERE action_type IN ('HUMAN_APPROVAL_GRANTED', 'APPROVAL_CONSUMED')
                AND (intent_payload->>'intent_event_id' = %s
                     OR intent_payload->>'current_intent_event_id' = %s)
                LIMIT 1
                """,
                (request.proposal_id, request.proposal_id),
            )
            approval_row = cur.fetchone()
            cur.close()
        finally:
            conn.close()

        if approval_row is None:
            return JSONResponse(
                status_code=202,
                content={
                    "message": "Proposal requires human approval before execution.",
                },
            )

    # decision is APPROVED (or ESCALATED with approval) -- proceed

    # --- Step 5: Check Docker availability ---
    if not check_docker_available():
        return JSONResponse(
            status_code=503,
            content={"error": "Docker is not available."},
        )

    # --- Step 6: Extract command from intent_payload ---
    intent_payload = intent_event["intent_payload"]
    if isinstance(intent_payload, str):
        intent_payload = json.loads(intent_payload)
    command = intent_payload.get("content", "")

    # --- Step 7: Extract chain_id ---
    chain_id = intent_payload.get("chain_id", "")

    # --- Step 8-9: Run in Blast Box ---
    config = BlastBoxConfig()
    result = run_in_blastbox(command=command, config=config)

    # --- Step 10: Build evidence packet ---
    packet = create_evidence_packet(
        proposal_id=request.proposal_id,
        chain_id=chain_id,
        actor_id=intent_event["actor_id"],
        action_type=intent_payload.get("action_type", "unknown"),
        command=command,
        result=result,
        config=config,
    )

    # --- Step 11: Log to Audit Spine ---
    evidence_event_id = log_evidence_to_spine(audit, packet)

    # --- Step 12: Return evidence ---
    return JSONResponse(
        status_code=200,
        content={
            "evidence_event_id": evidence_event_id,
            "evidence_packet": packet.model_dump(),
        },
    )
