"""
Liveness Model -- Timeout handling for ESCALATED proposals.
Constitutional Reference: SS I.3 -- Tiered Autonomy.

Prevents ESCALATED proposals from becoming zombie chains by enforcing
time-bounded review windows with automatic denial on timeout.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum


# ---------------------------------------------------------------------------
# Configuration (from env vars with defaults)
# ---------------------------------------------------------------------------

ESCALATION_INITIAL_TIMEOUT_SECONDS = int(
    os.environ.get("ESCALATION_INITIAL_TIMEOUT_SECONDS", "300")
)
ESCALATION_MAX_TIMEOUT_SECONDS = int(
    os.environ.get("ESCALATION_MAX_TIMEOUT_SECONDS", "3600")
)


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class EscalationState(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    AUTO_DENIED_TIMEOUT = "AUTO_DENIED_TIMEOUT"
    RESOLVED = "RESOLVED"


@dataclass
class EscalationTracker:
    intent_event_id: str
    policy_event_id: str
    actor_id: str
    escalated_at: datetime
    state: EscalationState
    expires_at: datetime  # escalated_at + initial_timeout
    hard_deadline: datetime  # escalated_at + max_timeout


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def check_escalation_status(audit, intent_event_id: str) -> EscalationState:
    """Check the current state of an escalated proposal.

    Args:
        audit: AuditSpineManager instance
        intent_event_id: The INBOUND_INTENT event ID

    Returns:
        EscalationState enum value
    """
    # Check if resolved (has approval, denial, or auto-deny event)
    conn = audit._connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id FROM audit_events
            WHERE action_type IN (
                'HUMAN_APPROVAL_GRANTED', 'HUMAN_DENIAL',
                'APPROVAL_CONSUMED', 'AUTO_DENIED_TIMEOUT'
            )
            AND (intent_payload->>'intent_event_id' = %s
                 OR intent_payload->>'current_intent_event_id' = %s)
            LIMIT 1
            """,
            (intent_event_id, intent_event_id),
        )
        if cur.fetchone() is not None:
            cur.close()
            return EscalationState.RESOLVED

        # Get the intent event to find escalated_at time
        cur.execute(
            """
            SELECT created_at FROM audit_events
            WHERE id = %s
            LIMIT 1
            """,
            (intent_event_id,),
        )
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()

    if row is None:
        return EscalationState.PENDING_REVIEW

    escalated_at = row[0]
    if escalated_at.tzinfo is None:
        escalated_at = escalated_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    hard_deadline = escalated_at + timedelta(seconds=ESCALATION_MAX_TIMEOUT_SECONDS)
    expires_at = escalated_at + timedelta(seconds=ESCALATION_INITIAL_TIMEOUT_SECONDS)

    if now > hard_deadline:
        return EscalationState.AUTO_DENIED_TIMEOUT
    if now > expires_at:
        return EscalationState.HUMAN_REQUIRED
    return EscalationState.PENDING_REVIEW


def _find_intent_for_policy_eval(audit, policy_event) -> str | None:
    """Reverse-lookup: find the INBOUND_INTENT that preceded a POLICY_EVAL.

    The policy engine does not store intent_event_id in POLICY_EVAL payloads.
    Instead, we find the most recent INBOUND_INTENT by the same actor created
    at or just before the POLICY_EVAL timestamp.
    """
    actor_id = policy_event["actor_id"]
    created_at = policy_event["created_at"]

    conn = audit._connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id FROM audit_events
            WHERE action_type = 'INBOUND_INTENT'
              AND actor_id = %s
              AND created_at <= %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (actor_id, created_at),
        )
        row = cur.fetchone()
        cur.close()
        if row is not None:
            return str(row[0])
        return None
    finally:
        conn.close()


def _batch_escalated_with_intents(audit) -> list[dict]:
    """Batch query: get all ESCALATED policy evals with their matching intents.

    Uses a single SQL query with a lateral join to efficiently pair each
    POLICY_EVAL:* event (decision=ESCALATED) with the preceding
    INBOUND_INTENT by the same actor. Returns a list of dicts with
    policy_event_id, intent_event_id, actor_id, and intent_created_at.
    """
    conn = audit._connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT pe.id AS policy_id,
                   pe.actor_id,
                   intent.id AS intent_id,
                   intent.created_at AS intent_created_at
            FROM audit_events pe
            CROSS JOIN LATERAL (
                SELECT id, created_at
                FROM audit_events
                WHERE action_type = 'INBOUND_INTENT'
                  AND actor_id = pe.actor_id
                  AND created_at <= pe.created_at
                ORDER BY created_at DESC
                LIMIT 1
            ) intent
            WHERE pe.action_type LIKE 'POLICY_EVAL:%%'
              AND pe.intent_payload->>'decision' = 'ESCALATED'
            ORDER BY pe.created_at DESC
            """
        )
        rows = cur.fetchall()
        cur.close()
    finally:
        conn.close()

    results = []
    for policy_id, actor_id, intent_id, intent_created_at in rows:
        results.append({
            "policy_event_id": str(policy_id),
            "actor_id": actor_id,
            "intent_event_id": str(intent_id),
            "intent_created_at": intent_created_at,
        })
    return results


def _batch_resolved_intent_ids(audit, intent_ids: list[str]) -> set[str]:
    """Batch check which intent_event_ids have been resolved.

    Returns a set of intent_event_ids that have at least one resolution event
    (approval, denial, consumed, or auto-deny).
    """
    if not intent_ids:
        return set()

    conn = audit._connect()
    try:
        cur = conn.cursor()
        # Use ANY() for efficient batch lookup
        cur.execute(
            """
            SELECT DISTINCT
                COALESCE(
                    intent_payload->>'intent_event_id',
                    intent_payload->>'current_intent_event_id'
                ) AS resolved_id
            FROM audit_events
            WHERE action_type IN (
                'HUMAN_APPROVAL_GRANTED', 'HUMAN_DENIAL',
                'APPROVAL_CONSUMED', 'AUTO_DENIED_TIMEOUT'
            )
            AND (
                intent_payload->>'intent_event_id' = ANY(%s)
                OR intent_payload->>'current_intent_event_id' = ANY(%s)
            )
            """,
            (intent_ids, intent_ids),
        )
        rows = cur.fetchall()
        cur.close()
    finally:
        conn.close()

    return {str(row[0]) for row in rows if row[0] is not None}


def _classify_escalation_batch(
    intent_event_id: str,
    intent_created_at,
    resolved_ids: set[str],
) -> EscalationState:
    """Classify a single escalation using pre-fetched data (no DB calls)."""
    if intent_event_id in resolved_ids:
        return EscalationState.RESOLVED

    escalated_at = intent_created_at
    if escalated_at.tzinfo is None:
        escalated_at = escalated_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    hard_deadline = escalated_at + timedelta(seconds=ESCALATION_MAX_TIMEOUT_SECONDS)
    expires_at = escalated_at + timedelta(seconds=ESCALATION_INITIAL_TIMEOUT_SECONDS)

    if now > hard_deadline:
        return EscalationState.AUTO_DENIED_TIMEOUT
    if now > expires_at:
        return EscalationState.HUMAN_REQUIRED
    return EscalationState.PENDING_REVIEW


def auto_deny_expired_escalations(audit) -> list[str]:
    """Find and auto-deny all expired escalations.

    Queries all ESCALATED policy evaluations, checks for resolution,
    and auto-denies any that have passed the hard deadline.

    Returns:
        List of intent_event_ids that were auto-denied.
    """
    pairs = _batch_escalated_with_intents(audit)
    if not pairs:
        return []

    # Batch-fetch all resolved intent IDs
    all_intent_ids = [p["intent_event_id"] for p in pairs]
    resolved_ids = _batch_resolved_intent_ids(audit, all_intent_ids)

    auto_denied = []
    for pair in pairs:
        intent_event_id = pair["intent_event_id"]
        policy_event_id = pair["policy_event_id"]
        actor_id = pair["actor_id"]
        intent_created_at = pair["intent_created_at"]

        state = _classify_escalation_batch(
            intent_event_id, intent_created_at, resolved_ids,
        )
        if state == EscalationState.AUTO_DENIED_TIMEOUT:
            audit.log_event(
                actor_id="system:gateway",
                action_type="AUTO_DENIED_TIMEOUT",
                intent_payload={
                    "intent_event_id": intent_event_id,
                    "policy_event_id": policy_event_id,
                    "actor_id": actor_id,
                    "reason": "Escalation expired -- auto-denied after timeout",
                    "auto_denied_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            auto_denied.append(intent_event_id)
            # Add to resolved set so subsequent duplicates are skipped
            resolved_ids.add(intent_event_id)

    return auto_denied


def get_escalation_summary(audit) -> dict:
    """Get summary counts of escalation states.

    Uses batch queries to efficiently classify all ESCALATED proposals.

    Returns:
        Dict with counts: {pending: N, human_required: N, auto_denied: N, resolved: N}
    """
    pairs = _batch_escalated_with_intents(audit)
    if not pairs:
        return {"pending": 0, "human_required": 0, "auto_denied": 0, "resolved": 0}

    # Batch-fetch all resolved intent IDs
    all_intent_ids = [p["intent_event_id"] for p in pairs]
    resolved_ids = _batch_resolved_intent_ids(audit, all_intent_ids)

    summary = {"pending": 0, "human_required": 0, "auto_denied": 0, "resolved": 0}

    for pair in pairs:
        intent_event_id = pair["intent_event_id"]
        intent_created_at = pair["intent_created_at"]

        state = _classify_escalation_batch(
            intent_event_id, intent_created_at, resolved_ids,
        )
        if state == EscalationState.PENDING_REVIEW:
            summary["pending"] += 1
        elif state == EscalationState.HUMAN_REQUIRED:
            summary["human_required"] += 1
        elif state == EscalationState.AUTO_DENIED_TIMEOUT:
            summary["auto_denied"] += 1
        elif state == EscalationState.RESOLVED:
            summary["resolved"] += 1

    return summary


def build_escalation_tracker(audit, intent_event_id: str, policy_event_id: str) -> EscalationTracker | None:
    """Build an EscalationTracker for a specific escalation."""
    intent_event = audit.get_event(intent_event_id)
    if intent_event is None:
        return None

    escalated_at = intent_event["created_at"]
    if isinstance(escalated_at, str):
        escalated_at = datetime.fromisoformat(escalated_at)
    if escalated_at.tzinfo is None:
        escalated_at = escalated_at.replace(tzinfo=timezone.utc)

    state = check_escalation_status(audit, intent_event_id)

    return EscalationTracker(
        intent_event_id=intent_event_id,
        policy_event_id=policy_event_id,
        actor_id=intent_event["actor_id"],
        escalated_at=escalated_at,
        state=state,
        expires_at=escalated_at + timedelta(seconds=ESCALATION_INITIAL_TIMEOUT_SECONDS),
        hard_deadline=escalated_at + timedelta(seconds=ESCALATION_MAX_TIMEOUT_SECONDS),
    )
