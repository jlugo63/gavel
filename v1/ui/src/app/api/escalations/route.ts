/**
 * API Route: GET /api/escalations
 * Returns escalated policy evaluations with resolution status.
 */

import { NextResponse } from "next/server";
import { Pool } from "pg";

export const dynamic = "force-dynamic";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

interface EscalationRow {
  policy_event_id: string;
  actor_id: string;
  policy_payload: Record<string, unknown>;
  escalated_at: string;
  resolution_event_id: string | null;
  intent_event_id: string | null;
}

export async function GET() {
  const { rows } = await pool.query<EscalationRow>(
    `SELECT
       pe.id as policy_event_id,
       pe.actor_id,
       pe.intent_payload as policy_payload,
       pe.created_at as escalated_at,
       pe.intent_payload->>'intent_event_id' as intent_event_id,
       (SELECT r.id FROM audit_events r
        WHERE r.action_type IN (
          'HUMAN_APPROVAL_GRANTED', 'HUMAN_DENIAL',
          'APPROVAL_CONSUMED', 'AUTO_DENIED_TIMEOUT'
        )
        AND (
          r.intent_payload->>'intent_event_id' = pe.intent_payload->>'intent_event_id'
          OR r.intent_payload->>'current_intent_event_id' = pe.intent_payload->>'intent_event_id'
        )
        LIMIT 1
       ) as resolution_event_id
     FROM audit_events pe
     WHERE pe.action_type LIKE 'POLICY_EVAL:%'
       AND pe.intent_payload->>'decision' = 'ESCALATED'
     ORDER BY pe.created_at DESC
     LIMIT 50`
  );

  const now = Date.now();
  const escalations = rows.map((row) => {
    const escalatedAt = new Date(row.escalated_at).getTime();
    const elapsedMs = now - escalatedAt;
    const elapsedSeconds = elapsedMs / 1000;

    let state: string;
    if (row.resolution_event_id) {
      state = "RESOLVED";
    } else if (elapsedSeconds > 3600) {
      state = "AUTO_DENIED_TIMEOUT";
    } else if (elapsedSeconds > 300) {
      state = "HUMAN_REQUIRED";
    } else {
      state = "PENDING_REVIEW";
    }

    const payload = row.policy_payload as Record<string, unknown>;

    return {
      policy_event_id: row.policy_event_id,
      actor_id: row.actor_id,
      intent_event_id: row.intent_event_id,
      action_type: payload.action_type ?? payload.intent_action ?? "unknown",
      content: payload.content ?? payload.action_content ?? "",
      risk_score: Number(payload.risk_score ?? 0),
      decision: payload.decision,
      escalated_at: row.escalated_at,
      elapsed_seconds: Math.round(elapsedSeconds),
      initial_timeout_remaining: Math.max(0, 300 - elapsedSeconds),
      hard_deadline_remaining: Math.max(0, 3600 - elapsedSeconds),
      state,
      resolution_event_id: row.resolution_event_id,
    };
  });

  const counts = {
    pending_review: escalations.filter((e) => e.state === "PENDING_REVIEW").length,
    human_required: escalations.filter((e) => e.state === "HUMAN_REQUIRED").length,
    auto_denied: escalations.filter((e) => e.state === "AUTO_DENIED_TIMEOUT").length,
    resolved: escalations.filter((e) => e.state === "RESOLVED").length,
  };

  return NextResponse.json({ escalations, counts });
}
