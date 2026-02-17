/**
 * Database Helper — SELECT-Only Audit Spine Access
 * Gavel Reference: §I.1 — Immutable History
 *
 * This module provides READ-ONLY parameterized queries against
 * the governance_control_plane database. No UPDATE/DELETE/INSERT
 * code paths exist in this file or anywhere in the UI.
 */

import { Pool } from "pg";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Connection pool (singleton)
// ---------------------------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

export const AuditEventSchema = z.object({
  id: z.string().uuid(),
  created_at: z.coerce.date(),
  actor_id: z.string(),
  action_type: z.string(),
  intent_payload: z.record(z.string(), z.unknown()),
  policy_version: z.string(),
  event_hash: z.string(),
  previous_event_hash: z.string(),
});

export type AuditEvent = z.infer<typeof AuditEventSchema>;

export const ChainStatusSchema = z.object({
  total_events: z.coerce.number(),
  chain_valid: z.boolean(),
  break_at: z.string().uuid().nullable(),
});

export type ChainStatus = z.infer<typeof ChainStatusSchema>;

// ---------------------------------------------------------------------------
// Queries — ALL SELECT-ONLY
// ---------------------------------------------------------------------------

export async function verifyChain(): Promise<ChainStatus> {
  const { rows } = await pool.query(
    "SELECT total_events, chain_valid, break_at FROM audit_spine_verify_chain()"
  );
  return ChainStatusSchema.parse(rows[0]);
}

export async function getEvents(
  page: number,
  pageSize: number = 20
): Promise<{ events: AuditEvent[]; total: number }> {
  const offset = (page - 1) * pageSize;

  const [countResult, dataResult] = await Promise.all([
    pool.query("SELECT count(*)::int AS total FROM audit_events"),
    pool.query(
      `SELECT id, created_at, actor_id, action_type,
              intent_payload, policy_version, event_hash, previous_event_hash
       FROM audit_events
       ORDER BY created_at DESC, id DESC
       LIMIT $1 OFFSET $2`,
      [pageSize, offset]
    ),
  ]);

  return {
    total: countResult.rows[0].total,
    events: dataResult.rows.map((r: Record<string, unknown>) =>
      AuditEventSchema.parse(r)
    ),
  };
}

export async function getIntentsWithPolicyEvals(
  page: number,
  pageSize: number = 20
): Promise<{
  intents: (AuditEvent & {
    policy_decision: string | null;
    policy_risk_score: number | null;
    policy_event_id: string | null;
    is_approved: boolean;
  })[];
  total: number;
}> {
  const offset = (page - 1) * pageSize;

  const countResult = await pool.query(
    "SELECT count(*)::int AS total FROM audit_events WHERE action_type = 'INBOUND_INTENT'"
  );

  // For each INBOUND_INTENT, find the closest subsequent POLICY_EVAL
  // for the same actor_id within 10 seconds, and check for HUMAN_APPROVAL_GRANTED.
  const dataResult = await pool.query(
    `SELECT
       i.id, i.created_at, i.actor_id, i.action_type,
       i.intent_payload, i.policy_version, i.event_hash, i.previous_event_hash,
       p.intent_payload->>'decision'   AS policy_decision,
       (p.intent_payload->>'risk_score')::float AS policy_risk_score,
       p.id::text                      AS policy_event_id,
       (a.id IS NOT NULL)              AS is_approved
     FROM audit_events i
     LEFT JOIN LATERAL (
       SELECT pe.id, pe.intent_payload
       FROM audit_events pe
       WHERE pe.action_type LIKE 'POLICY_EVAL:%'
         AND pe.actor_id = i.actor_id
         AND pe.created_at >= i.created_at
         AND pe.created_at <= i.created_at + interval '10 seconds'
       ORDER BY pe.created_at ASC
       LIMIT 1
     ) p ON true
     LEFT JOIN LATERAL (
       SELECT ae.id
       FROM audit_events ae
       WHERE ae.action_type = 'HUMAN_APPROVAL_GRANTED'
         AND ae.intent_payload->>'intent_event_id' = i.id::text
       LIMIT 1
     ) a ON true
     WHERE i.action_type = 'INBOUND_INTENT'
     ORDER BY i.created_at DESC, i.id DESC
     LIMIT $1 OFFSET $2`,
    [pageSize, offset]
  );

  return {
    total: countResult.rows[0].total,
    intents: dataResult.rows.map((r: Record<string, unknown>) => ({
      ...AuditEventSchema.parse(r),
      policy_decision: (r.policy_decision as string) ?? null,
      policy_risk_score: r.policy_risk_score != null ? Number(r.policy_risk_score) : null,
      policy_event_id: (r.policy_event_id as string) ?? null,
      is_approved: Boolean(r.is_approved),
    })),
  };
}

export async function getPolicyEvals(
  page: number,
  pageSize: number = 20
): Promise<{ evals: AuditEvent[]; total: number }> {
  const offset = (page - 1) * pageSize;

  const [countResult, dataResult] = await Promise.all([
    pool.query(
      "SELECT count(*)::int AS total FROM audit_events WHERE action_type LIKE 'POLICY_EVAL:%'"
    ),
    pool.query(
      `SELECT id, created_at, actor_id, action_type,
              intent_payload, policy_version, event_hash, previous_event_hash
       FROM audit_events
       WHERE action_type LIKE 'POLICY_EVAL:%'
       ORDER BY created_at DESC, id DESC
       LIMIT $1 OFFSET $2`,
      [pageSize, offset]
    ),
  ]);

  return {
    total: countResult.rows[0].total,
    evals: dataResult.rows.map((r: Record<string, unknown>) =>
      AuditEventSchema.parse(r)
    ),
  };
}
