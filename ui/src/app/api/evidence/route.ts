/**
 * API Route: GET /api/evidence
 * Returns the most recent EVIDENCE_PACKET audit events.
 */

import { NextResponse } from "next/server";
import { Pool } from "pg";

export const dynamic = "force-dynamic";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function GET() {
  const { rows } = await pool.query(
    `SELECT id, actor_id, action_type, intent_payload, created_at
     FROM audit_events
     WHERE action_type = 'EVIDENCE_PACKET'
     ORDER BY created_at DESC
     LIMIT 100`
  );

  return NextResponse.json(rows);
}
