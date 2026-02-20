/**
 * API Route: GET /api/chain/[chain_id]
 * Returns all audit events associated with a specific chain (intent) ID.
 */

import { NextRequest, NextResponse } from "next/server";
import { Pool } from "pg";

export const dynamic = "force-dynamic";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ chain_id: string }> }
) {
  const { chain_id } = await params;

  const { rows } = await pool.query(
    `SELECT id, actor_id, action_type, intent_payload, event_hash, created_at
     FROM audit_events
     WHERE intent_payload::text LIKE '%' || $1 || '%'
     ORDER BY created_at ASC`,
    [chain_id]
  );

  return NextResponse.json(rows);
}
