/**
 * API Route: POST /api/approve
 * Proxies approval requests to the Governance Gateway.
 * The UI never writes to the database directly.
 */

import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:8000";
const HUMAN_API_KEY = process.env.HUMAN_API_KEY ?? "";

export async function POST(request: NextRequest) {
  if (!HUMAN_API_KEY) {
    return NextResponse.json(
      { error: "HUMAN_API_KEY is not configured on the server." },
      { status: 500 }
    );
  }

  const body = await request.json();

  const resp = await fetch(`${GATEWAY_URL}/approve`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${HUMAN_API_KEY}`,
    },
    body: JSON.stringify(body),
  });

  const data = await resp.json();
  return NextResponse.json(data, { status: resp.status });
}
