# Gavel — Dashboard UI

Read-only monitoring dashboard for Gavel.
Displays audit events, inbound intents, and policy decisions from the Audit Spine.

**Gavel Reference:** This dashboard is monitoring-only per §I.1 (Immutable History).
All database access is SELECT-only — no INSERT, UPDATE, or DELETE code paths exist.

## Prerequisites

- Node.js 18+
- PostgreSQL governance database running (via `docker compose up -d` from project root)

## Setup

```bash
cd ui
cp .env.local.example .env.local   # edit if your DB config differs
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Pages

| Route | Description |
|-------|-------------|
| `/admin/events` | All audit events, newest first, with expandable JSON payloads |
| `/admin/intents` | Inbound agent intents with associated policy decisions |
| `/admin/policy` | Policy evaluation outcomes with decision/risk indicators |

Every page includes the **Integrity Status Header** which verifies the
hash chain on each load. If tampering is detected, a critical alert is shown.

## Architecture

- **Next.js 16 App Router** with `force-dynamic` on all routes (no caching)
- **Server Components** for direct DB access via `pg` (node-postgres)
- **Zod** for runtime validation of database rows
- **Tailwind CSS** for styling
