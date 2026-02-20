export const dynamic = "force-dynamic";

const EVENT_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  INBOUND_INTENT: { bg: "bg-blue-950", text: "text-blue-300", dot: "bg-blue-400" },
  "POLICY_EVAL:APPROVED": { bg: "bg-emerald-950", text: "text-emerald-300", dot: "bg-emerald-400" },
  "POLICY_EVAL:DENIED": { bg: "bg-red-950", text: "text-red-300", dot: "bg-red-500" },
  "POLICY_EVAL:ESCALATED": { bg: "bg-amber-950", text: "text-amber-300", dot: "bg-amber-400" },
  HUMAN_APPROVAL_GRANTED: { bg: "bg-emerald-950", text: "text-emerald-300", dot: "bg-emerald-400" },
  HUMAN_DENIAL: { bg: "bg-red-950", text: "text-red-300", dot: "bg-red-500" },
  EVIDENCE_PACKET: { bg: "bg-purple-950", text: "text-purple-300", dot: "bg-purple-400" },
  EVIDENCE_REVIEW_DETERMINISTIC: { bg: "bg-indigo-950", text: "text-indigo-300", dot: "bg-indigo-400" },
  EVIDENCE_AUTO_APPROVE: { bg: "bg-emerald-950", text: "text-emerald-300", dot: "bg-emerald-400" },
  EVIDENCE_AUTO_DENY: { bg: "bg-red-950", text: "text-red-300", dot: "bg-red-500" },
  AUTO_DENIED_TIMEOUT: { bg: "bg-red-950", text: "text-red-300", dot: "bg-red-500" },
};

const DEFAULT_COLOR = { bg: "bg-zinc-800", text: "text-zinc-400", dot: "bg-zinc-500" };

interface ChainEvent {
  id: string;
  actor_id: string;
  action_type: string;
  intent_payload: Record<string, unknown>;
  event_hash: string;
  created_at: string;
}

function EventBadge({ actionType }: { actionType: string }) {
  const c = EVENT_COLORS[actionType] ?? DEFAULT_COLOR;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-mono px-2 py-0.5 rounded ${c.bg} ${c.text}`}>
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {actionType}
    </span>
  );
}

function ChainStatusBadge({ events }: { events: ChainEvent[] }) {
  const lastEvent = events[events.length - 1];
  if (!lastEvent) return null;

  const type = lastEvent.action_type;
  if (type === "HUMAN_APPROVAL_GRANTED" || type === "APPROVAL_CONSUMED" || type === "EVIDENCE_AUTO_APPROVE")
    return <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300">APPROVED</span>;
  if (type === "HUMAN_DENIAL" || type === "AUTO_DENIED_TIMEOUT" || type === "EVIDENCE_AUTO_DENY")
    return <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-950 text-red-300">DENIED</span>;
  if (type.includes("ESCALATED"))
    return <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300">ESCALATED</span>;
  return <span className="text-xs font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">IN PROGRESS</span>;
}

function TimelineCard({ event }: { event: ChainEvent }) {
  const ts = new Date(event.created_at).toISOString().replace("T", " ").slice(0, 23);

  return (
    <div className="relative pl-8">
      {/* Timeline dot */}
      <div className="absolute left-0 top-3 w-3 h-3 rounded-full bg-zinc-700 border-2 border-zinc-500" />

      <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4">
        <div className="flex items-center gap-3 flex-wrap mb-2">
          <EventBadge actionType={event.action_type} />
          <span className="font-mono text-xs text-zinc-400">{ts}</span>
          <span className="font-mono text-xs text-zinc-500">{event.actor_id}</span>
        </div>
        <div className="font-mono text-xs text-zinc-600">
          {event.event_hash.slice(0, 16)}...
        </div>
        <details className="mt-2">
          <summary className="text-xs text-zinc-500 cursor-pointer hover:text-zinc-300 transition-colors">
            Show payload
          </summary>
          <pre className="mt-2 text-xs font-mono text-zinc-300 bg-zinc-950 rounded p-3 overflow-x-auto max-h-64">
            {JSON.stringify(event.intent_payload, null, 2)}
          </pre>
        </details>
      </div>
    </div>
  );
}

export default async function ChainTimelinePage({
  params,
}: {
  params: Promise<{ chain_id: string }>;
}) {
  const { chain_id } = await params;

  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL ?? "http://localhost:3000";
  const res = await fetch(`${baseUrl}/api/chain/${chain_id}`, { cache: "no-store" });
  const events: ChainEvent[] = await res.json();

  const actor = events.length > 0 ? events[0].actor_id : "unknown";

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-lg font-bold text-zinc-200 mb-2">Chain Timeline</h1>
        <div className="flex flex-wrap items-center gap-4 text-sm">
          <div className="font-mono text-xs text-zinc-400 bg-zinc-900 px-2 py-1 rounded border border-zinc-800 break-all">
            {chain_id}
          </div>
          <div className="text-zinc-500">
            Actor: <span className="font-mono text-zinc-300">{actor}</span>
          </div>
          <div className="text-zinc-500">
            Events: <span className="font-mono text-zinc-300">{events.length}</span>
          </div>
          <ChainStatusBadge events={events} />
        </div>
      </div>

      {events.length === 0 ? (
        <div className="text-center py-12 text-zinc-500">
          No events found for this chain ID.
        </div>
      ) : (
        <div className="relative space-y-4">
          {/* Vertical line */}
          <div className="absolute left-[5px] top-3 bottom-3 w-0.5 bg-zinc-800" />
          {events.map((event) => (
            <TimelineCard key={event.id} event={event} />
          ))}
        </div>
      )}
    </div>
  );
}
