import { getEvents } from "@/lib/db";
import { ExpandableRow } from "@/components/expandable-row";
import { Pagination } from "@/components/pagination";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 20;

export default async function EventsPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string }>;
}) {
  const params = await searchParams;
  const page = Math.max(1, parseInt(params.page ?? "1", 10));
  const { events, total } = await getEvents(page, PAGE_SIZE);

  return (
    <div>
      <h1 className="text-lg font-bold mb-4 text-zinc-200">
        Audit Events
        <span className="ml-2 text-sm font-normal text-zinc-500">
          All events in the Audit Spine (newest first)
        </span>
      </h1>

      <div className="overflow-x-auto rounded border border-zinc-800">
        <table className="w-full text-left">
          <thead className="bg-zinc-900 text-xs text-zinc-400 uppercase tracking-wider">
            <tr>
              <th className="px-3 py-2">Timestamp</th>
              <th className="px-3 py-2">Actor</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">Policy Ver.</th>
              <th className="px-3 py-2">Event Hash</th>
              <th className="px-3 py-2">Prev Hash</th>
              <th className="px-3 py-2 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <ExpandableRow
                key={e.id}
                cells={[
                  <span key="ts" className="font-mono text-xs text-zinc-400">
                    {e.created_at.toISOString().replace("T", " ").slice(0, 23)}
                  </span>,
                  <span key="actor" className="font-mono text-xs">
                    {e.actor_id}
                  </span>,
                  <span
                    key="action"
                    className={`font-mono text-xs px-1.5 py-0.5 rounded ${
                      e.action_type.startsWith("POLICY_EVAL")
                        ? "bg-blue-950 text-blue-300"
                        : e.action_type === "INBOUND_INTENT"
                        ? "bg-amber-950 text-amber-300"
                        : "bg-zinc-800 text-zinc-300"
                    }`}
                  >
                    {e.action_type}
                  </span>,
                  <span key="pv" className="font-mono text-xs text-zinc-500">
                    {e.policy_version}
                  </span>,
                  <span key="hash" className="font-mono text-xs text-zinc-500">
                    {e.event_hash.slice(0, 16)}...
                  </span>,
                  <span
                    key="prev"
                    className="font-mono text-xs text-zinc-600"
                  >
                    {e.previous_event_hash === "GENESIS"
                      ? "GENESIS"
                      : `${e.previous_event_hash.slice(0, 16)}...`}
                  </span>,
                ]}
                expandedContent={
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">
                      Event ID: {e.id}
                    </div>
                    <pre className="text-xs font-mono text-zinc-300 bg-zinc-950 rounded p-3 overflow-x-auto max-h-64">
                      {JSON.stringify(e.intent_payload, null, 2)}
                    </pre>
                  </div>
                }
              />
            ))}
          </tbody>
        </table>
      </div>

      <Pagination total={total} pageSize={PAGE_SIZE} currentPage={page} />
    </div>
  );
}
