import { getIntentsWithPolicyEvals } from "@/lib/db";
import { ExpandableRow } from "@/components/expandable-row";
import { Pagination } from "@/components/pagination";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 20;

function DecisionBadge({ decision }: { decision: string | null }) {
  if (!decision) {
    return (
      <span className="text-xs px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-500">
        PENDING
      </span>
    );
  }
  const colors: Record<string, string> = {
    APPROVED: "bg-emerald-950 text-emerald-300",
    DENIED: "bg-red-950 text-red-300",
    ESCALATED: "bg-amber-950 text-amber-300",
  };
  return (
    <span
      className={`text-xs font-mono px-1.5 py-0.5 rounded ${
        colors[decision] ?? "bg-zinc-800 text-zinc-400"
      }`}
    >
      {decision}
    </span>
  );
}

export default async function IntentsPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string }>;
}) {
  const params = await searchParams;
  const page = Math.max(1, parseInt(params.page ?? "1", 10));
  const { intents, total } = await getIntentsWithPolicyEvals(page, PAGE_SIZE);

  return (
    <div>
      <h1 className="text-lg font-bold mb-4 text-zinc-200">
        Inbound Intents
        <span className="ml-2 text-sm font-normal text-zinc-500">
          Raw agent proposals before policy evaluation
        </span>
      </h1>

      <div className="overflow-x-auto rounded border border-zinc-800">
        <table className="w-full text-left">
          <thead className="bg-zinc-900 text-xs text-zinc-400 uppercase tracking-wider">
            <tr>
              <th className="px-3 py-2">Timestamp</th>
              <th className="px-3 py-2">Actor</th>
              <th className="px-3 py-2">Intent Action</th>
              <th className="px-3 py-2">Policy Decision</th>
              <th className="px-3 py-2">Risk Score</th>
              <th className="px-3 py-2 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {intents.map((intent) => {
              const payload = intent.intent_payload as Record<string, unknown>;
              const intentAction = (payload.action_type as string) ?? "unknown";

              return (
                <ExpandableRow
                  key={intent.id}
                  cells={[
                    <span
                      key="ts"
                      className="font-mono text-xs text-zinc-400"
                    >
                      {intent.created_at
                        .toISOString()
                        .replace("T", " ")
                        .slice(0, 23)}
                    </span>,
                    <span key="actor" className="font-mono text-xs">
                      {intent.actor_id}
                    </span>,
                    <span
                      key="action"
                      className="font-mono text-xs px-1.5 py-0.5 rounded bg-amber-950 text-amber-300"
                    >
                      {intentAction}
                    </span>,
                    <DecisionBadge
                      key="decision"
                      decision={intent.policy_decision}
                    />,
                    <span key="risk" className="font-mono text-xs">
                      {intent.policy_risk_score != null ? (
                        <span
                          className={
                            intent.policy_risk_score >= 0.8
                              ? "text-red-400"
                              : intent.policy_risk_score > 0
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }
                        >
                          {intent.policy_risk_score.toFixed(2)}
                        </span>
                      ) : (
                        <span className="text-zinc-600">-</span>
                      )}
                    </span>,
                  ]}
                  expandedContent={
                    <div className="space-y-2">
                      <div className="text-xs text-zinc-500">
                        Intent Event ID: {intent.id}
                        {intent.policy_event_id && (
                          <span className="ml-4">
                            Policy Event ID: {intent.policy_event_id}
                          </span>
                        )}
                      </div>
                      <div>
                        <div className="text-xs text-zinc-500 mb-1">
                          Raw Intent Payload:
                        </div>
                        <pre className="text-xs font-mono text-zinc-300 bg-zinc-950 rounded p-3 overflow-x-auto max-h-64">
                          {JSON.stringify(intent.intent_payload, null, 2)}
                        </pre>
                      </div>
                    </div>
                  }
                />
              );
            })}
          </tbody>
        </table>
      </div>

      <Pagination total={total} pageSize={PAGE_SIZE} currentPage={page} />
    </div>
  );
}
