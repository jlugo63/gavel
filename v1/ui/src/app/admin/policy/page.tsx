import { getPolicyEvals } from "@/lib/db";
import { ExpandableRow } from "@/components/expandable-row";
import { Pagination } from "@/components/pagination";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 20;

function DecisionBadge({ decision }: { decision: string }) {
  const config: Record<string, { bg: string; text: string; dot: string }> = {
    APPROVED: {
      bg: "bg-emerald-950",
      text: "text-emerald-300",
      dot: "bg-emerald-400",
    },
    DENIED: { bg: "bg-red-950", text: "text-red-300", dot: "bg-red-500" },
    ESCALATED: {
      bg: "bg-amber-950",
      text: "text-amber-300",
      dot: "bg-amber-400",
    },
  };
  const c = config[decision] ?? {
    bg: "bg-zinc-800",
    text: "text-zinc-400",
    dot: "bg-zinc-500",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-mono px-2 py-0.5 rounded ${c.bg} ${c.text}`}
    >
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {decision}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color =
    score >= 0.8
      ? "bg-red-500"
      : score > 0
      ? "bg-amber-500"
      : "bg-emerald-500";

  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span
        className={`font-mono text-xs ${
          score >= 0.8
            ? "text-red-400"
            : score > 0
            ? "text-amber-400"
            : "text-emerald-400"
        }`}
      >
        {score.toFixed(2)}
      </span>
    </div>
  );
}

export default async function PolicyPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string }>;
}) {
  const params = await searchParams;
  const page = Math.max(1, parseInt(params.page ?? "1", 10));
  const { evals, total } = await getPolicyEvals(page, PAGE_SIZE);

  return (
    <div>
      <h1 className="text-lg font-bold mb-4 text-zinc-200">
        Policy Decisions
        <span className="ml-2 text-sm font-normal text-zinc-500">
          Governance evaluation outcomes
        </span>
      </h1>

      <div className="overflow-x-auto rounded border border-zinc-800">
        <table className="w-full text-left">
          <thead className="bg-zinc-900 text-xs text-zinc-400 uppercase tracking-wider">
            <tr>
              <th className="px-3 py-2">Timestamp</th>
              <th className="px-3 py-2">Actor</th>
              <th className="px-3 py-2">Eval Type</th>
              <th className="px-3 py-2">Decision</th>
              <th className="px-3 py-2">Risk Score</th>
              <th className="px-3 py-2 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {evals.map((ev) => {
              const payload = ev.intent_payload as Record<string, unknown>;
              const decision = (payload.decision as string) ?? "UNKNOWN";
              const riskScore = Number(payload.risk_score ?? 0);
              const violations = (payload.violations as Array<Record<string, string>>) ?? [];

              return (
                <ExpandableRow
                  key={ev.id}
                  cells={[
                    <span
                      key="ts"
                      className="font-mono text-xs text-zinc-400"
                    >
                      {ev.created_at
                        .toISOString()
                        .replace("T", " ")
                        .slice(0, 23)}
                    </span>,
                    <span key="actor" className="font-mono text-xs">
                      {ev.actor_id}
                    </span>,
                    <span
                      key="type"
                      className="font-mono text-xs px-1.5 py-0.5 rounded bg-blue-950 text-blue-300"
                    >
                      {ev.action_type.replace("POLICY_EVAL:", "")}
                    </span>,
                    <DecisionBadge key="dec" decision={decision} />,
                    <RiskBar key="risk" score={riskScore} />,
                  ]}
                  expandedContent={
                    <div className="space-y-2">
                      <div className="text-xs text-zinc-500">
                        Event ID: {ev.id}
                      </div>
                      {violations.length > 0 && (
                        <div>
                          <div className="text-xs text-zinc-500 mb-1">
                            Violations:
                          </div>
                          <ul className="space-y-1">
                            {violations.map((v, i) => (
                              <li
                                key={i}
                                className="text-xs font-mono text-red-300 bg-red-950/50 rounded px-2 py-1"
                              >
                                <span className="text-red-500 font-bold">
                                  [{v.rule}]
                                </span>{" "}
                                {v.description}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      <div>
                        <div className="text-xs text-zinc-500 mb-1">
                          Full Payload:
                        </div>
                        <pre className="text-xs font-mono text-zinc-300 bg-zinc-950 rounded p-3 overflow-x-auto max-h-64">
                          {JSON.stringify(ev.intent_payload, null, 2)}
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
