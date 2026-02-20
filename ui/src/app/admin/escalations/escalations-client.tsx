"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";

interface Escalation {
  policy_event_id: string;
  actor_id: string;
  intent_event_id: string | null;
  action_type: string;
  content: string;
  risk_score: number;
  decision: string;
  escalated_at: string;
  elapsed_seconds: number;
  initial_timeout_remaining: number;
  hard_deadline_remaining: number;
  state: string;
  resolution_event_id: string | null;
}

interface EscalationData {
  escalations: Escalation[];
  counts: {
    pending_review: number;
    human_required: number;
    auto_denied: number;
    resolved: number;
  };
}

const STATE_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  PENDING_REVIEW: { bg: "bg-amber-950", text: "text-amber-300", dot: "bg-amber-400" },
  HUMAN_REQUIRED: { bg: "bg-orange-950", text: "text-orange-300", dot: "bg-orange-400" },
  AUTO_DENIED_TIMEOUT: { bg: "bg-red-950", text: "text-red-300", dot: "bg-red-500" },
  RESOLVED: { bg: "bg-emerald-950", text: "text-emerald-300", dot: "bg-emerald-400" },
};

function StateBadge({ state }: { state: string }) {
  const c = STATE_COLORS[state] ?? { bg: "bg-zinc-800", text: "text-zinc-400", dot: "bg-zinc-500" };
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-mono px-2 py-0.5 rounded ${c.bg} ${c.text}`}>
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {state.replace(/_/g, " ")}
    </span>
  );
}

function formatElapsed(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

function formatRemaining(seconds: number): string {
  if (seconds <= 0) return "Expired";
  return formatElapsed(Math.round(seconds));
}

function RiskBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.8 ? "bg-red-500" : score > 0 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`font-mono text-xs ${score >= 0.8 ? "text-red-400" : score > 0 ? "text-amber-400" : "text-emerald-400"}`}>
        {score.toFixed(2)}
      </span>
    </div>
  );
}

function CountCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className={`rounded border px-4 py-2 text-center ${color}`}>
      <div className="text-2xl font-mono font-bold">{count}</div>
      <div className="text-xs uppercase tracking-wider mt-1">{label}</div>
    </div>
  );
}

export function EscalationsClient() {
  const router = useRouter();
  const [data, setData] = useState<EscalationData | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch("/api/escalations");
      const json: EscalationData = await res.json();
      setData(json);
    } catch {
      setError("Failed to fetch escalations");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  async function handleAction(action: "approve" | "deny", escalation: Escalation) {
    if (!escalation.intent_event_id) return;
    setActionLoading(`${action}-${escalation.policy_event_id}`);
    setError(null);

    try {
      const body: Record<string, string> = {
        intent_event_id: escalation.intent_event_id,
        policy_event_id: escalation.policy_event_id,
      };
      if (action === "deny") {
        body.reason = "Denied via dashboard";
      }

      const resp = await fetch(`/api/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        const respData = await resp.json();
        setError(respData.detail ?? respData.error ?? `${action} failed`);
        return;
      }

      await fetchData();
      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setActionLoading(null);
    }
  }

  if (loading) {
    return (
      <div className="text-center py-12 text-zinc-500">Loading escalations...</div>
    );
  }

  if (!data) {
    return (
      <div className="text-center py-12 text-red-400">Failed to load escalations.</div>
    );
  }

  const { escalations, counts } = data;

  return (
    <div>
      <h1 className="text-lg font-bold mb-4 text-zinc-200">
        SLA Escalations
        <span className="ml-2 text-sm font-normal text-zinc-500">
          Pending human review with timeout tracking (auto-refreshes every 10s)
        </span>
      </h1>

      {error && (
        <div className="mb-4 text-sm text-red-400 bg-red-950/50 border border-red-800 rounded px-3 py-2">
          {error}
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <CountCard label="Pending Review" count={counts.pending_review} color="border-amber-800 bg-amber-950/30 text-amber-300" />
        <CountCard label="Human Required" count={counts.human_required} color="border-orange-800 bg-orange-950/30 text-orange-300" />
        <CountCard label="Auto-Denied" count={counts.auto_denied} color="border-red-800 bg-red-950/30 text-red-300" />
        <CountCard label="Resolved" count={counts.resolved} color="border-emerald-800 bg-emerald-950/30 text-emerald-300" />
      </div>

      <div className="overflow-x-auto rounded border border-zinc-800">
        <table className="w-full text-left">
          <thead className="bg-zinc-900 text-xs text-zinc-400 uppercase tracking-wider">
            <tr>
              <th className="px-3 py-2">State</th>
              <th className="px-3 py-2">Actor</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Escalated At</th>
              <th className="px-3 py-2">Elapsed</th>
              <th className="px-3 py-2">Initial (5m)</th>
              <th className="px-3 py-2">Deadline (1h)</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {escalations.length === 0 ? (
              <tr>
                <td colSpan={9} className="text-center py-12 text-zinc-500 text-sm">
                  No escalations found.
                </td>
              </tr>
            ) : (
              escalations.map((esc) => {
                const ts = new Date(esc.escalated_at).toISOString().replace("T", " ").slice(0, 23);
                const canAct = esc.state === "PENDING_REVIEW" || esc.state === "HUMAN_REQUIRED";
                const hasIds = esc.intent_event_id != null;
                const contentStr = String(esc.content ?? "");

                return (
                  <tr
                    key={esc.policy_event_id}
                    className="border-b border-zinc-800 hover:bg-zinc-900 transition-colors"
                  >
                    <td className="px-3 py-2 text-sm">
                      <StateBadge state={esc.state} />
                    </td>
                    <td className="px-3 py-2 text-sm font-mono text-xs">{esc.actor_id}</td>
                    <td className="px-3 py-2 text-sm">
                      <span className="font-mono text-xs text-zinc-300" title={contentStr}>
                        {contentStr.length > 40 ? contentStr.slice(0, 40) + "..." : contentStr || String(esc.action_type)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-sm">
                      <RiskBar score={esc.risk_score} />
                    </td>
                    <td className="px-3 py-2 text-sm font-mono text-xs text-zinc-400">{ts}</td>
                    <td className="px-3 py-2 text-sm font-mono text-xs text-zinc-400">
                      {formatElapsed(esc.elapsed_seconds)}
                    </td>
                    <td className="px-3 py-2 text-sm font-mono text-xs">
                      <span className={esc.initial_timeout_remaining <= 0 ? "text-red-400" : "text-amber-400"}>
                        {formatRemaining(esc.initial_timeout_remaining)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-sm font-mono text-xs">
                      <span className={esc.hard_deadline_remaining <= 0 ? "text-red-400" : "text-red-300"}>
                        {formatRemaining(esc.hard_deadline_remaining)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-sm">
                      {canAct && hasIds ? (
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => handleAction("approve", esc)}
                            disabled={actionLoading !== null}
                            className="text-xs font-mono px-2 py-1 rounded bg-emerald-800 hover:bg-emerald-700 text-emerald-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
                          >
                            {actionLoading === `approve-${esc.policy_event_id}` ? "..." : "Approve"}
                          </button>
                          <button
                            onClick={() => handleAction("deny", esc)}
                            disabled={actionLoading !== null}
                            className="text-xs font-mono px-2 py-1 rounded bg-red-800 hover:bg-red-700 text-red-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
                          >
                            {actionLoading === `deny-${esc.policy_event_id}` ? "..." : "Deny"}
                          </button>
                        </div>
                      ) : canAct && !hasIds ? (
                        <span className="text-xs font-mono text-zinc-600" title="Missing intent_event_id">No IDs</span>
                      ) : esc.state === "RESOLVED" ? (
                        <span className="text-xs font-mono text-zinc-600">Resolved</span>
                      ) : (
                        <span className="text-xs font-mono text-zinc-600">Timed out</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
