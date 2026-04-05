export const dynamic = "force-dynamic";

interface EvidenceEvent {
  id: string;
  actor_id: string;
  action_type: string;
  intent_payload: Record<string, unknown>;
  created_at: string;
}

function ExitCodeBadge({ code }: { code: number }) {
  return (
    <span
      className={`font-mono text-xs px-1.5 py-0.5 rounded ${
        code === 0
          ? "bg-emerald-950 text-emerald-300"
          : "bg-red-950 text-red-300"
      }`}
    >
      {code}
    </span>
  );
}

function EvidenceRow({ event }: { event: EvidenceEvent }) {
  const payload = event.intent_payload;
  const blastBox = (payload.blast_box as Record<string, unknown>) ?? {};
  const environment = (payload.environment as Record<string, unknown>) ?? {};

  const command = (payload.command as string) ?? "";
  const exitCode = Number(blastBox.exit_code ?? payload.exit_code ?? -1);
  const durationMs = Number(blastBox.duration_ms ?? payload.duration_ms ?? payload.duration ?? 0);
  const evidenceHash = (payload.evidence_hash as string) ?? "";
  const stdout = (blastBox.stdout as string) ?? (payload.stdout as string) ?? "";
  const stderr = (blastBox.stderr as string) ?? (payload.stderr as string) ?? "";
  const timedOut = blastBox.timed_out ?? payload.timed_out ?? false;
  const workspaceDiff =
    (blastBox.workspace_diff as Record<string, unknown>) ??
    (payload.workspace_diff as Record<string, unknown>) ??
    null;
  const ts = new Date(event.created_at).toISOString().replace("T", " ").slice(0, 23);

  return (
    <details className="group border-b border-zinc-800">
      <summary className="flex items-center cursor-pointer hover:bg-zinc-900 transition-colors px-3 py-2 text-sm">
        <span className="w-44 shrink-0 font-mono text-xs text-zinc-400">{ts}</span>
        <span className="w-36 shrink-0 font-mono text-xs truncate">{event.actor_id}</span>
        <span className="w-64 shrink-0 font-mono text-xs text-zinc-300 truncate" title={command}>
          {command.length > 60 ? command.slice(0, 60) + "..." : command}
        </span>
        <span className="w-20 shrink-0"><ExitCodeBadge code={exitCode} /></span>
        <span className="w-20 shrink-0 font-mono text-xs text-zinc-400">{durationMs}ms</span>
        <span className="w-36 shrink-0 font-mono text-xs text-zinc-500" title={evidenceHash}>
          {evidenceHash.slice(0, 16)}
        </span>
        <span className="ml-auto text-zinc-600 text-xs group-open:rotate-180 transition-transform">
          &#9660;
        </span>
      </summary>
      <div className="px-4 py-3 bg-zinc-900/50 space-y-3">
        <div>
          <div className="text-xs text-zinc-500 mb-1">Full Command</div>
          <pre className="text-xs font-mono text-zinc-300 bg-zinc-950 rounded p-2 overflow-x-auto">{command}</pre>
        </div>

        {stdout && (
          <div>
            <div className="text-xs text-zinc-500 mb-1">stdout</div>
            <pre className="text-xs font-mono text-zinc-300 bg-zinc-950 rounded p-2 overflow-x-auto max-h-48">{stdout}</pre>
          </div>
        )}

        {stderr && (
          <div>
            <div className="text-xs text-zinc-500 mb-1">stderr</div>
            <pre className="text-xs font-mono text-red-300 bg-zinc-950 rounded p-2 overflow-x-auto max-h-48">{stderr}</pre>
          </div>
        )}

        {workspaceDiff && (
          <div>
            <div className="text-xs text-zinc-500 mb-1">Workspace Diff</div>
            <div className="flex gap-3 text-xs font-mono">
              {(workspaceDiff.added as string[] | undefined)?.length ? (
                <span className="text-emerald-400">+{(workspaceDiff.added as string[]).length} added</span>
              ) : null}
              {(workspaceDiff.modified as string[] | undefined)?.length ? (
                <span className="text-amber-400">~{(workspaceDiff.modified as string[]).length} modified</span>
              ) : null}
              {(workspaceDiff.deleted as string[] | undefined)?.length ? (
                <span className="text-red-400">-{(workspaceDiff.deleted as string[]).length} deleted</span>
              ) : null}
            </div>
          </div>
        )}

        {timedOut && (
          <div className="text-xs font-mono text-red-400 bg-red-950/50 rounded px-2 py-1">
            Execution timed out
          </div>
        )}

        <div>
          <div className="text-xs text-zinc-500 mb-1">Sandbox Proof</div>
          <div className="flex flex-wrap gap-3 text-xs font-mono text-zinc-400">
            <span>network: {String(environment.network_mode ?? "n/a")}</span>
            <span>image: {String(environment.image ?? "n/a")}</span>
            <span>mem: {String(environment.memory_limit ?? "n/a")}</span>
            <span>cpu: {String(environment.cpu_limit ?? "n/a")}</span>
            {environment.timeout_seconds != null && (
              <span>timeout: {String(environment.timeout_seconds)}s</span>
            )}
          </div>
        </div>

        <div>
          <div className="text-xs text-zinc-500 mb-1">Evidence Hash</div>
          <span className="font-mono text-xs text-purple-400 break-all">{evidenceHash}</span>
        </div>
      </div>
    </details>
  );
}

export default async function EvidencePage() {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL ?? "http://localhost:3000";
  const res = await fetch(`${baseUrl}/api/evidence`, { cache: "no-store" });
  const events: EvidenceEvent[] = await res.json();

  return (
    <div>
      <h1 className="text-lg font-bold mb-4 text-zinc-200">
        Evidence Packets
        <span className="ml-2 text-sm font-normal text-zinc-500">
          Sandbox execution evidence from the Blast Box
        </span>
      </h1>

      <div className="overflow-x-auto rounded border border-zinc-800">
        {/* Header */}
        <div className="flex items-center bg-zinc-900 text-xs text-zinc-400 uppercase tracking-wider px-3 py-2">
          <span className="w-44 shrink-0">Timestamp</span>
          <span className="w-36 shrink-0">Actor</span>
          <span className="w-64 shrink-0">Command</span>
          <span className="w-20 shrink-0">Exit</span>
          <span className="w-20 shrink-0">Duration</span>
          <span className="w-36 shrink-0">Evidence Hash</span>
          <span className="ml-auto w-8"></span>
        </div>

        {events.length === 0 ? (
          <div className="text-center py-12 text-zinc-500 text-sm">
            No evidence packets recorded yet.
          </div>
        ) : (
          events.map((event) => <EvidenceRow key={event.id} event={event} />)
        )}
      </div>
    </div>
  );
}
