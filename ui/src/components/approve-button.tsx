"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export function ApproveButton({
  intentEventId,
  policyEventId,
  isApproved,
  isDenied,
}: {
  intentEventId: string;
  policyEventId: string;
  isApproved: boolean;
  isDenied: boolean;
}) {
  const router = useRouter();
  const [loading, setLoading] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (isApproved) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400" />
        APPROVED
      </span>
    );
  }

  if (isDenied) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded bg-red-950 text-red-300">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-400" />
        DENIED
      </span>
    );
  }

  async function handleAction(action: "approve" | "deny") {
    setLoading(action);
    setError(null);

    try {
      const resp = await fetch(`/api/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          intent_event_id: intentEventId,
          policy_event_id: policyEventId,
        }),
      });

      if (!resp.ok) {
        const data = await resp.json();
        setError(data.detail ?? data.error ?? `${action} failed`);
        return;
      }

      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="flex items-center gap-1.5">
      <button
        onClick={() => handleAction("approve")}
        disabled={loading !== null}
        className="text-xs font-mono px-2 py-1 rounded bg-emerald-800 hover:bg-emerald-700 text-emerald-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
      >
        {loading === "approve" ? "..." : "Approve"}
      </button>
      <button
        onClick={() => handleAction("deny")}
        disabled={loading !== null}
        className="text-xs font-mono px-2 py-1 rounded bg-red-800 hover:bg-red-700 text-red-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
      >
        {loading === "deny" ? "..." : "Deny"}
      </button>
      {error && (
        <span className="text-xs text-red-400">{error}</span>
      )}
    </div>
  );
}
