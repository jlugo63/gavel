"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export function ApproveButton({
  intentEventId,
  policyEventId,
  isApproved,
}: {
  intentEventId: string;
  policyEventId: string;
  isApproved: boolean;
}) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (isApproved) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400" />
        APPROVED
      </span>
    );
  }

  async function handleApprove() {
    setLoading(true);
    setError(null);

    try {
      const resp = await fetch("/api/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          intent_event_id: intentEventId,
          policy_event_id: policyEventId,
        }),
      });

      if (!resp.ok) {
        const data = await resp.json();
        setError(data.detail ?? data.error ?? "Approval failed");
        return;
      }

      // Refresh the page to show updated data from the Audit Spine
      router.refresh();
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={handleApprove}
        disabled={loading}
        className="text-xs font-mono px-2 py-1 rounded bg-amber-800 hover:bg-amber-700 text-amber-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors cursor-pointer"
      >
        {loading ? "Approving..." : "Approve"}
      </button>
      {error && (
        <span className="text-xs text-red-400">{error}</span>
      )}
    </div>
  );
}
