import { verifyChain } from "@/lib/db";

export async function IntegrityHeader() {
  const chain = await verifyChain();

  return (
    <div
      className={`px-4 py-2 text-sm font-mono flex items-center justify-between ${
        chain.chain_valid
          ? "bg-emerald-950 border-b border-emerald-800 text-emerald-300"
          : "bg-red-950 border-b border-red-700 text-red-300 animate-pulse"
      }`}
    >
      <div className="flex items-center gap-2">
        <span
          className={`inline-block w-2 h-2 rounded-full ${
            chain.chain_valid ? "bg-emerald-400" : "bg-red-500"
          }`}
        />
        {chain.chain_valid ? (
          <span>System Integrity: SECURE</span>
        ) : (
          <span>CRITICAL: TAMPER DETECTED</span>
        )}
      </div>
      <div className="flex items-center gap-4 text-xs">
        <span>{chain.total_events} events in chain</span>
        {!chain.chain_valid && chain.break_at && (
          <span className="text-red-400 font-bold">
            Break at: {chain.break_at}
          </span>
        )}
      </div>
    </div>
  );
}
