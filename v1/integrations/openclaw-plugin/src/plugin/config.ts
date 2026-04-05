/**
 * Configuration — reads from environment variables.
 *
 * OpenClaw injects env vars declared in the plugin's config.
 * These can also be set manually or via openclaw.json.
 */

export interface GovernanceConfig {
  gatewayUrl: string;
  actorId: string;
  apiKey: string;
  failOpen: boolean;
  timeoutMs: number;
}

export function loadConfig(): GovernanceConfig {
  const failOpenRaw = (process.env.GOVERNANCE_FAIL_OPEN ?? "false").toLowerCase();

  return {
    gatewayUrl: (process.env.GOVERNANCE_GATEWAY_URL ?? "http://localhost:8000").replace(/\/+$/, ""),
    actorId: process.env.GOVERNANCE_ACTOR_ID ?? "agent:openclaw",
    apiKey: process.env.HUMAN_API_KEY ?? "",
    failOpen: failOpenRaw === "true" || failOpenRaw === "1",
    timeoutMs: 5_000,
  };
}
