/**
 * Gavel Governance Plugin — Entry Point
 *
 * Registers a before_tool_call hook that submits every agent action
 * to the Gavel governance gateway for policy evaluation. The agent
 * cannot execute without gateway approval.
 *
 * IMPORTANT: register() must be SYNCHRONOUS — OpenClaw does not
 * await async plugin registration.
 */

import type { OpenClawPluginApi } from "../types.js";
import { loadConfig } from "./config.js";
import { createToolCallHook } from "./tool-interceptor.js";

function tryOn(
  api: OpenClawPluginApi,
  hookName: string,
  handler: (...args: unknown[]) => void,
  label: string
): boolean {
  try {
    if (!api.on) {
      console.warn(`[gavel] ${label}: api.on not available`);
      return false;
    }
    api.on(hookName, handler);
    return true;
  } catch (err) {
    console.warn(`[gavel] ${label}: api.on('${hookName}') threw`, err);
    return false;
  }
}

async function checkHealth(gatewayUrl: string): Promise<void> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3_000);
    const resp = await fetch(`${gatewayUrl}/health`, { signal: controller.signal });
    clearTimeout(timeout);

    if (resp.ok) {
      console.log(`[gavel] Gateway health check passed.`);
    } else {
      console.warn(`[gavel] Gateway returned ${resp.status}. Hook will fail closed on calls.`);
    }
  } catch {
    console.warn(`[gavel] Gateway unreachable at ${gatewayUrl}. Hook will fail closed on calls.`);
  }
}

export default {
  id: "gavel-governance",
  name: "Gavel Governance",

  register(api: OpenClawPluginApi): void {
    const config = loadConfig();

    console.log(`[gavel] Gavel Governance Plugin active — gateway: ${config.gatewayUrl}`);

    // Register the before_tool_call hook
    const toolHook = createToolCallHook(config);
    const registered = tryOn(
      api,
      "before_tool_call",
      toolHook as (...args: unknown[]) => void,
      "before_tool_call"
    );

    if (registered) {
      console.log("[gavel] before_tool_call hook registered. All tool calls require gateway approval.");
    } else {
      console.error("[gavel] FAILED to register before_tool_call hook. Plugin is NOT enforcing governance.");
    }

    // Fire-and-forget health check (register is synchronous, health check is async)
    void checkHealth(config.gatewayUrl);
  },
};
