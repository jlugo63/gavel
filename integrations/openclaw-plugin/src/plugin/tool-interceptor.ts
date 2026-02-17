/**
 * Tool Interceptor — before_tool_call hook handler.
 *
 * On every tool call, extracts the tool name and arguments, maps them
 * to a governance action type, and POSTs to the governance gateway.
 * Returns { block: true, blockReason } to deny, or {} to allow.
 */

import type { GovernanceConfig } from "./config.js";
import type {
  BeforeToolCallEvent,
  BeforeToolCallResult,
  ProposalRequest,
  ProposalResponse,
  ToolContext,
} from "../types.js";

// ---------------------------------------------------------------------------
// Tool name → action_type mapping
// ---------------------------------------------------------------------------

const ACTION_MAP: Record<string, string> = {
  // Shell execution
  exec: "bash",
  bash: "bash",
  shell: "bash",
  execute_command: "bash",
  run_command: "bash",

  // File writes
  write: "file_write",
  file_write: "file_write",
  apply_patch: "file_write",
  edit: "file_write",
  create_file: "file_write",
  write_file: "file_write",

  // File reads
  read: "file_read",
  file_read: "file_read",
  read_file: "file_read",

  // Network / API calls
  web_fetch: "api_call",
  web_search: "api_call",
  fetch: "api_call",
  http_request: "api_call",
};

function mapToolToActionType(toolName: string): string {
  const normalized = toolName.toLowerCase().replace(/-/g, "_");
  return ACTION_MAP[normalized] ?? "unknown";
}

// ---------------------------------------------------------------------------
// Content extraction
// ---------------------------------------------------------------------------

function extractContent(actionType: string, params: Record<string, unknown>): string {
  // For file operations, the path is what the policy engine needs to check
  if (actionType === "file_write" || actionType === "file_read") {
    const pathCandidates = ["path", "file_path", "filePath", "filename"];
    for (const key of pathCandidates) {
      if (typeof params[key] === "string") {
        return params[key] as string;
      }
    }
  }

  // For shell/api operations, extract the command or URL
  const candidates = ["command", "cmd", "input", "content", "url", "query", "path", "file_path"];
  for (const key of candidates) {
    if (typeof params[key] === "string") {
      return params[key] as string;
    }
  }
  // Fallback: serialize all params
  return JSON.stringify(params);
}

// ---------------------------------------------------------------------------
// Gateway call
// ---------------------------------------------------------------------------

async function callGateway(
  config: GovernanceConfig,
  actionType: string,
  content: string
): Promise<ProposalResponse> {
  const body: ProposalRequest = {
    actor_id: config.actorId,
    action_type: actionType,
    content,
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const resp = await fetch(`${config.gatewayUrl}/propose`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    // 200 = APPROVED, 403 = DENIED, 202 = ESCALATED — all return valid JSON
    if (resp.status === 200 || resp.status === 403 || resp.status === 202) {
      const data = (await resp.json()) as ProposalResponse;
      return data;
    }

    // Any other status is unexpected
    const text = await resp.text();
    throw new Error(`Gateway returned ${resp.status}: ${text.slice(0, 100)}`);
  } finally {
    clearTimeout(timeout);
  }
}

// ---------------------------------------------------------------------------
// Hook factory
// ---------------------------------------------------------------------------

export function createToolCallHook(
  config: GovernanceConfig
): (event: BeforeToolCallEvent, ctx: ToolContext) => Promise<BeforeToolCallResult | void> {
  return async (event: BeforeToolCallEvent, _ctx: ToolContext): Promise<BeforeToolCallResult | void> => {
    const actionType = mapToolToActionType(event.toolName);
    const content = extractContent(actionType, event.params);

    let response: ProposalResponse;
    try {
      response = await callGateway(config, actionType, content);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
      console.error(`[governance] Gateway call error: ${errMsg}`);
      // Gateway unreachable or timeout
      if (config.failOpen) {
        console.warn("[governance] Gateway unreachable. FAIL_OPEN=true — allowing action.");
        return {};
      }
      return {
        block: true,
        blockReason: `Governance gateway unavailable (${errMsg}). Failing closed.`,
      };
    }

    switch (response.decision) {
      case "APPROVED":
        return {};

      case "DENIED": {
        const violations = response.violations
          .map((v) => `[${v.rule}] ${v.description}`)
          .join("; ");
        return {
          block: true,
          blockReason: `DENIED: ${violations}`,
        };
      }

      case "ESCALATED":
        return {
          block: true,
          blockReason:
            `ESCALATED: Requires human approval. Risk score: ${response.risk_score}. ` +
            `Approve at dashboard or via POST /approve with ` +
            `intent_event_id: ${response.intent_event_id}, ` +
            `policy_event_id: ${response.policy_event_id}`,
        };

      default:
        return {
          block: true,
          blockReason: `Unknown governance decision: ${response.decision}. Failing closed.`,
        };
    }
  };
}
