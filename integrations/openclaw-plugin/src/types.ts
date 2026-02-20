/**
 * TypeScript definitions for the OpenClaw plugin API and governance types.
 */

// ---------------------------------------------------------------------------
// OpenClaw Plugin API (provided by OpenClaw at registration time)
// ---------------------------------------------------------------------------

export interface OpenClawPluginApi {
  on?(hookName: string, handler: (...args: unknown[]) => void): void;
  registerTool?(spec: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    execute: (...args: unknown[]) => Promise<unknown>;
  }): void;
}

// ---------------------------------------------------------------------------
// Hook event / result shapes
// ---------------------------------------------------------------------------

export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

export interface ToolContext {
  agentId?: string;
  sessionKey?: string;
  toolName: string;
}

export interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

// ---------------------------------------------------------------------------
// Governance Gateway types
// ---------------------------------------------------------------------------

export interface ProposalRequest {
  actor_id: string;
  action_type: string;
  content: string;
}

export interface ProposalResponse {
  decision: "APPROVED" | "DENIED" | "ESCALATED";
  risk_score: number;
  intent_event_id: string;
  policy_event_id: string;
  violations: Array<{ rule: string; description: string }>;
  message?: string;
}

export interface HealthResponse {
  status: string;
  service: string;
}
