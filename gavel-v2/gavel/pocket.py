"""
Gavel Pocket Agent — hybrid local governance agent (POC).

Runs as a persistent local process that:
  1. Monitors the Gavel gateway for escalated governance chains
  2. Uses Qwen (via Ollama) for fast local evaluation of governed actions
  3. Escalates to Claude (via Anthropic API) for complex/high-risk decisions
  4. Prompts the operator for final approval when needed
  5. Auto-resolves low-risk governed chains that pass Qwen evaluation

Architecture:
  ┌──────────────────────────────────────────────────────┐
  │                  Gavel Gateway (:8100)               │
  │   /gate → govern → chain created → SLA timer         │
  └────────┬──────────────────────────────────┬──────────┘
           │ poll /liveness                    │ /approve
  ┌────────▼──────────────────────────────────▼──────────┐
  │               Pocket Agent (this module)              │
  │                                                       │
  │  ┌─────────┐    risk < 0.7    ┌───────────────────┐  │
  │  │  Poller  │───────────────▶│  Qwen (Ollama)     │  │
  │  │         │                  │  Fast local eval   │  │
  │  └─────────┘    risk >= 0.7   └───────┬───────────┘  │
  │       │                               │              │
  │       │         ┌─────────────────────▼───────┐      │
  │       └────────▶│  Claude (Anthropic API)     │      │
  │                 │  Deep reasoning for complex  │      │
  │                 └─────────────┬───────────────┘      │
  │                               │                      │
  │                    ┌──────────▼──────────┐           │
  │                    │  Operator Prompt    │           │
  │                    │  (terminal / auto)  │           │
  │                    └────────────────────┘            │
  └──────────────────────────────────────────────────────┘

Usage:
  # Run with operator prompts (default)
  python -m gavel.pocket

  # Run in auto-approve mode for Qwen-approved chains (demo/testing)
  python -m gavel.pocket --auto

  # Custom gateway URL
  python -m gavel.pocket --gateway http://localhost:8100

  # Use Claude for all evaluations (no Ollama required)
  python -m gavel.pocket --claude-only
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from typing import Any, Optional

import httpx

log = logging.getLogger("gavel.pocket")

# ── Configuration ──────────────────────────────────────────────

GATEWAY_URL = "http://localhost:8100"
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "qwen2.5-coder:14b"

POLL_INTERVAL = 4  # seconds between liveness polls
QWEN_RISK_CEILING = 0.7  # above this, escalate to Claude
CLAUDE_MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a Gavel governance evaluator — part of a constitutional
governance framework for autonomous AI agents targeting EU AI Act compliance.

Your job: evaluate a governed action (tool call) from an AI agent and recommend
APPROVE or DENY with a rationale.

Rules:
- Read-only operations (Read, Glob, Grep, WebSearch) are almost always safe
- File modifications (Edit, Write) are safe if the path is in the project directory
- Bash commands need scrutiny: check for destructive patterns, network access, privilege escalation
- Any action touching credentials, secrets, production, or PII should be DENIED
- When unsure, DENY — the system degrades toward safety (Constitutional Article IV.2)

Respond with EXACTLY this JSON format:
{"decision": "APPROVE" or "DENY", "confidence": 0.0-1.0, "rationale": "brief reason"}
"""


# ── Ollama (Qwen) Client ──────────────────────────────────────

class OllamaClient:
    """Lightweight client for Ollama's chat API."""

    def __init__(self, base_url: str = OLLAMA_URL, model: str = OLLAMA_MODEL):
        self.base_url = base_url
        self.model = model
        self._client = httpx.Client(timeout=120)
        self.available = False

    def check(self) -> bool:
        """Check if Ollama is running and the model is available."""
        try:
            resp = self._client.get(f"{self.base_url}/api/tags")
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                # Exact match first, then prefix match
                if self.model in models:
                    self.available = True
                    return True
                # Try without tag, or match any model containing our base name
                base = self.model.split(":")[0]
                for m in models:
                    if m == self.model or m.startswith(base):
                        self.model = m  # use the actual available model name
                        self.available = True
                        return True
        except (httpx.HTTPError, KeyError, ValueError):
            pass  # Ollama unreachable or unexpected response shape
        self.available = False
        return False

    def evaluate(self, chain_context: str) -> dict:
        """Ask Qwen to evaluate a governed action. Returns parsed decision."""
        try:
            resp = self._client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": chain_context},
                    ],
                    "stream": False,
                    "format": "json",
                },
            )
            content = resp.json()["message"]["content"]
            return json.loads(content)
        except Exception as e:
            log.error("Qwen evaluation failed: %s", e)
            return {"decision": "DENY", "confidence": 0.0, "rationale": f"Qwen error: {e}"}


# ── Claude Client ──────────────────────────────────────────────

class ClaudeClient:
    """Lightweight client for the Anthropic Messages API."""

    def __init__(self, model: str = CLAUDE_MODEL):
        self.model = model
        self._client = httpx.Client(timeout=60)
        self.available = False
        self.api_key: Optional[str] = None

    def check(self) -> bool:
        """Check if ANTHROPIC_API_KEY is set."""
        import os
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        self.available = bool(self.api_key)
        return self.available

    def evaluate(self, chain_context: str) -> dict:
        """Ask Claude to evaluate a governed action."""
        if not self.api_key:
            return {"decision": "DENY", "confidence": 0.0, "rationale": "No API key"}
        try:
            resp = self._client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 256,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": chain_context}],
                },
            )
            content = resp.json()["content"][0]["text"]
            # Try to parse JSON from the response
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(content[start:end])
            return {"decision": "DENY", "confidence": 0.5, "rationale": content[:200]}
        except Exception as e:
            log.error("Claude evaluation failed: %s", e)
            return {"decision": "DENY", "confidence": 0.0, "rationale": f"Claude error: {e}"}


# ── Gateway Client ─────────────────────────────────────────────

class GavelClient:
    """Client for the Gavel governance gateway."""

    def __init__(self, base_url: str = GATEWAY_URL):
        self.base_url = base_url
        self._client = httpx.Client(timeout=10)

    def register(self, agent_id: str, display_name: str, capabilities: list[str]) -> dict:
        resp = self._client.post(
            f"{self.base_url}/agents/register",
            json={
                "agent_id": agent_id,
                "display_name": display_name,
                "agent_type": "pocket-agent",
                "capabilities": capabilities,
            },
        )
        return resp.json()

    def heartbeat(self, agent_id: str, activity: str) -> None:
        try:
            self._client.post(
                f"{self.base_url}/agents/{agent_id}/heartbeat",
                json={"activity": activity},
            )
        except httpx.HTTPError:
            pass  # Best-effort heartbeat — gateway may be temporarily unreachable

    def liveness(self) -> dict:
        resp = self._client.get(f"{self.base_url}/liveness")
        return resp.json()

    def chain(self, chain_id: str) -> dict:
        resp = self._client.get(f"{self.base_url}/chain/{chain_id}")
        if resp.status_code == 404:
            return {}
        return resp.json()

    def approve(self, chain_id: str, rationale: str, actor: str = "pocket-agent:qwen") -> dict:
        resp = self._client.post(
            f"{self.base_url}/approve",
            json={
                "chain_id": chain_id,
                "actor_id": actor,
                "role": "approver",
                "decision": "APPROVED",
                "rationale": rationale,
            },
        )
        return resp.json()

    def deny(self, chain_id: str, rationale: str, actor: str = "pocket-agent:qwen") -> dict:
        resp = self._client.post(
            f"{self.base_url}/approve",
            json={
                "chain_id": chain_id,
                "actor_id": actor,
                "role": "approver",
                "decision": "DENIED",
                "rationale": rationale,
            },
        )
        return resp.json()

    def status(self) -> dict:
        resp = self._client.get(f"{self.base_url}/status")
        return resp.json()


# ── Chain Context Builder ──────────────────────────────────────

def build_chain_context(chain_data: dict) -> str:
    """Build a human-readable evaluation prompt from chain data."""
    events = chain_data.get("events", [])
    intent = next((e for e in events if e["type"] == "INBOUND_INTENT"), None)
    if not intent:
        return json.dumps(chain_data, indent=2)[:2000]

    payload = intent.get("payload", {})
    tool = payload.get("tool_name", "unknown")
    tool_input = payload.get("tool_input", {})
    risk = payload.get("risk", "?")
    agent = intent.get("actor", "unknown")

    lines = [
        f"GOVERNED ACTION — requires your evaluation",
        f"",
        f"Chain ID:  {chain_data.get('chain_id', '?')}",
        f"Agent:     {agent}",
        f"Tool:      {tool}",
        f"Risk:      {risk}",
        f"Status:    {chain_data.get('status', '?')}",
        f"Integrity: {chain_data.get('integrity', '?')}",
        f"",
        f"Tool Input:",
        f"{json.dumps(tool_input, indent=2)[:800]}",
    ]

    if chain_data.get("roster"):
        lines.append(f"\nChain Roster: {json.dumps(chain_data['roster'])}")

    return "\n".join(lines)


# ── Pocket Agent Loop ──────────────────────────────────────────

class PocketAgent:
    """The hybrid governance agent that monitors and evaluates chains."""

    def __init__(
        self,
        gateway_url: str = GATEWAY_URL,
        auto_approve: bool = False,
        claude_only: bool = False,
    ):
        self.gavel = GavelClient(gateway_url)
        self.ollama = OllamaClient()
        self.claude = ClaudeClient()
        self.auto_approve = auto_approve
        self.claude_only = claude_only
        self.processed: set[str] = set()  # chain_ids we've already handled
        self.agent_id = "pocket-agent:governance-evaluator"

    def startup(self):
        """Check available backends and report status."""
        print("\n╔══════════════════════════════════════════════════╗")
        print("║         GAVEL POCKET AGENT — POC v0.1           ║")
        print("║    Hybrid Qwen/Claude governance evaluator       ║")
        print("╚══════════════════════════════════════════════════╝\n")

        try:
            status = self.gavel.status()
            print(f"  Gateway:  CONNECTED ({status['agents']} agents, {status['chains']} chains)")
        except Exception as e:
            print(f"  Gateway:  OFFLINE — {e}")
            print("  Start the gateway first: uvicorn gavel.gateway:app --port 8100")
            sys.exit(1)

        backends = []
        if not self.claude_only:
            backends.append("Ollama/Qwen")
        backends.append("Claude")
        backends.append("OperatorPrompt")
        reg = self.gavel.register(
            agent_id=self.agent_id,
            display_name="Pocket Agent (Governance Evaluator)",
            capabilities=backends,
        )
        print(f"  Registered: {self.agent_id} — DID: {reg.get('did', '?')[:24]}...")

        if not self.claude_only:
            if self.ollama.check():
                print(f"  Ollama:   AVAILABLE (model: {self.ollama.model})")
            else:
                print(f"  Ollama:   NOT AVAILABLE — will use Claude for all evaluations")
                self.claude_only = True

        if self.claude.check():
            print(f"  Claude:   AVAILABLE (model: {self.claude.model})")
        else:
            print(f"  Claude:   NO API KEY — set ANTHROPIC_API_KEY for escalation")
            if self.claude_only:
                print("  WARNING: No Qwen and no Claude — will prompt operator for all decisions")

        mode = "AUTO-APPROVE" if self.auto_approve else "OPERATOR PROMPT"
        print(f"\n  Mode:     {mode}")
        print(f"  Polling:  every {POLL_INTERVAL}s")
        print(f"  Qwen ceiling: risk < {QWEN_RISK_CEILING}")
        print()
        print("  Watching for escalated governance chains...\n")

    def run(self):
        """Main loop — poll for escalated chains and evaluate them."""
        self.startup()

        while True:
            try:
                self._tick()
            except KeyboardInterrupt:
                print("\n\nPocket agent stopped.")
                break
            except Exception as e:
                log.error("Tick error: %s", e)
            time.sleep(POLL_INTERVAL)

    def _tick(self):
        """Single poll cycle."""
        # Heartbeat — proves this agent is alive on the dashboard
        pending = len([c for c in self.processed])
        self.gavel.heartbeat(self.agent_id, f"Monitoring — {len(self.processed)} chains resolved")

        liveness = self.gavel.liveness()
        chains = liveness.get("chains", {})

        for chain_id in chains:
            if chain_id in self.processed:
                continue

            chain_data = self.gavel.chain(chain_id)
            if not chain_data or chain_data.get("status") != "ESCALATED":
                continue

            self._evaluate_chain(chain_id, chain_data)

    def _evaluate_chain(self, chain_id: str, chain_data: dict):
        """Evaluate a single escalated chain using the hybrid approach."""
        context = build_chain_context(chain_data)

        events = chain_data.get("events", [])
        intent = next((e for e in events if e["type"] == "INBOUND_INTENT"), None)
        risk = intent["payload"].get("risk", 0.5) if intent else 0.5
        tool = intent["payload"].get("tool_name", "?") if intent else "?"

        print(f"  ┌─ Chain {chain_id}")
        print(f"  │  Tool: {tool}  Risk: {risk}")

        # Route to Qwen or Claude based on risk
        if not self.claude_only and risk < QWEN_RISK_CEILING and self.ollama.available:
            print(f"  │  Evaluator: Qwen ({self.ollama.model})")
            result = self.ollama.evaluate(context)
            actor = self.agent_id
        elif self.claude.available:
            print(f"  │  Evaluator: Claude ({self.claude.model})")
            result = self.claude.evaluate(context)
            actor = self.agent_id
        else:
            # No LLM available — go straight to operator
            result = None
            actor = "human:operator"

        if result:
            decision = result.get("decision", "DENY").upper()
            confidence = result.get("confidence", 0.0)
            rationale = result.get("rationale", "No rationale")
            print(f"  │  Decision: {decision} (confidence: {confidence:.0%})")
            print(f"  │  Rationale: {rationale[:100]}")

            if self.auto_approve and decision == "APPROVE" and confidence >= 0.8:
                # Auto-approve high-confidence approvals
                self.gavel.approve(chain_id, f"[auto] {rationale}", actor)
                print(f"  └─ AUTO-APPROVED\n")
                self.processed.add(chain_id)
                return

            if decision == "DENY" and confidence >= 0.9:
                # Auto-deny high-confidence denials
                self.gavel.deny(chain_id, f"[auto] {rationale}", actor)
                print(f"  └─ AUTO-DENIED\n")
                self.processed.add(chain_id)
                return

        # Fall through to operator prompt
        print(f"  │")
        print(f"  │  Context:")
        for line in context.split("\n")[:12]:
            print(f"  │    {line}")
        print(f"  │")

        # In non-interactive mode (piped stdin), skip instead of blocking
        if not sys.stdin.isatty():
            print(f"  └─ Non-interactive — skipping (run interactively to approve)\n")
            return

        while True:
            choice = input(f"  └─ [A]pprove / [D]eny / [S]kip? ").strip().lower()
            if choice in ("a", "approve"):
                reason = input("     Rationale (Enter for default): ").strip()
                reason = reason or "Operator approved via pocket agent"
                self.gavel.approve(chain_id, reason, "human:operator")
                print(f"     APPROVED\n")
                break
            elif choice in ("d", "deny"):
                reason = input("     Rationale: ").strip() or "Operator denied"
                self.gavel.deny(chain_id, reason, "human:operator")
                print(f"     DENIED\n")
                break
            elif choice in ("s", "skip"):
                print(f"     Skipped (will re-check next cycle)\n")
                return
            else:
                print(f"     Invalid choice. Use A/D/S.")

        self.processed.add(chain_id)


# ── CLI Entry Point ────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Gavel Pocket Agent — hybrid Qwen/Claude governance evaluator",
    )
    parser.add_argument(
        "--gateway", default=GATEWAY_URL,
        help=f"Gavel gateway URL (default: {GATEWAY_URL})",
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Auto-approve/deny high-confidence decisions (no operator prompt)",
    )
    parser.add_argument(
        "--claude-only", action="store_true",
        help="Skip Ollama/Qwen, use Claude API for all evaluations",
    )
    parser.add_argument(
        "--model", default=OLLAMA_MODEL,
        help=f"Ollama model name (default: {OLLAMA_MODEL})",
    )
    parser.add_argument(
        "--ollama-url", default=OLLAMA_URL,
        help=f"Ollama API URL (default: {OLLAMA_URL})",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    agent = PocketAgent(
        gateway_url=args.gateway,
        auto_approve=args.auto,
        claude_only=args.claude_only,
    )
    if args.model != OLLAMA_MODEL:
        agent.ollama.model = args.model
    if args.ollama_url != OLLAMA_URL:
        agent.ollama.base_url = args.ollama_url

    agent.run()


if __name__ == "__main__":
    main()
