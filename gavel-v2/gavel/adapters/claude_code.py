"""
Gavel Claude Code Adapter — governance enforcement for Claude Code sessions.

This module is referenced from Claude Code's settings.json as a hook that
runs on every tool use.  It forces Gavel enrollment before any tool
execution is allowed, validates tool scope, and reports actions back to
the Gavel gateway for audit.

settings.json integration::

    {
      "hooks": {
        "PreToolUse": [
          {
            "type": "command",
            "command": "python -m gavel.adapters.claude_code pre_tool_use"
          }
        ],
        "PostToolUse": [
          {
            "type": "command",
            "command": "python -m gavel.adapters.claude_code post_tool_use"
          }
        ]
      }
    }

Protocol:
    The hook communicates with Claude Code via JSON on stdout.
    - ``{"status": "approved"}`` — tool execution is allowed
    - ``{"status": "blocked", "reason": "..."}`` — tool execution is denied
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gavel.hooks import classify_risk, should_govern, format_action_log

logger = logging.getLogger("gavel.adapters.claude_code")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GAVEL_API_BASE = os.environ.get("GAVEL_API_BASE", "http://localhost:8100")
ENROLL_ENDPOINT = f"{GAVEL_API_BASE}/agents/enroll"
REPORT_ENDPOINT_TEMPLATE = GAVEL_API_BASE + "/agents/{agent_id}/report"

TOKEN_CACHE_DIR = Path(os.environ.get(
    "GAVEL_TOKEN_CACHE_DIR",
    Path.home() / ".gavel" / "sessions",
))

REGISTRATION_TIMEOUT_SECONDS = int(
    os.environ.get("GAVEL_REGISTRATION_TIMEOUT", "10"),
)
REGISTRATION_MAX_RETRIES = int(
    os.environ.get("GAVEL_REGISTRATION_RETRIES", "3"),
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class RegistrationError(Exception):
    """Raised when Gavel enrollment fails."""


class ToolBlockedError(Exception):
    """Raised when a tool invocation is blocked by governance."""

    def __init__(self, tool_name: str, reason: str) -> None:
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"Tool '{tool_name}' blocked: {reason}")


# ---------------------------------------------------------------------------
# Session token cache
# ---------------------------------------------------------------------------

class SessionTokenCache:
    """File-backed token cache scoped to the current Claude Code session.

    Tokens are stored as JSON files in ``~/.gavel/sessions/``, keyed by a
    hash of the session identifier.  This avoids re-enrolling on every tool
    invocation within the same session.
    """

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._cache_dir = TOKEN_CACHE_DIR
        self._cache_file = self._cache_dir / f"{self._session_hash}.json"

    @property
    def _session_hash(self) -> str:
        return hashlib.sha256(
            self._session_id.encode("utf-8"),
        ).hexdigest()[:24]

    def get(self) -> dict[str, Any] | None:
        """Retrieve cached token data, or ``None`` if absent / corrupt."""
        if not self._cache_file.exists():
            return None
        try:
            data = json.loads(self._cache_file.read_text(encoding="utf-8"))
            if "agent_id" not in data:
                return None
            return data
        except (json.JSONDecodeError, OSError):
            return None

    def store(self, token_data: dict[str, Any]) -> None:
        """Persist enrolment response to the session cache."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        token_data["cached_at"] = datetime.now(timezone.utc).isoformat()
        token_data["session_id"] = self._session_id
        self._cache_file.write_text(
            json.dumps(token_data, indent=2, default=str),
            encoding="utf-8",
        )

    def invalidate(self) -> None:
        """Remove the cached token."""
        if self._cache_file.exists():
            self._cache_file.unlink()

    def exists(self) -> bool:
        return self._cache_file.exists()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_session_id() -> str:
    """Derive a stable session identifier from the environment.

    Uses ``CLAUDE_CODE_SESSION_ID`` when set by Claude Code, otherwise
    falls back to a hash of process ancestry and working directory.
    """
    explicit = os.environ.get("CLAUDE_CODE_SESSION_ID")
    if explicit:
        return explicit

    components = [
        str(os.getpid()),
        str(os.getppid()),
        os.getcwd(),
        os.environ.get("TERM_SESSION_ID", ""),
    ]
    return hashlib.sha256("|".join(components).encode()).hexdigest()[:32]


def _detect_admin_mode() -> bool:
    """Check whether admin mode should be requested during enrollment.

    Admin mode is only honoured outside production environments.
    """
    admin_flag = os.environ.get("GAVEL_ADMIN_MODE", "false").lower().strip()
    gavel_env = os.environ.get("GAVEL_ENV", "development").lower().strip()

    if admin_flag != "true":
        return False
    if gavel_env == "production":
        return False
    return True


def _get_machine_fingerprint() -> str:
    """Generate a non-reversible machine fingerprint for enrollment."""
    import platform
    import socket
    import uuid as uuid_mod

    components = [
        socket.gethostname(),
        platform.node(),
        str(uuid_mod.getnode()),
    ]
    return hashlib.sha256("|".join(components).encode("utf-8")).hexdigest()


def _build_enrollment_payload(
    operator: str | None = None,
) -> dict[str, Any]:
    """Build the enrollment application payload for ``POST /agents/enroll``.

    The structure matches :class:`gavel.enrollment.EnrollmentApplication`.
    """
    if operator is None:
        operator = os.environ.get(
            "GAVEL_OPERATOR",
            os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        )

    is_admin = _detect_admin_mode()
    session_id = _derive_session_id()
    agent_id = f"claude-code-{hashlib.sha256(session_id.encode()).hexdigest()[:12]}"

    tools = ["Read", "Glob", "Grep", "Edit", "Write", "Bash", "Agent",
             "WebFetch", "WebSearch", "NotebookEdit"]
    if is_admin:
        tools.append("*")

    return {
        "agent_id": agent_id,
        "display_name": f"Claude Code ({operator})",
        "agent_type": "claude_code",
        "owner": operator,
        "owner_contact": os.environ.get("GAVEL_OWNER_CONTACT", ""),
        "budget_tokens": int(os.environ.get("GAVEL_BUDGET_TOKENS", "500000")),
        "budget_usd": float(os.environ.get("GAVEL_BUDGET_USD", "5.0")),
        "purpose": {
            "summary": "Claude Code IDE agent performing coding tasks under Gavel governance",
            "operational_scope": "software development",
            "expected_lifetime": "session",
            "risk_tier": "standard",
        },
        "capabilities": {
            "tools": tools,
            "max_concurrent_chains": 1,
            "can_spawn_subagents": True,
            "network_access": is_admin,
            "file_system_access": True,
            "execution_access": True,
        },
        "resources": {
            "allowed_paths": [os.getcwd()],
            "allowed_hosts": ["localhost"],
            "allowed_env_vars": [],
            "max_file_size_mb": 10.0,
        },
        "boundaries": {
            "allowed_actions": ["*"] if is_admin else ["read", "write", "execute"],
            "blocked_patterns": [],
            "max_actions_per_minute": 120 if is_admin else 60,
            "max_risk_threshold": 1.0 if is_admin else 0.7,
        },
        "fallback": {
            "on_gateway_unreachable": "degrade",
            "on_budget_exceeded": "stop",
            "on_sla_timeout": "deny",
            "graceful_shutdown": True,
        },
        # Extra metadata (not part of EnrollmentApplication but useful)
        "_meta": {
            "admin_mode": is_admin,
            "machine_id": _get_machine_fingerprint(),
            "platform_version": os.environ.get("CLAUDE_CODE_VERSION", "unknown"),
            "registered_at": datetime.now(timezone.utc).isoformat(),
        },
    }


# ---------------------------------------------------------------------------
# Enrollment client (with retry + backoff)
# ---------------------------------------------------------------------------

def enroll_with_gavel(operator: str | None = None) -> dict[str, Any]:
    """Enroll this Claude Code session with ``POST /agents/enroll``.

    Retries transient failures with exponential backoff.  Client errors
    (4xx except 429) are not retried.

    Returns:
        Enrollment response dict from the gateway.

    Raises:
        RegistrationError: If enrollment fails after all retries.
    """
    payload = _build_enrollment_payload(operator)
    payload_bytes = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        ENROLL_ENDPOINT,
        data=payload_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    last_error: Exception | None = None
    for attempt in range(1, REGISTRATION_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(
                request, timeout=REGISTRATION_TIMEOUT_SECONDS,
            ) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))
                logger.info(
                    "Gavel enrollment successful: agent_id=%s attempt=%d",
                    response_data.get("agent_id", "unknown"),
                    attempt,
                )
                # Carry forward metadata the cache needs
                response_data.setdefault("agent_id", payload["agent_id"])
                response_data.setdefault(
                    "admin_mode", payload["_meta"]["admin_mode"],
                )
                return response_data

        except urllib.error.HTTPError as exc:
            last_error = exc
            body = exc.read().decode("utf-8", errors="replace")
            logger.warning(
                "Enrollment HTTP error: status=%d attempt=%d body=%s",
                exc.code, attempt, body[:200],
            )
            if 400 <= exc.code < 500 and exc.code != 429:
                raise RegistrationError(
                    f"Enrollment rejected (HTTP {exc.code}): {body[:200]}",
                ) from exc

        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            logger.warning(
                "Enrollment connection error: attempt=%d error=%s",
                attempt, exc,
            )

        if attempt < REGISTRATION_MAX_RETRIES:
            backoff = min(2 ** attempt, 8)
            time.sleep(backoff)

    raise RegistrationError(
        f"Failed to enroll with Gavel after {REGISTRATION_MAX_RETRIES} "
        f"attempts: {last_error}",
    )


def _report_action(
    agent_id: str,
    tool_name: str,
    tool_input: dict[str, Any],
    success: bool = True,
    chain_id: str | None = None,
) -> None:
    """Best-effort ``POST /agents/{id}/report`` after tool execution."""
    url = REPORT_ENDPOINT_TEMPLATE.format(agent_id=agent_id)
    payload = {
        "tool": tool_name,
        "tool_input_summary": _summarize_input(tool_name, tool_input),
        "success": success,
        "chain_id": chain_id,
    }
    payload_bytes = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=payload_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            resp.read()
    except Exception as exc:
        logger.warning("Failed to report action to Gavel: %s", exc)


def _summarize_input(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Create a safe summary of tool input (no secrets)."""
    if not tool_input:
        return ""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        return cmd[:100] + ("..." if len(cmd) > 100 else "")
    if tool_name in ("Read", "Write", "Edit"):
        return tool_input.get("file_path", "")[:100]
    if tool_name in ("Glob", "Grep"):
        return tool_input.get("pattern", "")[:80]
    return ""


# ---------------------------------------------------------------------------
# ClaudeCodeHook
# ---------------------------------------------------------------------------

class ClaudeCodeHook:
    """Main hook class invoked by Claude Code on tool-use events.

    Lifecycle:
        1. On first ``PreToolUse``, enroll with Gavel and cache the token.
        2. On subsequent calls, validate the cached enrollment.
        3. On ``PostToolUse``, report the tool execution for audit.
        4. If enrollment fails, block all tool execution.
    """

    def __init__(self) -> None:
        self._session_id = _derive_session_id()
        self._cache = SessionTokenCache(self._session_id)
        self._enrollment: dict[str, Any] | None = None

    # -- internal helpers ---------------------------------------------------

    def _ensure_enrolled(self) -> dict[str, Any]:
        """Return cached enrollment or perform a fresh enroll.

        Raises:
            RegistrationError: If enrollment fails.
        """
        if self._enrollment is not None:
            return self._enrollment

        cached = self._cache.get()
        if cached is not None:
            self._enrollment = cached
            return cached

        response = enroll_with_gavel()
        self._cache.store(response)
        self._enrollment = response
        return response

    # -- public hook entry points -------------------------------------------

    def pre_tool_use(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> dict[str, Any]:
        """``PreToolUse`` hook — called before every tool invocation.

        Ensures the session is enrolled and the tool falls within the
        granted scope.  Also runs risk classification from
        :mod:`gavel.hooks`.
        """
        try:
            enrollment = self._ensure_enrolled()
        except RegistrationError as exc:
            logger.error("Enrollment failed, blocking tool use: %s", exc)
            return {
                "status": "blocked",
                "reason": f"Gavel enrollment failed: {exc}",
                "tool": tool_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        agent_id = enrollment.get("agent_id", "unknown")
        is_admin = enrollment.get("admin_mode", False)

        # -- Risk classification (from gavel.hooks) -------------------------
        risk = classify_risk(tool_name, tool_input)
        governed = should_govern(risk)

        # -- Scope validation -----------------------------------------------
        if not is_admin:
            # Check allowed actions from enrollment boundaries
            allowed = enrollment.get("boundaries", {}).get(
                "allowed_actions", [],
            )
            if "*" not in allowed and tool_name not in allowed:
                # Map tool names to action categories for broader matching
                tool_action_map: dict[str, str] = {
                    "Read": "read", "Glob": "read", "Grep": "read",
                    "Edit": "write", "Write": "write", "NotebookEdit": "write",
                    "Bash": "execute", "Agent": "execute",
                    "WebFetch": "read", "WebSearch": "read",
                }
                action_category = tool_action_map.get(tool_name)
                if action_category not in allowed:
                    return {
                        "status": "blocked",
                        "reason": (
                            f"Tool '{tool_name}' (action: {action_category}) "
                            f"is outside the granted scope. "
                            f"Allowed actions: {allowed}"
                        ),
                        "tool": tool_name,
                        "risk": round(risk, 2),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

            # Check max risk threshold from enrollment boundaries
            max_risk = enrollment.get("boundaries", {}).get(
                "max_risk_threshold", 0.7,
            )
            if risk > max_risk:
                return {
                    "status": "blocked",
                    "reason": (
                        f"Tool '{tool_name}' risk ({risk:.2f}) exceeds "
                        f"enrolled threshold ({max_risk:.2f})"
                    ),
                    "tool": tool_name,
                    "risk": round(risk, 2),
                    "governed": governed,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

        # -- Approved -------------------------------------------------------
        log_entry = format_action_log(agent_id, tool_name, "pre", risk, tool_input)
        logger.debug("Pre-tool approved: %s", log_entry)

        return {
            "status": "approved",
            "tool": tool_name,
            "agent_id": agent_id,
            "risk": round(risk, 2),
            "governed": governed,
            "admin_mode": is_admin,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def post_tool_use(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_output: str | None = None,
    ) -> dict[str, Any]:
        """``PostToolUse`` hook — called after every tool invocation.

        Reports the tool execution to the Gavel gateway for audit.
        This hook never blocks — it only logs.
        """
        enrollment = self._enrollment or {}
        agent_id = enrollment.get("agent_id", "unregistered")

        risk = classify_risk(tool_name, tool_input)
        log_entry = format_action_log(agent_id, tool_name, "post", risk, tool_input)

        # Best-effort report to gateway
        reported = False
        if agent_id != "unregistered":
            try:
                _report_action(
                    agent_id=agent_id,
                    tool_name=tool_name,
                    tool_input=tool_input,
                    success=True,
                )
                reported = True
            except Exception as exc:
                logger.warning("Failed to report action: %s", exc)

        return {
            "status": "logged",
            "tool": tool_name,
            "agent_id": agent_id,
            "risk": round(risk, 2),
            "governed": should_govern(risk),
            "reported": reported,
            "session_id": self._session_id,
            "input_keys": list(tool_input.keys()) if tool_input else [],
            "has_output": tool_output is not None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def invalidate_session(self) -> None:
        """Clear cached enrollment, forcing re-enrollment on next use."""
        self._cache.invalidate()
        self._enrollment = None
        logger.info("Session invalidated — will re-enroll on next tool use")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _read_hook_input() -> dict[str, Any]:
    """Read hook input from stdin.

    Claude Code sends a JSON object on stdin with tool invocation details::

        {
            "tool_name": "Bash",
            "tool_input": {"command": "ls"}
        }
    """
    try:
        raw = sys.stdin.read()
        if raw.strip():
            return json.loads(raw)
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def main() -> None:
    """CLI entry point for the Claude Code hook.

    Usage::

        python -m gavel.adapters.claude_code pre_tool_use
        python -m gavel.adapters.claude_code post_tool_use
    """
    logging.basicConfig(
        level=os.environ.get("GAVEL_LOG_LEVEL", "WARNING").upper(),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if len(sys.argv) < 2:
        print(json.dumps({
            "status": "error",
            "reason": "Usage: python -m gavel.adapters.claude_code "
                      "<pre_tool_use|post_tool_use>",
        }))
        sys.exit(1)

    command = sys.argv[1].lower().strip()
    hook = ClaudeCodeHook()
    hook_input = _read_hook_input()

    tool_name = hook_input.get("tool_name", "unknown")
    tool_input = hook_input.get("tool_input", {})

    if command == "pre_tool_use":
        result = hook.pre_tool_use(tool_name, tool_input)
    elif command == "post_tool_use":
        tool_output = hook_input.get("tool_output")
        result = hook.post_tool_use(tool_name, tool_input, tool_output)
    else:
        result = {
            "status": "error",
            "reason": f"Unknown command: {command}. "
                      "Use 'pre_tool_use' or 'post_tool_use'.",
        }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
