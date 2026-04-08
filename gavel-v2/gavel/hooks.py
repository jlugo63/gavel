"""
Claude Code Hook Handler — risk classification and action governance.

Maps Claude Code tool calls to risk scores. Low-risk tools are auto-logged.
High-risk tools create governance chains that require approval.
"""

from __future__ import annotations

import re
from typing import Any

# Risk classification for Claude Code tools
TOOL_RISK: dict[str, float] = {
    # Low risk — read-only operations
    "Read": 0.1,
    "Glob": 0.1,
    "Grep": 0.1,
    "WebSearch": 0.1,
    "WebFetch": 0.15,
    # Medium risk — file modifications
    "Edit": 0.4,
    "Write": 0.4,
    "NotebookEdit": 0.4,
    # High risk — execution
    "Bash": 0.6,
    "Agent": 0.3,
}

# Bash command patterns that escalate risk
HIGH_RISK_PATTERNS = [
    r"rm\s+-rf",
    r"git\s+push",
    r"git\s+reset\s+--hard",
    r"docker\s+(push|rm|kill)",
    r"kubectl\s+(delete|apply|scale)",
    r"drop\s+table",
    r"truncate\s+",
    r"format\s+c:",
    r"shutdown",
    r"curl.*-X\s+(DELETE|PUT|POST)",
    r"npm\s+publish",
    r"pip\s+install(?!.*-e)",
]


def classify_risk(tool_name: str, args: dict[str, Any] | None = None) -> float:
    """Classify the risk of a Claude Code tool call.

    Returns a risk score from 0.0 (safe) to 1.0 (critical).
    """
    base = TOOL_RISK.get(tool_name, 0.3)

    if tool_name == "Bash" and args:
        command = args.get("command", "")
        for pattern in HIGH_RISK_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return min(1.0, base + 0.3)

    if tool_name == "Write" and args:
        path = args.get("file_path", "")
        if any(s in path.lower() for s in [".env", "credentials", "secret", "password", ".key"]):
            return 0.9

    return base


def should_govern(risk: float, threshold: float = 0.5) -> bool:
    """Whether this action should create a governance chain vs auto-log."""
    return risk >= threshold


def format_action_log(
    agent_id: str,
    tool_name: str,
    phase: str,
    risk: float,
    args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Format an action for dashboard logging."""
    return {
        "agent_id": agent_id,
        "tool": tool_name,
        "phase": phase,
        "risk": round(risk, 2),
        "governed": should_govern(risk),
        "args_summary": _summarize_args(tool_name, args),
    }


def build_risk_factors(tool_name: str, tool_input: dict) -> dict:
    """Bridge Claude Code tool calls to the RiskFactors structure used by TierPolicy.

    Maps tool metadata into a dict consumable by the governance tier system.
    """
    action_type_base = TOOL_RISK.get(tool_name, 0.3)

    # Flatten relevant string values from tool_input for indicator scanning
    scan_values = " ".join(str(v) for v in tool_input.values()).lower()

    # Production indicators
    touches_production = any(
        kw in scan_values for kw in ("prod", "production", "deploy")
    )

    # Financial indicators
    touches_financial = any(
        kw in scan_values for kw in ("payment", "billing", "invoice", "stripe")
    )

    # PII indicators
    touches_pii = any(
        kw in scan_values for kw in ("user", "customer", "email", "ssn", "password")
    )

    # Scope breadth — how wide the blast radius is
    scope_breadth_map: dict[str, float] = {
        "Read": 0.1,
        "Glob": 0.1,
        "Grep": 0.1,
        "Write": 0.1,
        "Edit": 0.1,
        "NotebookEdit": 0.1,
        "WebSearch": 0.2,
        "WebFetch": 0.2,
        "Bash": 0.5,
        "Agent": 0.6,
    }
    scope_breadth = scope_breadth_map.get(tool_name, 0.3)

    return {
        "action_type_base": action_type_base,
        "touches_production": touches_production,
        "touches_financial": touches_financial,
        "touches_pii": touches_pii,
        "scope_breadth": scope_breadth,
        "precedent_count": 0,
    }


def extract_scope_from_tool_input(tool_name: str, tool_input: dict) -> dict:
    """Auto-generate scope declarations from Claude Code tool inputs.

    Returns a dict with allow_paths, allow_commands, and allow_network.
    """
    if tool_name in ("Read", "Glob", "Grep"):
        path = tool_input.get("file_path") or tool_input.get("path", ".")
        return {
            "allow_paths": [path],
            "allow_commands": [],
            "allow_network": False,
        }

    if tool_name in ("Write", "Edit"):
        return {
            "allow_paths": [tool_input["file_path"]],
            "allow_commands": [],
            "allow_network": False,
        }

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        # Simple heuristic: extract tokens that look like file paths
        tokens = command.split()
        paths = [
            t for t in tokens
            if t.startswith("/") or t.startswith("./") or ("/" in t and not t.startswith("-"))
        ]
        allow_network = bool(re.search(r"\b(curl|wget|fetch)\b", command))
        return {
            "allow_paths": paths if paths else ["."],
            "allow_commands": [command],
            "allow_network": allow_network,
        }

    if tool_name in ("WebFetch", "WebSearch"):
        return {
            "allow_paths": [],
            "allow_commands": [],
            "allow_network": True,
        }

    if tool_name == "Agent":
        return {
            "allow_paths": ["."],
            "allow_commands": [],
            "allow_network": False,
        }

    # Default — broad scope
    return {
        "allow_paths": ["."],
        "allow_commands": [],
        "allow_network": False,
    }


def _summarize_args(tool_name: str, args: dict[str, Any] | None) -> str:
    """Create a safe summary of tool args (no secrets)."""
    if not args:
        return ""
    if tool_name == "Bash":
        cmd = args.get("command", "")
        return cmd[:100] + ("..." if len(cmd) > 100 else "")
    if tool_name in ("Read", "Write", "Edit"):
        return args.get("file_path", "")[:100]
    if tool_name in ("Glob", "Grep"):
        return args.get("pattern", "")[:80]
    return ""
