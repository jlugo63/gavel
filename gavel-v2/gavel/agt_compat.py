"""
AGT Compatibility Layer — graceful fallback when Microsoft's Agent Governance
Toolkit is not installed.

Tries to import the real `agent_os`, `agentmesh`, and `agent_control_plane`
packages. If any are missing, provides stub classes that replicate the
interface used throughout Gavel so the PoC runs standalone.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Callable, List, Optional


# ═══════════════════════════════════════════════════════════════
# agent_os — PolicyEngine
# ═══════════════════════════════════════════════════════════════

try:
    from agent_os import PolicyEngine as AgentOSEngine  # type: ignore[import-untyped]
    _AGENT_OS_AVAILABLE = True
except ImportError:
    _AGENT_OS_AVAILABLE = False

    class AgentOSEngine:  # type: ignore[no-redef]
        """Stub PolicyEngine that mirrors the real AgentOSEngine interface.

        Supports:
          - .add_custom_rule(rule)  — registers a PolicyRule
          - .custom_rules           — list of registered rules
          - .validate_request(req)  — runs validators, returns (allowed, reason)
        """

        def __init__(self) -> None:
            self.custom_rules: list[Any] = []

        def add_custom_rule(self, rule: Any) -> None:
            self.custom_rules.append(rule)

        def validate_request(self, request: Any) -> tuple[bool, str]:
            """Evaluate all custom rules against the request.

            Returns (True, "") if all pass, or (False, reason) on first failure.
            """
            for rule in self.custom_rules:
                # Check action type match
                if hasattr(rule, "action_types") and hasattr(request, "action_type"):
                    if request.action_type not in rule.action_types:
                        continue
                try:
                    if not rule.validator(request):
                        return False, f"Denied by rule: {rule.name}"
                except Exception as exc:
                    return False, f"Rule {rule.rule_id} error: {exc}"
            return True, ""


# ═══════════════════════════════════════════════════════════════
# agentmesh — AgentMeshClient
# ═══════════════════════════════════════════════════════════════

try:
    from agentmesh import AgentMeshClient  # type: ignore[import-untyped]
    _AGENTMESH_AVAILABLE = True
except ImportError:
    _AGENTMESH_AVAILABLE = False

    class _StubDID:
        """Minimal DID identity stub."""

        def __init__(self, agent_id: str) -> None:
            # Deterministic DID from agent_id
            h = hashlib.sha256(agent_id.encode()).hexdigest()[:16]
            self.did = f"did:gavel:stub:{h}"

        def __str__(self) -> str:
            return self.did

    class _StubTrustScore:
        """Minimal trust score stub."""

        def __init__(self) -> None:
            self.total_score: int = 500
            self.tier: str = "BASELINE"

    class _StubIdentity:
        """Wraps a DID for .identity access."""

        def __init__(self, agent_id: str) -> None:
            self.did = _StubDID(agent_id)

    class AgentMeshClient:  # type: ignore[no-redef]
        """Stub AgentMeshClient that mirrors the real interface.

        Supports:
          - AgentMeshClient(agent_id=...)
          - .identity.did
          - .trust_score.total_score / .trust_score.tier
          - .agent_did
        """

        def __init__(self, agent_id: str = "") -> None:
            self._agent_id = agent_id
            self.identity = _StubIdentity(agent_id)
            self.trust_score = _StubTrustScore()

        @property
        def agent_did(self) -> str:
            return str(self.identity.did)


# ═══════════════════════════════════════════════════════════════
# agent_control_plane.agent_kernel — PolicyRule, ActionType, etc.
# ═══════════════════════════════════════════════════════════════

try:
    from agent_control_plane.agent_kernel import (  # type: ignore[import-untyped]
        ActionType,
        AgentContext,
        ExecutionRequest,
        PermissionLevel,
        PolicyRule,
    )
    _AGENT_KERNEL_AVAILABLE = True
except ImportError:
    _AGENT_KERNEL_AVAILABLE = False

    class ActionType(str, Enum):  # type: ignore[no-redef]
        """Stub ActionType enum — covers the values used in Gavel."""
        FILE_READ = "file_read"
        FILE_WRITE = "file_write"
        CODE_EXECUTION = "code_execution"
        API_CALL = "api_call"
        WORKFLOW_TRIGGER = "workflow_trigger"
        DATA_ACCESS = "data_access"

    class PermissionLevel(str, Enum):  # type: ignore[no-redef]
        NONE = "none"
        READ = "read"
        WRITE = "write"
        ADMIN = "admin"

    class AgentContext:  # type: ignore[no-redef]
        """Stub agent context for policy evaluation."""

        def __init__(
            self,
            agent_id: str = "",
            session_id: str = "",
            created_at: Any = None,
            permissions: dict | None = None,
            metadata: dict | None = None,
        ) -> None:
            self.agent_id = agent_id
            self.session_id = session_id
            self.created_at = created_at
            self.permissions = permissions or {}
            self.metadata = metadata or {}

    class ExecutionRequest:  # type: ignore[no-redef]
        """Stub execution request for policy evaluation."""

        def __init__(
            self,
            request_id: str = "",
            agent_context: AgentContext | None = None,
            action_type: ActionType | None = None,
            parameters: dict | None = None,
            timestamp: Any = None,
            risk_score: float = 0.0,
        ) -> None:
            self.request_id = request_id
            self.agent_context = agent_context or AgentContext()
            self.action_type = action_type
            self.parameters = parameters or {}
            self.timestamp = timestamp
            self.risk_score = risk_score

    class PolicyRule:  # type: ignore[no-redef]
        """Stub policy rule with validator callback."""

        def __init__(
            self,
            rule_id: str = "",
            name: str = "",
            description: str = "",
            action_types: list | None = None,
            validator: Callable | None = None,
            priority: int = 0,
        ) -> None:
            self.rule_id = rule_id
            self.name = name
            self.description = description
            self.action_types = action_types or []
            self.validator = validator or (lambda req: True)
            self.priority = priority
