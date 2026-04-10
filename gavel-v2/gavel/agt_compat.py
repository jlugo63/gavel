"""
AGT Compatibility Layer — real Microsoft AGT packages first, stub fallbacks
only when packages aren't installed.

Tries to import the real `agent_os`, `agentmesh`, and `agent_control_plane`
packages (from agent-os-kernel and agentmesh-platform on PyPI). If any are
missing, provides stub classes that replicate the interface so Gavel runs
standalone.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════
# agent_os — PolicyEngine, StatelessKernel, etc.
# ═══════════════════════════════════════════════════════════════

try:
    from agent_os import PolicyEngine as AgentOSEngine  # type: ignore[import-untyped]
    from agent_os import StatelessKernel  # type: ignore[import-untyped]
    from agent_os import ExecutionContext  # type: ignore[import-untyped]
    from agent_os import KernelSpace  # type: ignore[import-untyped]
    from agent_os import MCPSecurityScanner  # type: ignore[import-untyped]
    from agent_os import PromptInjectionDetector  # type: ignore[import-untyped]
    from agent_os import FlightRecorder  # type: ignore[import-untyped]
    _AGENT_OS_AVAILABLE = True
except ImportError:
    _AGENT_OS_AVAILABLE = False

    class AgentOSEngine:  # type: ignore[no-redef]
        """Stub PolicyEngine that mirrors the real agent_os.PolicyEngine.

        Supports:
          - .add_custom_rule(rule)  — registers a PolicyRule
          - .custom_rules           — list of registered rules
          - .validate_request(req)  — runs validators, returns (allowed, reason)
        """

        def __init__(self) -> None:
            self.custom_rules: list[Any] = []

        def add_custom_rule(self, rule: Any) -> None:
            self.custom_rules.append(rule)

        def validate_request(self, request: Any) -> Tuple[bool, str]:
            """Evaluate all custom rules against the request.

            Returns (True, "") if all pass, or (False, reason) on first failure.
            """
            for rule in self.custom_rules:
                if hasattr(rule, "action_types") and hasattr(request, "action_type"):
                    if request.action_type not in rule.action_types:
                        continue
                try:
                    if not rule.validator(request):
                        return False, f"Denied by rule: {rule.name}"
                except Exception as exc:
                    return False, f"Rule {rule.rule_id} error: {exc}"
            return True, ""

    class StatelessKernel:  # type: ignore[no-redef]
        """Stub StatelessKernel — sub-millisecond policy evaluation."""

        def __init__(self, **kwargs: Any) -> None:
            self._kwargs = kwargs

        def execute(self, **kwargs: Any) -> Any:
            return {"status": "stub", "allowed": True}

    class ExecutionContext:  # type: ignore[no-redef]
        """Stub ExecutionContext — agent identity + policy binding."""

        def __init__(self, agent_id: str = "", policy_engine: Any = None, **kwargs: Any) -> None:
            self.agent_id = agent_id
            self.policy_engine = policy_engine

    class KernelSpace:  # type: ignore[no-redef]
        """Stub KernelSpace — full kernel with signals, VFS, protection rings."""

        def __init__(self, **kwargs: Any) -> None:
            self._kwargs = kwargs

    class MCPSecurityScanner:  # type: ignore[no-redef]
        """Stub MCPSecurityScanner — MCP tool poisoning detection."""

        def __init__(self, **kwargs: Any) -> None:
            self._kwargs = kwargs

        def scan(self, tool_definition: Any) -> Tuple[bool, str]:
            return True, "stub: no scan performed"

    class PromptInjectionDetector:  # type: ignore[no-redef]
        """Stub PromptInjectionDetector — prompt injection scanning."""

        def __init__(self, **kwargs: Any) -> None:
            self._kwargs = kwargs

        def detect(self, text: str) -> Tuple[bool, float]:
            return False, 0.0

    class FlightRecorder:  # type: ignore[no-redef]
        """Stub FlightRecorder — audit logging."""

        def __init__(self, **kwargs: Any) -> None:
            self._records: list[dict[str, Any]] = []

        def record(self, event: str, **kwargs: Any) -> None:
            self._records.append({"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), **kwargs})

        def export(self) -> list[dict[str, Any]]:
            return list(self._records)


# ═══════════════════════════════════════════════════════════════
# agentmesh — AgentMeshClient, TrustScore, AuditLog, etc.
# ═══════════════════════════════════════════════════════════════

try:
    from agentmesh import AgentMeshClient  # type: ignore[import-untyped]
    from agentmesh import TrustScore  # type: ignore[import-untyped]
    from agentmesh import AuditChain, AuditEntry, AuditLog  # type: ignore[import-untyped]
    from agentmesh import ComplianceEngine as MeshComplianceEngine  # type: ignore[import-untyped]
    from agentmesh import ComplianceFramework, ComplianceReport  # type: ignore[import-untyped]
    from agentmesh import CapabilityGrant, CapabilityRegistry, CapabilityScope  # type: ignore[import-untyped]
    from agentmesh import RiskScorer, RiskScore  # type: ignore[import-untyped]
    _AGENTMESH_AVAILABLE = True
except ImportError:
    _AGENTMESH_AVAILABLE = False

    class TrustScore:  # type: ignore[no-redef]
        """Stub TrustScore matching the real Pydantic model."""

        def __init__(self, total_score: int = 500, tier: str = "BASELINE") -> None:
            self.total_score = total_score
            self.tier = tier

        def update(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)

        def meets_threshold(self, threshold: int = 400) -> bool:
            return self.total_score >= threshold

    class AuditEntry:  # type: ignore[no-redef]
        """Stub AuditEntry."""

        def __init__(self, action: str = "", agent_id: str = "", **kwargs: Any) -> None:
            self.action = action
            self.agent_id = agent_id
            self.timestamp = datetime.now(timezone.utc).isoformat()
            self.metadata = kwargs

    class AuditLog:  # type: ignore[no-redef]
        """Stub AuditLog with log/verify/export."""

        def __init__(self) -> None:
            self._entries: list[AuditEntry] = []

        def log(self, entry: Any = None, **kwargs: Any) -> None:
            if entry is not None:
                self._entries.append(entry)
            else:
                self._entries.append(AuditEntry(**kwargs))

        def verify_integrity(self) -> bool:
            return True

        def export(self) -> list[Any]:
            return list(self._entries)

    class AuditChain:  # type: ignore[no-redef]
        """Stub AuditChain."""

        def __init__(self) -> None:
            self._chain: list[Any] = []

        def append(self, entry: Any) -> None:
            self._chain.append(entry)

    class RiskScore:  # type: ignore[no-redef]
        """Stub RiskScore."""

        def __init__(self, score: float = 0.0, category: str = "LOW", **kwargs: Any) -> None:
            self.score = score
            self.category = category

    class RiskScorer:  # type: ignore[no-redef]
        """Stub RiskScorer."""

        def __init__(self, **kwargs: Any) -> None:
            pass

        def score(self, **kwargs: Any) -> RiskScore:
            return RiskScore()

    class ComplianceFramework:  # type: ignore[no-redef]
        """Stub ComplianceFramework."""

        def __init__(self, name: str = "", **kwargs: Any) -> None:
            self.name = name

    class ComplianceReport:  # type: ignore[no-redef]
        """Stub ComplianceReport."""

        def __init__(self, **kwargs: Any) -> None:
            self.compliant = True
            self.findings: list[str] = []

    class MeshComplianceEngine:  # type: ignore[no-redef]
        """Stub agentmesh ComplianceEngine."""

        def __init__(self, **kwargs: Any) -> None:
            self._frameworks: list[Any] = []

        def add_framework(self, framework: Any) -> None:
            self._frameworks.append(framework)

        def evaluate(self, **kwargs: Any) -> ComplianceReport:
            return ComplianceReport()

    class CapabilityScope:  # type: ignore[no-redef]
        """Stub CapabilityScope."""

        def __init__(self, scope: str = "*", **kwargs: Any) -> None:
            self.scope = scope

    class CapabilityGrant:  # type: ignore[no-redef]
        """Stub CapabilityGrant."""

        def __init__(self, capability: str = "", scope: Any = None, **kwargs: Any) -> None:
            self.capability = capability
            self.scope = scope or CapabilityScope()

    class CapabilityRegistry:  # type: ignore[no-redef]
        """Stub CapabilityRegistry."""

        def __init__(self) -> None:
            self._grants: list[CapabilityGrant] = []

        def grant(self, cap: CapabilityGrant) -> None:
            self._grants.append(cap)

        def check(self, capability: str) -> bool:
            return any(g.capability == capability for g in self._grants)

    class _StubDID:
        """Minimal DID identity stub using Ed25519-style hash."""

        def __init__(self, agent_id: str) -> None:
            h = hashlib.md5(agent_id.encode()).hexdigest()
            self.did = f"did:mesh:{h}"

        def __str__(self) -> str:
            return self.did

    class _StubIdentity:
        """Wraps a DID for .identity access."""

        def __init__(self, agent_id: str) -> None:
            self._did = _StubDID(agent_id)
            self.did = self._did.did
            self.name = agent_id
            self.public_key = f"stub-ed25519-{hashlib.sha256(agent_id.encode()).hexdigest()[:16]}"
            self.status = "active"

    class AgentMeshClient:  # type: ignore[no-redef]
        """Stub AgentMeshClient matching the real agentmesh API.

        Supports:
          - AgentMeshClient(agent_id=...)
          - .agent_did        — DID string like did:mesh:...
          - .identity          — .did, .name, .public_key, .status
          - .trust_score       — TrustScore with .total_score, .tier, .update(), .meets_threshold()
          - .audit_log         — AuditLog with .log(), .verify_integrity(), .export()
          - .policy_engine     — PolicyEngine
        """

        def __init__(self, agent_id: str = "") -> None:
            self._agent_id = agent_id
            self.identity = _StubIdentity(agent_id)
            self.trust_score = TrustScore()
            self.audit_log = AuditLog()
            self.policy_engine = AgentOSEngine()

        @property
        def agent_did(self) -> str:
            return self.identity.did


# ═══════════════════════════════════════════════════════════════
# agent_control_plane — PolicyRule, ActionType, ExecutionRequest, etc.
# ═══════════════════════════════════════════════════════════════

try:
    from agent_control_plane.agent_kernel import (  # type: ignore[import-untyped]
        ActionType,
        AgentContext,
        ExecutionRequest,
        PermissionLevel,
        PolicyRule,
    )
    from agent_control_plane import ComplianceEngine  # type: ignore[import-untyped]
    from agent_control_plane import GovernanceLayer  # type: ignore[import-untyped]
    _AGENT_KERNEL_AVAILABLE = True
except ImportError:
    _AGENT_KERNEL_AVAILABLE = False

    class ActionType(str, Enum):  # type: ignore[no-redef]
        """Stub ActionType enum matching agent_control_plane values."""
        CODE_EXECUTION = "code_execution"
        FILE_READ = "file_read"
        FILE_WRITE = "file_write"
        API_CALL = "api_call"
        DATABASE_QUERY = "database_query"
        DATABASE_WRITE = "database_write"
        WORKFLOW_TRIGGER = "workflow_trigger"

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
            permissions: Optional[dict] = None,
            metadata: Optional[dict] = None,
        ) -> None:
            self.agent_id = agent_id
            self.session_id = session_id
            self.created_at = created_at
            self.permissions = permissions or {}
            self.metadata = metadata or {}

    class ExecutionRequest:  # type: ignore[no-redef]
        """Stub execution request matching agent_control_plane signature."""

        def __init__(
            self,
            request_id: str = "",
            agent_context: Optional[AgentContext] = None,
            action_type: Optional[ActionType] = None,
            parameters: Optional[dict] = None,
            timestamp: Any = None,
            status: str = "pending",
            risk_score: float = 0.0,
        ) -> None:
            self.request_id = request_id
            self.agent_context = agent_context or AgentContext()
            self.action_type = action_type
            self.parameters = parameters or {}
            self.timestamp = timestamp
            self.status = status
            self.risk_score = risk_score

    class PolicyRule:  # type: ignore[no-redef]
        """Stub policy rule with validator callback."""

        def __init__(
            self,
            rule_id: str = "",
            name: str = "",
            description: str = "",
            action_types: Optional[list] = None,
            validator: Optional[Callable] = None,
            priority: int = 0,
        ) -> None:
            self.rule_id = rule_id
            self.name = name
            self.description = description
            self.action_types = action_types or []
            self.validator = validator or (lambda req: True)
            self.priority = priority

    class ComplianceEngine:  # type: ignore[no-redef]
        """Stub agent_control_plane.ComplianceEngine."""

        def __init__(self, **kwargs: Any) -> None:
            pass

    class GovernanceLayer:  # type: ignore[no-redef]
        """Stub GovernanceLayer with create_default_governance factory."""

        def __init__(self, **kwargs: Any) -> None:
            self.policy_engine = AgentOSEngine()

        @classmethod
        def create_default_governance(cls) -> "GovernanceLayer":
            return cls()


# ═══════════════════════════════════════════════════════════════
# Status / introspection
# ═══════════════════════════════════════════════════════════════

def get_agt_status() -> Dict[str, Any]:
    """Return which AGT packages are available and what mode each is running in.

    Returns a dict like:
        {
            "agent_os": {"available": True, "mode": "real", "package": "agent-os-kernel"},
            "agentmesh": {"available": False, "mode": "stub", "package": "agentmesh-platform"},
            "agent_control_plane": {"available": True, "mode": "real", "package": "agent-os-kernel"},
            "all_real": False,
        }
    """
    status: Dict[str, Any] = {
        "agent_os": {
            "available": _AGENT_OS_AVAILABLE,
            "mode": "real" if _AGENT_OS_AVAILABLE else "stub",
            "package": "agent-os-kernel",
        },
        "agentmesh": {
            "available": _AGENTMESH_AVAILABLE,
            "mode": "real" if _AGENTMESH_AVAILABLE else "stub",
            "package": "agentmesh-platform",
        },
        "agent_control_plane": {
            "available": _AGENT_KERNEL_AVAILABLE,
            "mode": "real" if _AGENT_KERNEL_AVAILABLE else "stub",
            "package": "agent-os-kernel",
        },
        "all_real": _AGENT_OS_AVAILABLE and _AGENTMESH_AVAILABLE and _AGENT_KERNEL_AVAILABLE,
    }
    return status


# ═══════════════════════════════════════════════════════════════
# Public API — all exports
# ═══════════════════════════════════════════════════════════════

__all__ = [
    # Core (backward-compatible names)
    "AgentOSEngine",
    "AgentMeshClient",
    "PolicyRule",
    "ActionType",
    "ExecutionRequest",
    "AgentContext",
    "PermissionLevel",
    # Additional agent_os classes
    "StatelessKernel",
    "ExecutionContext",
    "KernelSpace",
    "MCPSecurityScanner",
    "PromptInjectionDetector",
    "FlightRecorder",
    # Additional agentmesh classes
    "TrustScore",
    "AuditLog",
    "AuditChain",
    "AuditEntry",
    "RiskScorer",
    "RiskScore",
    "MeshComplianceEngine",
    "ComplianceFramework",
    "ComplianceReport",
    "CapabilityGrant",
    "CapabilityRegistry",
    "CapabilityScope",
    # Additional agent_control_plane classes
    "ComplianceEngine",
    "GovernanceLayer",
    # Introspection
    "get_agt_status",
    # Availability flags
    "_AGENT_OS_AVAILABLE",
    "_AGENTMESH_AVAILABLE",
    "_AGENT_KERNEL_AVAILABLE",
]
