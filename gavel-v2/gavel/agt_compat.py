"""
AGT Compatibility Layer — real Microsoft AGT packages first, stub fallbacks
only when packages aren't installed.

Tries to import the real ``agent_os``, ``agentmesh``, and ``agent_control_plane``
packages (from agent-os-kernel and agentmesh-platform on PyPI). If any are
missing, provides stub classes that replicate the interface so Gavel runs
standalone.

Type safety is provided by ``gavel._agt_protocols`` — Protocol definitions
that both the real packages and these stubs satisfy.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


# ═══════════════════════════════════════════════════════════════
# agent_os — PolicyEngine, StatelessKernel, etc.
# ═══════════════════════════════════════════════════════════════


class _StubAgentOSEngine:
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

    def validate_request(self, request: Any) -> tuple[bool, str]:
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


class _StubStatelessKernel:
    """Stub StatelessKernel — sub-millisecond policy evaluation."""

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs

    def execute(self, **kwargs: Any) -> Any:
        return {"status": "stub", "allowed": True}


class _StubExecutionContext:
    """Stub ExecutionContext — agent identity + policy binding."""

    def __init__(self, agent_id: str = "", policy_engine: Any = None, **kwargs: Any) -> None:
        self.agent_id = agent_id
        self.policy_engine = policy_engine


class _StubKernelSpace:
    """Stub KernelSpace — full kernel with signals, VFS, protection rings."""

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs


class _StubMCPSecurityScanner:
    """Stub MCPSecurityScanner — MCP tool poisoning detection."""

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs

    def scan(self, tool_definition: Any) -> tuple[bool, str]:
        return True, "stub: no scan performed"


class _StubPromptInjectionDetector:
    """PromptInjectionDetector — delegates to gavel.prompt_injection.

    When the real agent_os package is not installed, this stub delegates
    to Gavel's own pattern-based detector for ATF D-2 compliance.
    """

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs
        from gavel.prompt_injection import PromptInjectionDetector as _RealDetector
        self._delegate = _RealDetector(**kwargs)

    def detect(self, text: str) -> tuple[bool, float]:
        return self._delegate.detect(text)

    def scan(self, text: str) -> Any:
        """Full scan with structured results."""
        return self._delegate.scan(text)

    def scan_fields(self, fields: dict[str, Any]) -> Any:
        """Scan multiple fields and merge results."""
        return self._delegate.scan_fields(fields)


class _StubFlightRecorder:
    """Stub FlightRecorder — audit logging."""

    def __init__(self, **kwargs: Any) -> None:
        self._records: list[dict[str, Any]] = []

    def record(self, event: str, **kwargs: Any) -> None:
        self._records.append({"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), **kwargs})

    def export(self) -> list[dict[str, Any]]:
        return list(self._records)


# Conditional imports — real package or stub fallback
try:
    from agent_os import PolicyEngine as AgentOSEngine  # pyright: ignore[reportMissingImports]
    from agent_os import StatelessKernel  # pyright: ignore[reportMissingImports]
    from agent_os import ExecutionContext  # pyright: ignore[reportMissingImports]
    from agent_os import KernelSpace  # pyright: ignore[reportMissingImports]
    from agent_os import MCPSecurityScanner  # pyright: ignore[reportMissingImports]
    from agent_os import PromptInjectionDetector  # pyright: ignore[reportMissingImports]
    from agent_os import FlightRecorder  # pyright: ignore[reportMissingImports]
    _AGENT_OS_AVAILABLE = True
except ImportError:
    _AGENT_OS_AVAILABLE = False
    AgentOSEngine: type[_StubAgentOSEngine] = _StubAgentOSEngine
    StatelessKernel: type[_StubStatelessKernel] = _StubStatelessKernel
    ExecutionContext: type[_StubExecutionContext] = _StubExecutionContext
    KernelSpace: type[_StubKernelSpace] = _StubKernelSpace
    MCPSecurityScanner: type[_StubMCPSecurityScanner] = _StubMCPSecurityScanner
    PromptInjectionDetector: type[_StubPromptInjectionDetector] = _StubPromptInjectionDetector
    FlightRecorder: type[_StubFlightRecorder] = _StubFlightRecorder


# ═══════════════════════════════════════════════════════════════
# agentmesh — AgentMeshClient, TrustScore, AuditLog, etc.
# ═══════════════════════════════════════════════════════════════


class _StubTrustScore:
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


class _StubAuditEntry:
    """Stub AuditEntry."""

    def __init__(self, action: str = "", agent_id: str = "", **kwargs: Any) -> None:
        self.action = action
        self.agent_id = agent_id
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.metadata = kwargs


class _StubAuditLog:
    """Stub AuditLog with log/verify/export."""

    def __init__(self) -> None:
        self._entries: list[_StubAuditEntry] = []

    def log(self, entry: Any = None, **kwargs: Any) -> None:
        if entry is not None:
            self._entries.append(entry)
        else:
            self._entries.append(_StubAuditEntry(**kwargs))

    def verify_integrity(self) -> bool:
        return True

    def export(self) -> list[Any]:
        return list(self._entries)


class _StubAuditChain:
    """Stub AuditChain."""

    def __init__(self) -> None:
        self._chain: list[Any] = []

    def append(self, entry: Any) -> None:
        self._chain.append(entry)


class _StubRiskScore:
    """Stub RiskScore."""

    def __init__(self, score: float = 0.0, category: str = "LOW", **kwargs: Any) -> None:
        self.score = score
        self.category = category


class _StubRiskScorer:
    """Stub RiskScorer."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def score(self, **kwargs: Any) -> _StubRiskScore:
        return _StubRiskScore()


class _StubComplianceFramework:
    """Stub ComplianceFramework."""

    def __init__(self, name: str = "", **kwargs: Any) -> None:
        self.name = name


class _StubComplianceReport:
    """Stub ComplianceReport."""

    def __init__(self, **kwargs: Any) -> None:
        self.compliant = True
        self.findings: list[str] = []


class _StubMeshComplianceEngine:
    """Stub agentmesh ComplianceEngine."""

    def __init__(self, **kwargs: Any) -> None:
        self._frameworks: list[Any] = []

    def add_framework(self, framework: Any) -> None:
        self._frameworks.append(framework)

    def evaluate(self, **kwargs: Any) -> _StubComplianceReport:
        return _StubComplianceReport()


class _StubCapabilityScope:
    """Stub CapabilityScope."""

    def __init__(self, scope: str = "*", **kwargs: Any) -> None:
        self.scope = scope


class _StubCapabilityGrant:
    """Stub CapabilityGrant."""

    def __init__(self, capability: str = "", scope: Any = None, **kwargs: Any) -> None:
        self.capability = capability
        self.scope = scope or _StubCapabilityScope()


class _StubCapabilityRegistry:
    """Stub CapabilityRegistry."""

    def __init__(self) -> None:
        self._grants: list[_StubCapabilityGrant] = []

    def grant(self, cap: _StubCapabilityGrant) -> None:
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


class _StubAgentMeshClient:
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
        self.trust_score = _StubTrustScore()
        self.audit_log = _StubAuditLog()
        self.policy_engine = _StubAgentOSEngine()

    @property
    def agent_did(self) -> str:
        return self.identity.did


# Conditional imports — real package or stub fallback
try:
    from agentmesh import AgentMeshClient  # pyright: ignore[reportMissingImports]
    from agentmesh import TrustScore  # pyright: ignore[reportMissingImports]
    from agentmesh import AuditChain, AuditEntry, AuditLog  # pyright: ignore[reportMissingImports]
    from agentmesh import ComplianceEngine as MeshComplianceEngine  # pyright: ignore[reportMissingImports]
    from agentmesh import ComplianceFramework, ComplianceReport  # pyright: ignore[reportMissingImports]
    from agentmesh import CapabilityGrant, CapabilityRegistry, CapabilityScope  # pyright: ignore[reportMissingImports]
    from agentmesh import RiskScorer, RiskScore  # pyright: ignore[reportMissingImports]
    _AGENTMESH_AVAILABLE = True
except ImportError:
    _AGENTMESH_AVAILABLE = False
    TrustScore: type[_StubTrustScore] = _StubTrustScore
    AuditEntry: type[_StubAuditEntry] = _StubAuditEntry
    AuditLog: type[_StubAuditLog] = _StubAuditLog
    AuditChain: type[_StubAuditChain] = _StubAuditChain
    RiskScore: type[_StubRiskScore] = _StubRiskScore
    RiskScorer: type[_StubRiskScorer] = _StubRiskScorer
    ComplianceFramework: type[_StubComplianceFramework] = _StubComplianceFramework
    ComplianceReport: type[_StubComplianceReport] = _StubComplianceReport
    MeshComplianceEngine: type[_StubMeshComplianceEngine] = _StubMeshComplianceEngine
    CapabilityScope: type[_StubCapabilityScope] = _StubCapabilityScope
    CapabilityGrant: type[_StubCapabilityGrant] = _StubCapabilityGrant
    CapabilityRegistry: type[_StubCapabilityRegistry] = _StubCapabilityRegistry
    AgentMeshClient: type[_StubAgentMeshClient] = _StubAgentMeshClient


# ═══════════════════════════════════════════════════════════════
# agent_control_plane — PolicyRule, ActionType, ExecutionRequest, etc.
# ═══════════════════════════════════════════════════════════════


class _StubActionType(str, Enum):
    """Stub ActionType enum matching agent_control_plane values."""
    CODE_EXECUTION = "code_execution"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    API_CALL = "api_call"
    DATABASE_QUERY = "database_query"
    DATABASE_WRITE = "database_write"
    WORKFLOW_TRIGGER = "workflow_trigger"


class _StubPermissionLevel(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class _StubAgentContext:
    """Stub agent context for policy evaluation."""

    def __init__(
        self,
        agent_id: str = "",
        session_id: str = "",
        created_at: Any = None,
        permissions: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id
        self.created_at = created_at
        self.permissions = permissions or {}
        self.metadata = metadata or {}


class _StubExecutionRequest:
    """Stub execution request matching agent_control_plane signature."""

    def __init__(
        self,
        request_id: str = "",
        agent_context: Optional[_StubAgentContext] = None,
        action_type: Optional[_StubActionType] = None,
        parameters: Optional[dict[str, Any]] = None,
        timestamp: Any = None,
        status: str = "pending",
        risk_score: float = 0.0,
    ) -> None:
        self.request_id = request_id
        self.agent_context = agent_context or _StubAgentContext()
        self.action_type = action_type
        self.parameters = parameters or {}
        self.timestamp = timestamp
        self.status = status
        self.risk_score = risk_score


class _StubPolicyRule:
    """Stub policy rule with validator callback."""

    def __init__(
        self,
        rule_id: str = "",
        name: str = "",
        description: str = "",
        action_types: Optional[list[Any]] = None,
        validator: Optional[Callable[..., bool]] = None,
        priority: int = 0,
    ) -> None:
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.action_types = action_types or []
        self.validator = validator or (lambda req: True)
        self.priority = priority


class _StubComplianceEngine:
    """Stub agent_control_plane.ComplianceEngine."""

    def __init__(self, **kwargs: Any) -> None:
        pass


class _StubGovernanceLayer:
    """Stub GovernanceLayer with create_default_governance factory."""

    def __init__(self, **kwargs: Any) -> None:
        self.policy_engine = _StubAgentOSEngine()

    @classmethod
    def create_default_governance(cls) -> _StubGovernanceLayer:
        return cls()


# Conditional imports — real package or stub fallback
try:
    from agent_control_plane.agent_kernel import (  # pyright: ignore[reportMissingImports]
        ActionType,
        AgentContext,
        ExecutionRequest,
        PermissionLevel,
        PolicyRule,
    )
    from agent_control_plane import ComplianceEngine  # pyright: ignore[reportMissingImports]
    from agent_control_plane import GovernanceLayer  # pyright: ignore[reportMissingImports]
    _AGENT_KERNEL_AVAILABLE = True
except ImportError:
    _AGENT_KERNEL_AVAILABLE = False
    ActionType = _StubActionType  # type: ignore[misc]
    PermissionLevel = _StubPermissionLevel  # type: ignore[misc]
    AgentContext: type[_StubAgentContext] = _StubAgentContext
    ExecutionRequest: type[_StubExecutionRequest] = _StubExecutionRequest
    PolicyRule: type[_StubPolicyRule] = _StubPolicyRule
    ComplianceEngine: type[_StubComplianceEngine] = _StubComplianceEngine
    GovernanceLayer: type[_StubGovernanceLayer] = _StubGovernanceLayer


# ═══════════════════════════════════════════════════════════════
# agent_compliance — EU AI Act risk classification (AGT v3.1.0)
# ═══════════════════════════════════════════════════════════════


class _StubRiskLevel(str, Enum):
    """EU AI Act risk levels per Article 6."""
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class _StubAgentRiskProfile:
    """Stub AgentRiskProfile — agent metadata for risk classification."""

    def __init__(
        self,
        agent_id: str = "",
        agent_type: str = "",
        capabilities: Optional[list[str]] = None,
        data_categories: Optional[list[str]] = None,
        deployment_context: str = "",
        intended_purpose: str = "",
    ) -> None:
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.capabilities = capabilities or []
        self.data_categories = data_categories or []
        self.deployment_context = deployment_context
        self.intended_purpose = intended_purpose


class _StubClassificationResult:
    """Stub ClassificationResult — output of EU AI Act risk classification."""

    def __init__(
        self,
        risk_level: _StubRiskLevel = _StubRiskLevel.MINIMAL,
        article_references: Optional[list[str]] = None,
        reasoning: str = "",
        classified_at: Optional[datetime] = None,
    ) -> None:
        self.risk_level = risk_level
        self.article_references = article_references or []
        self.reasoning = reasoning
        self.classified_at = classified_at or datetime.now(timezone.utc)


class _StubAnnexIVDocument:
    """Stub AnnexIVDocument — EU AI Act Annex IV technical documentation."""

    def __init__(
        self,
        document_id: str = "",
        agent_id: str = "",
        sections: Optional[dict[str, Any]] = None,
        generated_at: Optional[datetime] = None,
        version: str = "1.0",
    ) -> None:
        self.document_id = document_id or str(uuid.uuid4())
        self.agent_id = agent_id
        self.sections = sections or {}
        self.generated_at = generated_at or datetime.now(timezone.utc)
        self.version = version


class _StubEUAIActRiskClassifier:
    """Stub EUAIActRiskClassifier — delegates to Gavel's compliance module
    if available, otherwise returns a basic MINIMAL classification.
    """

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs
        self._delegate: Any = None
        try:
            from gavel.compliance import AnnexIVGenerator
            self._delegate = AnnexIVGenerator()
        except ImportError:
            pass

    def classify(self, agent_profile: _StubAgentRiskProfile) -> _StubClassificationResult:
        """Classify an agent's risk level under the EU AI Act."""
        # Delegate to Gavel's own compliance module if available
        if self._delegate is not None:
            try:
                result = self._delegate.classify_risk(agent_profile.agent_id)
                if result:
                    return _StubClassificationResult(
                        risk_level=_StubRiskLevel.HIGH,
                        article_references=["Article 6"],
                        reasoning=f"Classified via Gavel compliance module for {agent_profile.agent_id}",
                    )
            except Exception:
                logging.getLogger(__name__).debug(
                    "Compliance classify_risk failed for %s", agent_profile.agent_id, exc_info=True
                )
        # Fallback: basic classification
        return _StubClassificationResult(
            risk_level=_StubRiskLevel.MINIMAL,
            article_references=[],
            reasoning="Stub classification — no compliance module available",
        )


class _StubTechnicalDocumentationExporter:
    """Stub TechnicalDocumentationExporter — generates Annex IV documentation."""

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs

    def export(self, agent_id: str, context: Optional[dict[str, Any]] = None) -> _StubAnnexIVDocument:
        """Export Annex IV technical documentation for an agent."""
        return _StubAnnexIVDocument(
            agent_id=agent_id,
            sections=context or {"summary": "Stub documentation"},
        )


# Conditional imports — real package or stub fallback
try:
    from agent_compliance import (  # pyright: ignore[reportMissingImports]
        EUAIActRiskClassifier,
        RiskLevel,
        AgentRiskProfile,
        ClassificationResult,
        AnnexIVDocument,
        TechnicalDocumentationExporter,
    )
    _AGENT_COMPLIANCE_AVAILABLE = True
except ImportError:
    _AGENT_COMPLIANCE_AVAILABLE = False
    RiskLevel = _StubRiskLevel  # type: ignore[misc]
    AgentRiskProfile: type[_StubAgentRiskProfile] = _StubAgentRiskProfile
    ClassificationResult: type[_StubClassificationResult] = _StubClassificationResult
    AnnexIVDocument: type[_StubAnnexIVDocument] = _StubAnnexIVDocument
    EUAIActRiskClassifier: type[_StubEUAIActRiskClassifier] = _StubEUAIActRiskClassifier
    TechnicalDocumentationExporter: type[_StubTechnicalDocumentationExporter] = _StubTechnicalDocumentationExporter


# ═══════════════════════════════════════════════════════════════
# Status / introspection
# ═══════════════════════════════════════════════════════════════

def get_agt_status() -> dict[str, Any]:
    """Return which AGT packages are available and what mode each is running in.

    Returns a dict like:
        {
            "agent_os": {"available": True, "mode": "real", "package": "agent-os-kernel"},
            "agentmesh": {"available": False, "mode": "stub", "package": "agentmesh-platform"},
            "agent_control_plane": {"available": True, "mode": "real", "package": "agent-os-kernel"},
            "all_real": False,
        }
    """
    status: dict[str, Any] = {
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
        "agent_compliance": {
            "available": _AGENT_COMPLIANCE_AVAILABLE,
            "mode": "real" if _AGENT_COMPLIANCE_AVAILABLE else "stub",
            "package": "agent-compliance",
        },
        "all_real": _AGENT_OS_AVAILABLE and _AGENTMESH_AVAILABLE and _AGENT_KERNEL_AVAILABLE and _AGENT_COMPLIANCE_AVAILABLE,
    }
    return status


# ═══════════════════════════════════════════════════════════════
# Public API — all exports
# ═══════════════════════════════════════════════════════════════

__all__ = [
    # Core
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
    # AGT v3.1.0 — EU AI Act risk classification
    "EUAIActRiskClassifier",
    "RiskLevel",
    "AgentRiskProfile",
    "ClassificationResult",
    "AnnexIVDocument",
    "TechnicalDocumentationExporter",
    # Introspection
    "get_agt_status",
    # Availability flags
    "_AGENT_OS_AVAILABLE",
    "_AGENTMESH_AVAILABLE",
    "_AGENT_KERNEL_AVAILABLE",
    "_AGENT_COMPLIANCE_AVAILABLE",
]
