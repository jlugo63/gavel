"""
Protocol definitions for AGT (Agent Governance Toolkit) compatibility types.

Provides ``typing.Protocol`` / ``@runtime_checkable`` interfaces that both
the real AGT packages and the Gavel stub fallbacks satisfy.  Importing this
module has **no** runtime side-effects — it only defines structural types used
by the type-checker.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Protocol, runtime_checkable


# ═══════════════════════════════════════════════════════════════
# agent_os protocols
# ═══════════════════════════════════════════════════════════════


@runtime_checkable
class PolicyEngineProtocol(Protocol):
    """Structural type for agent_os.PolicyEngine / AgentOSEngine."""

    custom_rules: list[Any]

    def add_custom_rule(self, rule: Any) -> None: ...
    def validate_request(self, request: Any) -> tuple[bool, str]: ...


@runtime_checkable
class StatelessKernelProtocol(Protocol):
    """Structural type for agent_os.StatelessKernel."""

    def execute(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class ExecutionContextProtocol(Protocol):
    """Structural type for agent_os.ExecutionContext."""

    agent_id: str
    policy_engine: Any


@runtime_checkable
class KernelSpaceProtocol(Protocol):
    """Structural type for agent_os.KernelSpace."""
    ...


@runtime_checkable
class MCPSecurityScannerProtocol(Protocol):
    """Structural type for agent_os.MCPSecurityScanner."""

    def scan(self, tool_definition: Any) -> tuple[bool, str]: ...


@runtime_checkable
class PromptInjectionDetectorProtocol(Protocol):
    """Structural type for agent_os.PromptInjectionDetector."""

    def detect(self, text: str) -> tuple[bool, float]: ...
    def scan(self, text: str) -> Any: ...
    def scan_fields(self, fields: dict[str, Any]) -> Any: ...


@runtime_checkable
class FlightRecorderProtocol(Protocol):
    """Structural type for agent_os.FlightRecorder."""

    def record(self, event: str, **kwargs: Any) -> None: ...
    def export(self) -> list[dict[str, Any]]: ...


# ═══════════════════════════════════════════════════════════════
# agentmesh protocols
# ═══════════════════════════════════════════════════════════════


@runtime_checkable
class TrustScoreProtocol(Protocol):
    """Structural type for agentmesh.TrustScore."""

    total_score: int
    tier: str

    def update(self, **kwargs: Any) -> None: ...
    def meets_threshold(self, threshold: int = 400) -> bool: ...


@runtime_checkable
class AuditEntryProtocol(Protocol):
    """Structural type for agentmesh.AuditEntry."""

    action: str
    agent_id: str
    timestamp: str
    metadata: dict[str, Any]


@runtime_checkable
class AuditLogProtocol(Protocol):
    """Structural type for agentmesh.AuditLog."""

    def log(self, entry: Any = None, **kwargs: Any) -> None: ...
    def verify_integrity(self) -> bool: ...
    def export(self) -> list[Any]: ...


@runtime_checkable
class AuditChainProtocol(Protocol):
    """Structural type for agentmesh.AuditChain."""

    def append(self, entry: Any) -> None: ...


@runtime_checkable
class RiskScoreProtocol(Protocol):
    """Structural type for agentmesh.RiskScore."""

    score: float
    category: str


@runtime_checkable
class RiskScorerProtocol(Protocol):
    """Structural type for agentmesh.RiskScorer."""

    def score(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class ComplianceFrameworkProtocol(Protocol):
    """Structural type for agentmesh.ComplianceFramework."""

    name: str


@runtime_checkable
class ComplianceReportProtocol(Protocol):
    """Structural type for agentmesh.ComplianceReport."""

    compliant: bool
    findings: list[str]


@runtime_checkable
class MeshComplianceEngineProtocol(Protocol):
    """Structural type for agentmesh.ComplianceEngine."""

    def add_framework(self, framework: Any) -> None: ...
    def evaluate(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class CapabilityScopeProtocol(Protocol):
    """Structural type for agentmesh.CapabilityScope."""

    scope: str


@runtime_checkable
class CapabilityGrantProtocol(Protocol):
    """Structural type for agentmesh.CapabilityGrant."""

    capability: str
    scope: Any


@runtime_checkable
class CapabilityRegistryProtocol(Protocol):
    """Structural type for agentmesh.CapabilityRegistry."""

    def grant(self, cap: Any) -> None: ...
    def check(self, capability: str) -> bool: ...


@runtime_checkable
class AgentMeshClientProtocol(Protocol):
    """Structural type for agentmesh.AgentMeshClient."""

    identity: Any
    trust_score: Any
    audit_log: Any
    policy_engine: Any

    @property
    def agent_did(self) -> str: ...


# ═══════════════════════════════════════════════════════════════
# agent_control_plane protocols
# ═══════════════════════════════════════════════════════════════


@runtime_checkable
class AgentContextProtocol(Protocol):
    """Structural type for agent_control_plane.AgentContext."""

    agent_id: str
    session_id: str
    created_at: Any
    permissions: dict[str, Any]
    metadata: dict[str, Any]


@runtime_checkable
class ExecutionRequestProtocol(Protocol):
    """Structural type for agent_control_plane.ExecutionRequest."""

    request_id: str
    agent_context: Any
    action_type: Any
    parameters: dict[str, Any]
    timestamp: Any
    status: str
    risk_score: float


@runtime_checkable
class PolicyRuleProtocol(Protocol):
    """Structural type for agent_control_plane.PolicyRule."""

    rule_id: str
    name: str
    description: str
    action_types: list[Any]
    validator: Callable[..., bool]
    priority: int


@runtime_checkable
class ComplianceEngineProtocol(Protocol):
    """Structural type for agent_control_plane.ComplianceEngine."""
    ...


@runtime_checkable
class GovernanceLayerProtocol(Protocol):
    """Structural type for agent_control_plane.GovernanceLayer."""

    policy_engine: Any

    @classmethod
    def create_default_governance(cls) -> GovernanceLayerProtocol: ...


# ═══════════════════════════════════════════════════════════════
# agent_compliance protocols
# ═══════════════════════════════════════════════════════════════


@runtime_checkable
class AgentRiskProfileProtocol(Protocol):
    """Structural type for agent_compliance.AgentRiskProfile."""

    agent_id: str
    agent_type: str
    capabilities: list[str]
    data_categories: list[str]
    deployment_context: str
    intended_purpose: str


@runtime_checkable
class ClassificationResultProtocol(Protocol):
    """Structural type for agent_compliance.ClassificationResult."""

    risk_level: Any
    article_references: list[str]
    reasoning: str
    classified_at: Any


@runtime_checkable
class AnnexIVDocumentProtocol(Protocol):
    """Structural type for agent_compliance.AnnexIVDocument."""

    document_id: str
    agent_id: str
    sections: dict[str, Any]
    generated_at: Any
    version: str


@runtime_checkable
class EUAIActRiskClassifierProtocol(Protocol):
    """Structural type for agent_compliance.EUAIActRiskClassifier."""

    def classify(self, agent_profile: Any) -> Any: ...


@runtime_checkable
class TechnicalDocumentationExporterProtocol(Protocol):
    """Structural type for agent_compliance.TechnicalDocumentationExporter."""

    def export(self, agent_id: str, context: Optional[dict[str, Any]] = None) -> Any: ...
