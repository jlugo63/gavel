"""
Gavel — Constitutional governance for autonomous AI agents.

Built on Microsoft's Agent Governance Toolkit. Adds governance chains,
separation of powers, blast box execution, evidence review, and
tiered autonomy with escalation.
"""

__version__ = "0.1.0"

from gavel.chain import GovernanceChain, ChainEvent
from gavel.constitution import Constitution, Invariant
from gavel.separation import SeparationOfPowers
from gavel.blastbox import BlastBox, EvidencePacket
from gavel.evidence import EvidenceReviewer, ReviewResult
from gavel.tiers import TierPolicy, AutonomyTier
from gavel.liveness import LivenessMonitor, EscalationTimeout
from gavel.compliance import (
    AnnexIVGenerator,
    ComplianceStatus,
    IncidentSeverity,
    IncidentStatus,
    IncidentReport,
    IncidentClassifier,
    IncidentRegistry,
)
from gavel.anomaly_monitor import (
    AnomalyAlert,
    AnomalyMonitor,
    AnomalyMonitorConfig,
)
from gavel.explainability import ExplainabilityRenderer, ExplanationReport
from gavel.rate_limit import (
    RateLimiter,
    RateLimitResult,
    BudgetTracker,
    BudgetCheckResult,
    BudgetStatus,
)
from gavel.artifact import (
    GovernanceArtifact,
    PolicyDecisionAdapter,
    Principal,
    ArtifactEvent,
    EvidenceSummary,
    from_chain,
    verify_artifact,
)
from gavel.agents import AgentRegistry, AgentRecord, AgentStatus
from gavel.enrollment import EnrollmentRegistry, EnrollmentApplication, EnrollmentStatus
from gavel.baseline import BehavioralBaseline, DriftReport, BehavioralBaselineRegistry
from gavel.evasion import OversightEvasionDetector as EvasionDetector
from gavel.collusion import CollusionDetector
from gavel.privacy import PrivacyScanResult, PrivacyCategory, PrivacyFinding
from gavel.circuit_breaker import CircuitBreaker
from gavel.prompt_injection import PromptInjectionDetector
from gavel.identity import MutualVerifier, IdentityRegistry
from gavel.lineage import LineageGraph, LineageTracker

__all__ = [
    # Core governance
    "GovernanceChain",
    "ChainEvent",
    "Constitution",
    "Invariant",
    "SeparationOfPowers",
    "BlastBox",
    "EvidencePacket",
    "EvidenceReviewer",
    "ReviewResult",
    "TierPolicy",
    "AutonomyTier",
    "LivenessMonitor",
    "EscalationTimeout",
    # Compliance
    "AnnexIVGenerator",
    "ComplianceStatus",
    "IncidentSeverity",
    "IncidentStatus",
    "IncidentReport",
    "IncidentClassifier",
    "IncidentRegistry",
    # Artifacts
    "GovernanceArtifact",
    "PolicyDecisionAdapter",
    "Principal",
    "ArtifactEvent",
    "EvidenceSummary",
    "from_chain",
    "verify_artifact",
    # Anomaly monitoring
    "AnomalyAlert",
    "AnomalyMonitor",
    "AnomalyMonitorConfig",
    # Rate limiting
    "RateLimiter",
    "RateLimitResult",
    "BudgetTracker",
    "BudgetCheckResult",
    "BudgetStatus",
    # Explainability
    "ExplainabilityRenderer",
    "ExplanationReport",
    # Agent registry
    "AgentRegistry",
    "AgentRecord",
    "AgentStatus",
    # Enrollment
    "EnrollmentRegistry",
    "EnrollmentApplication",
    "EnrollmentStatus",
    # Behavioral baseline
    "BehavioralBaseline",
    "DriftReport",
    "BehavioralBaselineRegistry",
    # Detection
    "EvasionDetector",
    "CollusionDetector",
    "PromptInjectionDetector",
    # Privacy
    "PrivacyScanResult",
    "PrivacyCategory",
    "PrivacyFinding",
    # Circuit breaker
    "CircuitBreaker",
    # Identity
    "MutualVerifier",
    "IdentityRegistry",
    # Lineage
    "LineageGraph",
    "LineageTracker",
]
