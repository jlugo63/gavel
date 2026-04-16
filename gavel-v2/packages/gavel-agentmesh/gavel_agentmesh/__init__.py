"""
gavel-agentmesh — Constitutional governance chains for AGT AgentMesh.

Provides tamper-evident, multi-principal governance workflows with
separation of powers enforcement, integrated with AGT's trust and
policy infrastructure.
"""

from gavel_agentmesh.provider import (
    GavelTrustProvider,
    GovernanceArtifact,
    PolicyDecisionAdapter,
    ArtifactEvent,
    EvidenceSummary,
    Principal,
    from_governance_chain,
    verify_artifact,
)

__all__ = [
    "GavelTrustProvider",
    "GovernanceArtifact",
    "PolicyDecisionAdapter",
    "ArtifactEvent",
    "EvidenceSummary",
    "Principal",
    "from_governance_chain",
    "verify_artifact",
]
