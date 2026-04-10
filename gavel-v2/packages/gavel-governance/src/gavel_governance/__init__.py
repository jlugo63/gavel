"""
Gavel Governance Chains — tamper-evident multi-principal decision workflows.

Provides GovernanceArtifact schema, PolicyDecisionAdapter for AGT integration,
and standalone verification that requires only hashlib and json.
"""

from gavel_governance.artifact import (
    ArtifactEvent,
    EvidenceSummary,
    GovernanceArtifact,
    Principal,
    PolicyDecisionAdapter,
    from_governance_chain,
    verify_artifact,
)

__version__ = "0.1.0"

__all__ = [
    "ArtifactEvent",
    "EvidenceSummary",
    "GovernanceArtifact",
    "Principal",
    "PolicyDecisionAdapter",
    "from_governance_chain",
    "verify_artifact",
]
