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

__all__ = [
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
]
