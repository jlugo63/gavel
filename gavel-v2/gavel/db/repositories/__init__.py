"""Repositories package — persistence backends for Gavel.

Wave 2A owns chain-flow repos (chains, evidence, reviews,
execution_tokens). Wave 2B owns registry-style repos (agents,
enrollments, tokens, incidents). Each section below is maintained by
its owning wave.
"""

from __future__ import annotations

# ── Wave 2A exports (chain-flow) ──────────────────────────────────
from gavel.db.repositories.chains import ChainRepository
from gavel.db.repositories.evidence import EvidenceRepository
from gavel.db.repositories.execution_tokens import ExecutionTokenRepository
from gavel.db.repositories.reviews import ReviewRepository

# ── Wave 2B exports (registries) ──────────────────────────────────
from gavel.db.repositories.agents import AgentRepository
from gavel.db.repositories.enrollments import (
    EnrollmentRecordRow,
    EnrollmentRepository,
)
from gavel.db.repositories.incidents import IncidentRepository
from gavel.db.repositories.tokens import GovernanceTokenRepository

__all__ = [
    # Wave 2A
    "ChainRepository",
    "EvidenceRepository",
    "ExecutionTokenRepository",
    "ReviewRepository",
    # Wave 2B
    "AgentRepository",
    "EnrollmentRepository",
    "EnrollmentRecordRow",
    "GovernanceTokenRepository",
    "IncidentRepository",
]
