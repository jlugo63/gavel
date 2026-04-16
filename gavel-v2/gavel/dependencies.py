"""FastAPI dependency providers for Gavel services.

Single home for the `Depends()` callables that supply shared services to
routers. The lifecycle is unchanged from the previous module-global model
(process-scoped singletons), but services are now obtained through DI
which makes them overridable via `app.dependency_overrides`.

Wave 3: chains, evidence, review results, and execution tokens are no
longer in-memory dicts — they are persisted through repositories keyed
off a shared async sessionmaker.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Optional

from fastapi import Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.agents import AgentRegistry
from gavel.agt_compat import AgentMeshClient, AgentOSEngine
from gavel.blastbox import BlastBox
from gavel.compliance import IncidentRegistry
from gavel.constitution import Constitution
import gavel.db.engine as db_engine
from gavel.db.base import Base
from gavel.db.repositories import (
    AgentRepository,
    ChainRepository,
    EnrollmentRepository,
    EvidenceRepository,
    ExecutionTokenRepository,
    GovernanceTokenRepository,
    IncidentRepository,
    ReviewRepository,
)
from gavel.enrollment import EnrollmentRegistry, GovernanceToken, TokenManager
from gavel.events import EventBus
from gavel.evidence import EvidenceReviewer
from gavel.liveness import LivenessMonitor
from gavel.rate_limit import BudgetTracker, RateLimiter
from gavel.separation import SeparationOfPowers
from gavel.tiers import TierPolicy


# ---------------------------------------------------------------------------
# Per-chain concurrency control
# ---------------------------------------------------------------------------


class ChainLockManager:
    """Manages per-chain asyncio locks to prevent concurrent chain mutations.

    Two concurrent requests on the same chain_id can interleave appends and
    corrupt the hash chain. This manager provides a lazy-created asyncio.Lock
    per chain_id, so callers serialize mutations with:

        async with chain_locks.lock(chain_id):
            chain.append(...)
    """

    def __init__(self):
        self._locks: dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def lock(self, chain_id: str):
        if chain_id not in self._locks:
            self._locks[chain_id] = asyncio.Lock()
        async with self._locks[chain_id]:
            yield

    def discard(self, chain_id: str) -> None:
        self._locks.pop(chain_id, None)


# ---------------------------------------------------------------------------
# Singleton providers (lifespan-scoped via lru_cache).
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_constitution() -> Constitution:
    return Constitution()


@lru_cache(maxsize=1)
def get_separation() -> SeparationOfPowers:
    return SeparationOfPowers()


@lru_cache(maxsize=1)
def get_tier_policy() -> TierPolicy:
    return TierPolicy()


@lru_cache(maxsize=1)
def get_liveness() -> LivenessMonitor:
    return LivenessMonitor()


@lru_cache(maxsize=1)
def get_blastbox() -> BlastBox:
    return BlastBox()


@lru_cache(maxsize=1)
def get_evidence_reviewer() -> EvidenceReviewer:
    return EvidenceReviewer()


@lru_cache(maxsize=1)
def get_event_bus() -> EventBus:
    return EventBus()


@lru_cache(maxsize=1)
def get_agent_os() -> AgentOSEngine:
    return AgentOSEngine()


@lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    return RateLimiter()


@lru_cache(maxsize=1)
def get_budget_tracker() -> BudgetTracker:
    return BudgetTracker()


@lru_cache(maxsize=1)
def get_chain_lock_manager() -> ChainLockManager:
    return ChainLockManager()


# ---------------------------------------------------------------------------
# Database sessionmaker + repositories
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Cached async sessionmaker bound to the process-wide engine."""
    return db_engine.get_sessionmaker()


def get_chain_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> ChainRepository:
    return ChainRepository(sm)


def get_evidence_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> EvidenceRepository:
    return EvidenceRepository(sm)


def get_review_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> ReviewRepository:
    return ReviewRepository(sm)


def get_execution_token_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> ExecutionTokenRepository:
    return ExecutionTokenRepository(sm)


def get_agent_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> AgentRepository:
    return AgentRepository(sm)


def get_enrollment_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> EnrollmentRepository:
    return EnrollmentRepository(sm)


def get_governance_token_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> GovernanceTokenRepository:
    return GovernanceTokenRepository(sm)


def get_incident_repo(
    sm: async_sessionmaker[AsyncSession] = Depends(get_sessionmaker),
) -> IncidentRepository:
    return IncidentRepository(sm)


# ---------------------------------------------------------------------------
# Registry providers (repo-backed)
# ---------------------------------------------------------------------------


def get_agent_registry(
    bus: EventBus = Depends(get_event_bus),
    repo: AgentRepository = Depends(get_agent_repo),
) -> AgentRegistry:
    return _get_or_create_agent_registry(bus, repo._sessionmaker)


@lru_cache(maxsize=1)
def _get_or_create_agent_registry(bus: EventBus, sm) -> AgentRegistry:
    return AgentRegistry(bus, AgentRepository(sm))


def get_enrollment_registry(
    repo: EnrollmentRepository = Depends(get_enrollment_repo),
) -> EnrollmentRegistry:
    return _get_or_create_enrollment_registry(repo._sessionmaker)


@lru_cache(maxsize=1)
def _get_or_create_enrollment_registry(sm) -> EnrollmentRegistry:
    return EnrollmentRegistry(EnrollmentRepository(sm))


def get_token_manager(
    repo: GovernanceTokenRepository = Depends(get_governance_token_repo),
) -> TokenManager:
    return _get_or_create_token_manager(repo._sessionmaker)


@lru_cache(maxsize=1)
def _get_or_create_token_manager(sm) -> TokenManager:
    return TokenManager(GovernanceTokenRepository(sm))


def get_incident_registry(
    repo: IncidentRepository = Depends(get_incident_repo),
) -> IncidentRegistry:
    return _get_or_create_incident_registry(repo._sessionmaker)


@lru_cache(maxsize=1)
def _get_or_create_incident_registry(sm) -> IncidentRegistry:
    return IncidentRegistry(IncidentRepository(sm))


# ---------------------------------------------------------------------------
# Mesh client cache + factory
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _get_mesh_client_cache() -> dict[str, AgentMeshClient]:
    return {}


def get_mesh_client(actor_id: str) -> AgentMeshClient:
    cache = _get_mesh_client_cache()
    if actor_id not in cache:
        cache[actor_id] = AgentMeshClient(agent_id=actor_id)
    return cache[actor_id]


def get_mesh_client_factory():
    """Return the mesh-client factory callable.

    Endpoints that need to look up clients by actor_id at request time
    (rather than per-request) consume this provider so they can be
    overridden in tests.
    """
    return get_mesh_client


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


async def require_gavel_token(
    x_gavel_token: Optional[str] = Header(default=None),
    token_manager: TokenManager = Depends(get_token_manager),
) -> GovernanceToken:
    """FastAPI dependency that validates the X-Gavel-Token header."""
    if x_gavel_token is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_token", "detail": "X-Gavel-Token header is required"},
        )

    valid, reason, gov_token = await token_manager.validate(x_gavel_token)
    if not valid:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "token_invalid",
                "detail": reason,
                "agent_did": gov_token.agent_did if gov_token else None,
            },
        )

    return gov_token


# ---------------------------------------------------------------------------
# Reset helpers — used by tests that need a clean DI cache.
# ---------------------------------------------------------------------------


def reset_dependency_cache() -> None:
    """Clear all lru_cache singletons. Test-only helper."""
    for fn in (
        get_constitution,
        get_separation,
        get_tier_policy,
        get_liveness,
        get_blastbox,
        get_evidence_reviewer,
        get_event_bus,
        get_agent_os,
        get_rate_limiter,
        get_budget_tracker,
        get_chain_lock_manager,
        get_sessionmaker,
        _get_or_create_agent_registry,
        _get_or_create_enrollment_registry,
        _get_or_create_token_manager,
        _get_or_create_incident_registry,
        _get_mesh_client_cache,
    ):
        fn.cache_clear()


async def reset_db() -> None:
    """Drop & recreate the DB schema on the current engine.

    Test-only helper. Clears both Gavel's engine cache and the local
    sessionmaker cache so the next ``get_sessionmaker()`` picks up a
    fresh engine, then recreates every table registered on
    :class:`Base.metadata`.
    """
    # Tear down cached engine + sessionmaker so subsequent providers
    # build a new one against the current GAVEL_DB_URL.
    db_engine.reset_engine()
    get_sessionmaker.cache_clear()

    engine = db_engine.get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
