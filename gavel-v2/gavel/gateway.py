"""
Gavel Gateway — the FastAPI application that orchestrates governance chains.

This is where Microsoft's toolkit and Gavel's constitutional layer meet.
Incoming proposals hit Agent OS for policy evaluation, then flow through
Gavel's chain/separation/blastbox/evidence/tier pipeline.

This module is the thin orchestrator: it creates the FastAPI app, wires the
routers, and starts the lifespan tasks. Service instantiation lives in
`gavel.dependencies` and is consumed by routers via FastAPI `Depends()`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from gavel.request_id import RequestIDMiddleware, configure_request_id_logging

from gavel.chain import ChainStatus
from gavel.supervisor import Supervisor

from gavel.dependencies import (
    get_agent_os,
    get_agent_registry,
    get_chain_lock_manager,
    get_chain_repo,
    get_enrollment_registry,
    get_event_bus,
    get_evidence_repo,
    get_execution_token_repo,
    get_liveness,
    get_review_repo,
    get_sessionmaker,
)

from .gate import router as gate_router
from gavel.compliance_router import router as compliance_router
from gavel.routers import agent_router, governance_router, system_router


BLOCKED_PATTERNS = ["rm -rf", "drop table", "delete from", "format c:", "truncate", "shutdown"]


def _load_cedar_rules(engine) -> None:
    """Load Gavel constitutional rules into AGT PolicyEngine as custom rules.

    Note: the enrollment gate (ATF I-4/I-5/S-1/S-2) is enforced at the
    ``require_gavel_token`` dependency level — governance tokens are only
    issued to enrolled agents — so it is no longer duplicated here.
    """
    import re
    from gavel.agt_compat import PolicyRule, ActionType

    all_types = list(ActionType)

    def block_suspended(req):
        return req.agent_context.metadata.get("status") != "SUSPENDED"

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-kill-switch",
        name="Constitutional Kill Switch",
        description="Art. IV: Suspended agents are denied all actions",
        action_types=all_types,
        validator=block_suspended,
        priority=200,
    ))

    def block_dead(req):
        return req.agent_context.metadata.get("status") != "DEAD"

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-dead-agent",
        name="Dead Agent Block",
        description="Dead agents cannot perform actions",
        action_types=all_types,
        validator=block_dead,
        priority=195,
    ))

    def block_dangerous_commands(req):
        cmd = req.parameters.get("command", "")
        if not cmd:
            return True
        for pat in BLOCKED_PATTERNS:
            if pat in cmd.lower():
                return False
        from .hooks import HIGH_RISK_PATTERNS
        for pat in HIGH_RISK_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                return False
        return True

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-dangerous-commands",
        name="Dangerous Command Block",
        description="Art. II: Block destructive shell commands via Cedar policy",
        action_types=[ActionType.CODE_EXECUTION],
        validator=block_dangerous_commands,
        priority=180,
    ))

    def block_sensitive_writes(req):
        path = req.parameters.get("file_path", "").lower()
        if not path:
            return True
        sensitive = [".env", "credentials", "secret", "password", ".key", "token"]
        return not any(s in path for s in sensitive)

    engine.add_custom_rule(PolicyRule(
        rule_id="cedar-sensitive-file-guard",
        name="Sensitive File Guard",
        description="Art. II: Block writes to credential/secret files",
        action_types=[ActionType.FILE_WRITE],
        validator=block_sensitive_writes,
        priority=170,
    ))

    log = logging.getLogger("gavel.cedar")
    log.info(
        "Cedar enforcement active: %d rules loaded",
        len(engine.custom_rules),
    )


_cleanup_log = logging.getLogger("gavel.cleanup")

_TERMINAL_STATUSES = {
    ChainStatus.COMPLETED,
    ChainStatus.DENIED,
    ChainStatus.TIMED_OUT,
    ChainStatus.ROLLED_BACK,
}

DEFAULT_CHAIN_TTL_SECONDS = 3600  # 1 hour


async def cleanup_stale_chains(ttl_seconds: int = DEFAULT_CHAIN_TTL_SECONDS) -> int:
    """Remove completed/denied/timed-out chains and their associated data.

    Walks the chain repo for entries whose latest event (or ``created_at``
    if no events) is strictly older than the TTL, then deletes the chain,
    its evidence packet, review result, and any execution tokens. The
    per-chain :class:`ChainLockManager` is held for each delete so we
    serialize with in-flight mutations.
    """
    # Build repos directly from the sessionmaker — this function runs
    # outside of FastAPI's request lifecycle (called from
    # _periodic_cleanup), so we cannot use Depends().
    sm = get_sessionmaker()
    chain_repo = get_chain_repo(sm)
    evidence_repo = get_evidence_repo(sm)
    review_repo = get_review_repo(sm)
    execution_token_repo = get_execution_token_repo(sm)
    chain_locks = get_chain_lock_manager()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=ttl_seconds)
    stale_ids = await chain_repo.list_stale(cutoff)

    removed = 0
    for chain_id in stale_ids:
        chain = await chain_repo.get(chain_id)
        if chain is None:
            continue
        if chain.status not in _TERMINAL_STATUSES:
            continue
        async with chain_locks.lock(chain_id):
            await chain_repo.delete(chain_id)
            await evidence_repo.delete(chain_id)
            await review_repo.delete(chain_id)
            await execution_token_repo.delete_by_chain(chain_id)
        chain_locks.discard(chain_id)
        removed += 1

    if removed:
        _cleanup_log.info("GC: removed %d stale chains (TTL=%ds)", removed, ttl_seconds)
    return removed


async def _periodic_cleanup(interval_seconds: int = 300, ttl_seconds: int = DEFAULT_CHAIN_TTL_SECONDS):
    """Background task that periodically garbage-collects stale chains."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await cleanup_stale_chains(ttl_seconds)
        except Exception:
            _cleanup_log.exception("Error during periodic chain cleanup")


async def _auto_migrate() -> None:
    """Run Alembic migrations at startup so a fresh ``uvicorn`` just works.

    Skipped when ``GAVEL_SKIP_MIGRATE=1`` (e.g. in docker-compose where the
    separate ``gavel-migrate`` service handles it).

    Runs alembic in a subprocess because Alembic's async env.py calls
    ``asyncio.run()`` which conflicts with uvicorn's running event loop.
    """
    if os.environ.get("GAVEL_SKIP_MIGRATE", "").strip() in ("1", "true", "yes"):
        return

    log = logging.getLogger("gavel.migrate")
    alembic_ini = os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
    if not os.path.exists(alembic_ini):
        log.debug("alembic.ini not found — skipping auto-migrate")
        return

    log.info("Running auto-migrate (set GAVEL_SKIP_MIGRATE=1 to disable)")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alembic", "upgrade", "head",
        cwd=os.path.dirname(alembic_ini),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        log.error("Auto-migrate failed (exit %d): %s", proc.returncode, stderr.decode())
        raise RuntimeError(f"Alembic migration failed: {stderr.decode()}")
    log.info("Auto-migrate complete")


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """Start supervisor on startup, stop on shutdown."""
    await _auto_migrate()

    sm = get_sessionmaker()
    from gavel.db.repositories import AgentRepository
    from gavel.agents import AgentRegistry

    _load_cedar_rules(get_agent_os())

    bus = get_event_bus()
    agent_registry = AgentRegistry(bus, AgentRepository(sm))
    sup = Supervisor(bus, agent_registry, get_liveness())
    await sup.start()
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    yield
    cleanup_task.cancel()
    await sup.stop()


app = FastAPI(
    title="Gavel Governance Gateway",
    description="Constitutional governance for autonomous AI agents, built on Microsoft's Agent Governance Toolkit",
    version="0.2.0",
    lifespan=lifespan,
)

app.include_router(gate_router, prefix="/v1")
app.include_router(compliance_router, prefix="/v1")
app.include_router(governance_router, prefix="/v1")
app.include_router(agent_router, prefix="/v1")
app.include_router(system_router, prefix="/v1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8100", "http://localhost:3000", "http://localhost:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestIDMiddleware)

configure_request_id_logging("gavel")
