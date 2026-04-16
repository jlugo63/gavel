"""Wave 1 smoke tests for the Gavel DB foundation.

Scope:
  * URL resolution defaults and env-var override.
  * Alembic ``upgrade head`` on an empty SQLite creates all seven tables.
  * One insert + select roundtrip per ORM row class.

These tests are hermetic: each constructs its own engine against a
fresh ``sqlite+aiosqlite`` URL (file-scoped or in-memory), runs the
migration programmatically, and never touches the process-wide
``get_engine()`` cache except in the two URL-resolution tests that
explicitly exercise it.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from gavel.db import engine as engine_mod
from gavel.db.base import Base
from gavel.db.models import (
    AgentRecordRow,
    ChainEventRow,
    EnrollmentTokenRow,
    EvidencePacketRow,
    ExecutionTokenRow,
    GovernanceChainRow,
    IncidentRow,
    ReviewResultRow,
)


EXPECTED_TABLES = {
    "governance_chains",
    "chain_events",
    "agents",
    "enrollment_tokens",
    "incidents",
    "evidence_packets",
    "review_results",
    "execution_tokens",
}


# ── URL resolution ────────────────────────────────────────────────


def test_engine_defaults_to_sqlite_memory_when_env_unset(monkeypatch):
    """When GAVEL_DB_URL is unset and we're under pytest, default is sqlite memory."""
    monkeypatch.delenv("GAVEL_DB_URL", raising=False)
    engine_mod.reset_engine()
    try:
        url = engine_mod.resolve_database_url()
        assert url == "sqlite+aiosqlite:///:memory:"
        eng = engine_mod.get_engine()
        assert str(eng.url) == "sqlite+aiosqlite:///:memory:"
    finally:
        engine_mod.reset_engine()


def test_engine_honors_GAVEL_DB_URL_env(monkeypatch):
    custom = "sqlite+aiosqlite:///./_gavel_env_test.db"
    monkeypatch.setenv("GAVEL_DB_URL", custom)
    engine_mod.reset_engine()
    try:
        assert engine_mod.resolve_database_url() == custom
        eng = engine_mod.get_engine()
        assert str(eng.url) == custom
    finally:
        engine_mod.reset_engine()
        # Tidy: file was never opened (engine is lazy) but be defensive.
        try:
            os.remove("./_gavel_env_test.db")
        except FileNotFoundError:
            pass


# ── Alembic migration ─────────────────────────────────────────────


def _run_alembic_upgrade(url: str) -> None:
    """Run ``alembic upgrade head`` programmatically against ``url``."""
    import pathlib

    from alembic import command
    from alembic.config import Config

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "gavel" / "db" / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    # Override the env.py URL resolution by also setting it via env var
    # (env.py calls resolve_database_url, which checks GAVEL_DB_URL first).
    prev = os.environ.get("GAVEL_DB_URL")
    os.environ["GAVEL_DB_URL"] = url
    try:
        command.upgrade(cfg, "head")
    finally:
        if prev is None:
            os.environ.pop("GAVEL_DB_URL", None)
        else:
            os.environ["GAVEL_DB_URL"] = prev


def test_alembic_upgrade_head_on_empty_sqlite_creates_all_tables(tmp_path):
    """Running ``alembic upgrade head`` on an empty DB creates all seven tables."""
    db_path = tmp_path / "alembic_smoke.db"
    url = f"sqlite+aiosqlite:///{db_path.as_posix()}"

    _run_alembic_upgrade(url)

    # Inspect with a sync engine — simpler and sufficient for DDL check.
    sync_url = url.replace("sqlite+aiosqlite", "sqlite")
    from sqlalchemy import create_engine

    sync_engine = create_engine(sync_url)
    try:
        insp = inspect(sync_engine)
        present = set(insp.get_table_names())
        missing = EXPECTED_TABLES - present
        assert not missing, f"Missing tables after upgrade: {missing}. Present: {present}"
    finally:
        sync_engine.dispose()


# ── ORM roundtrip ─────────────────────────────────────────────────


@pytest.fixture
async def session_maker(tmp_path):
    """Fresh per-test engine against a file SQLite, schema created in-process."""
    db_path = tmp_path / "roundtrip.db"
    url = f"sqlite+aiosqlite:///{db_path.as_posix()}"
    eng = create_async_engine(url, future=True)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(eng, expire_on_commit=False, class_=AsyncSession)
    try:
        yield maker
    finally:
        await eng.dispose()


async def test_models_roundtrip_insert_select(session_maker):
    """Insert one row per ORM class, then select it back and assert PK match."""
    now = datetime.now(timezone.utc)

    chain_id = f"c-{uuid.uuid4().hex[:8]}"
    agent_id = f"agent-{uuid.uuid4().hex[:8]}"
    packet_id = f"ep-{uuid.uuid4().hex[:8]}"

    rows: list[tuple[type, dict, tuple]] = [
        (
            GovernanceChainRow,
            dict(chain_id=chain_id, status="PENDING", created_at=now, actor_roles={}),
            (GovernanceChainRow.chain_id, chain_id),
        ),
        (
            ChainEventRow,
            dict(
                chain_id=chain_id,
                sequence=0,
                event_id="evt-abc",
                event_type="INBOUND_INTENT",
                actor_id="agent:test",
                role_used="proposer",
                timestamp=now,
                payload={"foo": "bar"},
                prev_hash="",
                event_hash="deadbeef",
                request_id="req-1",
            ),
            (ChainEventRow.event_id, "evt-abc"),
        ),
        (
            AgentRecordRow,
            dict(
                agent_id=agent_id,
                display_name="Test Agent",
                agent_type="llm",
                did="did:gavel:agent:abc",
                trust_score=500,
                autonomy_tier=0,
                capabilities=["Read", "Write"],
                status="ACTIVE",
                registered_at=now,
                last_heartbeat=now,
            ),
            (AgentRecordRow.agent_id, agent_id),
        ),
        (
            EnrollmentTokenRow,
            dict(
                token="gvl_tok_abc123",
                agent_did="did:gavel:agent:abc",
                agent_id=agent_id,
                issued_at=now,
                expires_at=now,
                ttl_seconds=3600,
                revoked=False,
                scope={"roles": ["proposer"]},
            ),
            (EnrollmentTokenRow.token, "gvl_tok_abc123"),
        ),
        (
            IncidentRow,
            dict(
                incident_id="inc-xyz",
                agent_id=agent_id,
                severity="critical",
                status="open",
                title="Test incident",
                description="smoke test",
                detected_at=now,
                chain_ids=[chain_id],
                findings=["f1"],
                regulatory_references=["EU AI Act Article 73"],
            ),
            (IncidentRow.incident_id, "inc-xyz"),
        ),
        (
            EvidencePacketRow,
            dict(
                packet_id=packet_id,
                chain_id=chain_id,
                intent_event_id="evt-abc",
                command_argv=["echo", "hi"],
                scope={"allow_paths": ["/tmp"]},
                exit_code=0,
                stdout_hash="a" * 64,
                stderr_hash="b" * 64,
                diff_hash="c" * 64,
                stdout_preview="hi",
                files_modified=[],
                files_created=[],
                files_deleted=[],
                image="python:3.12-slim",
                network_mode="none",
                cpu="1",
                memory="512m",
                started_at=now,
                finished_at=now,
            ),
            (EvidencePacketRow.packet_id, packet_id),
        ),
        (
            ReviewResultRow,
            dict(
                packet_id=packet_id,
                chain_id=chain_id,
                verdict="PASS",
                findings=[{"check": "exit_code", "passed": True}],
                risk_delta=0.0,
                scope_compliance="FULL",
                review_hash="d" * 64,
                redacted_stdout="",
                redacted_stderr="",
                privacy_findings=[],
            ),
            (ReviewResultRow.packet_id, packet_id),
        ),
        (
            ExecutionTokenRow,
            dict(
                token_id="exec-t-abc",
                chain_id=chain_id,
                expires_at=now,
                used=False,
            ),
            (ExecutionTokenRow.token_id, "exec-t-abc"),
        ),
    ]

    # Insert all rows — governance_chains first so the FK from chain_events resolves.
    async with session_maker() as session:
        for row_cls, kwargs, _ in rows:
            session.add(row_cls(**kwargs))
        await session.commit()

    # Select each back by its PK column.
    async with session_maker() as session:
        for row_cls, _, (pk_col, pk_val) in rows:
            result = await session.execute(select(row_cls).where(pk_col == pk_val))
            fetched = result.scalar_one()
            assert fetched is not None, f"Failed to fetch {row_cls.__name__}"
