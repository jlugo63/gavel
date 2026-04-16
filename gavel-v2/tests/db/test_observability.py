"""Tests for gavel.db.observability — slow query logging."""

from __future__ import annotations

import logging

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from gavel.db.observability import install_slow_query_logging


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    try:
        yield eng
    finally:
        await eng.dispose()


async def test_install_respects_env_gating(monkeypatch, engine):
    monkeypatch.delenv("GAVEL_ENV", raising=False)
    monkeypatch.delenv("GAVEL_DB_LOG_SLOW", raising=False)
    assert install_slow_query_logging(engine) is False


async def test_install_when_production(monkeypatch, engine):
    monkeypatch.setenv("GAVEL_ENV", "production")
    assert install_slow_query_logging(engine) is True


async def test_install_when_override(monkeypatch, engine):
    monkeypatch.delenv("GAVEL_ENV", raising=False)
    monkeypatch.setenv("GAVEL_DB_LOG_SLOW", "1")
    assert install_slow_query_logging(engine) is True


async def test_install_is_idempotent(monkeypatch, engine):
    monkeypatch.setenv("GAVEL_DB_LOG_SLOW", "1")
    assert install_slow_query_logging(engine) is True
    assert install_slow_query_logging(engine) is False


async def test_slow_query_logged(engine, caplog):
    install_slow_query_logging(engine, threshold_ms=0, force=True)

    caplog.set_level(logging.WARNING, logger="gavel.db.slow_query")
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))

    records = [r for r in caplog.records if r.name == "gavel.db.slow_query"]
    assert records, "expected at least one slow_query warning"
    msg = records[0].getMessage()
    assert "slow_query" in msg
    assert "duration_ms=" in msg
    assert "SELECT 1" in msg


async def test_fast_query_not_logged_above_threshold(engine, caplog):
    install_slow_query_logging(engine, threshold_ms=60_000, force=True)

    caplog.set_level(logging.WARNING, logger="gavel.db.slow_query")
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))

    records = [r for r in caplog.records if r.name == "gavel.db.slow_query"]
    assert records == []


async def test_sql_truncated_to_200_chars(engine, caplog):
    install_slow_query_logging(engine, threshold_ms=0, force=True)

    long_literal = "x" * 500
    caplog.set_level(logging.WARNING, logger="gavel.db.slow_query")
    async with engine.connect() as conn:
        await conn.execute(text(f"SELECT '{long_literal}'"))

    records = [r for r in caplog.records if r.name == "gavel.db.slow_query"]
    assert records
    msg = records[0].getMessage()
    # Literal is truncated in the logged statement.
    assert "..." in msg
