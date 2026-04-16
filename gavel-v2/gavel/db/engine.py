"""Async engine + sessionmaker factory for Gavel.

Reads ``GAVEL_DB_URL`` from the environment. When unset, defaults to:

* ``sqlite+aiosqlite:///:memory:`` when running under pytest
  (``PYTEST_CURRENT_TEST`` set or ``pytest`` module imported).
* ``sqlite+aiosqlite:///./gavel.db`` for local dev.

Per the Wave 1 design decision (Option B, single code path): the DB is
mandatory — there is no dict fallback. An engine is always available.

SQLAlchemy's async engine is cached via ``functools.lru_cache``. Tests
that need a fresh engine should call :func:`reset_engine`.
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


_DEFAULT_TEST_URL = "sqlite+aiosqlite:///:memory:"
_DEFAULT_DEV_URL = "sqlite+aiosqlite:///./gavel.db"


def _running_under_pytest() -> bool:
    """Heuristic: are we inside a pytest run?

    We check both the ``PYTEST_CURRENT_TEST`` env var (set during test
    execution) and the presence of the ``pytest`` module in
    ``sys.modules`` (covers collection + fixture setup).
    """
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    return "pytest" in sys.modules


def _apply_production_tls(url: str) -> str:
    if os.environ.get("GAVEL_ENV") != "production":
        return url
    if not url.startswith("postgresql+asyncpg://"):
        return url
    if "sslmode=" in url:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}sslmode=require"


def resolve_database_url() -> str:
    """Resolve the database URL per Wave 1 precedence rules.

    1. ``GAVEL_DB_URL`` env var if set (and non-empty).
    2. ``sqlite+aiosqlite:///:memory:`` when running under pytest.
    3. ``sqlite+aiosqlite:///./gavel.db`` otherwise.
    """
    url = os.environ.get("GAVEL_DB_URL")
    if not url:
        url = _DEFAULT_TEST_URL if _running_under_pytest() else _DEFAULT_DEV_URL
    return _apply_production_tls(url)


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Return the process-wide async engine (cached)."""
    url = resolve_database_url()
    kwargs: dict = {"future": True}
    if url.startswith("postgresql+asyncpg://"):
        kwargs.update(pool_size=20, max_overflow=5, pool_pre_ping=True)
    engine = create_async_engine(url, **kwargs)
    from gavel.db.observability import install_slow_query_logging

    install_slow_query_logging(engine)
    return engine


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return a cached ``async_sessionmaker`` bound to the engine."""
    engine = get_engine()
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def reset_engine() -> None:
    """Clear the cached engine + sessionmaker.

    Used by tests that need to pick up a different ``GAVEL_DB_URL`` or
    start from a fresh database. Callers are responsible for disposing
    any prior engine themselves if they still hold a reference.
    """
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a session with commit/rollback.

    The commit step is wrapped in ``@db_retry`` so transient connection
    failures at commit time are retried with backoff and gated by the
    DB circuit breaker.

    Usage::

        async with session_scope() as session:
            session.add(row)
            # commit is automatic on clean exit; rollback on exception.
    """
    from gavel.db.resilience import db_retry

    maker = get_sessionmaker()
    session = maker()

    @db_retry
    async def _commit() -> None:
        await session.commit()

    try:
        yield session
        await _commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


__all__ = [
    "get_engine",
    "get_sessionmaker",
    "reset_engine",
    "resolve_database_url",
    "session_scope",
]
