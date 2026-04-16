"""Session-scoped fixtures for the integration suite.

The entire suite is gated on the ``GAVEL_INTEGRATION_DB_URL`` env var.
If unset, every test is cleanly skipped with a visible reason — no errors,
no false passes.

Responsibilities:

* Point ``gavel.db.engine`` + ``gavel.dependencies.get_sessionmaker`` at the
  integration URL (so the FastAPI app under ``TestClient`` uses real Postgres).
* Run ``alembic upgrade head`` against that URL once at session start, and
  ``alembic downgrade base`` at session end.
* Between tests, TRUNCATE every table (faster than drop/create each time).
* Disable the top-level ``tests/conftest.py`` ``_clean_db`` autouse fixture
  which is written for the in-memory SQLite path and would nuke the live
  Postgres schema.

Design notes
------------
Connection pooling: production code uses SQLAlchemy's default async pool
(pool_size=5, max_overflow=10). For the integration suite we force
``NullPool`` — pytest + Starlette's TestClient spin up a new event loop
per request, and asyncpg connections are bound to the loop they were
opened on. Pooling across loops on Windows' ProactorEventLoop surfaces as
``AttributeError: 'NoneType' object has no attribute 'send'`` on the next
request. ``NullPool`` gives us a fresh connection per checkout with no
cross-loop reuse, which is the right tradeoff for a serial test.
"""

from __future__ import annotations

import asyncio
import functools
import os
from typing import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import gavel.db.engine as db_engine
from gavel.db.base import Base
# Importing models registers them on ``Base.metadata`` so the TRUNCATE fixture
# can walk every table the repos touch.
from gavel.db import models  # noqa: F401
from gavel.db.repositories import enrollments as _enrollments_mod  # noqa: F401
import gavel.dependencies as gavel_deps


INTEGRATION_DB_URL_VAR = "GAVEL_INTEGRATION_DB_URL"
INTEGRATION_REDIS_URL_VAR = "GAVEL_INTEGRATION_REDIS_URL"


# ---------------------------------------------------------------------------
# Gate: skip the whole suite when the env var is absent.
# ---------------------------------------------------------------------------


def _integration_url() -> str | None:
    url = os.environ.get(INTEGRATION_DB_URL_VAR)
    return url if url else None


def pytest_collection_modifyitems(config, items):
    """If ``GAVEL_INTEGRATION_DB_URL`` is unset, mark every integration test
    as skipped with a clear reason. Other suites are untouched.
    """
    if _integration_url():
        return

    skip_marker = pytest.mark.skip(
        reason=(
            f"{INTEGRATION_DB_URL_VAR} not set — integration suite skipped. "
            f"Example: {INTEGRATION_DB_URL_VAR}="
            "postgresql+asyncpg://gavel:gavel@localhost:5432/gavel"
        )
    )
    for item in items:
        # Only stamp tests that actually live under tests/integration/.
        if "tests/integration" in item.nodeid.replace("\\", "/"):
            item.add_marker(skip_marker)


# ---------------------------------------------------------------------------
# Neutralise the top-level _clean_db autouse fixture for this subtree.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_db():
    """Override the top-level SQLite-targeted autouse ``_clean_db``.

    The parent ``tests/conftest.py`` resets the global engine and rebuilds
    the schema on an in-memory SQLite every test. For integration tests we
    keep the Postgres engine stable across the session and rely on TRUNCATE
    (see ``_truncate_tables``) for per-test isolation.
    """
    yield


# ---------------------------------------------------------------------------
# Session-scoped setup: point engine at Postgres + run migrations once.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def integration_db_url() -> str:
    url = _integration_url()
    if not url:
        pytest.skip(f"{INTEGRATION_DB_URL_VAR} not set")
    return url


def _install_nullpool_engine(url: str):
    """Build a NullPool async engine + sessionmaker and rebind the process.

    See the module docstring for why NullPool is required. We rebind
    ``gavel.db.engine.get_engine`` / ``get_sessionmaker`` so direct repo
    users (e.g. the cleanup task, and the integration test itself) hit the
    NullPool engine. The FastAPI app's cached ``Depends(get_sessionmaker)``
    wires through the dependencies module — it's overridden separately
    via ``app.dependency_overrides`` (see ``_override_app_dependency``).

    Returns the sessionmaker so callers can register FastAPI overrides.
    """
    db_engine.reset_engine()

    engine = create_async_engine(url, future=True, poolclass=pool.NullPool)
    sm = async_sessionmaker(engine, expire_on_commit=False)

    # Wrap in lru_cache so ``.cache_clear()`` callers (e.g.
    # ``reset_dependency_cache``) continue to work.
    @functools.lru_cache(maxsize=1)
    def _cached_engine():
        return engine

    @functools.lru_cache(maxsize=1)
    def _cached_sessionmaker():
        return sm

    db_engine.get_engine = _cached_engine  # type: ignore[assignment]
    db_engine.get_sessionmaker = _cached_sessionmaker  # type: ignore[assignment]

    # Swap the dependencies-module wrapper AND the gateway's import-time
    # alias (the gateway does ``from gavel.dependencies import get_sessionmaker``
    # at module load, capturing the original lru_cache). Rebinding both
    # module attributes catches the common call sites.
    gavel_deps.get_sessionmaker = _cached_sessionmaker  # type: ignore[assignment]

    return _cached_sessionmaker


def _override_app_dependency(sessionmaker_fn) -> None:
    """Register a FastAPI ``dependency_overrides`` entry so requests hit the
    NullPool engine.

    The routers were written with ``Depends(get_sessionmaker)`` resolved at
    import time, so monkey-patching the module attribute after the fact
    does not reach them. ``dependency_overrides`` is FastAPI's escape hatch
    and is keyed on the original callable identity.
    """
    from gavel.gateway import app
    # Use the ORIGINAL identity captured by ``Depends(...)`` in
    # ``gavel/dependencies.py`` — that's ``gavel_deps.get_sessionmaker`` as
    # it stood when ``dependencies.py`` was imported. Because those
    # ``Depends(get_sessionmaker)`` defaults bake in the function object at
    # function-definition time, we have to use the same callable object.
    # By the time this fixture runs, ``gavel_deps.get_sessionmaker`` has
    # been replaced, so we recover the original via the closure below:
    original = _ORIGINAL_GET_SESSIONMAKER
    app.dependency_overrides[original] = sessionmaker_fn


# Snapshot the original ``get_sessionmaker`` identity at conftest import
# time, BEFORE any patching happens. FastAPI ``Depends(...)`` matches by
# callable identity, so we need the object that was captured in the router
# signatures.
_ORIGINAL_GET_SESSIONMAKER = gavel_deps.get_sessionmaker


@pytest.fixture(scope="session", autouse=True)
def _setup_integration_database(integration_db_url: str) -> Iterator[None]:
    """Migrate up at session start, down at session end.

    Also rebinds the process-wide engine + sessionmaker to the integration
    URL so anything resolved from ``gavel.db.engine`` or
    ``gavel.dependencies.get_sessionmaker`` hits the live Postgres DB.
    """
    # Point the runtime at the integration URL for the whole session.
    os.environ["GAVEL_DB_URL"] = integration_db_url

    # Reset both the engine cache in ``gavel.db.engine`` and the cached
    # sessionmaker in ``gavel.dependencies`` so downstream consumers pick
    # up the new URL.
    db_engine.reset_engine()
    gavel_deps.get_sessionmaker.cache_clear()
    gavel_deps.reset_dependency_cache()

    # Alembic's env.py uses its own short-lived engine. That's fine — we
    # don't reuse it. ``env.py`` resolves the URL via ``resolve_database_url``,
    # which honours the ``GAVEL_DB_URL`` we just set.
    alembic_cfg = _make_alembic_config(integration_db_url)
    command.upgrade(alembic_cfg, "head")

    # AFTER migrations run, install the NullPool-backed engine. Doing this
    # before alembic would cause alembic to hold the only engine reference
    # and dispose it on exit — subsequent tests would then find a dead
    # engine.
    sessionmaker_fn = _install_nullpool_engine(integration_db_url)
    _override_app_dependency(sessionmaker_fn)

    try:
        yield
    finally:
        # Remove the FastAPI override so other (non-integration) runs of
        # the same process don't see a stale override.
        try:
            from gavel.gateway import app
            app.dependency_overrides.pop(_ORIGINAL_GET_SESSIONMAKER, None)
        except Exception:
            pass
        # Best-effort downgrade at session end. We don't fail the suite if
        # downgrade raises — the next session's upgrade is idempotent.
        try:
            command.downgrade(alembic_cfg, "base")
        except Exception:
            pass


def _make_alembic_config(url: str) -> Config:
    """Build an Alembic Config pointed at the project's alembic.ini.

    The project's ``env.py`` resolves the URL via
    ``gavel.db.engine.resolve_database_url`` (which reads ``GAVEL_DB_URL``),
    so we just need the config object — the URL is already in the env.
    """
    root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
    )
    ini_path = os.path.join(root, "alembic.ini")
    cfg = Config(ini_path)
    # Also set ``sqlalchemy.url`` explicitly so any caller that reads it
    # (e.g. offline mode) gets the right value.
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


# ---------------------------------------------------------------------------
# Function-scoped: truncate all tables between tests.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _truncate_tables(_setup_integration_database) -> Iterator[None]:
    """TRUNCATE every mapped table before each integration test.

    Runs *before* the test so the DB is empty when the test starts — simpler
    reasoning than "after" cleanup, and a failed test leaves state for
    inspection until the next run kicks off.
    """

    async def _do_truncate():
        engine = db_engine.get_engine()
        # Collect all known tables (core models + enrollment_records).
        table_names = [t.name for t in Base.metadata.sorted_tables]
        if not table_names:
            return
        async with engine.begin() as conn:
            quoted = ", ".join(f'"{n}"' for n in table_names)
            await conn.execute(
                text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE")
            )

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_do_truncate())
    finally:
        loop.close()

    # Reset the dependency-level caches so each test starts with fresh
    # registry singletons (they hold state like the mesh-client cache).
    gavel_deps.reset_dependency_cache()
    # Rebind the sessionmaker to the current engine so anything captured
    # during this test hits the same connection pool.
    gavel_deps.get_sessionmaker.cache_clear()

    yield


# ---------------------------------------------------------------------------
# Real Redis fixture (opt-in via GAVEL_INTEGRATION_REDIS_URL).
# ---------------------------------------------------------------------------


@pytest.fixture
async def real_redis_client():
    """Yield a real Redis asyncio client, or skip if unconfigured.

    Flushes the target DB before and after the test so state doesn't
    leak across runs. Use the ``redis_integration`` marker on the test.
    """
    url = os.environ.get(INTEGRATION_REDIS_URL_VAR)
    if not url:
        pytest.skip(f"{INTEGRATION_REDIS_URL_VAR} not set")

    import redis.asyncio as redis

    client = redis.from_url(url, decode_responses=False)
    try:
        await client.ping()
        await client.flushdb()
        yield client
    finally:
        try:
            await client.flushdb()
        except Exception:
            pass
        try:
            await client.aclose()
        except Exception:
            pass
