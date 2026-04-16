"""Shared fixtures for DB repository tests.

Each test function gets a fresh in-memory SQLite engine with all tables
created. No state leaks between tests.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from gavel.db.base import Base
# Importing models registers them on Base.metadata so create_all emits
# DDL for every table the repos touch.
from gavel.db import models  # noqa: F401
# The enrollment records table is declared in the repositories package
# (Wave 2B gap note — see gavel/db/repositories/enrollments.py). Import
# it so it's registered on Base.metadata before create_all runs.
from gavel.db.repositories import enrollments as _enrollments_mod  # noqa: F401


@pytest.fixture
async def sessionmaker():
    """Fresh per-test async sessionmaker against a private in-memory DB.

    Uses a StaticPool-free memory URL via a file-like shared cache isn't
    needed because each test builds its own engine and disposes at teardown.
    """
    # A unique-per-test in-memory DB. ``uri=true`` with ``cache=shared``
    # would leak state across engines; we use a private (default) memory DB
    # tied to this engine instance only.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    try:
        yield maker
    finally:
        await engine.dispose()
