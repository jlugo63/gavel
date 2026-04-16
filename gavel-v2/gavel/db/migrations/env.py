"""Alembic environment for Gavel.

Uses SQLAlchemy 2.x async engine support. The DB URL is resolved at
runtime by :func:`gavel.db.engine.resolve_database_url` (respects
``GAVEL_DB_URL``), not from ``alembic.ini``.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from gavel.db.base import Base
# Importing models registers them on ``Base.metadata`` for autogenerate.
from gavel.db import models  # noqa: F401
from gavel.db.engine import resolve_database_url


config = context.config

# Inject the runtime-resolved URL so downstream config reads it.
config.set_main_option("sqlalchemy.url", resolve_database_url())

if config.config_file_name is not None:
    # disable_existing_loggers=False — otherwise fileConfig() mutes
    # every non-alembic logger (including 'gavel'), which leaks into
    # the test suite when alembic is invoked programmatically.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emit SQL without a live DB."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online_async() -> None:
    """Run migrations in 'online' mode against the async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_migrations_online_async())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
