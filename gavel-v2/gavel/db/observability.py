"""Slow-query logging for the Gavel async engine.

Attaches ``before_cursor_execute`` / ``after_cursor_execute`` listeners to
the engine's underlying sync engine and logs statements whose wall-clock
duration exceeds ``threshold_ms``.
"""

from __future__ import annotations

import logging
import os
import time

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger("gavel.db.slow_query")

_STATEMENT_KEY = "_gavel_slow_query_start"
_INSTALLED_ATTR = "_gavel_slow_query_installed"
_MAX_SQL_CHARS = 200


def _should_install() -> bool:
    if os.environ.get("GAVEL_ENV") == "production":
        return True
    if os.environ.get("GAVEL_DB_LOG_SLOW") == "1":
        return True
    return False


def install_slow_query_logging(
    engine: AsyncEngine,
    threshold_ms: int = 500,
    force: bool = False,
) -> bool:
    """Attach slow-query listeners to *engine*.

    Returns ``True`` if listeners were installed, ``False`` otherwise.
    Idempotent per engine.
    """
    if not force and not _should_install():
        return False

    sync_engine = engine.sync_engine
    if getattr(sync_engine, _INSTALLED_ATTR, False):
        return False

    @event.listens_for(sync_engine, "before_cursor_execute")
    def _before(conn, cursor, statement, parameters, context, executemany):
        context._query_start_time = time.perf_counter()

    @event.listens_for(sync_engine, "after_cursor_execute")
    def _after(conn, cursor, statement, parameters, context, executemany):
        start = getattr(context, "_query_start_time", None)
        if start is None:
            return
        duration_ms = (time.perf_counter() - start) * 1000.0
        if duration_ms < threshold_ms:
            return
        truncated = statement[:_MAX_SQL_CHARS]
        if len(statement) > _MAX_SQL_CHARS:
            truncated += "..."
        logger.warning(
            "slow_query duration_ms=%.1f sql=%r",
            duration_ms,
            truncated,
        )

    setattr(sync_engine, _INSTALLED_ATTR, True)
    return True


__all__ = ["install_slow_query_logging"]
