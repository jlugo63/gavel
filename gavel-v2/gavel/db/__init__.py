"""Gavel DB package — SQLAlchemy 2.x async foundation.

Provides the async engine, sessionmaker, session_scope context manager,
and the declarative ``Base`` that all ORM rows inherit from. ORM models
live in :mod:`gavel.db.models`.

This package is intentionally side-by-side with the existing in-memory
code paths. Wave 1 lands the foundation only; no providers are swapped
here.
"""

from __future__ import annotations

from gavel.db.base import Base
from gavel.db.engine import (
    get_engine,
    get_sessionmaker,
    reset_engine,
    resolve_database_url,
    session_scope,
)

__all__ = [
    "Base",
    "get_engine",
    "get_sessionmaker",
    "reset_engine",
    "resolve_database_url",
    "session_scope",
]
