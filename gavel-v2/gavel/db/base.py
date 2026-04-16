"""Declarative base for all Gavel ORM row classes.

Kept deliberately tiny. No mixins in Wave 1 — ``created_at``/``updated_at``
live on each row explicitly where they already exist on the Pydantic
source of truth.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for Gavel ORM rows."""

    pass


__all__ = ["Base"]
