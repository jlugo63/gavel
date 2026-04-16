"""Gavel API routers — split from the gateway god module."""

from .governance_router import governance_router
from .agent_router import agent_router
from .system_router import system_router

__all__ = [
    "governance_router",
    "agent_router",
    "system_router",
]
