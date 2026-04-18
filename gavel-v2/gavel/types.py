"""Shared type primitives used across multiple Gavel modules.

This module is a leaf dependency — it MUST NOT import from any other
``gavel.*`` module to avoid circular imports.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Three-level severity used by detection and monitoring modules.

    Shared by: collusion, evasion, fairness violation scoring.
    Modules that need additional levels (e.g. CRITICAL) define their own
    domain-specific severity enum.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
