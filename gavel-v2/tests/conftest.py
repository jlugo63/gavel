"""Shared fixtures for Gavel Phase 3 test suite."""

from __future__ import annotations

import os
import sys

import pytest

# Ensure gavel package is importable
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), ".."),
)

from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    EnrollmentRegistry,
    FallbackBehavior,
    PurposeDeclaration,
    ResourceAllowlist,
    TokenManager,
)
from gavel.events import EventBus
from gavel.agents import AgentRegistry
from gavel.chain import GovernanceChain
from gavel.tiers import TierPolicy


def _valid_application(agent_id: str = "agent:test", **overrides) -> EnrollmentApplication:
    """Build a valid EnrollmentApplication with sensible defaults."""
    kwargs = dict(
        agent_id=agent_id,
        display_name="Test Agent",
        agent_type="llm",
        owner="dev@gavel.eu",
        owner_contact="dev@gavel.eu",
        budget_tokens=100_000,
        budget_usd=50.0,
        purpose=PurposeDeclaration(
            summary="Integration test agent for governance validation",
            operational_scope="testing",
            expected_lifetime="session",
            risk_tier="standard",
        ),
        capabilities=CapabilityManifest(
            tools=["Read", "Write", "Bash"],
            max_concurrent_chains=2,
            can_spawn_subagents=False,
            network_access=False,
            file_system_access=True,
            execution_access=True,
        ),
        resources=ResourceAllowlist(
            allowed_paths=["/tmp/gavel-test"],
            allowed_hosts=[],
            allowed_env_vars=["PATH"],
            max_file_size_mb=5.0,
        ),
        boundaries=ActionBoundaries(
            allowed_actions=["read", "write", "execute"],
            blocked_patterns=["rm -rf /"],
            max_actions_per_minute=30,
            max_risk_threshold=0.7,
        ),
        fallback=FallbackBehavior(
            on_gateway_unreachable="stop",
            on_budget_exceeded="stop",
            on_sla_timeout="deny",
            graceful_shutdown=True,
        ),
    )
    kwargs.update(overrides)
    return EnrollmentApplication(**kwargs)


@pytest.fixture
def valid_app():
    return _valid_application()


@pytest.fixture
def enrollment_registry():
    return EnrollmentRegistry()


@pytest.fixture
def token_manager():
    return TokenManager()


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def agent_registry(event_bus):
    return AgentRegistry(event_bus)


@pytest.fixture
def governance_chain():
    return GovernanceChain()


@pytest.fixture
def tier_policy():
    return TierPolicy()
