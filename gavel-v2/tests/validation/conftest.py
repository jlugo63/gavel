"""
Shared fixtures and helpers for the validation suite.

Unlike the unit-test conftest (tests/conftest.py), these fixtures build
full scenario contexts — multi-agent rosters, tenant registries, baselines
primed with enrollment snapshots, and so on. Helpers here are deliberately
chunky because validation tests should read like scenarios, not like
constructor boilerplate.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

# Ensure gavel package is importable when running pytest from the repo root.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    FallbackBehavior,
    HighRiskCategory,
    PurposeDeclaration,
    ResourceAllowlist,
)


# ── Application builder ────────────────────────────────────────
#
# The existing unit-test conftest has `_valid_application()`. We re-export
# a validation-layer variant that lets each test dial high-risk agents,
# prohibited purposes, etc. without duplicating defaults.


def build_application(
    agent_id: str = "agent:validation",
    *,
    display_name: str = "Validation Agent",
    owner: str = "sec@gavel.eu",
    owner_contact: str = "sec@gavel.eu",
    purpose_summary: str = "Integration validation agent for governance checks",
    operational_scope: str = "testing",
    risk_tier: str = "standard",
    tools: list[str] | None = None,
    high_risk_category: HighRiskCategory = HighRiskCategory.NONE,
    **overrides: Any,
) -> EnrollmentApplication:
    """Build an EnrollmentApplication with validation-friendly defaults.

    Tests override only the fields that matter for their scenario, so each
    test's intent is obvious from its call site.
    """
    kwargs = dict(
        agent_id=agent_id,
        display_name=display_name,
        agent_type="llm",
        owner=owner,
        owner_contact=owner_contact,
        budget_tokens=100_000,
        budget_usd=50.0,
        purpose=PurposeDeclaration(
            summary=purpose_summary,
            operational_scope=operational_scope,
            expected_lifetime="session",
            risk_tier=risk_tier,
        ),
        capabilities=CapabilityManifest(
            tools=tools or ["Read", "Write"],
            max_concurrent_chains=1,
            can_spawn_subagents=False,
            network_access=False,
            file_system_access=True,
            execution_access=False,
        ),
        resources=ResourceAllowlist(
            allowed_paths=["/tmp/gavel-validation"],
            allowed_hosts=[],
            allowed_env_vars=["PATH"],
            max_file_size_mb=5.0,
        ),
        boundaries=ActionBoundaries(
            allowed_actions=["read", "write"],
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
        high_risk_category=high_risk_category,
    )
    kwargs.update(overrides)
    return EnrollmentApplication(**kwargs)


@pytest.fixture
def build_app():
    """Expose build_application as a fixture so tests can call it fluently."""
    return build_application


# ── Ollama availability ────────────────────────────────────────
#
# V10 (and future V1) use local Ollama models as evaluators. If the daemon
# isn't running or the required model is missing, the test should skip
# cleanly instead of erroring.


def _ollama_available(model: str) -> tuple[bool, str]:
    """Return (is_available, reason). Non-throwing."""
    try:
        import urllib.request
        import json as _json
        req = urllib.request.Request(
            "http://localhost:11434/api/tags",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            body = _json.loads(resp.read().decode("utf-8"))
        tags = {m.get("name", "").split(":")[0]: m.get("name", "") for m in body.get("models", [])}
        # Match either exact name or family prefix
        for full_name in tags.values():
            if full_name == model or full_name.startswith(model.split(":")[0] + ":"):
                return True, full_name
        return False, f"model '{model}' not found in ollama (have: {sorted(tags.values())})"
    except Exception as exc:  # pragma: no cover — environment-dependent
        return False, f"ollama daemon not reachable: {exc}"


@pytest.fixture(scope="session")
def ollama_auditor() -> dict[str, Any]:
    """Session-scoped Ollama client for the V10 blind auditor.

    Returns a dict with `generate(prompt: str) -> str`. If Ollama is not
    available, the fixture raises pytest.skip with a useful reason.
    """
    preferred_model = "gemma4:26b"
    ok, reason_or_name = _ollama_available(preferred_model)
    if not ok:
        pytest.skip(f"Ollama blind auditor unavailable: {reason_or_name}")

    resolved_model = reason_or_name

    def _generate(prompt: str, *, timeout: int = 300) -> str:
        import urllib.request
        import json as _json
        payload = _json.dumps({
            "model": resolved_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0},  # Deterministic audit
        }).encode("utf-8")
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = _json.loads(resp.read().decode("utf-8"))
        return body.get("response", "")

    return {"model": resolved_model, "generate": _generate}


# ── Deterministic time for drift tests ────────────────────────


@pytest.fixture
def fixed_now() -> datetime:
    """A stable UTC anchor for scenario tests so timestamps compare."""
    return datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)
