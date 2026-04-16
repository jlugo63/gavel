"""Proof point: FastAPI Depends() overrides actually swap the registry.

Demonstrates that an endpoint parameterized over `get_agent_registry`
will pick up `app.dependency_overrides[get_agent_registry]` instead of
the cached singleton — i.e. DI is wired correctly end-to-end.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from gavel.agents import AgentRegistry
from gavel.dependencies import get_agent_registry, get_enrollment_registry
from gavel.events import EventBus
from gavel.gateway import app


class _SentinelRegistry:
    """Drop-in fake exposing only the surface /v1/agents/{id} touches."""

    SENTINEL = {
        "agent_id": "sentinel-only",
        "display_name": "Sentinel Agent",
        "agent_type": "fake",
        "status": "ACTIVE",
        "trust_score": 0.99,
        "autonomy_tier": 1,
        "registered_at": "2026-01-01T00:00:00+00:00",
        "last_heartbeat": None,
        "capabilities": [],
        "metadata": {"injected": True},
    }

    def __init__(self):
        self.calls: list[str] = []

    class _Record:
        def __init__(self, payload):
            self._payload = payload

        def model_dump(self, mode: str = "json"):
            return dict(self._payload)

    async def get(self, agent_id):
        self.calls.append(agent_id)
        if agent_id == "sentinel-only":
            return self._Record(self.SENTINEL)
        return None


def test_override_swaps_agent_registry_for_endpoint():
    """The endpoint must see the injected fake, not the real registry."""
    fake = _SentinelRegistry()

    app.dependency_overrides[get_agent_registry] = lambda: fake
    try:
        client = TestClient(app)
        resp = client.get("/v1/agents/sentinel-only")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Sentinel-specific values prove the fake was consulted
        assert body["agent_id"] == "sentinel-only"
        assert body["display_name"] == "Sentinel Agent"
        assert body["metadata"] == {"injected": True}
        # Fake recorded the lookup
        assert fake.calls == ["sentinel-only"]
    finally:
        app.dependency_overrides.pop(get_agent_registry, None)


def test_override_returns_404_when_fake_says_unknown():
    """Different override → different behavior. Confirms wiring isn't accidental."""
    fake = _SentinelRegistry()

    app.dependency_overrides[get_agent_registry] = lambda: fake
    try:
        client = TestClient(app)
        resp = client.get("/v1/agents/not-known-to-fake")
        assert resp.status_code == 404
        assert fake.calls == ["not-known-to-fake"]
    finally:
        app.dependency_overrides.pop(get_agent_registry, None)


def test_real_registry_restored_after_override_removed():
    """After clearing the override the endpoint hits the real provider again."""
    fake = _SentinelRegistry()
    app.dependency_overrides[get_agent_registry] = lambda: fake
    app.dependency_overrides.pop(get_agent_registry, None)

    client = TestClient(app)
    # The real registry has no "sentinel-only" agent → 404, but fake.calls stays empty.
    resp = client.get("/v1/agents/sentinel-only")
    assert resp.status_code == 404
    assert fake.calls == []
