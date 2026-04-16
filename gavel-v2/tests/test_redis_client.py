"""Tests for ``gavel.redis_client`` — the Phase 11 Redis bootstrap."""

from __future__ import annotations

import pytest

import gavel.redis_client as redis_client
from gavel.redis_client import (
    REDIS_URL_VAR,
    close_redis,
    get_redis,
    is_redis_configured,
)


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch):
    """Ensure each test starts with the module cache cleared."""
    monkeypatch.setattr(redis_client, "_client", None)
    monkeypatch.delenv(REDIS_URL_VAR, raising=False)
    yield
    monkeypatch.setattr(redis_client, "_client", None)


class TestIsRedisConfigured:
    def test_false_when_env_unset(self):
        assert is_redis_configured() is False

    def test_false_when_env_empty(self, monkeypatch):
        monkeypatch.setenv(REDIS_URL_VAR, "")
        assert is_redis_configured() is False

    def test_true_when_env_set(self, monkeypatch):
        monkeypatch.setenv(REDIS_URL_VAR, "redis://localhost:6379/0")
        assert is_redis_configured() is True


class TestGetRedis:
    async def test_returns_none_when_unconfigured(self):
        assert await get_redis() is None

    async def test_returns_client_when_configured(self, mock_redis_url):
        client = await get_redis()
        assert client is not None
        # Round-trip against the fakeredis instance to prove it's live.
        await client.set(b"gavel:probe", b"1")
        assert await client.get(b"gavel:probe") == b"1"

    async def test_cached_across_calls(self, mock_redis_url):
        a = await get_redis()
        b = await get_redis()
        assert a is b


class TestCloseRedis:
    async def test_noop_when_no_client(self):
        await close_redis()
        assert redis_client._client is None

    async def test_clears_cache(self, monkeypatch, fakeredis_client):
        monkeypatch.setenv(REDIS_URL_VAR, "redis://fake")
        monkeypatch.setattr(redis_client, "_client", fakeredis_client)

        assert await get_redis() is fakeredis_client
        await close_redis()
        assert redis_client._client is None


class TestLazyImport:
    """The redis package must stay optional — no module-level import.

    Asserting the lazy-import directly requires scrubbing ``sys.modules``
    which is fragile on Windows pytest workers. We do the weaker but
    stable check: ``gavel.redis_client``'s module globals must not
    contain a top-level ``redis`` or ``Redis`` binding.
    """

    def test_no_top_level_redis_binding(self):
        assert "Redis" not in vars(redis_client)
        mod_redis = vars(redis_client).get("redis")
        # Only acceptable top-level binding is the stdlib-ish absence;
        # importing ``redis.asyncio as redis`` inside ``get_redis`` must
        # not leak into module globals.
        assert mod_redis is None
