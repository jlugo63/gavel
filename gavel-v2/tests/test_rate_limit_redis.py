"""Tests for the Redis-backed RateLimiter implementation (ATF S-3).

Uses the ``fakeredis_client`` fixture from conftest.py to provide an
in-memory Redis-compatible backend without requiring a real Redis server.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from gavel.rate_limit import (
    InProcessRateLimiter,
    RateLimitResult,
    RateLimiter,
    RedisRateLimiter,
    create_rate_limiter,
)


# ══════════════════════════════════════════════════════════════
# Factory tests
# ══════════════════════════════════════════════════════════════


class TestCreateRateLimiter:
    """Verify the factory dispatches correctly."""

    def test_returns_in_process_when_no_redis(self):
        limiter = create_rate_limiter(redis=None)
        assert isinstance(limiter, InProcessRateLimiter)

    async def test_returns_redis_when_client_provided(self, fakeredis_client):
        limiter = create_rate_limiter(redis=fakeredis_client)
        assert isinstance(limiter, RedisRateLimiter)


# ══════════════════════════════════════════════════════════════
# RedisRateLimiter tests
# ══════════════════════════════════════════════════════════════


class TestRedisRateLimiter:
    """Sliding window rate limiter tests — Redis-backed implementation."""

    async def test_allows_actions_within_limit(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=5)

        for i in range(5):
            result = await rl.check_and_record("agent:a", now=1000.0 + i * 0.1)
            assert result.allowed is True
            assert result.current_count == i + 1
            assert result.limit == 5

    async def test_denies_action_exceeding_limit(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=3)

        now = 1000.0
        for i in range(3):
            result = await rl.check_and_record("agent:a", now=now + i * 0.1)
            assert result.allowed is True

        result = await rl.check_and_record("agent:a", now=now + 0.5)
        assert result.allowed is False
        assert result.current_count == 3
        assert result.limit == 3
        assert "exceeded" in result.reason.lower()

    async def test_retry_after_is_positive(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 1.0)

        result = await rl.check_and_record("agent:a", now=now + 2.0)
        assert result.allowed is False
        assert result.retry_after_seconds > 0
        assert result.retry_after_seconds <= 60.0

    async def test_window_slides_allows_after_expiry(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 1.0)

        # Should be denied at now + 2
        result = await rl.check_and_record("agent:a", now=now + 2.0)
        assert result.allowed is False

        # After 60 seconds, the window has slid past both entries
        result = await rl.check_and_record("agent:a", now=now + 61.0)
        assert result.allowed is True
        assert result.current_count == 1

    async def test_unconfigured_agent_is_allowed(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        result = await rl.check_and_record("agent:unknown")
        assert result.allowed is True

    async def test_separate_agents_have_separate_limits(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=1)
        await rl.configure("agent:b", max_actions_per_minute=1)

        now = 1000.0
        result_a = await rl.check_and_record("agent:a", now=now)
        result_b = await rl.check_and_record("agent:b", now=now)

        assert result_a.allowed is True
        assert result_b.allowed is True

        # Both should now be at limit
        assert (await rl.check_and_record("agent:a", now=now + 0.1)).allowed is False
        assert (await rl.check_and_record("agent:b", now=now + 0.1)).allowed is False

    async def test_get_usage(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=10)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 1.0)

        usage = await rl.get_usage("agent:a", now=now + 2.0)
        assert usage["current_count"] == 2
        assert usage["limit"] == 10
        assert usage["remaining"] == 8

    async def test_reset_clears_window(self, fakeredis_client):
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 0.1)

        # At limit
        assert (await rl.check_and_record("agent:a", now=now + 0.2)).allowed is False

        # Reset
        await rl.reset("agent:a")

        # Should be allowed again
        result = await rl.check_and_record("agent:a", now=now + 0.3)
        assert result.allowed is True
        assert result.current_count == 1

    async def test_denied_action_is_not_recorded(self, fakeredis_client):
        """Denied actions should not consume a window slot."""
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 0.1)

        # These denials should not add to the window
        await rl.check_and_record("agent:a", now=now + 0.2)
        await rl.check_and_record("agent:a", now=now + 0.3)

        usage = await rl.get_usage("agent:a", now=now + 0.4)
        assert usage["current_count"] == 2  # Still just 2, not 4

    async def test_high_rate_limit(self, fakeredis_client):
        """Agent with a high limit should handle many actions."""
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:fast", max_actions_per_minute=1000)

        now = 1000.0
        for i in range(100):
            result = await rl.check_and_record("agent:fast", now=now + i * 0.01)
            assert result.allowed is True

        usage = await rl.get_usage("agent:fast", now=now + 1.0)
        assert usage["current_count"] == 100
        assert usage["remaining"] == 900

    async def test_concurrent_check_serializes(self, fakeredis_client):
        """Fire many concurrent check_and_record calls and verify correctness.

        Note: Redis commands are inherently serialized per-connection, so
        concurrent coroutines issuing pipelined commands will interleave
        correctly. We verify the final count is accurate.
        """
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:c", max_actions_per_minute=40)

        now = 1000.0
        results = await asyncio.gather(
            *[rl.check_and_record("agent:c", now=now + i * 0.001) for i in range(50)]
        )

        allowed = [r for r in results if r.allowed]
        denied = [r for r in results if not r.allowed]

        # Should allow exactly 40
        assert len(allowed) == 40
        assert len(denied) == 10

        usage = await rl.get_usage("agent:c", now=now + 0.1)
        assert usage["current_count"] == 40
        assert usage["remaining"] == 0

    async def test_cleanup_inactive_removes_stale(self, fakeredis_client):
        """cleanup_inactive should remove agents with old last-seen timestamps."""
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("old-agent", max_actions_per_minute=10)
        await rl.configure("new-agent", max_actions_per_minute=10)

        now = 100000.0
        await rl.check_and_record("old-agent", now=now - 90000)
        await rl.check_and_record("new-agent", now=now - 100)

        removed = await rl.cleanup_inactive(max_age_seconds=86400, now=now)
        assert removed == 1

        # old-agent's data should be gone
        usage_old = await rl.get_usage("old-agent", now=now)
        assert usage_old["limit"] == 0  # limit key deleted
        assert usage_old["current_count"] == 0  # window deleted

        # new-agent should still be intact
        usage_new = await rl.get_usage("new-agent", now=now)
        assert usage_new["limit"] == 10

    async def test_cleanup_no_stale(self, fakeredis_client):
        """cleanup_inactive with no stale agents returns 0."""
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("active", max_actions_per_minute=10)

        now = 1000.0
        await rl.check_and_record("active", now=now)

        removed = await rl.cleanup_inactive(max_age_seconds=86400, now=now)
        assert removed == 0

    async def test_configure_updates_limit(self, fakeredis_client):
        """Calling configure twice should update the limit."""
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=5)
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 0.1)

        result = await rl.check_and_record("agent:a", now=now + 0.2)
        assert result.allowed is False
        assert result.limit == 2

    async def test_get_usage_unconfigured(self, fakeredis_client):
        """get_usage for an unknown agent returns zeros."""
        rl = RedisRateLimiter(fakeredis_client)
        usage = await rl.get_usage("agent:nobody", now=1000.0)
        assert usage["limit"] == 0
        assert usage["current_count"] == 0
        assert usage["remaining"] == 0

    async def test_result_type(self, fakeredis_client):
        """All returns should be RateLimitResult instances."""
        rl = RedisRateLimiter(fakeredis_client)
        await rl.configure("agent:a", max_actions_per_minute=1)

        r1 = await rl.check_and_record("agent:a", now=1000.0)
        assert isinstance(r1, RateLimitResult)
        assert r1.allowed is True

        r2 = await rl.check_and_record("agent:a", now=1000.1)
        assert isinstance(r2, RateLimitResult)
        assert r2.allowed is False


# ══════════════════════════════════════════════════════════════
# Protocol conformance
# ══════════════════════════════════════════════════════════════


class TestProtocolConformance:
    """Verify both implementations satisfy the RateLimiter protocol."""

    def test_in_process_is_rate_limiter(self):
        assert isinstance(InProcessRateLimiter(), RateLimiter)

    async def test_redis_is_rate_limiter(self, fakeredis_client):
        assert isinstance(RedisRateLimiter(fakeredis_client), RateLimiter)
