"""Tests for gavel.chain_lock — InProcess and Redis implementations."""

from __future__ import annotations

import asyncio

import pytest

from gavel.chain_lock import (
    ChainLockManager,
    InProcessChainLockManager,
    RedisChainLockManager,
    create_chain_lock_manager,
)


# -----------------------------------------------------------------------
# InProcessChainLockManager
# -----------------------------------------------------------------------


class TestInProcessChainLockManager:
    """Unit tests for the asyncio.Lock-based implementation."""

    @pytest.mark.asyncio
    async def test_lock_acquires_and_releases(self):
        mgr = InProcessChainLockManager()
        async with mgr.lock("chain-1"):
            # Inside the lock — should not raise.
            pass

    @pytest.mark.asyncio
    async def test_lock_serializes_concurrent_access(self):
        """Two coroutines on the same chain_id must not overlap."""
        mgr = InProcessChainLockManager()
        order: list[str] = []

        async def worker(name: str):
            async with mgr.lock("chain-1"):
                order.append(f"{name}-enter")
                await asyncio.sleep(0.01)
                order.append(f"{name}-exit")

        await asyncio.gather(worker("a"), worker("b"))

        # One must fully complete before the other starts.
        assert order in (
            ["a-enter", "a-exit", "b-enter", "b-exit"],
            ["b-enter", "b-exit", "a-enter", "a-exit"],
        )

    @pytest.mark.asyncio
    async def test_different_chains_do_not_block(self):
        """Locks on different chain_ids are independent."""
        mgr = InProcessChainLockManager()
        order: list[str] = []

        async def worker(chain_id: str):
            async with mgr.lock(chain_id):
                order.append(f"{chain_id}-enter")
                await asyncio.sleep(0.01)
                order.append(f"{chain_id}-exit")

        await asyncio.gather(worker("chain-1"), worker("chain-2"))

        # Both should enter before either exits (parallel execution).
        assert order[:2] == ["chain-1-enter", "chain-2-enter"] or \
               order[:2] == ["chain-2-enter", "chain-1-enter"]

    @pytest.mark.asyncio
    async def test_discard_removes_lock(self):
        mgr = InProcessChainLockManager()
        async with mgr.lock("chain-1"):
            pass
        assert "chain-1" in mgr._locks
        mgr.discard("chain-1")
        assert "chain-1" not in mgr._locks

    @pytest.mark.asyncio
    async def test_discard_nonexistent_is_noop(self):
        mgr = InProcessChainLockManager()
        mgr.discard("no-such-chain")  # Should not raise.

    def test_implements_protocol(self):
        mgr = InProcessChainLockManager()
        assert isinstance(mgr, ChainLockManager)


# -----------------------------------------------------------------------
# RedisChainLockManager
# -----------------------------------------------------------------------


class TestRedisChainLockManager:
    """Unit tests for the Redis-backed implementation using fakeredis."""

    @pytest.mark.asyncio
    async def test_lock_acquires_and_releases(self, fakeredis_client):
        mgr = RedisChainLockManager(fakeredis_client, ttl=5)
        async with mgr.lock("chain-1"):
            # Key should exist in Redis while held.
            val = await fakeredis_client.get("chain_lock:chain-1")
            assert val is not None

        # After release, key should be gone.
        val = await fakeredis_client.get("chain_lock:chain-1")
        assert val is None

    @pytest.mark.asyncio
    async def test_lock_serializes_concurrent_access(self, fakeredis_client):
        """Two coroutines on the same chain_id must not overlap."""
        mgr = RedisChainLockManager(fakeredis_client, ttl=5)
        order: list[str] = []

        async def worker(name: str):
            async with mgr.lock("chain-1"):
                order.append(f"{name}-enter")
                await asyncio.sleep(0.01)
                order.append(f"{name}-exit")

        await asyncio.gather(worker("a"), worker("b"))

        assert order in (
            ["a-enter", "a-exit", "b-enter", "b-exit"],
            ["b-enter", "b-exit", "a-enter", "a-exit"],
        )

    @pytest.mark.asyncio
    async def test_different_chains_do_not_block(self, fakeredis_client):
        mgr = RedisChainLockManager(fakeredis_client, ttl=5)
        order: list[str] = []

        async def worker(chain_id: str):
            async with mgr.lock(chain_id):
                order.append(f"{chain_id}-enter")
                await asyncio.sleep(0.01)
                order.append(f"{chain_id}-exit")

        await asyncio.gather(worker("chain-1"), worker("chain-2"))

        assert order[:2] == ["chain-1-enter", "chain-2-enter"] or \
               order[:2] == ["chain-2-enter", "chain-1-enter"]

    @pytest.mark.asyncio
    async def test_lua_release_safety(self, fakeredis_client):
        """Release must NOT delete the key if another holder took over."""
        mgr = RedisChainLockManager(fakeredis_client, ttl=5)

        # Acquire then simulate another holder overwriting the key.
        async with mgr.lock("chain-1"):
            # Overwrite with a different token while we still "hold" it.
            await fakeredis_client.set("chain_lock:chain-1", b"intruder-token")

        # The Lua release should have been a no-op because the token didn't match.
        val = await fakeredis_client.get("chain_lock:chain-1")
        assert val == b"intruder-token"

    @pytest.mark.asyncio
    async def test_lock_timeout_raises(self, fakeredis_client):
        """If the lock can't be acquired within retries, TimeoutError is raised."""
        # Manually hold the lock.
        await fakeredis_client.set("chain_lock:chain-1", b"held", nx=True, ex=60)

        # Use a very short retry budget.
        mgr = RedisChainLockManager(fakeredis_client, ttl=5)
        # Patch retry params for fast failure.
        import gavel.chain_lock as cl
        orig_retries = cl._MAX_RETRIES
        orig_delay = cl._RETRY_DELAY
        cl._MAX_RETRIES = 3
        cl._RETRY_DELAY = 0.01
        try:
            with pytest.raises(TimeoutError, match="Could not acquire chain lock"):
                async with mgr.lock("chain-1"):
                    pass  # pragma: no cover
        finally:
            cl._MAX_RETRIES = orig_retries
            cl._RETRY_DELAY = orig_delay

    @pytest.mark.asyncio
    async def test_discard_deletes_key(self, fakeredis_client):
        mgr = RedisChainLockManager(fakeredis_client, ttl=5)
        await fakeredis_client.set("chain_lock:chain-1", b"some-token")

        mgr.discard("chain-1")
        # discard fires a background task — give it a moment.
        await asyncio.sleep(0.05)

        val = await fakeredis_client.get("chain_lock:chain-1")
        assert val is None

    @pytest.mark.asyncio
    async def test_discard_nonexistent_is_noop(self, fakeredis_client):
        mgr = RedisChainLockManager(fakeredis_client, ttl=5)
        mgr.discard("no-such-chain")  # Should not raise.
        await asyncio.sleep(0.05)

    def test_implements_protocol(self, fakeredis_client):
        mgr = RedisChainLockManager(fakeredis_client)
        assert isinstance(mgr, ChainLockManager)


# -----------------------------------------------------------------------
# Factory
# -----------------------------------------------------------------------


class TestFactory:
    """Tests for create_chain_lock_manager()."""

    def test_returns_inprocess_when_redis_is_none(self):
        mgr = create_chain_lock_manager(redis=None)
        assert isinstance(mgr, InProcessChainLockManager)

    def test_returns_redis_when_client_provided(self, fakeredis_client):
        mgr = create_chain_lock_manager(redis=fakeredis_client)
        assert isinstance(mgr, RedisChainLockManager)


# -----------------------------------------------------------------------
# DI integration
# -----------------------------------------------------------------------


class TestDIWiring:
    """Verify get_chain_lock_manager() from dependencies.py."""

    def test_returns_inprocess_without_redis(self):
        from gavel.dependencies import get_chain_lock_manager, reset_dependency_cache

        reset_dependency_cache()
        mgr = get_chain_lock_manager()
        assert isinstance(mgr, InProcessChainLockManager)

    def test_returns_redis_with_mock_redis_url(self, mock_redis_url):
        from gavel.dependencies import get_chain_lock_manager, reset_dependency_cache

        reset_dependency_cache()
        mgr = get_chain_lock_manager()
        assert isinstance(mgr, RedisChainLockManager)
