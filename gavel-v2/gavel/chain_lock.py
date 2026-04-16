"""Distributed chain-lock manager for Gavel Phase 11.

Provides per-chain mutual exclusion so concurrent requests cannot corrupt
hash chains by interleaving appends.  Two implementations:

* **InProcessChainLockManager** — ``asyncio.Lock`` dict, single-instance only.
* **RedisChainLockManager** — ``SET NX EX`` + Lua release (Redlock-style,
  single-Redis).  Safe across replicas.

Use :func:`create_chain_lock_manager` to obtain the correct implementation
based on whether ``GAVEL_REDIS_URL`` is configured.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from typing import AsyncIterator, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# Default lock TTL in seconds — long enough for any realistic chain mutation,
# short enough to auto-release on process crash.
DEFAULT_LOCK_TTL = 30

# Retry parameters for Redis lock acquisition.
_RETRY_DELAY = 0.05  # 50 ms between retries
_MAX_RETRIES = 200  # 50 ms * 200 = 10 s max wait


def _key(chain_id: str) -> str:
    """Redis key for the per-chain lock."""
    return f"chain_lock:{chain_id}"


# Lua script: release lock only if the caller still owns it (token match).
_RELEASE_SCRIPT = (
    "if redis.call('get', KEYS[1]) == ARGV[1] "
    "then return redis.call('del', KEYS[1]) "
    "else return 0 end"
)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ChainLockManager(Protocol):
    """Async context-manager lock per ``chain_id`` + discard."""

    def lock(self, chain_id: str) -> AsyncIterator[None]: ...  # pragma: no cover

    def discard(self, chain_id: str) -> None: ...  # pragma: no cover


# ---------------------------------------------------------------------------
# InProcess implementation
# ---------------------------------------------------------------------------


class InProcessChainLockManager:
    """Single-process chain lock using ``asyncio.Lock`` per chain_id.

    Suitable when only one Gavel replica is running.
    """

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def lock(self, chain_id: str) -> AsyncIterator[None]:
        if chain_id not in self._locks:
            self._locks[chain_id] = asyncio.Lock()
        async with self._locks[chain_id]:
            yield

    def discard(self, chain_id: str) -> None:
        self._locks.pop(chain_id, None)


# ---------------------------------------------------------------------------
# Redis implementation
# ---------------------------------------------------------------------------


class RedisChainLockManager:
    """Distributed chain lock backed by Redis ``SET NX EX``.

    Acquire: ``SET chain_lock:{chain_id} {token} NX EX {ttl}``
    Release: Lua script that deletes the key only if the token matches.

    Parameters
    ----------
    redis:
        An ``redis.asyncio.Redis`` instance (must already be connected).
    ttl:
        Lock auto-expiry in seconds.
    """

    def __init__(self, redis, *, ttl: int = DEFAULT_LOCK_TTL) -> None:  # noqa: ANN001
        self._redis = redis
        self._ttl = ttl

    @asynccontextmanager
    async def lock(self, chain_id: str) -> AsyncIterator[None]:
        key = _key(chain_id)
        token = secrets.token_hex(16).encode()

        # Spin-retry until the lock is acquired or we time out.
        for attempt in range(_MAX_RETRIES):
            acquired = await self._redis.set(key, token, nx=True, ex=self._ttl)
            if acquired:
                break
            await asyncio.sleep(_RETRY_DELAY)
        else:
            raise TimeoutError(
                f"Could not acquire chain lock for {chain_id!r} "
                f"after {_MAX_RETRIES * _RETRY_DELAY:.1f}s"
            )

        try:
            yield
        finally:
            # Safe release — only delete if we still own it.
            await self._redis.eval(_RELEASE_SCRIPT, 1, key, token)

    def discard(self, chain_id: str) -> None:
        """Delete the Redis key unconditionally.

        Called when a chain is permanently removed. Uses a fire-and-forget
        coroutine scheduled on the running loop so the synchronous call
        signature stays compatible with the protocol.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._async_discard(chain_id))
        except RuntimeError:
            # No running loop — nothing to clean up.
            pass

    async def _async_discard(self, chain_id: str) -> None:
        try:
            await self._redis.delete(_key(chain_id))
        except Exception:
            logger.warning("Failed to discard chain lock key for %s", chain_id, exc_info=True)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_chain_lock_manager(
    redis=None,  # noqa: ANN001
) -> ChainLockManager:
    """Return the appropriate :class:`ChainLockManager` implementation.

    When *redis* is supplied (non-``None``), returns a
    :class:`RedisChainLockManager`.  Otherwise returns an
    :class:`InProcessChainLockManager`.

    Callers in production use this via :func:`gavel.dependencies.get_chain_lock_manager`,
    which resolves the Redis client from ``gavel.redis_client``.
    """
    if redis is not None:
        logger.info("Using RedisChainLockManager for distributed chain locking")
        return RedisChainLockManager(redis)
    logger.info("Using InProcessChainLockManager (single-instance mode)")
    return InProcessChainLockManager()


__all__ = [
    "ChainLockManager",
    "InProcessChainLockManager",
    "RedisChainLockManager",
    "create_chain_lock_manager",
]
