"""Async Redis client factory for Gavel coordination services.

Activated by ``GAVEL_REDIS_URL``. When unset, :func:`get_redis` returns
``None`` and downstream subsystems fall back to their InProcess impls.
The redis package is imported lazily so ``import gavel`` works in envs
that never install the ``[redis]`` extra.
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from redis.asyncio import Redis


REDIS_URL_VAR = "GAVEL_REDIS_URL"

_client: Optional["Redis"] = None
_lock = asyncio.Lock()


def _resolve_url() -> Optional[str]:
    url = os.environ.get(REDIS_URL_VAR)
    return url if url else None


def is_redis_configured() -> bool:
    """True if ``GAVEL_REDIS_URL`` is set (and non-empty)."""
    return _resolve_url() is not None


async def get_redis() -> Optional["Redis"]:
    """Return a connected Redis client, or ``None`` if unconfigured.

    Cached per-process behind an ``asyncio.Lock``. Callers pick their
    impl at construction time::

        client = await get_redis()
        return RedisXYZ(client) if client else InProcessXYZ()
    """
    global _client
    if _client is not None:
        return _client

    url = _resolve_url()
    if url is None:
        return None

    async with _lock:
        if _client is not None:
            return _client

        import redis.asyncio as redis  # lazy: keep redis optional.

        candidate = redis.from_url(url, decode_responses=False)
        try:
            await candidate.ping()
        except Exception as exc:
            try:
                await candidate.aclose()
            except Exception:
                pass
            raise RuntimeError(
                f"Redis at {url!r} unreachable: {exc!r}. "
                f"Unset {REDIS_URL_VAR} to disable, or fix connectivity."
            ) from exc

        _client = candidate
        return _client


async def close_redis() -> None:
    """Test-only: close + clear the cached client."""
    global _client
    if _client is None:
        return
    try:
        await _client.aclose()
    except Exception:
        pass
    _client = None


__all__ = [
    "REDIS_URL_VAR",
    "close_redis",
    "get_redis",
    "is_redis_configured",
]
