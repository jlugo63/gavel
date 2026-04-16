"""
Gavel Rate Limiter & Budget Tracker — ATF S-3 and S-4 runtime enforcement.

ATF S-3 (Rate Limiting):
  Agents declare max_actions_per_minute at enrollment. This module enforces
  that limit at runtime using a sliding window algorithm. Actions that exceed
  the rate are denied with retry-after information.

ATF S-4 (Budget Enforcement):
  Agents declare budget_tokens and budget_usd at enrollment. This module
  tracks cumulative spend per agent and denies actions when the budget is
  exhausted. Budget is decremented per action based on reported token/USD
  costs.

Both enforcers are designed to plug into the gate path (gate.py) before
action execution. They serialise concurrent access with an asyncio.Lock
so they are safe to call from any coroutine on a single event loop.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from redis.asyncio import Redis

log = logging.getLogger("gavel.rate_limit")


# ── S-3: Rate Limiting ───────────────────────────────────────────


class RateLimitResult(BaseModel):
    """Result of a rate limit check."""
    allowed: bool
    current_count: int = 0
    limit: int = 60
    retry_after_seconds: float = 0.0
    reason: str = ""


@runtime_checkable
class RateLimiter(Protocol):
    """Protocol for per-agent sliding window rate limiters (ATF S-3).

    Implementations must provide configure, check_and_record, get_usage,
    reset, and cleanup_inactive with the signatures below.
    """

    async def configure(self, agent_id: str, max_actions_per_minute: int) -> None: ...

    async def check_and_record(self, agent_id: str, now: Optional[float] = None) -> RateLimitResult: ...

    async def get_usage(self, agent_id: str, now: Optional[float] = None) -> dict: ...

    async def reset(self, agent_id: str) -> None: ...

    async def cleanup_inactive(self, max_age_seconds: float = 86400, now: Optional[float] = None) -> int: ...


class InProcessRateLimiter:
    """Per-agent sliding window rate limiter (ATF S-3) — in-process implementation.

    Uses a sliding window log algorithm: each action's timestamp is recorded,
    and the window is pruned on every check. This gives exact per-minute
    enforcement without the boundary issues of fixed windows.

    Concurrency-safe via a single asyncio.Lock.
    """

    def __init__(self) -> None:
        self._windows: dict[str, list[float]] = {}  # agent_id -> sorted timestamps
        self._limits: dict[str, int] = {}            # agent_id -> max_actions_per_minute
        self._last_seen: dict[str, float] = {}       # agent_id -> last activity timestamp
        self._lock = asyncio.Lock()

    async def configure(self, agent_id: str, max_actions_per_minute: int) -> None:
        """Set the rate limit for an agent (called at enrollment)."""
        async with self._lock:
            self._limits[agent_id] = max_actions_per_minute
            if agent_id not in self._windows:
                self._windows[agent_id] = []
        log.debug("Rate limit configured: agent=%s limit=%d/min", agent_id, max_actions_per_minute)

    async def check_and_record(self, agent_id: str, now: Optional[float] = None) -> RateLimitResult:
        """Check if an action is allowed and record it if so.

        This is an atomic check-and-record: if the action is allowed, its
        timestamp is added to the window. If denied, nothing is recorded.

        Args:
            agent_id: The agent requesting the action.
            now: Current timestamp (seconds since epoch). Defaults to time.monotonic().

        Returns:
            RateLimitResult with allowed=True if the action can proceed.
        """
        if now is None:
            now = time.monotonic()

        async with self._lock:
            self._last_seen[agent_id] = now

            limit = self._limits.get(agent_id)
            if limit is None:
                # No limit configured — allow (unconfigured agents aren't rate-limited)
                return RateLimitResult(allowed=True, reason="No rate limit configured")

            window = self._windows.get(agent_id, [])
            cutoff = now - 60.0  # 1-minute sliding window

            # Prune expired entries
            window = [ts for ts in window if ts > cutoff]

            current_count = len(window)

            if current_count >= limit:
                # Denied — calculate retry_after from oldest entry in window
                oldest = window[0] if window else now
                retry_after = oldest + 60.0 - now
                retry_after = max(0.0, retry_after)

                log.warning(
                    "S-3 rate limit exceeded: agent=%s count=%d limit=%d retry_after=%.1fs",
                    agent_id, current_count, limit, retry_after,
                )
                self._windows[agent_id] = window
                return RateLimitResult(
                    allowed=False,
                    current_count=current_count,
                    limit=limit,
                    retry_after_seconds=round(retry_after, 2),
                    reason=f"Rate limit exceeded: {current_count}/{limit} actions per minute",
                )

            # Allowed — record this action
            window.append(now)
            self._windows[agent_id] = window

            return RateLimitResult(
                allowed=True,
                current_count=current_count + 1,
                limit=limit,
                reason="Within rate limit",
            )

    async def get_usage(self, agent_id: str, now: Optional[float] = None) -> dict:
        """Get current rate limit usage for an agent (read-only, no recording)."""
        if now is None:
            now = time.monotonic()

        async with self._lock:
            limit = self._limits.get(agent_id, 0)
            window = self._windows.get(agent_id, [])
            cutoff = now - 60.0
            current = len([ts for ts in window if ts > cutoff])
            return {
                "agent_id": agent_id,
                "current_count": current,
                "limit": limit,
                "remaining": max(0, limit - current),
            }

    async def reset(self, agent_id: str) -> None:
        """Clear the sliding window for an agent (e.g., on re-enrollment)."""
        async with self._lock:
            self._windows[agent_id] = []

    async def cleanup_inactive(self, max_age_seconds: float = 86400, now: Optional[float] = None) -> int:
        """Remove agents with no activity in the last *max_age_seconds*.

        Returns the number of agents removed.
        """
        if now is None:
            now = time.monotonic()
        cutoff = now - max_age_seconds
        removed = 0
        async with self._lock:
            stale = [aid for aid, ts in self._last_seen.items() if ts < cutoff]
            for aid in stale:
                self._windows.pop(aid, None)
                self._limits.pop(aid, None)
                self._last_seen.pop(aid, None)
                removed += 1
        if removed:
            log.info("Rate limiter cleanup: removed %d inactive agents", removed)
        return removed


class RedisRateLimiter:
    """Per-agent sliding window rate limiter (ATF S-3) — Redis-backed implementation.

    Uses Redis sorted sets for the sliding window log: each action is stored
    as a member with score=timestamp. On check, expired entries are pruned
    with ``ZREMRANGEBYSCORE``, the current count obtained with ``ZCARD``,
    and new actions recorded with ``ZADD``.

    Rate limits are stored in ``gavel:rate:limit:{agent_id}`` keys.
    Last-seen timestamps are stored in ``gavel:rate:seen:{agent_id}`` keys.
    Sliding windows are stored in ``gavel:rate:{agent_id}`` sorted sets.

    This implementation enables accurate rate limiting across multiple
    Gavel replicas sharing the same Redis instance.
    """

    # Key prefixes
    _WINDOW_KEY = "gavel:rate:{agent_id}"
    _LIMIT_KEY = "gavel:rate:limit:{agent_id}"
    _SEEN_KEY = "gavel:rate:seen:{agent_id}"

    def __init__(self, redis: "Redis") -> None:
        self._redis = redis

    def _window_key(self, agent_id: str) -> str:
        return self._WINDOW_KEY.format(agent_id=agent_id)

    def _limit_key(self, agent_id: str) -> str:
        return self._LIMIT_KEY.format(agent_id=agent_id)

    def _seen_key(self, agent_id: str) -> str:
        return self._SEEN_KEY.format(agent_id=agent_id)

    async def configure(self, agent_id: str, max_actions_per_minute: int) -> None:
        """Set the rate limit for an agent (called at enrollment)."""
        await self._redis.set(self._limit_key(agent_id), str(max_actions_per_minute))
        log.debug("Rate limit configured (Redis): agent=%s limit=%d/min", agent_id, max_actions_per_minute)

    async def check_and_record(self, agent_id: str, now: Optional[float] = None) -> RateLimitResult:
        """Check if an action is allowed and record it if so.

        Uses a Redis transaction (pipeline) to atomically prune the window,
        check the count, and conditionally record the action.

        Args:
            agent_id: The agent requesting the action.
            now: Current timestamp (seconds since epoch). Defaults to time.time().

        Returns:
            RateLimitResult with allowed=True if the action can proceed.
        """
        if now is None:
            now = time.time()

        # Update last-seen
        await self._redis.set(self._seen_key(agent_id), str(now))

        # Check if a limit is configured
        raw_limit = await self._redis.get(self._limit_key(agent_id))
        if raw_limit is None:
            return RateLimitResult(allowed=True, reason="No rate limit configured")

        limit = int(raw_limit)
        wkey = self._window_key(agent_id)
        cutoff = now - 60.0

        # Use a pipeline for atomic prune + count + conditional add
        pipe = self._redis.pipeline(transaction=True)
        pipe.zremrangebyscore(wkey, "-inf", cutoff)
        pipe.zcard(wkey)
        results = await pipe.execute()

        current_count = results[1]

        if current_count >= limit:
            # Denied — find oldest entry to compute retry_after
            oldest_entries = await self._redis.zrange(wkey, 0, 0, withscores=True)
            if oldest_entries:
                oldest_ts = oldest_entries[0][1]
            else:
                oldest_ts = now
            retry_after = max(0.0, oldest_ts + 60.0 - now)

            log.warning(
                "S-3 rate limit exceeded (Redis): agent=%s count=%d limit=%d retry_after=%.1fs",
                agent_id, current_count, limit, retry_after,
            )
            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                limit=limit,
                retry_after_seconds=round(retry_after, 2),
                reason=f"Rate limit exceeded: {current_count}/{limit} actions per minute",
            )

        # Allowed — record this action. Use timestamp as both score and
        # a unique member (append a counter suffix to avoid collisions
        # when multiple actions share the exact same timestamp).
        member = f"{now}:{current_count}"
        pipe2 = self._redis.pipeline(transaction=True)
        pipe2.zadd(wkey, {member: now})
        # Set a TTL on the sorted set so stale windows auto-expire
        pipe2.expire(wkey, 120)
        await pipe2.execute()

        return RateLimitResult(
            allowed=True,
            current_count=current_count + 1,
            limit=limit,
            reason="Within rate limit",
        )

    async def get_usage(self, agent_id: str, now: Optional[float] = None) -> dict:
        """Get current rate limit usage for an agent (read-only, no recording)."""
        if now is None:
            now = time.time()

        raw_limit = await self._redis.get(self._limit_key(agent_id))
        limit = int(raw_limit) if raw_limit is not None else 0

        wkey = self._window_key(agent_id)
        cutoff = now - 60.0

        # Prune and count
        pipe = self._redis.pipeline(transaction=True)
        pipe.zremrangebyscore(wkey, "-inf", cutoff)
        pipe.zcard(wkey)
        results = await pipe.execute()
        current = results[1]

        return {
            "agent_id": agent_id,
            "current_count": current,
            "limit": limit,
            "remaining": max(0, limit - current),
        }

    async def reset(self, agent_id: str) -> None:
        """Clear the sliding window for an agent (e.g., on re-enrollment)."""
        await self._redis.delete(self._window_key(agent_id))

    async def cleanup_inactive(self, max_age_seconds: float = 86400, now: Optional[float] = None) -> int:
        """Remove agents with no activity in the last *max_age_seconds*.

        Scans for ``gavel:rate:seen:*`` keys and removes agents whose
        last-seen timestamp is older than the cutoff.

        Returns the number of agents removed.
        """
        if now is None:
            now = time.time()
        cutoff = now - max_age_seconds
        removed = 0

        # Scan for all seen keys
        pattern = "gavel:rate:seen:*"
        async for key in self._redis.scan_iter(match=pattern):
            raw_ts = await self._redis.get(key)
            if raw_ts is None:
                continue
            ts = float(raw_ts)
            if ts < cutoff:
                # Extract agent_id from key
                if isinstance(key, bytes):
                    key_str = key.decode("utf-8")
                else:
                    key_str = key
                agent_id = key_str.removeprefix("gavel:rate:seen:")
                pipe = self._redis.pipeline(transaction=True)
                pipe.delete(self._window_key(agent_id))
                pipe.delete(self._limit_key(agent_id))
                pipe.delete(self._seen_key(agent_id))
                await pipe.execute()
                removed += 1

        if removed:
            log.info("Rate limiter cleanup (Redis): removed %d inactive agents", removed)
        return removed


def create_rate_limiter(redis: Optional["Redis"] = None) -> RateLimiter:
    """Factory: return a Redis-backed limiter if *redis* is provided, else in-process.

    Typical usage from the DI layer::

        client = await get_redis()
        limiter = create_rate_limiter(client)
    """
    if redis is not None:
        return RedisRateLimiter(redis)  # type: ignore[return-value]
    return InProcessRateLimiter()  # type: ignore[return-value]


# ── S-4: Budget Enforcement ──────────────────────────────────────


class BudgetStatus(BaseModel):
    """Current budget state for an agent."""
    agent_id: str
    budget_tokens: int = 0          # Total token budget declared at enrollment
    budget_usd: float = 0.0         # Total USD budget declared at enrollment
    tokens_used: int = 0            # Cumulative tokens consumed
    usd_used: float = 0.0           # Cumulative USD consumed
    tokens_remaining: int = 0       # Tokens left
    usd_remaining: float = 0.0     # USD left
    exhausted: bool = False         # True if any budget dimension is exhausted


class BudgetCheckResult(BaseModel):
    """Result of a budget check."""
    allowed: bool
    reason: str = ""
    tokens_remaining: int = 0
    usd_remaining: float = 0.0


class BudgetTracker:
    """Per-agent cumulative budget tracker (ATF S-4).

    Tracks token and USD spend per agent. Agents declare their budget at
    enrollment; this module decrements on each action and denies when
    exhausted.

    An agent's budget is exhausted when EITHER dimension hits zero
    (tokens or USD), whichever is configured. If only one dimension is
    set (e.g., budget_tokens > 0 but budget_usd == 0), only that
    dimension is enforced.

    Concurrency-safe via a single asyncio.Lock.
    """

    def __init__(self) -> None:
        self._budgets: dict[str, dict] = {}  # agent_id -> budget state
        self._lock = asyncio.Lock()

    async def configure(self, agent_id: str, budget_tokens: int = 0, budget_usd: float = 0.0) -> None:
        """Set the budget for an agent (called at enrollment).

        Args:
            agent_id: The agent ID.
            budget_tokens: Maximum token budget (0 = not enforced).
            budget_usd: Maximum USD budget (0.0 = not enforced).
        """
        async with self._lock:
            self._budgets[agent_id] = {
                "budget_tokens": budget_tokens,
                "budget_usd": budget_usd,
                "tokens_used": 0,
                "usd_used": 0.0,
            }
        log.debug(
            "Budget configured: agent=%s tokens=%d usd=%.2f",
            agent_id, budget_tokens, budget_usd,
        )

    async def check_and_decrement(
        self,
        agent_id: str,
        token_cost: int = 0,
        usd_cost: float = 0.0,
    ) -> BudgetCheckResult:
        """Check if an action is within budget and decrement if so.

        This is atomic: if the action would exceed the budget, nothing is
        decremented. If allowed, the costs are subtracted immediately.

        Args:
            agent_id: The agent requesting the action.
            token_cost: Number of tokens this action will consume.
            usd_cost: USD cost of this action.

        Returns:
            BudgetCheckResult with allowed=True if within budget.
        """
        async with self._lock:
            state = self._budgets.get(agent_id)
            if state is None:
                # No budget configured — allow
                return BudgetCheckResult(
                    allowed=True,
                    reason="No budget configured",
                )

            budget_tokens = state["budget_tokens"]
            budget_usd = state["budget_usd"]
            tokens_used = state["tokens_used"]
            usd_used = state["usd_used"]

            # Check token budget (only if configured)
            if budget_tokens > 0:
                tokens_remaining = budget_tokens - tokens_used
                if token_cost > tokens_remaining:
                    log.warning(
                        "S-4 token budget exceeded: agent=%s used=%d budget=%d cost=%d",
                        agent_id, tokens_used, budget_tokens, token_cost,
                    )
                    return BudgetCheckResult(
                        allowed=False,
                        reason=f"Token budget exhausted: {tokens_remaining} remaining, {token_cost} requested",
                        tokens_remaining=tokens_remaining,
                        usd_remaining=round(budget_usd - usd_used, 6) if budget_usd > 0 else 0.0,
                    )

            # Check USD budget (only if configured)
            if budget_usd > 0:
                usd_remaining = budget_usd - usd_used
                if usd_cost > usd_remaining + 1e-9:  # float tolerance
                    log.warning(
                        "S-4 USD budget exceeded: agent=%s used=%.4f budget=%.4f cost=%.4f",
                        agent_id, usd_used, budget_usd, usd_cost,
                    )
                    return BudgetCheckResult(
                        allowed=False,
                        reason=f"USD budget exhausted: ${usd_remaining:.4f} remaining, ${usd_cost:.4f} requested",
                        tokens_remaining=budget_tokens - tokens_used if budget_tokens > 0 else 0,
                        usd_remaining=round(usd_remaining, 6),
                    )

            # Within budget — decrement
            state["tokens_used"] += token_cost
            state["usd_used"] += usd_cost

            new_tokens_remaining = budget_tokens - state["tokens_used"] if budget_tokens > 0 else 0
            new_usd_remaining = round(budget_usd - state["usd_used"], 6) if budget_usd > 0 else 0.0

            return BudgetCheckResult(
                allowed=True,
                reason="Within budget",
                tokens_remaining=new_tokens_remaining,
                usd_remaining=new_usd_remaining,
            )

    async def get_status(self, agent_id: str) -> Optional[BudgetStatus]:
        """Get current budget status for an agent."""
        async with self._lock:
            state = self._budgets.get(agent_id)
            if state is None:
                return None

            budget_tokens = state["budget_tokens"]
            budget_usd = state["budget_usd"]
            tokens_used = state["tokens_used"]
            usd_used = state["usd_used"]
            tokens_remaining = max(0, budget_tokens - tokens_used)
            usd_remaining = round(max(0.0, budget_usd - usd_used), 6)

            # Exhausted if any configured dimension is at zero
            exhausted = False
            if budget_tokens > 0 and tokens_remaining <= 0:
                exhausted = True
            if budget_usd > 0 and usd_remaining <= 0:
                exhausted = True

            return BudgetStatus(
                agent_id=agent_id,
                budget_tokens=budget_tokens,
                budget_usd=budget_usd,
                tokens_used=tokens_used,
                usd_used=round(usd_used, 6),
                tokens_remaining=tokens_remaining,
                usd_remaining=usd_remaining,
                exhausted=exhausted,
            )

    async def reset(self, agent_id: str) -> None:
        """Reset an agent's usage counters (keeps budget limits)."""
        async with self._lock:
            state = self._budgets.get(agent_id)
            if state:
                state["tokens_used"] = 0
                state["usd_used"] = 0.0
