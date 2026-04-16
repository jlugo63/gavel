"""
Event Bus — the central nervous system of the monitoring dashboard.

All governance actions, agent heartbeats, and status changes publish
events here. The SSE endpoint drains events to all connected dashboards.

Phase 11 adds a Redis-backed implementation for cross-replica fan-out.
When ``GAVEL_REDIS_URL`` is set, :func:`create_event_bus` returns a
:class:`RedisEventBus` that uses Redis pub/sub. Otherwise it returns the
original :class:`InProcessEventBus` (renamed from ``EventBus``).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from gavel.request_id import get_request_id

logger = logging.getLogger(__name__)


class DashboardEvent(BaseModel):
    """A single event for the monitoring dashboard."""

    event_type: str  # chain_event, agent_heartbeat, agent_status_change, escalation, action
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str = ""
    chain_id: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = Field(default_factory=get_request_id)

    def to_sse(self) -> str:
        """Format as Server-Sent Event."""
        data = self.model_dump(mode="json")
        return f"event: {self.event_type}\ndata: {json.dumps(data, default=str)}\n\n"


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class EventBusProtocol(Protocol):
    """Public interface for event bus implementations."""

    async def publish(self, event: DashboardEvent) -> None: ...

    async def subscribe(self) -> AsyncGenerator[DashboardEvent, None]: ...

    @property
    def subscriber_count(self) -> int: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


# ---------------------------------------------------------------------------
# InProcessEventBus (original implementation)
# ---------------------------------------------------------------------------


class InProcessEventBus:
    """Fan-out event bus using asyncio.Queue per subscriber.

    An asyncio.Lock protects ``_subscribers`` so that concurrent
    ``publish()`` and ``subscribe()`` calls cannot mutate the list
    while it is being iterated.
    """

    def __init__(self):
        self._subscribers: list[asyncio.Queue[DashboardEvent]] = []
        self._lock: asyncio.Lock = asyncio.Lock()

    async def publish(self, event: DashboardEvent) -> None:
        """Push event to all subscriber queues."""
        async with self._lock:
            dead = []
            for i, queue in enumerate(self._subscribers):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(i)
            # Remove dead subscribers (full queues = disconnected clients)
            for i in reversed(dead):
                self._subscribers.pop(i)

    async def subscribe(self) -> AsyncGenerator[DashboardEvent, None]:
        """Yield events as they arrive. One generator per dashboard client."""
        queue: asyncio.Queue[DashboardEvent] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            async with self._lock:
                if queue in self._subscribers:
                    self._subscribers.remove(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def start(self) -> None:
        """No-op for in-process implementation."""

    async def stop(self) -> None:
        """No-op for in-process implementation."""


# ---------------------------------------------------------------------------
# RedisEventBus
# ---------------------------------------------------------------------------

REDIS_CHANNEL = b"gavel:events"


class RedisEventBus:
    """Redis pub/sub event bus for cross-replica dashboard fan-out.

    ``publish()`` serializes the :class:`DashboardEvent` to JSON and
    ``PUBLISH``es it to the ``gavel:events`` channel.  A background
    listener task subscribes to the same channel and fans incoming
    messages out to per-client ``asyncio.Queue`` instances — exactly
    like :class:`InProcessEventBus` does locally.
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client
        self._subscribers: list[asyncio.Queue[DashboardEvent]] = []
        self._lock: asyncio.Lock = asyncio.Lock()
        self._listener_task: asyncio.Task | None = None
        self._pubsub: Any | None = None
        self._running: bool = False

    async def publish(self, event: DashboardEvent) -> None:
        """Serialize *event* to JSON and PUBLISH to Redis."""
        data = event.model_dump(mode="json")
        payload = json.dumps(data, default=str).encode("utf-8")
        try:
            await self._redis.publish(REDIS_CHANNEL, payload)
        except Exception:
            logger.exception("RedisEventBus: failed to publish event")

    async def subscribe(self) -> AsyncGenerator[DashboardEvent, None]:
        """Yield events as they arrive.  One generator per dashboard client."""
        queue: asyncio.Queue[DashboardEvent] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            async with self._lock:
                if queue in self._subscribers:
                    self._subscribers.remove(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Start the background Redis subscription listener."""
        if self._running:
            return
        self._running = True
        self._pubsub = self._redis.pubsub()
        await self._pubsub.subscribe(REDIS_CHANNEL)
        self._listener_task = asyncio.create_task(self._listen())
        logger.info("RedisEventBus: listener started on channel %s", REDIS_CHANNEL)

    async def stop(self) -> None:
        """Stop the background listener and clean up the pub/sub connection."""
        self._running = False
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        if self._pubsub is not None:
            try:
                await self._pubsub.unsubscribe(REDIS_CHANNEL)
                await self._pubsub.aclose()
            except Exception:
                pass
            self._pubsub = None
        logger.info("RedisEventBus: listener stopped")

    # -- internal ------------------------------------------------------------

    async def _listen(self) -> None:
        """Background task: read messages from Redis and fan out locally."""
        try:
            while self._running:
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
                if message is None:
                    # No message within timeout — loop to check _running flag.
                    await asyncio.sleep(0.01)
                    continue
                if message["type"] != "message":
                    continue
                try:
                    raw = message["data"]
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8")
                    data = json.loads(raw)
                    event = DashboardEvent(**data)
                except Exception:
                    logger.exception("RedisEventBus: failed to deserialize message")
                    continue
                await self._fan_out(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("RedisEventBus: listener crashed")

    async def _fan_out(self, event: DashboardEvent) -> None:
        """Push *event* to every local subscriber queue."""
        async with self._lock:
            dead = []
            for i, queue in enumerate(self._subscribers):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(i)
            for i in reversed(dead):
                self._subscribers.pop(i)


# ---------------------------------------------------------------------------
# Backward-compatible alias — conftest.py and many modules import ``EventBus``
# and construct it directly.
# ---------------------------------------------------------------------------

EventBus = InProcessEventBus


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


async def create_event_bus() -> InProcessEventBus | RedisEventBus:
    """Return the appropriate event bus for the current environment.

    When ``GAVEL_REDIS_URL`` is set and reachable, returns a started
    :class:`RedisEventBus`.  Otherwise falls back to the in-process
    implementation.
    """
    from gavel.redis_client import get_redis, is_redis_configured

    if not is_redis_configured():
        logger.info("create_event_bus: Redis not configured — using InProcessEventBus")
        return InProcessEventBus()

    client = await get_redis()
    if client is None:
        logger.warning("create_event_bus: Redis configured but unavailable — using InProcessEventBus")
        return InProcessEventBus()

    bus = RedisEventBus(client)
    await bus.start()
    logger.info("create_event_bus: using RedisEventBus")
    return bus
