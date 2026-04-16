"""
Event Bus — the central nervous system of the monitoring dashboard.

All governance actions, agent heartbeats, and status changes publish
events here. The SSE endpoint drains events to all connected dashboards.

Phase 11 adds a Redis-backed implementation for cross-replica fan-out.
When ``GAVEL_REDIS_URL`` is set, :func:`create_event_bus` returns a
:class:`RedisEventBus` that uses Redis pub/sub. Otherwise it returns the
original :class:`InProcessEventBus` (renamed from ``EventBus``).

Phase 14 adds :class:`PersistentEventBus` which uses Redis Streams for
durable, ordered, replayable event delivery.  Activated by setting
``GAVEL_EVENT_PERSISTENCE=1`` alongside ``GAVEL_REDIS_URL``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional, Protocol, runtime_checkable

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
# EventRetentionPolicy
# ---------------------------------------------------------------------------


@dataclass
class EventRetentionPolicy:
    """Controls how long and how many events are retained in the stream."""

    max_events: int = 10_000
    max_age_seconds: Optional[int] = 86_400  # 24 hours
    trim_interval_seconds: int = 300  # 5 minutes


# ---------------------------------------------------------------------------
# PersistentEventBus (Redis Streams)
# ---------------------------------------------------------------------------

STREAM_KEY = b"gavel:event_stream"


class PersistentEventBus:
    """Durable event bus using Redis Streams.

    Unlike :class:`RedisEventBus` (pub/sub), events survive subscriber
    disconnects.  Subscribers can resume from a specific stream ID and
    replay historical events.

    Uses ``XADD``, ``XREAD``, ``XRANGE``, ``XLEN``, and ``XTRIM``.
    """

    def __init__(
        self,
        redis_client: Any,
        retention: EventRetentionPolicy | None = None,
    ) -> None:
        self._redis = redis_client
        self._retention = retention or EventRetentionPolicy()
        self._subscribers: list[asyncio.Queue[DashboardEvent]] = []
        self._lock: asyncio.Lock = asyncio.Lock()
        self._running: bool = False
        self._listener_task: asyncio.Task | None = None
        self._last_id: bytes = b"$"  # only new messages for the listener

    # -- publish -------------------------------------------------------------

    async def publish(self, event: DashboardEvent) -> str:
        """Serialize *event* and ``XADD`` to the stream.

        Returns the stream entry ID assigned by Redis.
        """
        data = event.model_dump(mode="json")
        payload = json.dumps(data, default=str)
        try:
            entry_id: bytes = await self._redis.xadd(
                STREAM_KEY, {"data": payload}
            )
            # Auto-trim after publish according to retention policy.
            await self._auto_trim()
            return entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)
        except Exception:
            logger.exception("PersistentEventBus: failed to publish event")
            return ""

    # -- subscribe (live) ----------------------------------------------------

    async def subscribe(self) -> AsyncGenerator[DashboardEvent, None]:
        """Yield events as they arrive.  One generator per dashboard client.

        Events are fanned out from a background listener task that uses
        ``XREAD BLOCK``.
        """
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

    async def subscribe_from(
        self, event_id: str
    ) -> AsyncGenerator[DashboardEvent, None]:
        """Resume subscription from a specific stream ID.

        First replays all events after *event_id*, then switches to live
        delivery via the normal subscriber queue.
        """
        # Replay events after the given ID.
        entries = await self._redis.xrange(STREAM_KEY, min=b"(" + event_id.encode(), max=b"+")
        last_seen = event_id
        for eid, fields in entries:
            raw = fields.get(b"data") or fields.get("data")
            if raw is None:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            try:
                data = json.loads(raw)
                ev = DashboardEvent(**data)
                yield ev
                last_seen = eid.decode() if isinstance(eid, bytes) else str(eid)
            except Exception:
                logger.exception("PersistentEventBus: failed to deserialize replayed event")

        # Now switch to live — we need a queue but only for events AFTER last_seen.
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

    # -- replay --------------------------------------------------------------

    async def replay(
        self,
        since: str | None = None,
        count: int | None = None,
    ) -> list[DashboardEvent]:
        """Fetch historical events from the stream.

        Parameters
        ----------
        since:
            Stream ID to start from (exclusive).  Defaults to ``-``
            (beginning of stream).
        count:
            Maximum number of events to return.
        """
        min_id = b"(" + since.encode() if since else b"-"
        kwargs: dict[str, Any] = {}
        if count is not None:
            kwargs["count"] = count
        entries = await self._redis.xrange(STREAM_KEY, min=min_id, max=b"+", **kwargs)
        events: list[DashboardEvent] = []
        for _eid, fields in entries:
            raw = fields.get(b"data") or fields.get("data")
            if raw is None:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            try:
                data = json.loads(raw)
                events.append(DashboardEvent(**data))
            except Exception:
                logger.exception("PersistentEventBus: failed to deserialize replayed event")
        return events

    # -- stream management ---------------------------------------------------

    async def stream_length(self) -> int:
        """Return the number of entries in the stream (``XLEN``)."""
        try:
            return await self._redis.xlen(STREAM_KEY)
        except Exception:
            return 0

    async def trim(self, max_length: int) -> None:
        """Trim the stream to approximately *max_length* entries."""
        await self._redis.xtrim(STREAM_KEY, maxlen=max_length, approximate=True)

    # -- lifecycle -----------------------------------------------------------

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def start(self) -> None:
        """Start the background stream listener."""
        if self._running:
            return
        self._running = True
        self._last_id = b"$"
        self._listener_task = asyncio.create_task(self._listen())
        logger.info("PersistentEventBus: listener started on stream %s", STREAM_KEY)

    async def stop(self) -> None:
        """Stop the background listener."""
        self._running = False
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        logger.info("PersistentEventBus: listener stopped")

    # -- internal ------------------------------------------------------------

    async def _listen(self) -> None:
        """Background task: XREAD BLOCK and fan out to local subscribers."""
        try:
            while self._running:
                try:
                    result = await self._redis.xread(
                        {STREAM_KEY: self._last_id}, block=1000, count=100
                    )
                except Exception:
                    logger.exception("PersistentEventBus: XREAD failed")
                    await asyncio.sleep(1)
                    continue

                if not result:
                    continue

                for _stream_key, entries in result:
                    for entry_id, fields in entries:
                        self._last_id = entry_id
                        raw = fields.get(b"data") or fields.get("data")
                        if raw is None:
                            continue
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8")
                        try:
                            data = json.loads(raw)
                            event = DashboardEvent(**data)
                        except Exception:
                            logger.exception(
                                "PersistentEventBus: failed to deserialize stream entry"
                            )
                            continue
                        await self._fan_out(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("PersistentEventBus: listener crashed")

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

    async def _auto_trim(self) -> None:
        """Trim stream if it exceeds retention max_events."""
        try:
            length = await self._redis.xlen(STREAM_KEY)
            if length > self._retention.max_events:
                await self._redis.xtrim(
                    STREAM_KEY, maxlen=self._retention.max_events, approximate=True
                )
        except Exception:
            logger.debug("PersistentEventBus: auto-trim skipped", exc_info=True)


# ---------------------------------------------------------------------------
# Backward-compatible alias — conftest.py and many modules import ``EventBus``
# and construct it directly.
# ---------------------------------------------------------------------------

EventBus = InProcessEventBus


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

PERSISTENCE_ENV_VAR = "GAVEL_EVENT_PERSISTENCE"


async def create_event_bus(
    persistent: bool | None = None,
) -> InProcessEventBus | RedisEventBus | PersistentEventBus:
    """Return the appropriate event bus for the current environment.

    When ``GAVEL_REDIS_URL`` is set and reachable:
    - If *persistent* is ``True`` (or ``GAVEL_EVENT_PERSISTENCE=1``),
      returns a started :class:`PersistentEventBus` using Redis Streams.
    - Otherwise returns a started :class:`RedisEventBus` (pub/sub).

    Falls back to :class:`InProcessEventBus` when Redis is not configured
    or unavailable.
    """
    from gavel.redis_client import get_redis, is_redis_configured

    if not is_redis_configured():
        logger.info("create_event_bus: Redis not configured — using InProcessEventBus")
        return InProcessEventBus()

    client = await get_redis()
    if client is None:
        logger.warning("create_event_bus: Redis configured but unavailable — using InProcessEventBus")
        return InProcessEventBus()

    # Resolve persistence flag: explicit param > env var > default (False).
    want_persistent = persistent
    if want_persistent is None:
        want_persistent = os.environ.get(PERSISTENCE_ENV_VAR, "").strip() in ("1", "true", "yes")

    if want_persistent:
        bus: PersistentEventBus | RedisEventBus = PersistentEventBus(client)
        await bus.start()
        logger.info("create_event_bus: using PersistentEventBus (Redis Streams)")
        return bus

    bus = RedisEventBus(client)
    await bus.start()
    logger.info("create_event_bus: using RedisEventBus")
    return bus
