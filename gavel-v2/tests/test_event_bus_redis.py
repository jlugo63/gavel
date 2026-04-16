"""Tests for RedisEventBus — Phase 11 Wave 2.

Validates Redis pub/sub fan-out, serialization round-trip, multi-subscriber
delivery, lifecycle management, and factory selection logic.

fakeredis pub/sub support is limited, so we mock the Redis pub/sub
interface where necessary to avoid test-infrastructure blocking.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gavel.events import (
    DashboardEvent,
    EventBus,
    EventBusProtocol,
    InProcessEventBus,
    RedisEventBus,
    create_event_bus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: Any) -> DashboardEvent:
    defaults = dict(
        event_type="chain_event",
        agent_id="agent:test",
        chain_id="chain-001",
        payload={"action": "approve"},
        request_id="req-123",
    )
    defaults.update(overrides)
    return DashboardEvent(**defaults)


class FakePubSub:
    """Minimal fake Redis PubSub that supports subscribe/get_message/unsubscribe."""

    def __init__(self):
        self._channels: set[bytes] = set()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._subscribed = False

    async def subscribe(self, channel: bytes) -> None:
        self._channels.add(channel)
        self._subscribed = True

    async def unsubscribe(self, channel: bytes) -> None:
        self._channels.discard(channel)

    async def aclose(self) -> None:
        pass

    async def get_message(self, ignore_subscribe_messages: bool = True, timeout: float = 1.0) -> dict | None:
        try:
            return self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return None

    def inject_message(self, channel: bytes, data: bytes) -> None:
        """Test helper: push a message as if it came from Redis."""
        self._queue.put_nowait({
            "type": "message",
            "channel": channel,
            "data": data,
        })


class FakeRedisWithPubSub:
    """Minimal fake Redis client that returns a FakePubSub."""

    def __init__(self):
        self._pubsub = FakePubSub()
        self._published: list[tuple[bytes, bytes]] = []

    def pubsub(self) -> FakePubSub:
        return self._pubsub

    async def publish(self, channel: bytes, data: bytes) -> int:
        self._published.append((channel, data))
        # Simulate the message arriving on the subscription side.
        self._pubsub.inject_message(channel, data)
        return 1


# ---------------------------------------------------------------------------
# InProcessEventBus (backward-compat alias)
# ---------------------------------------------------------------------------


class TestEventBusAlias:
    """EventBus should remain usable as a constructor alias."""

    def test_alias_is_in_process(self):
        assert EventBus is InProcessEventBus

    def test_construct_via_alias(self):
        bus = EventBus()
        assert isinstance(bus, InProcessEventBus)


# ---------------------------------------------------------------------------
# InProcessEventBus — start/stop are no-ops
# ---------------------------------------------------------------------------


class TestInProcessEventBusLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop_noop(self):
        bus = InProcessEventBus()
        await bus.start()  # should not raise
        await bus.stop()   # should not raise

    @pytest.mark.asyncio
    async def test_publish_subscribe(self):
        bus = InProcessEventBus()
        event = _make_event()

        gen = bus.subscribe()
        subscriber = gen.__aiter__()

        # Start the subscriber — it blocks on queue.get() so run in a task
        task = asyncio.create_task(subscriber.__anext__())
        await asyncio.sleep(0.05)  # let the task register the queue

        # Publish after subscribing
        await bus.publish(event)

        got = await asyncio.wait_for(task, timeout=1.0)
        assert got.event_type == "chain_event"
        assert got.agent_id == "agent:test"

        # Cleanup
        await gen.aclose()

    @pytest.mark.asyncio
    async def test_subscriber_count(self):
        bus = InProcessEventBus()
        assert bus.subscriber_count == 0

        gen1 = bus.subscribe()
        sub1 = gen1.__aiter__()
        task = asyncio.create_task(sub1.__anext__())
        await asyncio.sleep(0.05)
        assert bus.subscriber_count == 1

        gen2 = bus.subscribe()
        sub2 = gen2.__aiter__()
        task2 = asyncio.create_task(sub2.__anext__())
        await asyncio.sleep(0.05)
        assert bus.subscriber_count == 2

        # Cancel tasks first (they hold the generator open), then close generators.
        task.cancel()
        task2.cancel()
        for t in (task, task2):
            try:
                await t
            except (asyncio.CancelledError, StopAsyncIteration):
                pass
        await gen1.aclose()
        await gen2.aclose()


# ---------------------------------------------------------------------------
# RedisEventBus — publish
# ---------------------------------------------------------------------------


class TestRedisEventBusPublish:
    @pytest.mark.asyncio
    async def test_publish_serializes_to_redis(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)

        event = _make_event()
        await bus.publish(event)

        assert len(fake_redis._published) == 1
        channel, raw = fake_redis._published[0]
        assert channel == b"gavel:events"

        data = json.loads(raw)
        assert data["event_type"] == "chain_event"
        assert data["agent_id"] == "agent:test"
        assert data["chain_id"] == "chain-001"
        assert data["payload"] == {"action": "approve"}

    @pytest.mark.asyncio
    async def test_publish_handles_redis_error(self):
        """publish() should log but not raise when Redis fails."""
        mock_redis = AsyncMock()
        mock_redis.publish.side_effect = ConnectionError("gone")
        bus = RedisEventBus(mock_redis)

        # Should not raise
        await bus.publish(_make_event())


# ---------------------------------------------------------------------------
# RedisEventBus — subscribe + fan-out
# ---------------------------------------------------------------------------


class TestRedisEventBusSubscribe:
    @pytest.mark.asyncio
    async def test_subscribe_receives_published_event(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)
        await bus.start()

        gen = bus.subscribe()
        subscriber = gen.__aiter__()

        # Wait for the subscriber queue to be registered
        task = asyncio.create_task(subscriber.__anext__())
        await asyncio.sleep(0.05)

        event = _make_event()
        await bus.publish(event)

        # Give the listener task a moment to process
        await asyncio.sleep(0.1)

        got = await asyncio.wait_for(task, timeout=2.0)
        assert got.event_type == "chain_event"
        assert got.agent_id == "agent:test"

        await gen.aclose()
        await bus.stop()

    @pytest.mark.asyncio
    async def test_multiple_subscribers_receive_same_event(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)
        await bus.start()

        gen1 = bus.subscribe()
        gen2 = bus.subscribe()
        sub1 = gen1.__aiter__()
        sub2 = gen2.__aiter__()

        task1 = asyncio.create_task(sub1.__anext__())
        task2 = asyncio.create_task(sub2.__anext__())
        await asyncio.sleep(0.05)

        assert bus.subscriber_count == 2

        await bus.publish(_make_event(event_type="escalation"))
        await asyncio.sleep(0.1)

        got1 = await asyncio.wait_for(task1, timeout=2.0)
        got2 = await asyncio.wait_for(task2, timeout=2.0)

        assert got1.event_type == "escalation"
        assert got2.event_type == "escalation"

        await gen1.aclose()
        await gen2.aclose()
        await bus.stop()

    @pytest.mark.asyncio
    async def test_subscriber_count(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)
        await bus.start()
        assert bus.subscriber_count == 0

        gen = bus.subscribe()
        sub = gen.__aiter__()
        task = asyncio.create_task(sub.__anext__())
        await asyncio.sleep(0.05)
        assert bus.subscriber_count == 1

        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, StopAsyncIteration):
            pass
        await gen.aclose()
        await bus.stop()


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestSerializationRoundTrip:
    @pytest.mark.asyncio
    async def test_event_survives_json_roundtrip(self):
        original = _make_event(
            payload={"nested": {"key": [1, 2, 3]}},
            agent_id="agent:roundtrip",
        )

        # Serialize as RedisEventBus.publish does
        data = original.model_dump(mode="json")
        raw = json.dumps(data, default=str).encode("utf-8")

        # Deserialize as RedisEventBus._listen does
        parsed = json.loads(raw.decode("utf-8"))
        restored = DashboardEvent(**parsed)

        assert restored.event_type == original.event_type
        assert restored.agent_id == original.agent_id
        assert restored.chain_id == original.chain_id
        assert restored.payload == original.payload
        assert restored.request_id == original.request_id

    @pytest.mark.asyncio
    async def test_timestamp_preserved(self):
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        original = _make_event(timestamp=ts)

        data = original.model_dump(mode="json")
        raw = json.dumps(data, default=str)
        restored = DashboardEvent(**json.loads(raw))

        assert restored.timestamp == ts


# ---------------------------------------------------------------------------
# Lifecycle — start / stop
# ---------------------------------------------------------------------------


class TestRedisEventBusLifecycle:
    @pytest.mark.asyncio
    async def test_start_creates_listener_task(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)

        assert bus._listener_task is None
        await bus.start()
        assert bus._listener_task is not None
        assert not bus._listener_task.done()

        await bus.stop()
        assert bus._listener_task is None

    @pytest.mark.asyncio
    async def test_double_start_is_safe(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)

        await bus.start()
        task1 = bus._listener_task
        await bus.start()  # second start should be no-op
        assert bus._listener_task is task1

        await bus.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_safe(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)
        await bus.stop()  # should not raise

    @pytest.mark.asyncio
    async def test_stop_cleans_up_pubsub(self):
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)
        await bus.start()
        assert bus._pubsub is not None
        await bus.stop()
        assert bus._pubsub is None


# ---------------------------------------------------------------------------
# Factory — create_event_bus
# ---------------------------------------------------------------------------


class TestCreateEventBus:
    @pytest.mark.asyncio
    async def test_returns_in_process_when_redis_not_configured(self):
        with patch("gavel.redis_client.is_redis_configured", return_value=False), \
             patch("gavel.redis_client.get_redis", new_callable=AsyncMock, return_value=None):
            bus = await create_event_bus()
            assert isinstance(bus, InProcessEventBus)

    @pytest.mark.asyncio
    async def test_returns_in_process_when_redis_unavailable(self):
        with patch("gavel.redis_client.is_redis_configured", return_value=True), \
             patch("gavel.redis_client.get_redis", new_callable=AsyncMock, return_value=None):
            bus = await create_event_bus()
            assert isinstance(bus, InProcessEventBus)

    @pytest.mark.asyncio
    async def test_returns_redis_bus_when_configured(self):
        fake_redis = FakeRedisWithPubSub()
        with patch("gavel.redis_client.is_redis_configured", return_value=True), \
             patch("gavel.redis_client.get_redis", new_callable=AsyncMock, return_value=fake_redis):
            bus = await create_event_bus()
            assert isinstance(bus, RedisEventBus)
            # Should already be started
            assert bus._listener_task is not None
            await bus.stop()


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_in_process_is_protocol_compliant(self):
        assert isinstance(InProcessEventBus(), EventBusProtocol)

    def test_redis_is_protocol_compliant(self):
        fake_redis = FakeRedisWithPubSub()
        assert isinstance(RedisEventBus(fake_redis), EventBusProtocol)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_full_queue_drops_subscriber(self):
        """When a subscriber queue is full, it should be removed."""
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)
        await bus.start()

        # Create a subscriber with a tiny queue
        queue = asyncio.Queue(maxsize=1)
        async with bus._lock:
            bus._subscribers.append(queue)

        # Fill the queue
        queue.put_nowait(_make_event())

        # Fan out another event — should drop the full subscriber
        await bus._fan_out(_make_event())

        assert bus.subscriber_count == 0
        await bus.stop()

    @pytest.mark.asyncio
    async def test_malformed_message_is_skipped(self):
        """Listener should skip messages that can't be deserialized."""
        fake_redis = FakeRedisWithPubSub()
        bus = RedisEventBus(fake_redis)
        await bus.start()

        gen = bus.subscribe()
        sub = gen.__aiter__()
        task = asyncio.create_task(sub.__anext__())
        await asyncio.sleep(0.05)

        # Inject a bad message followed by a good one
        fake_redis._pubsub.inject_message(b"gavel:events", b"not-valid-json")
        good = _make_event(event_type="good_event")
        data = json.dumps(good.model_dump(mode="json"), default=str).encode("utf-8")
        fake_redis._pubsub.inject_message(b"gavel:events", data)

        await asyncio.sleep(0.2)
        got = await asyncio.wait_for(task, timeout=2.0)
        assert got.event_type == "good_event"

        await gen.aclose()
        await bus.stop()
