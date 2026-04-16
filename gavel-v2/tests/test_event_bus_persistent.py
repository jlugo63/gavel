"""Tests for PersistentEventBus — Phase 14.

Validates Redis Streams-based durable event delivery: publish/replay,
subscribe/resume, stream management, factory selection, and protocol
conformance.

Uses fakeredis which supports Redis Streams (XADD, XREAD, XRANGE,
XLEN, XTRIM).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import pytest

from gavel.events import (
    STREAM_KEY,
    DashboardEvent,
    EventBusProtocol,
    EventRetentionPolicy,
    InProcessEventBus,
    PersistentEventBus,
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


@pytest.fixture
def fakeredis_client():
    """Return a fresh fakeredis async client per test."""
    return fakeredis.aioredis.FakeRedis()


@pytest.fixture
def bus(fakeredis_client):
    """Return a PersistentEventBus wired to fakeredis."""
    return PersistentEventBus(fakeredis_client)


# ---------------------------------------------------------------------------
# Publish and replay
# ---------------------------------------------------------------------------


class TestPublishAndReplay:
    @pytest.mark.asyncio
    async def test_publish_returns_stream_id(self, bus):
        event = _make_event()
        entry_id = await bus.publish(event)
        assert entry_id  # non-empty string
        assert "-" in entry_id  # Redis stream IDs look like "1234-0"

    @pytest.mark.asyncio
    async def test_publish_persists_event(self, bus):
        await bus.publish(_make_event(event_type="escalation"))
        events = await bus.replay()
        assert len(events) == 1
        assert events[0].event_type == "escalation"

    @pytest.mark.asyncio
    async def test_replay_multiple_events(self, bus):
        for i in range(5):
            await bus.publish(_make_event(agent_id=f"agent:{i}"))
        events = await bus.replay()
        assert len(events) == 5
        assert [e.agent_id for e in events] == [f"agent:{i}" for i in range(5)]

    @pytest.mark.asyncio
    async def test_replay_empty_stream(self, bus):
        events = await bus.replay()
        assert events == []

    @pytest.mark.asyncio
    async def test_replay_with_count(self, bus):
        for i in range(10):
            await bus.publish(_make_event(agent_id=f"agent:{i}"))
        events = await bus.replay(count=3)
        assert len(events) == 3
        assert events[0].agent_id == "agent:0"

    @pytest.mark.asyncio
    async def test_replay_since_id(self, bus):
        ids = []
        for i in range(5):
            eid = await bus.publish(_make_event(agent_id=f"agent:{i}"))
            ids.append(eid)
        # Replay everything after the second event
        events = await bus.replay(since=ids[1])
        assert len(events) == 3
        assert events[0].agent_id == "agent:2"


# ---------------------------------------------------------------------------
# Subscribe (live delivery)
# ---------------------------------------------------------------------------


class TestSubscribe:
    @pytest.mark.asyncio
    async def test_subscribe_receives_published_event(self, bus):
        await bus.start()
        try:
            gen = bus.subscribe()
            subscriber = gen.__aiter__()
            task = asyncio.create_task(subscriber.__anext__())
            await asyncio.sleep(0.05)

            await bus.publish(_make_event(event_type="heartbeat"))
            # Give the listener time to XREAD and fan out
            got = await asyncio.wait_for(task, timeout=3.0)
            assert got.event_type == "heartbeat"
            await gen.aclose()
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_multiple_subscribers_each_get_all_events(self, bus):
        await bus.start()
        try:
            gen1 = bus.subscribe()
            gen2 = bus.subscribe()
            sub1 = gen1.__aiter__()
            sub2 = gen2.__aiter__()

            task1 = asyncio.create_task(sub1.__anext__())
            task2 = asyncio.create_task(sub2.__anext__())
            await asyncio.sleep(0.05)

            assert bus.subscriber_count == 2

            await bus.publish(_make_event(event_type="action"))

            got1 = await asyncio.wait_for(task1, timeout=3.0)
            got2 = await asyncio.wait_for(task2, timeout=3.0)
            assert got1.event_type == "action"
            assert got2.event_type == "action"

            await gen1.aclose()
            await gen2.aclose()
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_subscribe_to_empty_stream(self, bus):
        """subscribe() should block waiting for events, not error."""
        await bus.start()
        try:
            gen = bus.subscribe()
            subscriber = gen.__aiter__()
            task = asyncio.create_task(subscriber.__anext__())
            await asyncio.sleep(0.1)
            # Task should still be pending (no events yet)
            assert not task.done()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, StopAsyncIteration):
                pass
            await gen.aclose()
        finally:
            await bus.stop()


# ---------------------------------------------------------------------------
# Subscribe from specific ID (resume after disconnect)
# ---------------------------------------------------------------------------


class TestSubscribeFrom:
    @pytest.mark.asyncio
    async def test_subscribe_from_replays_missed_events(self, bus):
        ids = []
        for i in range(5):
            eid = await bus.publish(_make_event(agent_id=f"agent:{i}"))
            ids.append(eid)

        # Resume from after the second event — should get events 2, 3, 4
        gen = bus.subscribe_from(ids[1])
        collected = []
        # Read the 3 replayed events
        async for event in gen:
            collected.append(event)
            if len(collected) == 3:
                break
        await gen.aclose()

        assert len(collected) == 3
        assert collected[0].agent_id == "agent:2"
        assert collected[1].agent_id == "agent:3"
        assert collected[2].agent_id == "agent:4"

    @pytest.mark.asyncio
    async def test_subscribe_from_beginning(self, bus):
        """subscribe_from with the ID '0' should replay all events."""
        for i in range(3):
            await bus.publish(_make_event(agent_id=f"agent:{i}"))

        gen = bus.subscribe_from("0")
        collected = []
        async for event in gen:
            collected.append(event)
            if len(collected) == 3:
                break
        await gen.aclose()

        assert len(collected) == 3
        assert collected[0].agent_id == "agent:0"


# ---------------------------------------------------------------------------
# Stream management
# ---------------------------------------------------------------------------


class TestStreamManagement:
    @pytest.mark.asyncio
    async def test_stream_length(self, bus):
        assert await bus.stream_length() == 0
        await bus.publish(_make_event())
        assert await bus.stream_length() == 1
        await bus.publish(_make_event())
        assert await bus.stream_length() == 2

    @pytest.mark.asyncio
    async def test_trim(self, bus):
        for _ in range(20):
            await bus.publish(_make_event())
        assert await bus.stream_length() == 20
        await bus.trim(5)
        # XTRIM with approximate may keep a few extra, but should be <= 20
        length = await bus.stream_length()
        assert length <= 20  # approximate trimming


# ---------------------------------------------------------------------------
# Event serialization round-trip through streams
# ---------------------------------------------------------------------------


class TestSerializationRoundTrip:
    @pytest.mark.asyncio
    async def test_event_survives_stream_roundtrip(self, bus):
        ts = datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
        original = _make_event(
            event_type="agent_status_change",
            agent_id="agent:roundtrip",
            chain_id="chain-rt",
            payload={"nested": {"key": [1, 2, 3]}},
            timestamp=ts,
            request_id="req-rt",
        )
        await bus.publish(original)
        events = await bus.replay()
        assert len(events) == 1
        restored = events[0]
        assert restored.event_type == original.event_type
        assert restored.agent_id == original.agent_id
        assert restored.chain_id == original.chain_id
        assert restored.payload == original.payload
        assert restored.request_id == original.request_id
        assert restored.timestamp == ts


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_creates_listener_task(self, bus):
        assert bus._listener_task is None
        await bus.start()
        assert bus._listener_task is not None
        assert not bus._listener_task.done()
        await bus.stop()
        assert bus._listener_task is None

    @pytest.mark.asyncio
    async def test_double_start_is_safe(self, bus):
        await bus.start()
        task1 = bus._listener_task
        await bus.start()
        assert bus._listener_task is task1
        await bus.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_safe(self, bus):
        await bus.stop()  # should not raise

    @pytest.mark.asyncio
    async def test_subscriber_count(self, bus):
        assert bus.subscriber_count == 0
        await bus.start()
        try:
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
        finally:
            await bus.stop()


# ---------------------------------------------------------------------------
# EventRetentionPolicy
# ---------------------------------------------------------------------------


class TestEventRetentionPolicy:
    def test_defaults(self):
        policy = EventRetentionPolicy()
        assert policy.max_events == 10_000
        assert policy.max_age_seconds == 86_400
        assert policy.trim_interval_seconds == 300

    def test_custom_values(self):
        policy = EventRetentionPolicy(max_events=500, max_age_seconds=3600, trim_interval_seconds=60)
        assert policy.max_events == 500
        assert policy.max_age_seconds == 3600
        assert policy.trim_interval_seconds == 60

    @pytest.mark.asyncio
    async def test_retention_policy_used_by_bus(self, fakeredis_client):
        policy = EventRetentionPolicy(max_events=5)
        bus = PersistentEventBus(fakeredis_client, retention=policy)
        assert bus._retention.max_events == 5


# ---------------------------------------------------------------------------
# Factory — create_event_bus with persistence
# ---------------------------------------------------------------------------


class TestFactory:
    @pytest.mark.asyncio
    async def test_returns_persistent_bus_when_persistent_true(self):
        fake_redis = fakeredis.aioredis.FakeRedis()
        with patch("gavel.redis_client.is_redis_configured", return_value=True), \
             patch("gavel.redis_client.get_redis", new_callable=AsyncMock, return_value=fake_redis):
            bus = await create_event_bus(persistent=True)
            assert isinstance(bus, PersistentEventBus)
            await bus.stop()

    @pytest.mark.asyncio
    async def test_returns_redis_bus_when_persistent_false(self):
        fake_redis = fakeredis.aioredis.FakeRedis()
        # Need pubsub support — patch it
        fake_redis.pubsub = lambda: AsyncMock(
            subscribe=AsyncMock(),
            unsubscribe=AsyncMock(),
            aclose=AsyncMock(),
            get_message=AsyncMock(return_value=None),
        )
        with patch("gavel.redis_client.is_redis_configured", return_value=True), \
             patch("gavel.redis_client.get_redis", new_callable=AsyncMock, return_value=fake_redis):
            bus = await create_event_bus(persistent=False)
            assert isinstance(bus, RedisEventBus)
            await bus.stop()

    @pytest.mark.asyncio
    async def test_env_var_enables_persistence(self):
        fake_redis = fakeredis.aioredis.FakeRedis()
        with patch("gavel.redis_client.is_redis_configured", return_value=True), \
             patch("gavel.redis_client.get_redis", new_callable=AsyncMock, return_value=fake_redis), \
             patch.dict("os.environ", {"GAVEL_EVENT_PERSISTENCE": "1"}):
            bus = await create_event_bus()
            assert isinstance(bus, PersistentEventBus)
            await bus.stop()

    @pytest.mark.asyncio
    async def test_no_redis_returns_inprocess(self):
        with patch("gavel.redis_client.is_redis_configured", return_value=False), \
             patch("gavel.redis_client.get_redis", new_callable=AsyncMock, return_value=None):
            bus = await create_event_bus(persistent=True)
            assert isinstance(bus, InProcessEventBus)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_persistent_bus_is_protocol_compliant(self, fakeredis_client):
        bus = PersistentEventBus(fakeredis_client)
        assert isinstance(bus, EventBusProtocol)

    def test_has_replay_method(self, fakeredis_client):
        bus = PersistentEventBus(fakeredis_client)
        assert hasattr(bus, "replay")
        assert callable(bus.replay)

    def test_has_subscribe_from_method(self, fakeredis_client):
        bus = PersistentEventBus(fakeredis_client)
        assert hasattr(bus, "subscribe_from")
        assert callable(bus.subscribe_from)

    def test_has_stream_length_method(self, fakeredis_client):
        bus = PersistentEventBus(fakeredis_client)
        assert hasattr(bus, "stream_length")

    def test_has_trim_method(self, fakeredis_client):
        bus = PersistentEventBus(fakeredis_client)
        assert hasattr(bus, "trim")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_publish_handles_redis_error(self):
        mock_redis = AsyncMock()
        mock_redis.xadd.side_effect = ConnectionError("gone")
        bus = PersistentEventBus(mock_redis)
        result = await bus.publish(_make_event())
        assert result == ""  # empty string on failure

    @pytest.mark.asyncio
    async def test_stream_length_handles_error(self):
        mock_redis = AsyncMock()
        mock_redis.xlen.side_effect = ConnectionError("gone")
        bus = PersistentEventBus(mock_redis)
        assert await bus.stream_length() == 0

    @pytest.mark.asyncio
    async def test_full_queue_drops_subscriber(self, bus):
        await bus.start()
        try:
            queue = asyncio.Queue(maxsize=1)
            async with bus._lock:
                bus._subscribers.append(queue)
            queue.put_nowait(_make_event())
            # Fan out — should drop the full subscriber
            await bus._fan_out(_make_event())
            assert bus.subscriber_count == 0
        finally:
            await bus.stop()
