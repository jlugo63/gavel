"""
Event Bus — the central nervous system of the monitoring dashboard.

All governance actions, agent heartbeats, and status changes publish
events here. The SSE endpoint drains events to all connected dashboards.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from pydantic import BaseModel, Field

from gavel.request_id import get_request_id


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


class EventBus:
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
