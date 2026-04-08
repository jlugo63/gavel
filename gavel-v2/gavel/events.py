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


class DashboardEvent(BaseModel):
    """A single event for the monitoring dashboard."""

    event_type: str  # chain_event, agent_heartbeat, agent_status_change, escalation, action
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str = ""
    chain_id: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)

    def to_sse(self) -> str:
        """Format as Server-Sent Event."""
        data = self.model_dump(mode="json")
        return f"event: {self.event_type}\ndata: {json.dumps(data, default=str)}\n\n"


class EventBus:
    """Fan-out event bus using asyncio.Queue per subscriber."""

    def __init__(self):
        self._subscribers: list[asyncio.Queue[DashboardEvent]] = []

    async def publish(self, event: DashboardEvent) -> None:
        """Push event to all subscriber queues."""
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
        self._subscribers.append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            if queue in self._subscribers:
                self._subscribers.remove(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)
