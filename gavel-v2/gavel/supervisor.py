"""
Supervisor — background task that monitors agent health and chain liveness.

Runs inside the FastAPI process as an asyncio task. Every tick:
1. Checks agent heartbeats — marks dead agents after 3 missed beats
2. Ticks the liveness monitor — processes SLA escalations
3. Publishes status events to the dashboard event bus
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from gavel.agents import AgentRegistry, AgentStatus
from gavel.events import EventBus, DashboardEvent
from gavel.liveness import LivenessMonitor


class Supervisor:
    """Background supervisor for agent health and chain liveness."""

    def __init__(
        self,
        event_bus: EventBus,
        registry: AgentRegistry,
        liveness: LivenessMonitor,
        tick_interval: float = 1.0,
        heartbeat_miss_threshold: int = 3,
    ):
        self._bus = event_bus
        self._registry = registry
        self._liveness = liveness
        self._tick_interval = tick_interval
        self._miss_threshold = heartbeat_miss_threshold
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        """Launch the supervisor as a background task."""
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """Gracefully stop the supervisor."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        """Main supervisor loop — runs every tick_interval seconds."""
        while self._running:
            try:
                await self._tick()
            except Exception:
                pass  # Supervisor must not crash
            await asyncio.sleep(self._tick_interval)

    async def _tick(self) -> None:
        """Single supervisor tick — check heartbeats and liveness."""
        now = datetime.now(timezone.utc)

        # Check agent heartbeats
        for agent in self._registry.get_all():
            if agent.status in (AgentStatus.SUSPENDED, AgentStatus.DEAD):
                continue

            elapsed = (now - agent.last_heartbeat).total_seconds()
            max_silence = agent.heartbeat_interval_s * self._miss_threshold

            if elapsed > max_silence and agent.status != AgentStatus.DEAD:
                self._registry.mark_dead(agent.agent_id)
                await self._bus.publish(DashboardEvent(
                    event_type="agent_dead",
                    agent_id=agent.agent_id,
                    payload={
                        "reason": f"Missed {self._miss_threshold} heartbeats "
                                  f"({elapsed:.0f}s silence, expected every {agent.heartbeat_interval_s}s)",
                        "last_heartbeat": agent.last_heartbeat.isoformat(),
                    },
                ))

        # Tick liveness — process SLA escalations
        escalations = self._liveness.tick()
        for chain_id, level in escalations:
            await self._bus.publish(DashboardEvent(
                event_type="escalation",
                chain_id=chain_id,
                payload={
                    "level": level.value,
                },
            ))
