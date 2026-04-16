"""Agent registry persistence backend.

Storage-only: this class round-trips ``gavel.agents.AgentRecord`` rows
to/from the ``agents`` table. Business logic (trust scoring, promotion
evaluation, event publication) stays in :class:`gavel.agents.AgentRegistry`.
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy import delete as sa_delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.agents import AgentRecord, AgentStatus
from gavel.db.models import AgentRecordRow


def _row_to_record(row: AgentRecordRow) -> AgentRecord:
    return AgentRecord(
        agent_id=row.agent_id,
        display_name=row.display_name,
        agent_type=row.agent_type,
        did=row.did,
        trust_score=row.trust_score,
        autonomy_tier=row.autonomy_tier,
        capabilities=list(row.capabilities or []),
        status=AgentStatus(row.status),
        registered_at=row.registered_at,
        last_heartbeat=row.last_heartbeat,
        heartbeat_interval_s=row.heartbeat_interval_s,
        chains_proposed=row.chains_proposed,
        chains_completed=row.chains_completed,
        violations=row.violations,
        successful_actions=row.successful_actions,
        session_id=row.session_id,
        current_activity=row.current_activity,
    )


def _record_to_row_kwargs(record: AgentRecord) -> dict:
    return {
        "agent_id": record.agent_id,
        "display_name": record.display_name,
        "agent_type": record.agent_type,
        "did": record.did,
        "trust_score": record.trust_score,
        "autonomy_tier": record.autonomy_tier,
        "capabilities": list(record.capabilities or []),
        "status": record.status.value if isinstance(record.status, AgentStatus) else str(record.status),
        "registered_at": record.registered_at,
        "last_heartbeat": record.last_heartbeat,
        "heartbeat_interval_s": record.heartbeat_interval_s,
        "chains_proposed": record.chains_proposed,
        "chains_completed": record.chains_completed,
        "violations": record.violations,
        "successful_actions": record.successful_actions,
        "session_id": record.session_id,
        "current_activity": record.current_activity,
    }


class AgentRepository:
    """Persistence backend for :class:`gavel.agents.AgentRegistry`."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    async def get(self, agent_id: str) -> AgentRecord | None:
        async with self._sessionmaker() as session:
            row = await session.get(AgentRecordRow, agent_id)
            if row is None:
                return None
            return _row_to_record(row)

    async def save(self, record: AgentRecord) -> None:
        """Upsert an agent record by ``agent_id``."""
        kwargs = _record_to_row_kwargs(record)
        async with self._sessionmaker() as session:
            row = await session.get(AgentRecordRow, record.agent_id)
            if row is None:
                row = AgentRecordRow(**kwargs)
                session.add(row)
            else:
                for key, value in kwargs.items():
                    setattr(row, key, value)
            await session.commit()

    async def delete(self, agent_id: str) -> None:
        async with self._sessionmaker() as session:
            await session.execute(
                sa_delete(AgentRecordRow).where(AgentRecordRow.agent_id == agent_id)
            )
            await session.commit()

    async def list_all(self) -> list[AgentRecord]:
        async with self._sessionmaker() as session:
            result = await session.execute(select(AgentRecordRow))
            rows: Iterable[AgentRecordRow] = result.scalars().all()
            return [_row_to_record(r) for r in rows]

    async def count_active(self) -> int:
        """Return the number of agents with ``status == ACTIVE``.

        Implemented as a ``COUNT(*)`` query rather than a full load so the
        system_status endpoint stays cheap as the roster grows.
        """
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(func.count())
                .select_from(AgentRecordRow)
                .where(AgentRecordRow.status == AgentStatus.ACTIVE.value)
            )
            return int(result.scalar_one())


__all__ = ["AgentRepository"]
