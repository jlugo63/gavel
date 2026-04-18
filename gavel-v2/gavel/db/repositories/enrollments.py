"""Enrollment record persistence backend.

Storage-only: round-trips ``gavel.enrollment.EnrollmentRecord`` values.
"""

from __future__ import annotations

from typing import Iterable

from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.db.models import EnrollmentRecordRow
from gavel.enrollment import (
    EnrollmentApplication,
    EnrollmentRecord,
    EnrollmentStatus,
)


def _row_to_record(row: EnrollmentRecordRow) -> EnrollmentRecord:
    return EnrollmentRecord(
        agent_id=row.agent_id,
        status=EnrollmentStatus(row.status),
        application=EnrollmentApplication.model_validate(row.application),
        enrolled_at=row.enrolled_at,
        reviewed_by=row.reviewed_by,
        rejection_reason=row.rejection_reason,
        violations=list(row.violations or []),
    )


def _record_to_row_kwargs(record: EnrollmentRecord) -> dict:
    status_val = (
        record.status.value
        if isinstance(record.status, EnrollmentStatus)
        else str(record.status)
    )
    return {
        "agent_id": record.agent_id,
        "status": status_val,
        "application": record.application.model_dump(mode="json"),
        "enrolled_at": record.enrolled_at,
        "reviewed_by": record.reviewed_by,
        "rejection_reason": record.rejection_reason,
        "violations": list(record.violations or []),
    }


class EnrollmentRepository:
    """Persistence backend for :class:`gavel.enrollment.EnrollmentRegistry`."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    async def get(self, agent_id: str) -> EnrollmentRecord | None:
        async with self._sessionmaker() as session:
            row = await session.get(EnrollmentRecordRow, agent_id)
            if row is None:
                return None
            return _row_to_record(row)

    async def save(self, record: EnrollmentRecord) -> None:
        kwargs = _record_to_row_kwargs(record)
        async with self._sessionmaker() as session:
            row = await session.get(EnrollmentRecordRow, record.agent_id)
            if row is None:
                row = EnrollmentRecordRow(**kwargs)
                session.add(row)
            else:
                for key, value in kwargs.items():
                    setattr(row, key, value)
            await session.commit()

    async def delete(self, agent_id: str) -> None:
        async with self._sessionmaker() as session:
            await session.execute(
                sa_delete(EnrollmentRecordRow).where(
                    EnrollmentRecordRow.agent_id == agent_id
                )
            )
            await session.commit()

    async def list_all(self) -> list[EnrollmentRecord]:
        async with self._sessionmaker() as session:
            result = await session.execute(select(EnrollmentRecordRow))
            rows: Iterable[EnrollmentRecordRow] = result.scalars().all()
            return [_row_to_record(r) for r in rows]

    async def list_by_status(self, status: str) -> list[EnrollmentRecord]:
        """Return records matching ``status`` (accepts Enum value or name)."""
        # Normalize to the stored string form.
        if isinstance(status, EnrollmentStatus):
            status_val = status.value
        else:
            status_val = str(status)
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(EnrollmentRecordRow).where(
                    EnrollmentRecordRow.status == status_val
                )
            )
            rows: Iterable[EnrollmentRecordRow] = result.scalars().all()
            return [_row_to_record(r) for r in rows]


__all__ = ["EnrollmentRepository"]
