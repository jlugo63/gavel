"""Incident registry persistence backend.

Storage-only: round-trips ``gavel.compliance.IncidentReport`` rows to/from
the ``incidents`` table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import and_, delete as sa_delete, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.compliance import IncidentReport, IncidentSeverity, IncidentStatus
from gavel.db.models import IncidentRow


def _ensure_aware(dt: datetime | None) -> datetime | None:
    """SQLite may return naive datetimes — normalise to UTC-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _row_to_incident(row: IncidentRow) -> IncidentReport:
    return IncidentReport(
        incident_id=row.incident_id,
        agent_id=row.agent_id,
        severity=IncidentSeverity(row.severity),
        status=IncidentStatus(row.status),
        title=row.title,
        description=row.description,
        detected_at=_ensure_aware(row.detected_at),
        reported_at=_ensure_aware(row.reported_at),
        resolved_at=_ensure_aware(row.resolved_at),
        deadline=_ensure_aware(row.deadline),
        chain_ids=list(row.chain_ids or []),
        findings=list(row.findings or []),
        regulatory_references=list(row.regulatory_references or []),
    )


def _incident_to_row_kwargs(incident: IncidentReport) -> dict:
    sev = (
        incident.severity.value
        if isinstance(incident.severity, IncidentSeverity)
        else str(incident.severity)
    )
    status_val = (
        incident.status.value
        if isinstance(incident.status, IncidentStatus)
        else str(incident.status)
    )
    return {
        "incident_id": incident.incident_id,
        "agent_id": incident.agent_id,
        "severity": sev,
        "status": status_val,
        "title": incident.title,
        "description": incident.description,
        "detected_at": incident.detected_at,
        "reported_at": incident.reported_at,
        "resolved_at": incident.resolved_at,
        "deadline": incident.deadline,
        "chain_ids": list(incident.chain_ids or []),
        "findings": list(incident.findings or []),
        "regulatory_references": list(incident.regulatory_references or []),
    }


class IncidentRepository:
    """Persistence backend for :class:`gavel.compliance.IncidentRegistry`."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    async def get(self, incident_id: str) -> IncidentReport | None:
        async with self._sessionmaker() as session:
            row = await session.get(IncidentRow, incident_id)
            if row is None:
                return None
            return _row_to_incident(row)

    async def save(self, incident: IncidentReport) -> None:
        kwargs = _incident_to_row_kwargs(incident)
        async with self._sessionmaker() as session:
            row = await session.get(IncidentRow, incident.incident_id)
            if row is None:
                row = IncidentRow(**kwargs)
                session.add(row)
            else:
                for key, value in kwargs.items():
                    setattr(row, key, value)
            await session.commit()

    async def delete(self, incident_id: str) -> None:
        async with self._sessionmaker() as session:
            await session.execute(
                sa_delete(IncidentRow).where(IncidentRow.incident_id == incident_id)
            )
            await session.commit()

    async def list_all(self) -> list[IncidentReport]:
        async with self._sessionmaker() as session:
            result = await session.execute(select(IncidentRow))
            rows: Iterable[IncidentRow] = result.scalars().all()
            return [_row_to_incident(r) for r in rows]

    async def list_by_agent(self, agent_id: str) -> list[IncidentReport]:
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(IncidentRow).where(IncidentRow.agent_id == agent_id)
            )
            rows: Iterable[IncidentRow] = result.scalars().all()
            return [_row_to_incident(r) for r in rows]

    async def list_overdue(self, now: datetime) -> list[IncidentReport]:
        """Return incidents past their deadline that aren't yet reported.

        An incident is overdue when ``deadline IS NOT NULL`` AND
        ``deadline < now`` AND ``reported_at IS NULL``. This mirrors
        ``IncidentReport.is_overdue``.
        """
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(IncidentRow).where(
                    and_(
                        IncidentRow.deadline.is_not(None),
                        IncidentRow.deadline < now,
                        IncidentRow.reported_at.is_(None),
                    )
                )
            )
            rows: Iterable[IncidentRow] = result.scalars().all()
            return [_row_to_incident(r) for r in rows]

    async def mark_reported(self, incident_id: str) -> bool:
        """Atomically mark an incident as reported.

        Returns ``True`` if the row was updated (was not previously
        reported), ``False`` if the incident does not exist or had
        already been marked reported.
        """
        now = datetime.now(timezone.utc)
        async with self._sessionmaker() as session:
            stmt = (
                sa_update(IncidentRow)
                .where(
                    and_(
                        IncidentRow.incident_id == incident_id,
                        IncidentRow.reported_at.is_(None),
                    )
                )
                .values(
                    reported_at=now,
                    status=IncidentStatus.REPORTED.value,
                )
            )
            result = await session.execute(stmt)
            await session.commit()
            return (result.rowcount or 0) > 0

    async def mark_resolved(self, incident_id: str) -> bool:
        """Atomically mark an incident as resolved.

        Returns ``True`` if the row was updated, ``False`` if the incident
        does not exist or had already been resolved.
        """
        now = datetime.now(timezone.utc)
        async with self._sessionmaker() as session:
            stmt = (
                sa_update(IncidentRow)
                .where(
                    and_(
                        IncidentRow.incident_id == incident_id,
                        IncidentRow.resolved_at.is_(None),
                    )
                )
                .values(
                    resolved_at=now,
                    status=IncidentStatus.RESOLVED.value,
                )
            )
            result = await session.execute(stmt)
            await session.commit()
            return (result.rowcount or 0) > 0


__all__ = ["IncidentRepository"]
