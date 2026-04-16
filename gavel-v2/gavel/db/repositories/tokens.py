"""Governance token persistence backend.

Storage-only: round-trips ``gavel.enrollment.GovernanceToken`` rows to/from
the ``enrollment_tokens`` table.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from sqlalchemy import delete as sa_delete, func, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.db.models import EnrollmentTokenRow
from gavel.enrollment import GovernanceToken


def _row_to_token(row: EnrollmentTokenRow) -> GovernanceToken:
    return GovernanceToken(
        token=row.token,
        agent_did=row.agent_did,
        agent_id=row.agent_id,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        ttl_seconds=row.ttl_seconds,
        revoked=row.revoked,
        scope=row.scope,
    )


def _token_to_row_kwargs(token: GovernanceToken) -> dict:
    return {
        "token": token.token,
        "agent_did": token.agent_did,
        "agent_id": token.agent_id,
        "issued_at": token.issued_at,
        "expires_at": token.expires_at,
        "ttl_seconds": token.ttl_seconds,
        "revoked": token.revoked,
        "scope": token.scope,
    }


class GovernanceTokenRepository:
    """Persistence backend for :class:`gavel.enrollment.TokenManager`."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    async def get(self, token: str) -> GovernanceToken | None:
        """Primary lookup — by the token string itself (header check path)."""
        async with self._sessionmaker() as session:
            row = await session.get(EnrollmentTokenRow, token)
            if row is None:
                return None
            return _row_to_token(row)

    async def get_by_agent(self, agent_did: str) -> list[GovernanceToken]:
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(EnrollmentTokenRow).where(
                    EnrollmentTokenRow.agent_did == agent_did
                )
            )
            rows: Iterable[EnrollmentTokenRow] = result.scalars().all()
            return [_row_to_token(r) for r in rows]

    async def save(self, token: GovernanceToken) -> None:
        """Upsert by token string (the primary key)."""
        kwargs = _token_to_row_kwargs(token)
        async with self._sessionmaker() as session:
            row = await session.get(EnrollmentTokenRow, token.token)
            if row is None:
                row = EnrollmentTokenRow(**kwargs)
                session.add(row)
            else:
                for key, value in kwargs.items():
                    setattr(row, key, value)
            await session.commit()

    async def delete(self, agent_did: str) -> int:
        """Revoke-by-agent — deletes every token for ``agent_did``.

        Returns the number of rows deleted (matches the existing revoke
        semantics: caller can detect "no token existed").
        """
        async with self._sessionmaker() as session:
            # Count first so we can return an accurate number that
            # matches across dialects (SQLite's rowcount is reliable
            # for bulk DELETE, but we use an explicit count for clarity
            # and determinism).
            count_result = await session.execute(
                select(func.count())
                .select_from(EnrollmentTokenRow)
                .where(EnrollmentTokenRow.agent_did == agent_did)
            )
            n = int(count_result.scalar_one())
            if n:
                await session.execute(
                    sa_delete(EnrollmentTokenRow).where(
                        EnrollmentTokenRow.agent_did == agent_did
                    )
                )
            await session.commit()
            return n

    async def mark_revoked(self, agent_did: str) -> int:
        """Flip ``revoked=True`` on every token for ``agent_did``.

        Unlike :meth:`delete`, this preserves the row so subsequent
        validations can report a ``revoked`` reason rather than
        ``not recognized``. Returns the number of rows updated.
        """
        async with self._sessionmaker() as session:
            count_result = await session.execute(
                select(func.count())
                .select_from(EnrollmentTokenRow)
                .where(EnrollmentTokenRow.agent_did == agent_did)
            )
            n = int(count_result.scalar_one())
            if n:
                await session.execute(
                    sa_update(EnrollmentTokenRow)
                    .where(EnrollmentTokenRow.agent_did == agent_did)
                    .values(revoked=True)
                )
            await session.commit()
            return n

    async def list_expired(self, now: datetime) -> list[str]:
        """Return token strings whose ``expires_at <= now``.

        Used for periodic cleanup planning; the caller can decide whether
        to delete-batch afterwards or report only.
        """
        async with self._sessionmaker() as session:
            result = await session.execute(
                select(EnrollmentTokenRow.token).where(
                    EnrollmentTokenRow.expires_at <= now
                )
            )
            return [row for row in result.scalars().all()]

    async def delete_expired(self, now: datetime) -> int:
        """Atomic batch delete of expired tokens. Returns rows deleted."""
        async with self._sessionmaker() as session:
            count_result = await session.execute(
                select(func.count())
                .select_from(EnrollmentTokenRow)
                .where(EnrollmentTokenRow.expires_at <= now)
            )
            n = int(count_result.scalar_one())
            if n:
                await session.execute(
                    sa_delete(EnrollmentTokenRow).where(
                        EnrollmentTokenRow.expires_at <= now
                    )
                )
            await session.commit()
            return n

    async def delete_revoked(self) -> int:
        """Atomic batch delete of revoked tokens. Returns rows deleted."""
        async with self._sessionmaker() as session:
            count_result = await session.execute(
                select(func.count())
                .select_from(EnrollmentTokenRow)
                .where(EnrollmentTokenRow.revoked.is_(True))
            )
            n = int(count_result.scalar_one())
            if n:
                await session.execute(
                    sa_delete(EnrollmentTokenRow).where(
                        EnrollmentTokenRow.revoked.is_(True)
                    )
                )
            await session.commit()
            return n


__all__ = ["GovernanceTokenRepository"]
