"""ExecutionTokenRepository — persistence for execution-token rows.

Current in-memory shape (``get_execution_tokens()`` returns a
``dict[token_id, dict]``)::

    {
        "token_id": "exec-t-xxxxxxxx",
        "chain_id": "c-...",
        "expires_at": "2024-01-01T00:00:00+00:00",  # ISO string
        "used": False,
    }

Locked Wave 2A decisions:

* ``get()`` returns a **snapshot dict** — a fresh, read-only copy of
  the row's fields. Callers cannot mutate a live record in place;
  mutations go through dedicated methods.
* ``mark_used()`` is a TOCTOU-safe atomic flip that returns ``False``
  when the token is already used. Implemented as a conditional
  ``UPDATE ... WHERE used = false`` that returns the affected row
  count — equivalent to the ``RETURNING`` idiom on Postgres and fully
  portable to SQLite.
* ``delete_by_chain()`` supports the cleanup path since
  ``ExecutionTokenRow.chain_id`` is indexed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import delete as sa_delete
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.db.models import ExecutionTokenRow


class ExecutionTokenRepository:
    """Async repository for execution tokens.

    Storage rows are typed (``DateTime(tz=True)`` for ``expires_at``)
    but the external snapshot dict uses ISO-string format for
    ``expires_at`` to match the rest of the API surface.
    """

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    async def get(self, token_id: str) -> Optional[dict]:
        """Return a snapshot dict, or ``None`` if the token doesn't exist."""
        async with self._sessionmaker() as session:
            row = await session.get(ExecutionTokenRow, token_id)
            if row is None:
                return None
            return _row_to_snapshot(row)

    async def save(self, token_id: str, token: dict) -> None:
        """Full upsert — used at token creation time.

        ``token`` is a dict whose ``expires_at`` may be an ISO string
        or a ``datetime``. Stored as typed DateTime.
        """
        expires_at = _coerce_datetime(token.get("expires_at"))
        chain_id = token.get("chain_id", "")
        used = bool(token.get("used", False))

        async with self._sessionmaker() as session:
            async with session.begin():
                existing = await session.get(ExecutionTokenRow, token_id)
                if existing is None:
                    session.add(
                        ExecutionTokenRow(
                            token_id=token_id,
                            chain_id=chain_id,
                            expires_at=expires_at,
                            used=used,
                        )
                    )
                else:
                    existing.chain_id = chain_id
                    existing.expires_at = expires_at
                    existing.used = used

    async def mark_used(self, token_id: str) -> bool:
        """Atomic flip of ``used`` to ``True``.

        Returns ``True`` if the token was previously unused and is now
        marked used; ``False`` if the token does not exist or was
        already used. TOCTOU-safe — a single conditional UPDATE does
        the check-and-set under one row lock.
        """
        async with self._sessionmaker() as session:
            async with session.begin():
                stmt = (
                    update(ExecutionTokenRow)
                    .where(ExecutionTokenRow.token_id == token_id)
                    .where(ExecutionTokenRow.used.is_(False))
                    .values(used=True)
                )
                result = await session.execute(stmt)
                return (result.rowcount or 0) > 0

    async def delete(self, token_id: str) -> None:
        async with self._sessionmaker() as session:
            async with session.begin():
                await session.execute(
                    sa_delete(ExecutionTokenRow).where(
                        ExecutionTokenRow.token_id == token_id
                    )
                )

    async def delete_by_chain(self, chain_id: str) -> None:
        """Remove every token belonging to a chain. Used by cleanup."""
        async with self._sessionmaker() as session:
            async with session.begin():
                await session.execute(
                    sa_delete(ExecutionTokenRow).where(
                        ExecutionTokenRow.chain_id == chain_id
                    )
                )


# ── helpers ───────────────────────────────────────────────────────


def _row_to_snapshot(row: ExecutionTokenRow) -> dict:
    """Produce a snapshot dict from a row.

    ``expires_at`` becomes an ISO string (UTC-aware) to match the API
    surface used by all callers.
    """
    expires = row.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return {
        "token_id": row.token_id,
        "chain_id": row.chain_id,
        "expires_at": expires.isoformat() if expires is not None else None,
        "used": bool(row.used),
    }


def _coerce_datetime(value) -> datetime:
    """Accept datetime or ISO string and return a tz-aware datetime.

    Bare (naive) values are interpreted as UTC — the entire codebase
    produces UTC timestamps, so this is the least-surprising choice.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    raise TypeError(
        f"expires_at must be datetime or ISO string, got {type(value).__name__}"
    )
