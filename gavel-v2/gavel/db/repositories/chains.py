"""ChainRepository — persistence for GovernanceChain + ChainEvent rows.

Design decisions (Wave 2A):

* The repo takes an ``async_sessionmaker`` at construction; each method
  opens its own short transaction via ``session_scope``-equivalent
  semantics. Route-level serialization still happens through
  :class:`~gavel.dependencies.ChainLockManager`, so session-per-request
  is not required yet (Wave 3 problem).
* ``get()`` rehydrates a full in-memory :class:`GovernanceChain` with
  every :class:`ChainEvent` reinstated *byte-identically* — the hash
  chain must verify after a round trip. ``request_id`` is preserved.
* ``actor_roles`` is persisted as ``dict[str, list[str]]`` on the row;
  the in-memory model uses ``dict[str, set[str]]``. Coercion both ways
  is done explicitly so JSON stays stable.
* ``save()`` is idempotent: the chain row is upserted, and new events
  are detected by ``sequence`` (rows already in the DB with a given
  ``(chain_id, sequence)`` are left alone — event rows are immutable
  once written, since the hash seals them).
* ``append_event()`` is the hot-path single-row insert used by routers
  holding a chain lock. It does not touch the chain-level row.
* ``list_stale()`` uses the latest event timestamp when events exist,
  falling back to ``created_at`` for empty chains. Filter is
  ``< cutoff`` to match :func:`gavel.gateway.cleanup_stale_chains`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from gavel.chain import ChainEvent, ChainStatus, EventType, GovernanceChain
from gavel.db.models import ChainEventRow, GovernanceChainRow


class ChainRepository:
    """Async repository for governance chains + events."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, chain_id: str) -> Optional[GovernanceChain]:
        """Load a chain by id, reconstructing the in-memory object.

        Returns ``None`` if the chain is not found (matches ``dict.get``
        semantics used at the call sites). Events are eager-loaded via
        ``selectinload`` in a single round-trip.
        """
        async with self._sessionmaker() as session:
            stmt = (
                select(GovernanceChainRow)
                .options(selectinload(GovernanceChainRow.events))
                .where(GovernanceChainRow.chain_id == chain_id)
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None
            ev_rows = list(row.events)

        return _row_to_chain(row, ev_rows)

    async def list_all(self) -> list[GovernanceChain]:
        """Return every chain. Events are loaded for each.

        Used by ``system_status``-style callers that render counts and
        basic metadata across all chains. If per-chain event payloads
        are not needed, prefer :meth:`count_all`.
        """
        async with self._sessionmaker() as session:
            rows = (
                (await session.execute(select(GovernanceChainRow))).scalars().all()
            )
            if not rows:
                return []

            ev_stmt = select(ChainEventRow).order_by(
                ChainEventRow.chain_id.asc(), ChainEventRow.sequence.asc()
            )
            ev_rows = (await session.execute(ev_stmt)).scalars().all()

        events_by_chain: dict[str, list[ChainEventRow]] = {}
        for ev in ev_rows:
            events_by_chain.setdefault(ev.chain_id, []).append(ev)

        return [_row_to_chain(r, events_by_chain.get(r.chain_id, [])) for r in rows]

    async def count_all(self) -> int:
        async with self._sessionmaker() as session:
            stmt = select(func.count()).select_from(GovernanceChainRow)
            return int((await session.execute(stmt)).scalar_one())

    async def list_stale(self, older_than: datetime) -> list[str]:
        """Return chain_ids whose latest activity is strictly before the cutoff.

        Latest activity = latest event timestamp if any events exist,
        otherwise the chain's ``created_at``. Mirrors the logic in
        :func:`gavel.gateway.cleanup_stale_chains`.
        """
        async with self._sessionmaker() as session:
            # Latest event timestamp per chain (may be NULL for empty chains).
            latest_ev = (
                select(
                    ChainEventRow.chain_id.label("cid"),
                    func.max(ChainEventRow.timestamp).label("last_ts"),
                )
                .group_by(ChainEventRow.chain_id)
                .subquery()
            )

            stmt = select(
                GovernanceChainRow.chain_id,
                GovernanceChainRow.created_at,
                latest_ev.c.last_ts,
            ).join(
                latest_ev,
                latest_ev.c.cid == GovernanceChainRow.chain_id,
                isouter=True,
            )
            rows = (await session.execute(stmt)).all()

        stale: list[str] = []
        for chain_id, created_at, last_ts in rows:
            effective = last_ts if last_ts is not None else created_at
            # SQLite may return naive datetimes — normalise before compare.
            effective = _ensure_aware(effective)
            cutoff = _ensure_aware(older_than)
            if effective < cutoff:
                stale.append(chain_id)
        return stale

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def save(self, chain: GovernanceChain) -> None:
        """Upsert chain row + insert any new events.

        Detection of new events is by ``sequence`` — anything already in
        the DB for this chain is left alone (event rows are immutable
        once written because the hash seals them). Chain-level fields
        (``status``, ``actor_roles``) are always overwritten with the
        in-memory snapshot.
        """
        actor_roles_json = {
            aid: sorted(list(roles))
            for aid, roles in chain._actor_roles.items()
        }

        async with self._sessionmaker() as session:
            async with session.begin():
                existing = await session.get(GovernanceChainRow, chain.chain_id)
                if existing is None:
                    session.add(
                        GovernanceChainRow(
                            chain_id=chain.chain_id,
                            status=_status_str(chain.status),
                            created_at=chain.created_at,
                            actor_roles=actor_roles_json,
                        )
                    )
                else:
                    existing.status = _status_str(chain.status)
                    existing.actor_roles = actor_roles_json
                    # created_at is immutable; don't overwrite.

                # Which sequences are already persisted?
                stmt = select(ChainEventRow.sequence).where(
                    ChainEventRow.chain_id == chain.chain_id
                )
                existing_seqs = {
                    int(s) for s in (await session.execute(stmt)).scalars().all()
                }

                for idx, event in enumerate(chain.events):
                    if idx in existing_seqs:
                        continue
                    session.add(_event_to_row(chain.chain_id, idx, event))

    async def append_event(self, chain_id: str, event: ChainEvent) -> None:
        """Hot-path single-event insert. Caller holds the chain lock.

        Sequence is derived from the current row count to match the
        in-memory append semantics. The chain row is assumed to exist.
        """
        async with self._sessionmaker() as session:
            async with session.begin():
                stmt = select(func.count()).select_from(ChainEventRow).where(
                    ChainEventRow.chain_id == chain_id
                )
                seq = int((await session.execute(stmt)).scalar_one())
                session.add(_event_to_row(chain_id, seq, event))

    async def delete(self, chain_id: str) -> None:
        """Delete a chain and all its events.

        Events are deleted first to respect the FK from
        ``chain_events.chain_id`` → ``governance_chains.chain_id``.
        """
        async with self._sessionmaker() as session:
            async with session.begin():
                await session.execute(
                    sa_delete(ChainEventRow).where(
                        ChainEventRow.chain_id == chain_id
                    )
                )
                await session.execute(
                    sa_delete(GovernanceChainRow).where(
                        GovernanceChainRow.chain_id == chain_id
                    )
                )


# ── helpers ───────────────────────────────────────────────────────


def _status_str(status) -> str:
    """Accept either a :class:`ChainStatus` enum or a raw string."""
    if isinstance(status, ChainStatus):
        return status.value
    return str(status)


def _event_to_row(chain_id: str, sequence: int, event: ChainEvent) -> ChainEventRow:
    return ChainEventRow(
        chain_id=chain_id,
        sequence=sequence,
        event_id=event.event_id,
        event_type=event.event_type.value,
        actor_id=event.actor_id,
        role_used=event.role_used,
        timestamp=event.timestamp,
        payload=event.payload,
        prev_hash=event.prev_hash,
        event_hash=event.event_hash,
        request_id=event.request_id,
    )


def _row_to_event(row: ChainEventRow) -> ChainEvent:
    return ChainEvent(
        event_id=row.event_id,
        chain_id=row.chain_id,
        event_type=EventType(row.event_type),
        actor_id=row.actor_id,
        role_used=row.role_used,
        timestamp=_ensure_aware(row.timestamp),
        payload=dict(row.payload or {}),
        prev_hash=row.prev_hash,
        event_hash=row.event_hash,
        request_id=row.request_id,
    )


def _row_to_chain(
    chain_row: GovernanceChainRow,
    event_rows: list[ChainEventRow],
) -> GovernanceChain:
    chain = GovernanceChain(chain_id=chain_row.chain_id)
    chain.status = ChainStatus(chain_row.status)
    chain.created_at = _ensure_aware(chain_row.created_at)
    chain.events = [_row_to_event(r) for r in event_rows]
    chain._actor_roles = {
        aid: set(roles or []) for aid, roles in (chain_row.actor_roles or {}).items()
    }
    return chain


def _ensure_aware(dt: datetime) -> datetime:
    """SQLite strips tzinfo; restore UTC assumption on the read path.

    All Gavel timestamps are produced as UTC-aware on the write path
    (see :class:`ChainEvent` / :class:`GovernanceChain`). Postgres
    round-trips tz-aware; SQLite returns naive. We re-attach UTC so the
    downstream hash recomputation sees identical ``isoformat()`` output.
    """
    if dt is None:
        return dt
    if dt.tzinfo is None:
        from datetime import timezone

        return dt.replace(tzinfo=timezone.utc)
    return dt
