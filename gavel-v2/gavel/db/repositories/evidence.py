"""EvidenceRepository — persistence for EvidencePacket rows.

Current in-memory semantics (``get_evidence_packets()`` returns a
``dict[chain_id, EvidencePacket]``):

* ``get(chain_id)``   → ``evidence_packets.get(chain_id)``
* ``save(cid, pkt)``  → ``evidence_packets[cid] = pkt``  (upsert)
* ``delete(cid)``     → ``evidence_packets.pop(cid, None)``

The underlying :class:`EvidencePacketRow` has ``packet_id`` as its PK,
but there is at most one packet per chain today, so we upsert keyed on
``chain_id``. ``ScopeDeclaration`` is serialised as a JSON dict using
``dataclasses.asdict``; on load we rebuild the dataclass.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.blastbox import EvidencePacket, ScopeDeclaration
from gavel.db.repositories.chains import _ensure_aware
from gavel.db.models import EvidencePacketRow


class EvidenceRepository:
    """Async repository for evidence packets keyed by ``chain_id``."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    async def get(self, chain_id: str) -> Optional[EvidencePacket]:
        async with self._sessionmaker() as session:
            stmt = select(EvidencePacketRow).where(
                EvidencePacketRow.chain_id == chain_id
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_packet(row)

    async def save(self, chain_id: str, packet: EvidencePacket) -> None:
        """Upsert: one packet per chain. Replaces any prior packet."""
        async with self._sessionmaker() as session:
            async with session.begin():
                # Upsert semantics match dict[chain_id] = packet: wipe any
                # prior row (regardless of its packet_id) and insert fresh.
                await session.execute(
                    sa_delete(EvidencePacketRow).where(
                        EvidencePacketRow.chain_id == chain_id
                    )
                )
                session.add(_packet_to_row(chain_id, packet))

    async def delete(self, chain_id: str) -> None:
        async with self._sessionmaker() as session:
            async with session.begin():
                await session.execute(
                    sa_delete(EvidencePacketRow).where(
                        EvidencePacketRow.chain_id == chain_id
                    )
                )


# ── helpers ───────────────────────────────────────────────────────


def _packet_to_row(chain_id: str, packet: EvidencePacket) -> EvidencePacketRow:
    return EvidencePacketRow(
        packet_id=packet.packet_id,
        chain_id=chain_id,
        intent_event_id=packet.intent_event_id,
        command_argv=list(packet.command_argv),
        scope=asdict(packet.scope) if packet.scope is not None else {},
        exit_code=packet.exit_code,
        stdout_hash=packet.stdout_hash,
        stderr_hash=packet.stderr_hash,
        diff_hash=packet.diff_hash,
        stdout_preview=packet.stdout_preview,
        files_modified=list(packet.files_modified),
        files_created=list(packet.files_created),
        files_deleted=list(packet.files_deleted),
        image=packet.image,
        image_digest=packet.image_digest,
        network_mode=packet.network_mode,
        cpu=packet.cpu,
        memory=packet.memory,
        started_at=packet.started_at,
        finished_at=packet.finished_at,
    )


def _row_to_packet(row: EvidencePacketRow) -> EvidencePacket:
    scope_kwargs = dict(row.scope or {})
    scope = ScopeDeclaration(**scope_kwargs) if scope_kwargs else ScopeDeclaration()
    return EvidencePacket(
        packet_id=row.packet_id,
        chain_id=row.chain_id,
        intent_event_id=row.intent_event_id,
        command_argv=list(row.command_argv or []),
        scope=scope,
        exit_code=row.exit_code,
        stdout_hash=row.stdout_hash,
        stderr_hash=row.stderr_hash,
        diff_hash=row.diff_hash,
        stdout_preview=row.stdout_preview,
        files_modified=list(row.files_modified or []),
        files_created=list(row.files_created or []),
        files_deleted=list(row.files_deleted or []),
        image=row.image,
        image_digest=row.image_digest,
        network_mode=row.network_mode,
        cpu=row.cpu,
        memory=row.memory,
        started_at=_ensure_aware(row.started_at),
        finished_at=_ensure_aware(row.finished_at),
    )
