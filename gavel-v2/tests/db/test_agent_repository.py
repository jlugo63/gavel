"""AgentRepository — CRUD round-trip + count_active."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gavel.agents import AgentRecord, AgentStatus
from gavel.db.repositories import AgentRepository


def _make_record(agent_id: str = "agent-1", status: AgentStatus = AgentStatus.ACTIVE) -> AgentRecord:
    now = datetime.now(timezone.utc)
    return AgentRecord(
        agent_id=agent_id,
        display_name=f"Agent {agent_id}",
        agent_type="llm",
        did=f"did:gavel:agent:{agent_id}",
        trust_score=612,
        autonomy_tier=1,
        capabilities=["read", "write"],
        status=status,
        registered_at=now,
        last_heartbeat=now,
        heartbeat_interval_s=30,
        chains_proposed=3,
        chains_completed=7,
        violations=1,
        successful_actions=42,
        session_id="sess-xyz",
        current_activity="Reviewing PR",
    )


async def test_save_then_get_roundtrips_all_fields(sessionmaker):
    repo = AgentRepository(sessionmaker)
    rec = _make_record()
    await repo.save(rec)

    loaded = await repo.get(rec.agent_id)
    assert loaded is not None
    assert loaded.agent_id == rec.agent_id
    assert loaded.display_name == rec.display_name
    assert loaded.did == rec.did
    assert loaded.trust_score == rec.trust_score
    assert loaded.autonomy_tier == rec.autonomy_tier
    assert loaded.capabilities == rec.capabilities
    assert loaded.status == rec.status
    assert loaded.chains_proposed == 3
    assert loaded.chains_completed == 7
    assert loaded.violations == 1
    assert loaded.successful_actions == 42
    assert loaded.session_id == "sess-xyz"
    assert loaded.current_activity == "Reviewing PR"


async def test_get_returns_none_for_unknown(sessionmaker):
    repo = AgentRepository(sessionmaker)
    assert await repo.get("nope") is None


async def test_save_is_upsert(sessionmaker):
    repo = AgentRepository(sessionmaker)
    rec = _make_record()
    await repo.save(rec)

    rec.trust_score = 999
    rec.current_activity = "Compiling"
    await repo.save(rec)

    loaded = await repo.get(rec.agent_id)
    assert loaded is not None
    assert loaded.trust_score == 999
    assert loaded.current_activity == "Compiling"

    # list_all must still have only one row
    all_records = await repo.list_all()
    assert len(all_records) == 1


async def test_delete_removes_row(sessionmaker):
    repo = AgentRepository(sessionmaker)
    rec = _make_record()
    await repo.save(rec)
    await repo.delete(rec.agent_id)
    assert await repo.get(rec.agent_id) is None


async def test_delete_missing_is_noop(sessionmaker):
    repo = AgentRepository(sessionmaker)
    # Must not raise.
    await repo.delete("does-not-exist")


async def test_list_all_returns_every_record(sessionmaker):
    repo = AgentRepository(sessionmaker)
    await repo.save(_make_record("a-1"))
    await repo.save(_make_record("a-2"))
    await repo.save(_make_record("a-3"))

    rows = await repo.list_all()
    assert {r.agent_id for r in rows} == {"a-1", "a-2", "a-3"}


async def test_count_active_only_counts_active_status(sessionmaker):
    repo = AgentRepository(sessionmaker)
    await repo.save(_make_record("a-1", AgentStatus.ACTIVE))
    await repo.save(_make_record("a-2", AgentStatus.ACTIVE))
    await repo.save(_make_record("a-3", AgentStatus.SUSPENDED))
    await repo.save(_make_record("a-4", AgentStatus.DEAD))
    await repo.save(_make_record("a-5", AgentStatus.IDLE))

    assert await repo.count_active() == 2


async def test_count_active_on_empty_table_is_zero(sessionmaker):
    repo = AgentRepository(sessionmaker)
    assert await repo.count_active() == 0
