"""EnrollmentRepository — CRUD + status filter."""

from __future__ import annotations

from datetime import datetime, timezone

from gavel.db.repositories import EnrollmentRepository
from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    EnrollmentRecord,
    EnrollmentStatus,
    FallbackBehavior,
    PurposeDeclaration,
    ResourceAllowlist,
)


def _make_application(agent_id: str = "agent-1") -> EnrollmentApplication:
    return EnrollmentApplication(
        agent_id=agent_id,
        display_name=f"Agent {agent_id}",
        agent_type="llm",
        owner="jane.doe",
        owner_contact="jane@example.com",
        budget_tokens=10_000,
        budget_usd=5.0,
        purpose=PurposeDeclaration(
            summary="Automates documentation edits",
            operational_scope="internal-docs",
            expected_lifetime="session",
            risk_tier="standard",
        ),
        capabilities=CapabilityManifest(tools=["read", "write"]),
        resources=ResourceAllowlist(allowed_paths=["/docs"]),
        boundaries=ActionBoundaries(allowed_actions=["read", "write"]),
        fallback=FallbackBehavior(),
    )


def _make_record(
    agent_id: str = "agent-1",
    status: EnrollmentStatus = EnrollmentStatus.ENROLLED,
) -> EnrollmentRecord:
    return EnrollmentRecord(
        agent_id=agent_id,
        status=status,
        application=_make_application(agent_id),
        enrolled_at=datetime.now(timezone.utc) if status == EnrollmentStatus.ENROLLED else None,
        reviewed_by="human-op" if status == EnrollmentStatus.ENROLLED else None,
        violations=["v1", "v2"] if status == EnrollmentStatus.INCOMPLETE else [],
    )


async def test_save_then_get_roundtrips(sessionmaker):
    repo = EnrollmentRepository(sessionmaker)
    rec = _make_record()
    await repo.save(rec)

    loaded = await repo.get(rec.agent_id)
    assert loaded is not None
    assert loaded.agent_id == rec.agent_id
    assert loaded.status == rec.status
    assert loaded.application.display_name == rec.application.display_name
    assert loaded.application.purpose.summary == rec.application.purpose.summary
    assert loaded.application.capabilities.tools == ["read", "write"]
    assert loaded.reviewed_by == "human-op"


async def test_get_unknown_returns_none(sessionmaker):
    repo = EnrollmentRepository(sessionmaker)
    assert await repo.get("missing") is None


async def test_save_is_upsert_and_preserves_violations(sessionmaker):
    repo = EnrollmentRepository(sessionmaker)
    rec = _make_record("agent-7", EnrollmentStatus.INCOMPLETE)
    await repo.save(rec)

    # Flip to enrolled.
    rec.status = EnrollmentStatus.ENROLLED
    rec.enrolled_at = datetime.now(timezone.utc)
    rec.violations = []
    await repo.save(rec)

    loaded = await repo.get("agent-7")
    assert loaded is not None
    assert loaded.status == EnrollmentStatus.ENROLLED
    assert loaded.violations == []

    rows = await repo.list_all()
    assert len(rows) == 1


async def test_delete_removes_row(sessionmaker):
    repo = EnrollmentRepository(sessionmaker)
    rec = _make_record()
    await repo.save(rec)
    await repo.delete(rec.agent_id)
    assert await repo.get(rec.agent_id) is None


async def test_list_all_returns_every_record(sessionmaker):
    repo = EnrollmentRepository(sessionmaker)
    await repo.save(_make_record("a-1", EnrollmentStatus.ENROLLED))
    await repo.save(_make_record("a-2", EnrollmentStatus.INCOMPLETE))
    await repo.save(_make_record("a-3", EnrollmentStatus.REJECTED))

    rows = await repo.list_all()
    assert {r.agent_id for r in rows} == {"a-1", "a-2", "a-3"}


async def test_list_by_status_filters(sessionmaker):
    repo = EnrollmentRepository(sessionmaker)
    await repo.save(_make_record("e-1", EnrollmentStatus.ENROLLED))
    await repo.save(_make_record("e-2", EnrollmentStatus.ENROLLED))
    await repo.save(_make_record("p-1", EnrollmentStatus.PENDING))
    await repo.save(_make_record("r-1", EnrollmentStatus.REJECTED))

    enrolled = await repo.list_by_status(EnrollmentStatus.ENROLLED)
    assert {r.agent_id for r in enrolled} == {"e-1", "e-2"}

    pending = await repo.list_by_status("PENDING")
    assert {r.agent_id for r in pending} == {"p-1"}

    none_matching = await repo.list_by_status("SUSPENDED")
    assert none_matching == []
