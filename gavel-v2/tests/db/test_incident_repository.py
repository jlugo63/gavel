"""IncidentRepository — CRUD + overdue query + atomic mark_reported."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gavel.compliance import IncidentReport, IncidentSeverity, IncidentStatus
from gavel.db.repositories import IncidentRepository


def _make_incident(
    incident_id: str = "inc-a1",
    agent_id: str = "agent-1",
    severity: IncidentSeverity = IncidentSeverity.CRITICAL,
    deadline: datetime | None = None,
    reported_at: datetime | None = None,
    resolved_at: datetime | None = None,
) -> IncidentReport:
    detected = datetime.now(timezone.utc)
    return IncidentReport(
        incident_id=incident_id,
        agent_id=agent_id,
        severity=severity,
        status=IncidentStatus.OPEN,
        title=f"Title for {incident_id}",
        description=f"Description for {incident_id}",
        detected_at=detected,
        reported_at=reported_at,
        resolved_at=resolved_at,
        deadline=deadline,
        chain_ids=["c-1", "c-2"],
        findings=["f-1"],
        regulatory_references=["Art. 73"],
    )


async def test_save_then_get_roundtrips(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    inc = _make_incident()
    await repo.save(inc)

    loaded = await repo.get(inc.incident_id)
    assert loaded is not None
    assert loaded.incident_id == inc.incident_id
    assert loaded.agent_id == inc.agent_id
    assert loaded.severity == IncidentSeverity.CRITICAL
    assert loaded.status == IncidentStatus.OPEN
    assert loaded.chain_ids == ["c-1", "c-2"]
    assert loaded.findings == ["f-1"]
    assert loaded.regulatory_references == ["Art. 73"]


async def test_get_unknown_returns_none(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    assert await repo.get("inc-missing") is None


async def test_save_is_upsert(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    inc = _make_incident()
    await repo.save(inc)

    inc.findings = ["updated"]
    await repo.save(inc)

    loaded = await repo.get(inc.incident_id)
    assert loaded is not None
    assert loaded.findings == ["updated"]

    rows = await repo.list_all()
    assert len(rows) == 1


async def test_delete_removes_row(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    inc = _make_incident()
    await repo.save(inc)
    await repo.delete(inc.incident_id)
    assert await repo.get(inc.incident_id) is None


async def test_list_by_agent_filters(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    await repo.save(_make_incident("inc-1", agent_id="a"))
    await repo.save(_make_incident("inc-2", agent_id="a"))
    await repo.save(_make_incident("inc-3", agent_id="b"))

    hits = await repo.list_by_agent("a")
    assert {i.incident_id for i in hits} == {"inc-1", "inc-2"}


async def test_list_overdue_excludes_reported_and_future(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    now = datetime.now(timezone.utc)

    # Overdue: deadline in past, not reported
    await repo.save(_make_incident(
        "inc-overdue",
        deadline=now - timedelta(hours=1),
    ))
    # Reported already — not overdue anymore
    await repo.save(_make_incident(
        "inc-reported",
        deadline=now - timedelta(hours=2),
        reported_at=now - timedelta(minutes=30),
    ))
    # Future deadline — not overdue
    await repo.save(_make_incident(
        "inc-future",
        deadline=now + timedelta(hours=1),
    ))
    # No deadline (MINOR) — not overdue
    await repo.save(_make_incident("inc-minor", deadline=None))

    overdue = await repo.list_overdue(now)
    assert {i.incident_id for i in overdue} == {"inc-overdue"}


async def test_mark_reported_is_atomic_idempotent_once(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    inc = _make_incident("inc-rep", deadline=datetime.now(timezone.utc) - timedelta(hours=1))
    await repo.save(inc)

    first = await repo.mark_reported("inc-rep")
    assert first is True

    second = await repo.mark_reported("inc-rep")
    assert second is False

    loaded = await repo.get("inc-rep")
    assert loaded is not None
    assert loaded.reported_at is not None
    assert loaded.status == IncidentStatus.REPORTED


async def test_mark_reported_missing_returns_false(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    assert await repo.mark_reported("inc-nope") is False


async def test_mark_resolved_is_atomic_idempotent_once(sessionmaker):
    repo = IncidentRepository(sessionmaker)
    await repo.save(_make_incident("inc-res"))

    assert await repo.mark_resolved("inc-res") is True
    assert await repo.mark_resolved("inc-res") is False

    loaded = await repo.get("inc-res")
    assert loaded is not None
    assert loaded.resolved_at is not None
    assert loaded.status == IncidentStatus.RESOLVED
