"""Tests for gavel.capa — ISO 42001 Clause 10 CAPA lifecycle."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from gavel.capa import (
    CAPARegistry,
    CAPAStatus,
    CorrectiveAction,
    NonConformity,
)


def _nc(**kw) -> NonConformity:
    defaults = dict(
        title="Test NC",
        description="A test nonconformity",
        source="audit",
        severity="major",
        detected_by="auditor:alice",
        related_requirements=["ATF B-4"],
    )
    defaults.update(kw)
    return NonConformity(**defaults)


def _action(nc_id: str, **kw) -> CorrectiveAction:
    defaults = dict(
        nc_id=nc_id,
        description="Fix the issue",
        assigned_to="eng:bob",
        due_date=datetime.now(timezone.utc) + timedelta(days=14),
        root_cause="Missing validation",
        preventive_measures=["Add input validation", "Add regression test"],
    )
    defaults.update(kw)
    return CorrectiveAction(**defaults)


class TestNonConformityLifecycle:
    def test_file_and_retrieve(self):
        reg = CAPARegistry()
        nc = _nc()
        nc_id = reg.file_nonconformity(nc)
        assert nc_id == nc.nc_id
        retrieved = reg.get_nonconformity(nc_id)
        assert retrieved is not None
        assert retrieved.title == "Test NC"

    def test_get_nonexistent_returns_none(self):
        reg = CAPARegistry()
        assert reg.get_nonconformity("nc-does-not-exist") is None

    def test_nc_id_auto_generated(self):
        nc = _nc()
        assert nc.nc_id.startswith("nc-")
        assert len(nc.nc_id) > 3

    def test_file_multiple_ncs(self):
        reg = CAPARegistry()
        nc1 = _nc(title="NC one")
        nc2 = _nc(title="NC two")
        reg.file_nonconformity(nc1)
        reg.file_nonconformity(nc2)
        assert reg.get_nonconformity(nc1.nc_id).title == "NC one"
        assert reg.get_nonconformity(nc2.nc_id).title == "NC two"


class TestCorrectiveActionLifecycle:
    def test_create_and_retrieve_action(self):
        reg = CAPARegistry()
        nc = _nc()
        reg.file_nonconformity(nc)
        action = _action(nc.nc_id)
        aid = reg.create_action(action)
        assert aid == action.action_id

        actions = reg.get_actions(nc.nc_id)
        assert len(actions) == 1
        assert actions[0].status == CAPAStatus.OPEN

    def test_full_status_transition(self):
        reg = CAPARegistry()
        nc = _nc()
        reg.file_nonconformity(nc)
        action = _action(nc.nc_id)
        reg.create_action(action)

        reg.update_status(action.action_id, CAPAStatus.ROOT_CAUSE_IDENTIFIED)
        assert reg._actions[action.action_id].status == CAPAStatus.ROOT_CAUSE_IDENTIFIED

        reg.update_status(action.action_id, CAPAStatus.ACTION_PLANNED)
        assert reg._actions[action.action_id].status == CAPAStatus.ACTION_PLANNED

        reg.update_status(action.action_id, CAPAStatus.ACTION_TAKEN)
        a = reg._actions[action.action_id]
        assert a.status == CAPAStatus.ACTION_TAKEN
        assert a.completed_at is not None

        reg.update_status(action.action_id, CAPAStatus.VERIFIED, verified_by="qa:carol")
        a = reg._actions[action.action_id]
        assert a.status == CAPAStatus.VERIFIED
        assert a.verified_at is not None
        assert a.verified_by == "qa:carol"

        reg.update_status(action.action_id, CAPAStatus.CLOSED)
        assert reg._actions[action.action_id].status == CAPAStatus.CLOSED

    def test_update_unknown_action_raises(self):
        reg = CAPARegistry()
        with pytest.raises(KeyError):
            reg.update_status("ca-nonexistent", CAPAStatus.CLOSED)

    def test_action_id_auto_generated(self):
        action = _action("nc-test")
        assert action.action_id.startswith("ca-")


class TestOpenNonconformities:
    def test_open_returns_ncs_without_closed_actions(self):
        reg = CAPARegistry()
        nc1 = _nc(title="Open NC")
        nc2 = _nc(title="Closed NC")
        reg.file_nonconformity(nc1)
        reg.file_nonconformity(nc2)

        action = _action(nc2.nc_id)
        reg.create_action(action)
        reg.update_status(action.action_id, CAPAStatus.CLOSED)

        open_ncs = reg.get_open()
        assert len(open_ncs) == 1
        assert open_ncs[0].nc_id == nc1.nc_id

    def test_nc_with_open_action_is_still_open(self):
        reg = CAPARegistry()
        nc = _nc()
        reg.file_nonconformity(nc)
        action = _action(nc.nc_id)
        reg.create_action(action)

        open_ncs = reg.get_open()
        assert len(open_ncs) == 1


class TestOverdueDetection:
    def test_past_due_action_is_overdue(self):
        reg = CAPARegistry()
        nc = _nc()
        reg.file_nonconformity(nc)
        action = _action(nc.nc_id, due_date=datetime(2024, 1, 1, tzinfo=timezone.utc))
        reg.create_action(action)

        overdue = reg.get_overdue(now=datetime(2024, 6, 1, tzinfo=timezone.utc))
        assert len(overdue) == 1
        assert overdue[0].action_id == action.action_id

    def test_closed_action_not_overdue(self):
        reg = CAPARegistry()
        nc = _nc()
        reg.file_nonconformity(nc)
        action = _action(nc.nc_id, due_date=datetime(2024, 1, 1, tzinfo=timezone.utc))
        reg.create_action(action)
        reg.update_status(action.action_id, CAPAStatus.CLOSED)

        overdue = reg.get_overdue(now=datetime(2024, 6, 1, tzinfo=timezone.utc))
        assert len(overdue) == 0

    def test_verified_action_not_overdue(self):
        reg = CAPARegistry()
        nc = _nc()
        reg.file_nonconformity(nc)
        action = _action(nc.nc_id, due_date=datetime(2024, 1, 1, tzinfo=timezone.utc))
        reg.create_action(action)
        reg.update_status(action.action_id, CAPAStatus.VERIFIED, verified_by="qa:carol")

        overdue = reg.get_overdue(now=datetime(2024, 6, 1, tzinfo=timezone.utc))
        assert len(overdue) == 0

    def test_future_due_date_not_overdue(self):
        reg = CAPARegistry()
        nc = _nc()
        reg.file_nonconformity(nc)
        action = _action(nc.nc_id, due_date=datetime(2030, 1, 1, tzinfo=timezone.utc))
        reg.create_action(action)

        overdue = reg.get_overdue(now=datetime(2024, 6, 1, tzinfo=timezone.utc))
        assert len(overdue) == 0


class TestSummary:
    def test_summary_counts(self):
        reg = CAPARegistry()
        nc1 = _nc(severity="critical")
        nc2 = _nc(severity="major")
        nc3 = _nc(severity="minor")
        reg.file_nonconformity(nc1)
        reg.file_nonconformity(nc2)
        reg.file_nonconformity(nc3)

        action = _action(nc1.nc_id)
        reg.create_action(action)
        reg.update_status(action.action_id, CAPAStatus.CLOSED)

        s = reg.summary()
        assert s["total"] == 3
        assert s["open"] == 2
        assert s["closed"] == 1
        assert s["by_severity"]["critical"] == 1
        assert s["by_severity"]["major"] == 1
        assert s["by_severity"]["minor"] == 1

    def test_empty_summary(self):
        reg = CAPARegistry()
        s = reg.summary()
        assert s["total"] == 0
        assert s["open"] == 0
        assert s["closed"] == 0
        assert s["overdue_actions"] == 0
        assert s["by_severity"] == {}
