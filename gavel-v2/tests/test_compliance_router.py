"""Tests for the compliance API router — HTTP endpoint tests for
Annex IV documentation, incident management, and compliance status.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport

from gavel.compliance import (
    IncidentRegistry,
    IncidentSeverity,
    IncidentStatus,
)
from gavel.compliance_router import (
    router,
    CreateIncidentRequest,
    IncidentResponse,
    ComplianceStatusSummary,
)
from gavel.db.repositories import (
    ChainRepository,
    EnrollmentRepository,
    IncidentRepository,
    ReviewRepository,
)
from gavel.dependencies import (
    get_chain_repo,
    get_constitution,
    get_enrollment_registry,
    get_event_bus,
    get_incident_registry,
    get_review_repo,
    get_tier_policy,
)
from gavel.enrollment import EnrollmentRegistry, EnrollmentStatus
from gavel.chain import GovernanceChain, ChainStatus, EventType
from gavel.constitution import Constitution
from gavel.tiers import TierPolicy
from gavel.events import EventBus
import gavel.db.engine as db_engine

from conftest import _valid_application

# We need a minimal FastAPI app for testing the router
from fastapi import FastAPI


@pytest.fixture
def test_app():
    """Create a test FastAPI app with the compliance router wired in."""
    app = FastAPI()
    app.include_router(router, prefix="/v1")

    sm = db_engine.get_sessionmaker()
    incident_reg = IncidentRegistry(IncidentRepository(sm))
    enrollment_reg = EnrollmentRegistry(EnrollmentRepository(sm))
    chain_repo = ChainRepository(sm)
    review_repo = ReviewRepository(sm)
    constitution = Constitution()
    tier_policy = TierPolicy()
    event_bus = EventBus()

    app.dependency_overrides[get_incident_registry] = lambda: incident_reg
    app.dependency_overrides[get_enrollment_registry] = lambda: enrollment_reg
    app.dependency_overrides[get_chain_repo] = lambda: chain_repo
    app.dependency_overrides[get_review_repo] = lambda: review_repo
    app.dependency_overrides[get_constitution] = lambda: constitution
    app.dependency_overrides[get_tier_policy] = lambda: tier_policy
    app.dependency_overrides[get_event_bus] = lambda: event_bus

    # Store refs for test access
    app.state.incident_registry = incident_reg
    app.state.enrollment_registry = enrollment_reg
    app.state.chain_repo = chain_repo

    return app


@pytest.fixture
async def client(test_app):
    """Async HTTP client for testing."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestIncidentEndpoints:
    """Test incident CRUD via HTTP."""

    @pytest.mark.asyncio
    async def test_list_incidents_empty(self, client):
        resp = await client.get("/v1/incidents")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_create_incident(self, client):
        resp = await client.post("/v1/incidents", json={
            "agent_id": "agent:test",
            "title": "Test incident",
            "description": "Something happened",
            "severity": "critical",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["incident_id"].startswith("inc-")
        assert data["severity"] == "critical"
        assert data["status"] == "open"
        assert data["is_overdue"] is False

    @pytest.mark.asyncio
    async def test_create_incident_auto_severity(self, client):
        resp = await client.post("/v1/incidents", json={
            "agent_id": "agent:test",
            "title": "Kill switch fired",
            "description": "Agent killed",
            "event_type": "kill_switch_activated",
        })
        assert resp.status_code == 201
        assert resp.json()["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_get_incident(self, client):
        # Create first
        create_resp = await client.post("/v1/incidents", json={
            "agent_id": "agent:a",
            "title": "Test",
            "description": "Desc",
            "severity": "minor",
        })
        inc_id = create_resp.json()["incident_id"]

        # Get
        resp = await client.get(f"/v1/incidents/{inc_id}")
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == "agent:a"

    @pytest.mark.asyncio
    async def test_get_incident_not_found(self, client):
        resp = await client.get("/v1/incidents/inc-nonexistent")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_filter_severity(self, client):
        await client.post("/v1/incidents", json={
            "agent_id": "agent:a", "title": "Critical", "description": "D", "severity": "critical"})
        await client.post("/v1/incidents", json={
            "agent_id": "agent:b", "title": "Minor", "description": "D", "severity": "minor"})

        resp = await client.get("/v1/incidents?severity=critical")
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_list_filter_agent(self, client):
        await client.post("/v1/incidents", json={
            "agent_id": "agent:x", "title": "Inc1", "description": "D", "severity": "minor"})
        await client.post("/v1/incidents", json={
            "agent_id": "agent:y", "title": "Inc2", "description": "D", "severity": "minor"})

        resp = await client.get("/v1/incidents?agent_id=agent:x")
        assert len(resp.json()) == 1

    @pytest.mark.asyncio
    async def test_mark_reported(self, client):
        create_resp = await client.post("/v1/incidents", json={
            "agent_id": "agent:a", "title": "Test", "description": "D", "severity": "serious"})
        inc_id = create_resp.json()["incident_id"]

        resp = await client.patch(f"/v1/incidents/{inc_id}/report")
        assert resp.status_code == 200
        assert resp.json()["status"] == "reported"
        assert resp.json()["reported_at"] is not None

    @pytest.mark.asyncio
    async def test_mark_resolved(self, client):
        create_resp = await client.post("/v1/incidents", json={
            "agent_id": "agent:a", "title": "Test", "description": "D", "severity": "standard"})
        inc_id = create_resp.json()["incident_id"]

        resp = await client.patch(f"/v1/incidents/{inc_id}/resolve")
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_mark_reported_not_found(self, client):
        resp = await client.patch("/v1/incidents/inc-fake/report")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_mark_resolved_not_found(self, client):
        resp = await client.patch("/v1/incidents/inc-fake/resolve")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_overdue_empty(self, client):
        resp = await client.get("/v1/incidents/overdue")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_overdue_with_backdated(self, test_app, client):
        # Create incident and backdate deadline in-place.
        reg: IncidentRegistry = test_app.state.incident_registry
        incident = await reg.report("agent:a", "Old", "Desc", IncidentSeverity.CRITICAL)
        # Force-update deadline via the repo's underlying persistence.
        repo: IncidentRepository = reg._repo
        sm = repo._sessionmaker
        from sqlalchemy import update
        from gavel.db.models import IncidentRow
        async with sm() as session:
            async with session.begin():
                await session.execute(
                    update(IncidentRow)
                    .where(IncidentRow.incident_id == incident.incident_id)
                    .values(deadline=datetime.now(timezone.utc) - timedelta(days=1))
                )

        resp = await client.get("/v1/incidents/overdue")
        assert len(resp.json()) == 1


class TestAnnexIVEndpoint:
    """Test Annex IV documentation generation via HTTP."""

    @pytest.mark.asyncio
    async def test_annex_iv_no_enrollment(self, client):
        resp = await client.get("/v1/agents/agent:unknown/compliance/annex-iv")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_annex_iv_with_enrollment(self, test_app, client):
        # Submit enrollment
        reg = test_app.state.enrollment_registry
        app = _valid_application()
        await reg.submit(app)

        resp = await client.get("/v1/agents/agent:test/compliance/annex-iv")
        assert resp.status_code == 200
        data = resp.json()
        assert "sections" in data
        assert "1_general_description" in data["sections"]
        assert data["annex_iv_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_annex_iv_has_all_sections(self, test_app, client):
        reg = test_app.state.enrollment_registry
        await reg.submit(_valid_application())

        resp = await client.get("/v1/agents/agent:test/compliance/annex-iv")
        sections = resp.json()["sections"]
        for i in range(1, 10):
            assert any(k.startswith(f"{i}_") for k in sections), f"Missing section {i}"


class TestComplianceStatusEndpoint:
    """Test overall compliance status summary."""

    @pytest.mark.asyncio
    async def test_status_empty(self, client):
        resp = await client.get("/v1/compliance/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_agents"] == 0
        assert data["total_incidents"] == 0

    @pytest.mark.asyncio
    async def test_status_with_data(self, test_app, client):
        # Add enrollment
        reg = test_app.state.enrollment_registry
        await reg.submit(_valid_application())

        # Add incident
        await client.post("/v1/incidents", json={
            "agent_id": "agent:test", "title": "Test", "description": "D", "severity": "serious"})

        resp = await client.get("/v1/compliance/status")
        data = resp.json()
        assert data["total_agents"] >= 1
        assert data["total_incidents"] == 1
        assert "serious" in data["incidents_by_severity"]
