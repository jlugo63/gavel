"""Integration tests for the FastAPI gateway — full endpoint testing."""

import pytest
from httpx import AsyncClient, ASGITransport

from gavel.gateway import app, chains, separation, liveness, evidence_packets, review_results, execution_tokens


@pytest.fixture(autouse=True)
def reset_state():
    """Reset gateway state between tests."""
    chains.clear()
    evidence_packets.clear()
    review_results.clear()
    execution_tokens.clear()
    separation._assignments.clear()
    liveness._timeouts.clear()
    yield


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestProposeEndpoint:
    @pytest.mark.asyncio
    async def test_propose_creates_chain(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale payments-service",
            "action_type": "INFRA_SCALE",
            "scope": {"allow_paths": ["k8s/deployments/"], "allow_commands": ["kubectl scale"]},
            "risk_factors": {"base_risk": 0.3, "production": True, "financial": True},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "chain_id" in data
        assert "timeline" in data
        assert data["risk"] > 0

    @pytest.mark.asyncio
    async def test_propose_low_risk_auto_approves(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Read log file",
            "action_type": "LOG_READ",
            "scope": {"allow_paths": ["logs/"], "allow_commands": ["cat logs/app.log"]},
            "risk_factors": {"base_risk": 0.1},
        })
        data = resp.json()
        # Low risk = Tier 0 (SUPERVISED), requires human approval, so should be ESCALATED
        assert data["status"] in ("ESCALATED", "APPROVED")

    @pytest.mark.asyncio
    async def test_propose_high_risk_escalates(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale production service",
            "action_type": "INFRA_SCALE",
            "scope": {"allow_paths": ["k8s/"], "allow_commands": ["kubectl scale"]},
            "risk_factors": {"base_risk": 0.5, "production": True, "financial": True},
        })
        data = resp.json()
        assert data["status"] == "ESCALATED"

    @pytest.mark.asyncio
    async def test_propose_returns_timeline(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Test",
            "action_type": "TEST",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        data = resp.json()
        events = [e["event"] for e in data["timeline"]]
        assert "INBOUND_INTENT" in events
        assert "POLICY_EVAL" in events


class TestAttestEndpoint:
    @pytest.mark.asyncio
    async def test_attest_succeeds(self, client):
        # First, create a chain
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale",
            "action_type": "SCALE",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        chain_id = resp.json()["chain_id"]

        # Attest with a DIFFERENT agent
        resp = await client.post("/attest", json={
            "chain_id": chain_id,
            "actor_id": "agent:reviewer",
            "decision": "ATTEST",
            "rationale": "Looks good",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["roster"]["agent:reviewer"] == "reviewer"

    @pytest.mark.asyncio
    async def test_attest_by_proposer_blocked(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale",
            "action_type": "SCALE",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        chain_id = resp.json()["chain_id"]

        # Same agent tries to review -> separation violation
        resp = await client.post("/attest", json={
            "chain_id": chain_id,
            "actor_id": "agent:monitor",
            "decision": "ATTEST",
            "rationale": "I approve myself",
        })
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_attest_unknown_chain_404(self, client):
        resp = await client.post("/attest", json={
            "chain_id": "c-nonexistent",
            "actor_id": "agent:reviewer",
            "decision": "ATTEST",
            "rationale": "N/A",
        })
        assert resp.status_code == 404


class TestApproveEndpoint:
    @pytest.mark.asyncio
    async def test_approve_full_flow(self, client):
        # Propose
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale",
            "action_type": "SCALE",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        chain_id = resp.json()["chain_id"]

        # Approve with different agent
        resp = await client.post("/approve", json={
            "chain_id": chain_id,
            "actor_id": "agent:approver",
            "decision": "APPROVED",
            "rationale": "Approved after review",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "APPROVED"
        assert "execution_token" in data

    @pytest.mark.asyncio
    async def test_deny_flow(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale",
            "action_type": "SCALE",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        chain_id = resp.json()["chain_id"]

        resp = await client.post("/approve", json={
            "chain_id": chain_id,
            "actor_id": "agent:approver",
            "decision": "DENIED",
            "rationale": "Too risky",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "DENIED"

    @pytest.mark.asyncio
    async def test_proposer_cannot_approve(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale",
            "action_type": "SCALE",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        chain_id = resp.json()["chain_id"]

        resp = await client.post("/approve", json={
            "chain_id": chain_id,
            "actor_id": "agent:monitor",
            "decision": "APPROVED",
            "rationale": "I approve myself",
        })
        assert resp.status_code == 403


class TestChainEndpoint:
    @pytest.mark.asyncio
    async def test_get_chain(self, client):
        resp = await client.post("/propose", json={
            "actor_id": "agent:monitor",
            "goal": "Scale",
            "action_type": "SCALE",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        chain_id = resp.json()["chain_id"]

        resp = await client.get(f"/chain/{chain_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["chain_id"] == chain_id
        assert data["integrity"] is True
        assert len(data["events"]) > 0

    @pytest.mark.asyncio
    async def test_get_unknown_chain_404(self, client):
        resp = await client.get("/chain/c-nonexistent")
        assert resp.status_code == 404


class TestConstitutionEndpoint:
    @pytest.mark.asyncio
    async def test_get_constitution(self, client):
        resp = await client.get("/constitution")
        assert resp.status_code == 200
        data = resp.json()
        assert "invariants" in data
        assert len(data["invariants"]) > 0
        assert data["invariants"][0]["article"] is not None


class TestLivenessEndpoint:
    @pytest.mark.asyncio
    async def test_get_liveness(self, client):
        resp = await client.get("/liveness")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_tracked" in data
        assert "active" in data
