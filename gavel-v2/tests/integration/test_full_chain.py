"""Integration test: complete governance chain from propose to verify."""

import pytest
from httpx import AsyncClient, ASGITransport

from gavel.gateway import app, chains, separation, liveness, evidence_packets, review_results, execution_tokens


@pytest.fixture(autouse=True)
def reset_state():
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


class TestScenarioZero:
    """
    The full payments-service scaling scenario:
    propose -> attest -> approve -> execution token minted
    """

    @pytest.mark.asyncio
    async def test_full_governance_flow(self, client):
        # Step 1: Propose
        resp = await client.post("/propose", json={
            "actor_id": "agent:ops-monitor",
            "role": "proposer",
            "goal": "Scale payments-service from 3 to 6 replicas",
            "action_type": "INFRA_SCALE",
            "action_content": {
                "service": "payments-service",
                "current_replicas": 3,
                "target_replicas": 6,
            },
            "scope": {
                "allow_paths": ["k8s/deployments/payments-service.yaml"],
                "allow_commands": ["kubectl scale deployment payments-service --replicas=6"],
                "allow_network": False,
            },
            "expected_outcomes": [
                "payments-service replica count == 6",
                "p99 latency < 200ms within 5 minutes",
            ],
            "risk_factors": {
                "base_risk": 0.3,
                "production": True,
                "financial": True,
            },
        })
        assert resp.status_code == 200
        proposal = resp.json()
        chain_id = proposal["chain_id"]
        assert proposal["risk"] == 0.65

        # Step 2: Attest (different agent)
        resp = await client.post("/attest", json={
            "chain_id": chain_id,
            "actor_id": "agent:infra-reviewer",
            "role": "reviewer",
            "decision": "ATTEST",
            "rationale": "Diff is minimal and scoped. Proportionate response.",
        })
        assert resp.status_code == 200
        attest_data = resp.json()
        assert "agent:infra-reviewer" in attest_data["roster"]

        # Step 3: Approve (third distinct agent)
        resp = await client.post("/approve", json={
            "chain_id": chain_id,
            "actor_id": "agent:risk-senior",
            "role": "approver",
            "decision": "APPROVED",
            "rationale": "Consistent with prior scaling events.",
        })
        assert resp.status_code == 200
        approval = resp.json()
        assert approval["status"] == "APPROVED"
        assert "execution_token" in approval

        # Step 4: Verify the complete chain
        resp = await client.get(f"/chain/{chain_id}")
        assert resp.status_code == 200
        chain_data = resp.json()

        # Hash chain integrity
        assert chain_data["integrity"] is True

        # Three distinct principals
        roster = chain_data["roster"]
        assert roster["agent:ops-monitor"] == "proposer"
        assert roster["agent:infra-reviewer"] == "reviewer"
        assert roster["agent:risk-senior"] == "approver"
        assert len(set(roster.keys())) == 3

        # Complete timeline
        event_types = [e["type"] for e in chain_data["events"]]
        assert "INBOUND_INTENT" in event_types
        assert "POLICY_EVAL" in event_types
        assert "APPROVAL_GRANTED" in event_types

    @pytest.mark.asyncio
    async def test_three_agent_separation_enforced(self, client):
        """Verify no actor holds two roles on the same chain."""
        resp = await client.post("/propose", json={
            "actor_id": "agent:ops-monitor",
            "goal": "Scale",
            "action_type": "INFRA_SCALE",
            "risk_factors": {"base_risk": 0.5, "production": True},
        })
        chain_id = resp.json()["chain_id"]

        # Proposer tries to attest -> blocked
        resp = await client.post("/attest", json={
            "chain_id": chain_id,
            "actor_id": "agent:ops-monitor",
            "decision": "ATTEST",
            "rationale": "Self-attest",
        })
        assert resp.status_code == 403

        # Proposer tries to approve -> blocked
        resp = await client.post("/approve", json={
            "chain_id": chain_id,
            "actor_id": "agent:ops-monitor",
            "decision": "APPROVED",
            "rationale": "Self-approve",
        })
        assert resp.status_code == 403

        # Reviewer attests
        resp = await client.post("/attest", json={
            "chain_id": chain_id,
            "actor_id": "agent:reviewer",
            "decision": "ATTEST",
            "rationale": "Looks safe",
        })
        assert resp.status_code == 200

        # Reviewer tries to approve -> blocked
        resp = await client.post("/approve", json={
            "chain_id": chain_id,
            "actor_id": "agent:reviewer",
            "decision": "APPROVED",
            "rationale": "I also approve",
        })
        assert resp.status_code == 403

        # Third agent approves -> success
        resp = await client.post("/approve", json={
            "chain_id": chain_id,
            "actor_id": "agent:approver",
            "decision": "APPROVED",
            "rationale": "Approved",
        })
        assert resp.status_code == 200
