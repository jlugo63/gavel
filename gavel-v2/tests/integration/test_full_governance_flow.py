"""End-to-end governance flow against a real Postgres.

Single marquee test: enroll a proposer + an approver, propose an action,
attest, approve, execute, and verify the hash chain came through intact
via a direct repository read. Proves the full FastAPI → repo → asyncpg
→ Postgres stack preserves chain integrity across a real network DB.

Marked ``integration`` so the default pytest run (``-m 'not integration'``)
skips it. Require ``GAVEL_INTEGRATION_DB_URL`` to run.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gavel.db.repositories import ChainRepository
from gavel.dependencies import get_sessionmaker
from gavel.enrollment import (
    ActionBoundaries,
    CapabilityManifest,
    EnrollmentApplication,
    FallbackBehavior,
    PurposeDeclaration,
    ResourceAllowlist,
)
from gavel.gateway import app


pytestmark = pytest.mark.integration


def _valid_enrollment(agent_id: str, display_name: str) -> dict:
    """Build an enrollment payload that clears ATF validation.

    Mirrors the shape used by ``tests/conftest.py::_valid_application`` but
    returned as a JSON-serialisable dict for ``TestClient.post``. The
    minimal-risk declaration keeps the app out of the EU AI Act Art. 5
    prohibited-practice branch.
    """
    return EnrollmentApplication(
        agent_id=agent_id,
        display_name=display_name,
        agent_type="llm",
        owner="dev@gavel.eu",
        owner_contact="dev@gavel.eu",
        budget_tokens=100_000,
        budget_usd=50.0,
        purpose=PurposeDeclaration(
            summary="Integration test agent for governance flow validation",
            operational_scope="testing",
            expected_lifetime="session",
            risk_tier="standard",
        ),
        capabilities=CapabilityManifest(
            tools=["Read", "Write"],
            max_concurrent_chains=2,
            can_spawn_subagents=False,
            network_access=False,
            file_system_access=True,
            execution_access=True,
        ),
        resources=ResourceAllowlist(
            allowed_paths=["/tmp/gavel-test"],
            allowed_hosts=[],
            allowed_env_vars=["PATH"],
            max_file_size_mb=5.0,
        ),
        boundaries=ActionBoundaries(
            allowed_actions=["read", "write", "execute"],
            blocked_patterns=["rm -rf /"],
            max_actions_per_minute=30,
            max_risk_threshold=0.7,
        ),
        fallback=FallbackBehavior(
            on_gateway_unreachable="stop",
            on_budget_exceeded="stop",
            on_sla_timeout="deny",
            graceful_shutdown=True,
        ),
    ).model_dump(mode="json")


def test_full_governance_flow_against_postgres():
    """Enroll → propose → attest → approve → execute, all via HTTP + real Postgres."""
    client = TestClient(app)

    # ---- 1. Register + enroll the proposer ---------------------------------
    proposer_id = "agent:itest-proposer"
    reviewer_id = "agent:itest-reviewer"
    approver_id = "agent:itest-approver"

    register = client.post(
        "/v1/agents/register",
        json={
            "agent_id": proposer_id,
            "display_name": "Integration Proposer",
            "agent_type": "llm",
            "capabilities": ["Read", "Write"],
        },
    )
    assert register.status_code == 200, register.text

    enroll = client.post("/v1/agents/enroll", json=_valid_enrollment(proposer_id, "Integration Proposer"))
    assert enroll.status_code == 200, enroll.text
    enroll_body = enroll.json()
    assert enroll_body["enrolled"] is True, enroll_body
    proposer_token = enroll_body["governance_token"]["token"]

    # The approver needs a governance token too (every governance endpoint
    # requires one). Enroll a second agent with a distinct actor_id so the
    # separation-of-powers check is satisfied.
    approver_enroll = client.post(
        "/v1/agents/enroll",
        json=_valid_enrollment(approver_id, "Integration Approver"),
    )
    assert approver_enroll.status_code == 200, approver_enroll.text
    approver_token = approver_enroll.json()["governance_token"]["token"]

    reviewer_enroll = client.post(
        "/v1/agents/enroll",
        json=_valid_enrollment(reviewer_id, "Integration Reviewer"),
    )
    assert reviewer_enroll.status_code == 200, reviewer_enroll.text
    reviewer_token = reviewer_enroll.json()["governance_token"]["token"]

    # ---- 2. Propose --------------------------------------------------------
    # No ``allow_commands`` → no blastbox execution. ``production=True`` bumps
    # the risk so the chain escalates (vs. the Tier-1 auto-approve path),
    # giving us the attest → approve → execute arc with 4+ events.
    propose = client.post(
        "/v1/propose",
        headers={"X-Gavel-Token": proposer_token},
        json={
            "actor_id": proposer_id,
            "goal": "Integration test: write a file to the sandbox",
            "action_type": "FILE_WRITE",
            "action_content": {"path": "/tmp/gavel-test/out.txt", "content": "hello"},
            "scope": {
                "allow_paths": ["/tmp/gavel-test"],
                "allow_commands": [],
                "allow_network": False,
            },
            "expected_outcomes": ["File written under sandbox path"],
            "risk_factors": {
                "base_risk": 0.7,
                "production": True,
                "financial": True,
                "pii": True,
            },
        },
    )
    assert propose.status_code == 200, propose.text
    chain_id = propose.json()["chain_id"]
    assert propose.json()["status"] == "ESCALATED"

    # ---- 3. Independent reviewer attests -----------------------------------
    attest = client.post(
        "/v1/attest",
        headers={"X-Gavel-Token": reviewer_token},
        json={
            "chain_id": chain_id,
            "actor_id": reviewer_id,
            "decision": "ATTEST",
            "rationale": "Scope is minimal and sandboxed.",
        },
    )
    assert attest.status_code == 200, attest.text

    # ---- 4. Independent approver approves ----------------------------------
    approve = client.post(
        "/v1/approve",
        headers={"X-Gavel-Token": approver_token},
        json={
            "chain_id": chain_id,
            "actor_id": approver_id,
            "decision": "APPROVED",
            "rationale": "Review clean, risk acceptable.",
        },
    )
    assert approve.status_code == 200, approve.text
    execution_token = approve.json()["execution_token"]
    assert execution_token.startswith("exec-t-")

    # ---- 5. Execute --------------------------------------------------------
    execute = client.post(
        "/v1/execute",
        json={"chain_id": chain_id, "execution_token": execution_token},
    )
    assert execute.status_code == 200, execute.text
    exec_body = execute.json()
    assert exec_body["status"] == "COMPLETED"
    assert exec_body["token_revoked"] is True

    # ---- 6. Read the chain back --------------------------------------------
    chain_get = client.get(f"/v1/chain/{chain_id}")
    assert chain_get.status_code == 200, chain_get.text
    chain_doc = chain_get.json()

    assert chain_doc["integrity"] is True
    # Must have at least propose (INBOUND_INTENT), attest (REVIEW_ATTESTATION),
    # approve (APPROVAL_GRANTED), and execute (EXECUTION_STARTED / COMPLETED)
    # plus the policy eval + execution token mint. 4+ is the floor.
    assert len(chain_doc["events"]) >= 4, chain_doc["events"]

    # ---- 7. Direct repo query — integrity preserved across a DB round trip -
    sm = get_sessionmaker()
    chain_repo = ChainRepository(sm)

    import asyncio

    async def _read():
        loaded = await chain_repo.get(chain_id)
        assert loaded is not None
        assert loaded.verify_integrity() is True
        return loaded

    loaded = asyncio.get_event_loop().run_until_complete(_read()) if False else None
    loop = asyncio.new_event_loop()
    try:
        loaded = loop.run_until_complete(_read())
    finally:
        loop.close()

    assert loaded is not None

    # ---- 8. Execution token is marked used ---------------------------------
    from gavel.db.repositories import ExecutionTokenRepository

    token_repo = ExecutionTokenRepository(sm)

    async def _read_token():
        return await token_repo.get(execution_token)

    loop = asyncio.new_event_loop()
    try:
        token_record = loop.run_until_complete(_read_token())
    finally:
        loop.close()

    assert token_record is not None
    assert token_record.get("used") is True
