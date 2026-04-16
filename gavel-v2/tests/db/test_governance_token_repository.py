"""GovernanceTokenRepository — CRUD + expiry batch + revoke-by-agent."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gavel.db.repositories import GovernanceTokenRepository
from gavel.enrollment import GovernanceToken


def _make_token(
    token: str = "gvl_tok_aaaa",
    agent_did: str = "did:gavel:agent:a1",
    agent_id: str = "agent-1",
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    revoked: bool = False,
    scope: dict | None = None,
) -> GovernanceToken:
    now = issued_at or datetime.now(timezone.utc)
    return GovernanceToken(
        token=token,
        agent_did=agent_did,
        agent_id=agent_id,
        issued_at=now,
        expires_at=expires_at or (now + timedelta(hours=1)),
        ttl_seconds=3600,
        revoked=revoked,
        scope=scope,
    )


async def test_save_then_get_roundtrips(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    tok = _make_token(scope={"chain": ["propose"]})
    await repo.save(tok)

    loaded = await repo.get(tok.token)
    assert loaded is not None
    assert loaded.token == tok.token
    assert loaded.agent_did == tok.agent_did
    assert loaded.agent_id == tok.agent_id
    assert loaded.ttl_seconds == 3600
    assert loaded.revoked is False
    assert loaded.scope == {"chain": ["propose"]}


async def test_get_unknown_returns_none(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    assert await repo.get("gvl_tok_missing") is None


async def test_save_upserts_same_token(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    tok = _make_token()
    await repo.save(tok)

    tok.revoked = True
    await repo.save(tok)

    loaded = await repo.get(tok.token)
    assert loaded is not None
    assert loaded.revoked is True


async def test_get_by_agent_returns_all_tokens_for_did(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    did = "did:gavel:agent:shared"
    await repo.save(_make_token(token="gvl_tok_1", agent_did=did))
    await repo.save(_make_token(token="gvl_tok_2", agent_did=did))
    await repo.save(_make_token(token="gvl_tok_3", agent_did="did:gavel:agent:other"))

    hits = await repo.get_by_agent(did)
    assert {t.token for t in hits} == {"gvl_tok_1", "gvl_tok_2"}


async def test_delete_returns_count_deleted(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    did = "did:gavel:agent:revokeme"
    await repo.save(_make_token(token="gvl_tok_1", agent_did=did))
    await repo.save(_make_token(token="gvl_tok_2", agent_did=did))
    await repo.save(_make_token(token="gvl_tok_keep", agent_did="did:gavel:agent:other"))

    deleted = await repo.delete(did)
    assert deleted == 2

    # Second call removes nothing.
    assert await repo.delete(did) == 0

    # The unrelated token is untouched.
    assert await repo.get("gvl_tok_keep") is not None


async def test_delete_nonexistent_did_returns_zero(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    assert await repo.delete("did:gavel:agent:ghost") == 0


async def test_list_expired_returns_only_past_due_tokens(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    now = datetime.now(timezone.utc)

    await repo.save(_make_token(
        token="gvl_tok_old",
        issued_at=now - timedelta(hours=2),
        expires_at=now - timedelta(minutes=30),
    ))
    await repo.save(_make_token(
        token="gvl_tok_fresh",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    ))

    expired = await repo.list_expired(now)
    assert expired == ["gvl_tok_old"]


async def test_delete_expired_is_atomic_and_counts(sessionmaker):
    repo = GovernanceTokenRepository(sessionmaker)
    now = datetime.now(timezone.utc)

    await repo.save(_make_token(
        token="gvl_tok_exp1",
        issued_at=now - timedelta(hours=3),
        expires_at=now - timedelta(hours=1),
    ))
    await repo.save(_make_token(
        token="gvl_tok_exp2",
        issued_at=now - timedelta(hours=4),
        expires_at=now - timedelta(minutes=5),
        agent_did="did:gavel:agent:other",
    ))
    await repo.save(_make_token(
        token="gvl_tok_alive",
        issued_at=now,
        expires_at=now + timedelta(hours=2),
        agent_did="did:gavel:agent:alive",
    ))

    n = await repo.delete_expired(now)
    assert n == 2

    # The live token remains.
    assert await repo.get("gvl_tok_alive") is not None
    assert await repo.get("gvl_tok_exp1") is None
    assert await repo.get("gvl_tok_exp2") is None

    # Idempotent: running again removes nothing.
    assert await repo.delete_expired(now) == 0
