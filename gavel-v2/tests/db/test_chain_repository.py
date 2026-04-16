"""Tests for ``ChainRepository`` (Wave 2A).

The most important guard here is the **hash byte-identity** test: a
chain that is saved and then reloaded must produce the exact same
``event_hash`` when ``compute_hash()`` is re-run on every event. If
that ever fails, the tamper seal is broken by persistence round-trip.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from gavel.chain import ChainStatus, EventType, GovernanceChain
from gavel.db.repositories.chains import ChainRepository


async def test_roundtrip_multiple_events_hash_byte_identical(sessionmaker):
    """Save then load — every event's recomputed hash must match."""
    repo = ChainRepository(sessionmaker)

    chain = GovernanceChain()
    chain.append(
        EventType.INBOUND_INTENT,
        actor_id="agent:proposer",
        role_used="proposer",
        payload={"action": "deploy", "targets": ["env:staging"]},
    )
    chain.append(
        EventType.POLICY_EVAL,
        actor_id="agent:policy",
        role_used="evaluator",
        payload={"decision": "ok"},
    )
    chain.append(
        EventType.BLASTBOX_EVIDENCE,
        actor_id="agent:blastbox",
        role_used="evidence",
        payload={"exit_code": 0, "diff_hash": "a" * 64},
    )
    chain.status = ChainStatus.EVALUATING

    # Capture expected hashes from the source-of-truth in-memory chain.
    original_hashes = [(e.event_id, e.event_hash) for e in chain.events]
    original_latest = chain.latest_hash

    await repo.save(chain)
    loaded = await repo.get(chain.chain_id)

    assert loaded is not None
    assert loaded.chain_id == chain.chain_id
    assert loaded.status == ChainStatus.EVALUATING
    assert len(loaded.events) == 3

    # Byte-identity: recomputed hashes match stored hashes.
    for saved_event, loaded_event in zip(chain.events, loaded.events):
        assert loaded_event.event_id == saved_event.event_id
        assert loaded_event.event_hash == saved_event.event_hash
        # And recomputation from the loaded payload matches too.
        assert loaded_event.compute_hash() == saved_event.event_hash

    # The prev_hash linkage and latest_hash must survive the round trip.
    assert loaded.latest_hash == original_latest
    assert [(e.event_id, e.event_hash) for e in loaded.events] == original_hashes

    # And the chain still verifies end-to-end.
    assert loaded.verify_integrity() is True


async def test_get_missing_returns_none(sessionmaker):
    repo = ChainRepository(sessionmaker)
    assert await repo.get("c-does-not-exist") is None


async def test_save_is_idempotent(sessionmaker):
    """Re-saving an unchanged chain must not duplicate events."""
    repo = ChainRepository(sessionmaker)

    chain = GovernanceChain()
    chain.append(EventType.INBOUND_INTENT, "a:1", "proposer", {"n": 1})
    chain.append(EventType.POLICY_EVAL, "a:2", "evaluator", {"n": 2})

    await repo.save(chain)
    await repo.save(chain)  # second save — same events

    loaded = await repo.get(chain.chain_id)
    assert loaded is not None
    assert len(loaded.events) == 2

    # Append a new event locally, save again: only the new one is inserted.
    chain.append(EventType.BLASTBOX_EVIDENCE, "a:3", "evidence", {"n": 3})
    await repo.save(chain)

    loaded2 = await repo.get(chain.chain_id)
    assert loaded2 is not None
    assert len(loaded2.events) == 3
    assert loaded2.verify_integrity() is True


async def test_append_event_hot_path(sessionmaker):
    """``append_event`` inserts a single row without rewriting the chain row."""
    repo = ChainRepository(sessionmaker)
    chain = GovernanceChain()
    chain.append(EventType.INBOUND_INTENT, "a:1", "proposer", {"n": 1})
    await repo.save(chain)

    # Append locally, then push via the narrow path.
    new_event = chain.append(EventType.POLICY_EVAL, "a:2", "evaluator", {"n": 2})
    await repo.append_event(chain.chain_id, new_event)

    loaded = await repo.get(chain.chain_id)
    assert loaded is not None
    assert len(loaded.events) == 2
    assert loaded.events[1].event_id == new_event.event_id
    assert loaded.verify_integrity() is True


async def test_delete_removes_chain_and_events(sessionmaker):
    repo = ChainRepository(sessionmaker)
    chain = GovernanceChain()
    chain.append(EventType.INBOUND_INTENT, "a:1", "proposer")
    await repo.save(chain)

    await repo.delete(chain.chain_id)
    assert await repo.get(chain.chain_id) is None
    assert await repo.count_all() == 0


async def test_list_stale_returns_only_old_chains(sessionmaker):
    repo = ChainRepository(sessionmaker)

    now = datetime.now(timezone.utc)
    old_chain = GovernanceChain(chain_id="c-old")
    old_chain.append(EventType.INBOUND_INTENT, "a:1", "proposer")
    # Backdate the last event's timestamp to two hours ago.
    old_chain.events[-1].timestamp = now - timedelta(hours=2)

    fresh_chain = GovernanceChain(chain_id="c-fresh")
    fresh_chain.append(EventType.INBOUND_INTENT, "a:1", "proposer")
    # Default timestamp is ~now.

    await repo.save(old_chain)
    await repo.save(fresh_chain)

    cutoff = now - timedelta(hours=1)
    stale = await repo.list_stale(cutoff)

    assert "c-old" in stale
    assert "c-fresh" not in stale


async def test_list_stale_uses_created_at_for_empty_chain(sessionmaker):
    """An empty chain (no events) should use ``created_at`` for staleness."""
    repo = ChainRepository(sessionmaker)

    now = datetime.now(timezone.utc)
    empty_old = GovernanceChain(chain_id="c-empty-old")
    empty_old.created_at = now - timedelta(hours=2)

    empty_fresh = GovernanceChain(chain_id="c-empty-fresh")
    empty_fresh.created_at = now

    await repo.save(empty_old)
    await repo.save(empty_fresh)

    stale = await repo.list_stale(now - timedelta(hours=1))
    assert "c-empty-old" in stale
    assert "c-empty-fresh" not in stale


async def test_list_all_and_count_all(sessionmaker):
    repo = ChainRepository(sessionmaker)
    assert await repo.count_all() == 0
    assert await repo.list_all() == []

    for i in range(3):
        c = GovernanceChain(chain_id=f"c-{i}")
        c.append(EventType.INBOUND_INTENT, f"a:{i}", "proposer")
        await repo.save(c)

    assert await repo.count_all() == 3
    all_chains = await repo.list_all()
    assert {c.chain_id for c in all_chains} == {"c-0", "c-1", "c-2"}
    # Events were loaded for each.
    assert all(len(c.events) == 1 for c in all_chains)


async def test_actor_roles_roundtrip_as_json(sessionmaker):
    """Actor roles are persisted as ``dict[str, list[str]]`` and rehydrate to sets."""
    repo = ChainRepository(sessionmaker)

    chain = GovernanceChain()
    chain.append(EventType.INBOUND_INTENT, "agent:alice", "proposer")
    chain.append(EventType.POLICY_EVAL, "agent:alice", "evaluator")
    chain.append(EventType.EVIDENCE_REVIEW, "agent:bob", "reviewer")

    await repo.save(chain)
    loaded = await repo.get(chain.chain_id)

    assert loaded is not None
    assert loaded._actor_roles["agent:alice"] == {"proposer", "evaluator"}
    assert loaded._actor_roles["agent:bob"] == {"reviewer"}
    # And the helper still works post-load.
    assert set(loaded.get_actors_by_role("proposer")) == {"agent:alice"}
    assert set(loaded.get_actors_by_role("reviewer")) == {"agent:bob"}
