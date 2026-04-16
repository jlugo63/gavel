"""Tests for ``ExecutionTokenRepository`` (Wave 2A).

Key behaviours:

* ``get()`` returns a snapshot dict in the legacy shape (not the ORM row).
* ``mark_used()`` is TOCTOU-safe: the second call must return ``False``.
* ``delete_by_chain()`` deletes every token belonging to a chain.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from gavel.db.repositories.execution_tokens import ExecutionTokenRepository


def _token_payload(token_id: str, chain_id: str = "c-exec-1", **overrides) -> dict:
    payload = {
        "token_id": token_id,
        "chain_id": chain_id,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "used": False,
    }
    payload.update(overrides)
    return payload


async def test_save_get_roundtrip(sessionmaker):
    repo = ExecutionTokenRepository(sessionmaker)

    assert await repo.get("exec-t-missing") is None

    token = _token_payload("exec-t-1")
    await repo.save(token["token_id"], token)

    snap = await repo.get(token["token_id"])
    assert snap is not None
    assert snap["token_id"] == "exec-t-1"
    assert snap["chain_id"] == "c-exec-1"
    assert snap["used"] is False
    # expires_at round-trips as an ISO string.
    assert isinstance(snap["expires_at"], str)
    datetime.fromisoformat(snap["expires_at"])  # parseable


async def test_get_returns_snapshot_not_live_record(sessionmaker):
    """Mutating the returned dict must not affect stored state."""
    repo = ExecutionTokenRepository(sessionmaker)
    await repo.save("exec-t-snap", _token_payload("exec-t-snap"))

    snap = await repo.get("exec-t-snap")
    assert snap is not None
    snap["used"] = True  # local mutation on the snapshot

    # Re-reading shows original state — mutation was not persisted.
    snap2 = await repo.get("exec-t-snap")
    assert snap2 is not None
    assert snap2["used"] is False


async def test_mark_used_toctou_safe(sessionmaker):
    """Second ``mark_used`` call must return False."""
    repo = ExecutionTokenRepository(sessionmaker)
    await repo.save("exec-t-mu", _token_payload("exec-t-mu"))

    first = await repo.mark_used("exec-t-mu")
    second = await repo.mark_used("exec-t-mu")

    assert first is True
    assert second is False

    snap = await repo.get("exec-t-mu")
    assert snap is not None
    assert snap["used"] is True


async def test_mark_used_missing_returns_false(sessionmaker):
    repo = ExecutionTokenRepository(sessionmaker)
    assert await repo.mark_used("exec-t-ghost") is False


async def test_delete_single(sessionmaker):
    repo = ExecutionTokenRepository(sessionmaker)
    await repo.save("exec-t-d", _token_payload("exec-t-d"))
    await repo.delete("exec-t-d")
    assert await repo.get("exec-t-d") is None


async def test_delete_by_chain(sessionmaker):
    repo = ExecutionTokenRepository(sessionmaker)
    await repo.save("exec-t-a", _token_payload("exec-t-a", chain_id="c-target"))
    await repo.save("exec-t-b", _token_payload("exec-t-b", chain_id="c-target"))
    await repo.save("exec-t-c", _token_payload("exec-t-c", chain_id="c-other"))

    await repo.delete_by_chain("c-target")

    assert await repo.get("exec-t-a") is None
    assert await repo.get("exec-t-b") is None
    # Unrelated chain's token stays.
    other = await repo.get("exec-t-c")
    assert other is not None
    assert other["chain_id"] == "c-other"


async def test_save_is_upsert(sessionmaker):
    repo = ExecutionTokenRepository(sessionmaker)
    await repo.save("exec-t-up", _token_payload("exec-t-up", used=False))
    await repo.save("exec-t-up", _token_payload("exec-t-up", used=True))

    snap = await repo.get("exec-t-up")
    assert snap is not None
    assert snap["used"] is True


async def test_save_accepts_datetime_for_expires_at(sessionmaker):
    """``expires_at`` may be a datetime (naive or aware) — we accept both."""
    repo = ExecutionTokenRepository(sessionmaker)

    aware = datetime.now(timezone.utc) + timedelta(minutes=10)
    await repo.save(
        "exec-t-dt",
        {
            "token_id": "exec-t-dt",
            "chain_id": "c-1",
            "expires_at": aware,
            "used": False,
        },
    )
    snap = await repo.get("exec-t-dt")
    assert snap is not None
    assert snap["expires_at"].startswith(aware.strftime("%Y-%m-%dT"))
