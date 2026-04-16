"""Tests for ``EvidenceRepository`` (Wave 2A)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gavel.blastbox import EvidencePacket, ScopeDeclaration
from gavel.db.repositories.evidence import EvidenceRepository


def _sample_packet(chain_id: str = "c-evidence-1", **overrides) -> EvidencePacket:
    now = datetime.now(timezone.utc)
    kwargs = dict(
        chain_id=chain_id,
        intent_event_id="evt-intent-1",
        command_argv=["echo", "hi"],
        scope=ScopeDeclaration(
            allow_paths=["/tmp/gavel"],
            allow_commands=["echo"],
            allow_network=False,
            max_duration_seconds=30,
            max_memory_mb=256,
            max_cpu=1,
        ),
        exit_code=0,
        stdout_hash="a" * 64,
        stderr_hash="b" * 64,
        diff_hash="c" * 64,
        stdout_preview="hi",
        files_modified=["/tmp/gavel/out.txt"],
        files_created=[],
        files_deleted=[],
        image="python:3.12-slim",
        image_digest="sha256:abc",
        network_mode="none",
        cpu="1",
        memory="256m",
        started_at=now,
        finished_at=now,
    )
    kwargs.update(overrides)
    return EvidencePacket(**kwargs)


async def test_save_get_delete_roundtrip(sessionmaker):
    repo = EvidenceRepository(sessionmaker)

    assert await repo.get("c-missing") is None

    packet = _sample_packet()
    await repo.save(packet.chain_id, packet)

    loaded = await repo.get(packet.chain_id)
    assert loaded is not None
    assert loaded.packet_id == packet.packet_id
    assert loaded.chain_id == packet.chain_id
    assert loaded.intent_event_id == packet.intent_event_id
    assert loaded.command_argv == packet.command_argv
    assert loaded.exit_code == 0
    assert loaded.stdout_hash == packet.stdout_hash
    assert loaded.files_modified == packet.files_modified
    # Scope rehydrates into a ScopeDeclaration with the same fields.
    assert isinstance(loaded.scope, ScopeDeclaration)
    assert loaded.scope.allow_paths == ["/tmp/gavel"]
    assert loaded.scope.allow_network is False
    assert loaded.scope.max_memory_mb == 256

    # Hash of the loaded packet matches the original — scope fields that
    # feed into compute_hash must be preserved.
    assert loaded.compute_hash() == packet.compute_hash()

    await repo.delete(packet.chain_id)
    assert await repo.get(packet.chain_id) is None


async def test_save_is_upsert_replaces_prior(sessionmaker):
    """Saving a second packet for the same chain_id replaces the first."""
    repo = EvidenceRepository(sessionmaker)

    first = _sample_packet(exit_code=0)
    await repo.save(first.chain_id, first)

    second = _sample_packet(chain_id=first.chain_id, exit_code=1)
    await repo.save(second.chain_id, second)

    loaded = await repo.get(first.chain_id)
    assert loaded is not None
    assert loaded.exit_code == 1
    assert loaded.packet_id == second.packet_id


async def test_delete_missing_is_noop(sessionmaker):
    repo = EvidenceRepository(sessionmaker)
    # Must not raise.
    await repo.delete("c-never-saved")
