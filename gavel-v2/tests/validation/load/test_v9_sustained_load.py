"""
V9 — Sustained Load: Chain + Evidence Review (Wave 4).

Goal: prove the hash-chained governance ledger holds its structural
properties under volume that would represent a real enterprise workload
— hundreds of concurrent chains, tens of thousands of events, all
verified and exportable.

Scenarios:
  L1  Deep chain    — 10,000 events on a single chain, integrity holds
                     at every checkpoint, throughput floor met.
  L2  Wide fleet    — 500 concurrent chains × 20 events = 10,000 events
                     total, each chain independently verifiable.
  L3  Export scale  — to_artifact() on a 10,000-event chain produces a
                     JSON-serializable blob in reasonable time.
  L4  Tamper at scale — flipping a single byte in a single event of a
                     10,000-event chain is still caught by verify_integrity().
                     This is the "needle in haystack" boundary check.

Throughput floors are **loose** — they're meant to detect 10x regressions,
not benchmark micro-performance. Typical wall times on a modern machine:
  - L1 deep chain append: ~1.5s
  - L1 deep chain verify: ~0.3s
  - L2 wide fleet: ~2s
  - L3 artifact export: ~0.5s

If any floor is exceeded, something in the append/verify hot path got
measurably slower.
"""

from __future__ import annotations

import json
import time

import pytest

from gavel.chain import (
    ChainStatus,
    EventType,
    GovernanceChain,
)


DEEP_CHAIN_SIZE = 10_000
WIDE_FLEET_CHAINS = 500
WIDE_FLEET_EVENTS_PER_CHAIN = 20


def _build_deep_chain(size: int) -> GovernanceChain:
    """Append `size` events rotating through the full EventType roster."""
    chain = GovernanceChain(chain_id="c-v9-deep")
    event_types = list(EventType)
    for i in range(size):
        et = event_types[i % len(event_types)]
        chain.append(
            event_type=et,
            actor_id=f"agent:worker-{i % 10}",
            role_used="executor" if i % 4 == 0 else "reviewer",
            payload={"seq": i, "note": f"sustained load event {i}"},
        )
    return chain


# ── L1: deep chain ──────────────────────────────────────────


class TestDeepChain:
    """A single chain with 10,000 events. Production-scale: a busy agent
    accumulating a month's worth of governance events on one chain."""

    def test_append_throughput_and_integrity(self) -> None:
        t0 = time.perf_counter()
        chain = _build_deep_chain(DEEP_CHAIN_SIZE)
        append_elapsed = time.perf_counter() - t0

        assert len(chain.events) == DEEP_CHAIN_SIZE

        # Integrity holds end-to-end.
        t1 = time.perf_counter()
        assert chain.verify_integrity() is True
        verify_elapsed = time.perf_counter() - t1

        # Loose floors: 30s for append (~3ms per event), 10s for verify.
        # Actual wall time is ~1.5s append + ~0.3s verify on modern hw.
        assert append_elapsed < 30.0, (
            f"deep chain append regressed: {append_elapsed:.2f}s for "
            f"{DEEP_CHAIN_SIZE} events"
        )
        assert verify_elapsed < 10.0, (
            f"deep chain verify regressed: {verify_elapsed:.2f}s for "
            f"{DEEP_CHAIN_SIZE} events"
        )

        # Hash linkage: every event (except the first) has prev_hash ==
        # previous event's event_hash.
        for i in range(1, len(chain.events)):
            assert chain.events[i].prev_hash == chain.events[i - 1].event_hash, (
                f"hash linkage broken at event {i}"
            )

    def test_midstream_verify_checkpoints(self) -> None:
        """Verify integrity at 1000/5000/10000 events — every checkpoint
        must pass, no integrity regression as the chain grows."""
        chain = GovernanceChain(chain_id="c-v9-checkpoints")
        for i in range(DEEP_CHAIN_SIZE):
            chain.append(
                event_type=EventType.POLICY_EVAL,
                actor_id=f"agent:chk-{i % 5}",
                role_used="reviewer",
                payload={"i": i},
            )
            if i + 1 in (1_000, 5_000, 10_000):
                assert chain.verify_integrity() is True, (
                    f"integrity failed at checkpoint {i + 1}"
                )


# ── L2: wide fleet ──────────────────────────────────────────


class TestWideFleet:
    """500 independent chains × 20 events each. Models a production fleet
    where many agents run many short chains in parallel.

    The point here is isolation at scale: 500 chains must each compute
    their own hash sequence, no cross-chain contamination, no shared
    state bugs surfacing when the same GovernanceChain class is
    instantiated this many times."""

    def test_wide_fleet_all_chains_verify(self) -> None:
        t0 = time.perf_counter()
        chains: list[GovernanceChain] = []
        for c in range(WIDE_FLEET_CHAINS):
            chain = GovernanceChain(chain_id=f"c-v9-wide-{c:04d}")
            for e in range(WIDE_FLEET_EVENTS_PER_CHAIN):
                chain.append(
                    event_type=EventType.INBOUND_INTENT,
                    actor_id=f"agent:fleet-{c % 20}",
                    role_used="proposer",
                    payload={"chain_index": c, "event_index": e},
                )
            chains.append(chain)
        build_elapsed = time.perf_counter() - t0

        total_events = WIDE_FLEET_CHAINS * WIDE_FLEET_EVENTS_PER_CHAIN
        assert sum(len(c.events) for c in chains) == total_events

        # Each chain verifies independently.
        t1 = time.perf_counter()
        for chain in chains:
            assert chain.verify_integrity() is True, (
                f"chain {chain.chain_id} failed integrity"
            )
        verify_elapsed = time.perf_counter() - t1

        # Loose floors.
        assert build_elapsed < 30.0, (
            f"wide fleet build regressed: {build_elapsed:.2f}s for {total_events} events"
        )
        assert verify_elapsed < 10.0, (
            f"wide fleet verify regressed: {verify_elapsed:.2f}s for {total_events} events"
        )

        # Unique chain ids — no accidental aliasing.
        assert len({c.chain_id for c in chains}) == WIDE_FLEET_CHAINS


# ── L3: artifact export at scale ────────────────────────────


class TestArtifactExportAtScale:
    """A 10,000-event chain must still produce a portable artifact that
    JSON-serializes cleanly and passes external verification."""

    def test_deep_chain_exports_and_verifies(self) -> None:
        chain = _build_deep_chain(DEEP_CHAIN_SIZE)

        t0 = time.perf_counter()
        artifact = chain.to_artifact()
        export_elapsed = time.perf_counter() - t0
        assert export_elapsed < 10.0, (
            f"artifact export regressed: {export_elapsed:.2f}s"
        )

        # Artifact is JSON-serializable (auditors will receive this as JSON).
        blob = json.dumps(artifact, default=str)
        assert len(blob) > 0
        reloaded = json.loads(blob)
        assert reloaded["chain_id"] == "c-v9-deep"
        assert len(reloaded["events"]) == DEEP_CHAIN_SIZE
        assert reloaded["integrity"] is True

        # External verification on the exported artifact still works.
        # GovernanceChain.verify_artifact is a classmethod returning
        # {"valid": bool, "events": int, "errors": list}.
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is True, (
            f"exported artifact failed external verification: {result}"
        )
        assert result["events"] == DEEP_CHAIN_SIZE
        assert result["errors"] == []


# ── L4: tamper at scale ─────────────────────────────────────


class TestTamperAtScale:
    """A single-byte tamper anywhere in a 10,000-event chain must still
    be caught. This is the "needle in haystack" boundary — if the
    verifier short-circuits or samples, a deep chain could hide a tamper.
    It doesn't, and this test pins that invariant."""

    def test_single_event_payload_mutation_caught(self) -> None:
        chain = _build_deep_chain(DEEP_CHAIN_SIZE)
        assert chain.verify_integrity() is True

        # Tamper with event at index 7,342 (arbitrary — deep in the chain).
        target = chain.events[7_342]
        original_note = target.payload.get("note")
        target.payload["note"] = "TAMPERED"
        assert target.payload["note"] != original_note

        assert chain.verify_integrity() is False, (
            "tamper at index 7342 of a 10k-event chain was NOT caught"
        )

    def test_single_event_actor_substitution_caught(self) -> None:
        chain = _build_deep_chain(DEEP_CHAIN_SIZE)
        assert chain.verify_integrity() is True

        # Tamper with actor_id near the end.
        chain.events[9_998].actor_id = "agent:evil"

        assert chain.verify_integrity() is False, (
            "late-chain actor substitution was NOT caught"
        )
