"""Tests for gavel.witness — external audit witness."""

from __future__ import annotations

import hashlib

from gavel.witness import (
    ChainCheckpoint,
    CheckpointDivergenceKind,
    CheckpointRegistry,
    InMemoryWitness,
    verify_against_witnesses,
)


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _fresh_chain(n: int) -> list[str]:
    return [_hash(f"event-{i}") for i in range(n)]


class TestCheckpoint:
    def test_fingerprint_deterministic(self):
        c1 = ChainCheckpoint(
            chain_id="c-0",
            height=5,
            tip_hash=_hash("tip"),
            genesis_hash=_hash("gen"),
        )
        c2 = ChainCheckpoint(
            chain_id="c-0",
            height=5,
            tip_hash=_hash("tip"),
            genesis_hash=_hash("gen"),
            taken_at=c1.taken_at,
        )
        assert c1.fingerprint() == c2.fingerprint()

    def test_fingerprint_differs_on_tip(self):
        c1 = ChainCheckpoint(
            chain_id="c-0",
            height=5,
            tip_hash=_hash("tip-a"),
            genesis_hash=_hash("gen"),
        )
        c2 = ChainCheckpoint(
            chain_id="c-0",
            height=5,
            tip_hash=_hash("tip-b"),
            genesis_hash=_hash("gen"),
            taken_at=c1.taken_at,
        )
        assert c1.fingerprint() != c2.fingerprint()


class TestInMemoryWitness:
    def test_endorse_and_verify(self):
        w = InMemoryWitness("witness:alpha")
        cp = ChainCheckpoint(
            chain_id="c-0",
            height=3,
            tip_hash=_hash("tip"),
            genesis_hash=_hash("gen"),
        )
        end = w.endorse(cp)
        assert end.witness_id == "witness:alpha"
        assert w.verify(end)

    def test_verify_fails_on_tampered_signature(self):
        w = InMemoryWitness("witness:alpha")
        cp = ChainCheckpoint(
            chain_id="c-0",
            height=3,
            tip_hash=_hash("tip"),
            genesis_hash=_hash("gen"),
        )
        end = w.endorse(cp)
        end_bad = end.model_copy(update={"signature": "0" * 64})
        assert not w.verify(end_bad)

    def test_verify_fails_for_other_witness(self):
        a = InMemoryWitness("witness:a")
        b = InMemoryWitness("witness:b")
        cp = ChainCheckpoint(
            chain_id="c-0",
            height=1,
            tip_hash=_hash("tip"),
            genesis_hash=_hash("gen"),
        )
        end = a.endorse(cp)
        assert not b.verify(end)


class TestRegistry:
    def test_submit_to_multiple_witnesses(self):
        reg = CheckpointRegistry()
        reg.register_witness(InMemoryWitness("w1"))
        reg.register_witness(InMemoryWitness("w2"))
        cp = ChainCheckpoint(
            chain_id="c-0",
            height=1,
            tip_hash=_hash("tip"),
            genesis_hash=_hash("gen"),
        )
        endorsements = reg.submit(cp)
        assert {e.witness_id for e in endorsements} == {"w1", "w2"}
        assert reg.endorsements_for(cp.fingerprint()) == endorsements


class TestDivergence:
    def _fresh(self) -> tuple[list[str], CheckpointRegistry]:
        history = _fresh_chain(10)
        reg = CheckpointRegistry()
        reg.register_witness(InMemoryWitness("w"))
        # Witness the tip at height 5.
        cp = ChainCheckpoint(
            chain_id="c-0",
            height=5,
            tip_hash=history[4],
            genesis_hash=history[0],
        )
        reg.submit(cp)
        return history, reg

    def test_consistent_chain_has_no_divergence(self):
        history, reg = self._fresh()
        divs = verify_against_witnesses(
            current_height=len(history),
            current_tip_hash=history[-1],
            current_genesis_hash=history[0],
            chain_history=history,
            registry=reg,
        )
        assert divs == []

    def test_genesis_mismatch_detected(self):
        history, reg = self._fresh()
        new_genesis = _hash("forged-genesis")
        new_history = [new_genesis] + history[1:]
        divs = verify_against_witnesses(
            current_height=len(new_history),
            current_tip_hash=new_history[-1],
            current_genesis_hash=new_genesis,
            chain_history=new_history,
            registry=reg,
        )
        assert any(d.kind == CheckpointDivergenceKind.GENESIS_MISMATCH for d in divs)

    def test_regression_detected(self):
        history, reg = self._fresh()
        truncated = history[:3]  # chain is now shorter than witnessed height 5
        divs = verify_against_witnesses(
            current_height=len(truncated),
            current_tip_hash=truncated[-1],
            current_genesis_hash=truncated[0],
            chain_history=truncated,
            registry=reg,
        )
        assert any(
            d.kind == CheckpointDivergenceKind.HEIGHT_REGRESSION for d in divs
        )

    def test_missing_tip_detected(self):
        history, reg = self._fresh()
        # Rewrite the event at the witnessed height.
        rewritten = list(history)
        rewritten[4] = _hash("forged-tip")
        divs = verify_against_witnesses(
            current_height=len(rewritten),
            current_tip_hash=rewritten[-1],
            current_genesis_hash=rewritten[0],
            chain_history=rewritten,
            registry=reg,
        )
        assert any(d.kind == CheckpointDivergenceKind.MISSING for d in divs)

    def test_longer_chain_still_consistent(self):
        history, reg = self._fresh()
        extended = history + [_hash("new-10"), _hash("new-11")]
        divs = verify_against_witnesses(
            current_height=len(extended),
            current_tip_hash=extended[-1],
            current_genesis_hash=extended[0],
            chain_history=extended,
            registry=reg,
        )
        assert divs == []
