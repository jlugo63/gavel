"""
V3 — Tamper Detection Under Attack (Wave 1).

Goal: prove the governance chain's tamper detection catches the realistic
attack vectors an auditor or adversary would try. This is the foundation
claim of the whole platform: "the audit trail cannot be forged without
detection." If V3 fails, nothing else in the compliance story holds.

Attack vectors:
  A1  Payload mutation        — flip a value inside event.payload
  A2  Actor substitution      — rewrite event.actor_id after the fact
  A3  Hash forgery            — replace event_hash with a valid-looking hash
  A4  Event reorder           — swap two events' positions in the list

Plus one documented-boundary test:
  B1  Truncation              — pop the last event. verify_integrity()
      CANNOT detect this alone. This is a real limit addressed by
      external audit witnesses (merkle commitments). The test pins
      the boundary so we notice if the contract changes.

The second half of the file asserts that tampered chains also fail
`GovernanceChain.verify_artifact()` — the portable offline verifier used
by third parties to check chains without the runtime. A tamper that
passes one verifier but fails the other would be a severe regression.
"""

from __future__ import annotations

import pytest

from gavel.chain import ChainEvent, EventType, GovernanceChain


# ── Helpers ────────────────────────────────────────────────────


def _build_chain() -> GovernanceChain:
    """Build a realistic 5-event governance chain for tampering."""
    chain = GovernanceChain(chain_id="c-v3-tamper")
    chain.append(
        event_type=EventType.INBOUND_INTENT,
        actor_id="agent:proposer",
        role_used="proposer",
        payload={"action": "read", "target": "/tmp/gavel-validation/input.json"},
    )
    chain.append(
        event_type=EventType.POLICY_EVAL,
        actor_id="gavel:policy-engine",
        role_used="system",
        payload={"verdict": "allow", "matched_rule": "R-12"},
    )
    chain.append(
        event_type=EventType.EVIDENCE_REVIEW,
        actor_id="agent:reviewer",
        role_used="reviewer",
        payload={"checks_passed": 7, "checks_failed": 0},
    )
    chain.append(
        event_type=EventType.APPROVAL_GRANTED,
        actor_id="agent:approver",
        role_used="approver",
        payload={"risk_score": 0.12, "approver_notes": "clean"},
    )
    chain.append(
        event_type=EventType.EXECUTION_COMPLETED,
        actor_id="agent:executor",
        role_used="executor",
        payload={"duration_ms": 42, "exit_code": 0},
    )
    return chain


# ── Sanity ──────────────────────────────────────────────────────


class TestBaselineIntegrity:
    """Pin the non-tampered baseline so we know the test harness is sane."""

    def test_untouched_chain_verifies(self) -> None:
        chain = _build_chain()
        assert chain.verify_integrity() is True
        assert len(chain.events) == 5
        # Artifact export should also verify.
        artifact = chain.to_artifact()
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is True
        assert result["events"] == 5
        assert result["errors"] == []


# ── A1–A4 positive detection ───────────────────────────────────


class TestTamperDetection:
    """Every attack vector must be detected by verify_integrity()
    AND by verify_artifact() (the portable offline verifier)."""

    def test_a1_payload_mutation(self) -> None:
        """A1: flipping a field inside an event's payload must be caught."""
        chain = _build_chain()
        # Attacker rewrites the approver's risk assessment after the fact.
        chain.events[3].payload["risk_score"] = 0.99
        assert chain.verify_integrity() is False, (
            "verify_integrity() failed to catch payload mutation — "
            "event_hash should no longer match compute_hash()"
        )
        # Same tamper must fail the offline artifact verifier.
        # (We export *after* the tamper because the artifact snapshots whatever
        # is currently on disk/in memory.)
        artifact = chain.to_artifact()
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is False
        assert any("hash mismatch" in e for e in result["errors"]), (
            f"expected hash-mismatch error, got: {result['errors']}"
        )

    def test_a2_actor_substitution(self) -> None:
        """A2: rewriting who performed an event must be caught.

        This is the attack that makes audit trails valuable: if an adversary
        can replace `agent:proposer` with `agent:innocent`, the whole roster
        concept collapses.
        """
        chain = _build_chain()
        chain.events[0].actor_id = "agent:innocent"
        assert chain.verify_integrity() is False
        artifact = chain.to_artifact()
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is False
        # The tamper is in event 0, so the first error should reference it.
        assert result["errors"], "artifact verifier produced no errors for actor substitution"

    def test_a3_hash_forgery(self) -> None:
        """A3: replacing event_hash with a plausible-looking value must be caught.

        The attacker can't know the correct hash because it depends on the
        (now-modified) content, so any replacement we try will be wrong by
        definition. This test is intentionally trivial — it pins the
        property that the hash is content-bound, not stored independently.
        """
        chain = _build_chain()
        forged = "0" * 64  # 64 hex chars — looks like a SHA-256
        chain.events[2].event_hash = forged
        assert chain.verify_integrity() is False
        # The downstream event's prev_hash still points at the real hash,
        # so the break should be detectable both at the forged event and
        # at the event that follows.
        artifact = chain.to_artifact()
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is False
        assert len(result["errors"]) >= 1

    def test_a4_event_reorder(self) -> None:
        """A4: swapping two events' positions must be caught.

        Each event's prev_hash pins its position in the chain, so any swap
        breaks at least one prev_hash link.
        """
        chain = _build_chain()
        # Swap approval and review — a plausible attack to make it look
        # like the approver signed off before the reviewer checked evidence.
        chain.events[2], chain.events[3] = chain.events[3], chain.events[2]
        assert chain.verify_integrity() is False
        artifact = chain.to_artifact()
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is False
        assert any("prev_hash mismatch" in e for e in result["errors"]), (
            f"expected prev_hash error on swap, got: {result['errors']}"
        )


# ── B1 documented boundary ─────────────────────────────────────


class TestTruncationBoundary:
    """Document the known limit: GovernanceChain.verify_integrity() cannot
    detect truncation of the chain's tail.

    Each remaining event is still correctly hash-linked to the one before
    it, so the chain looks internally consistent. Truncation detection
    requires an external witness that remembers the expected chain length
    or publishes a merkle commitment of the historical state.

    This test FAILING in the future would actually be a GOOD thing — it
    would mean verify_integrity() gained length verification. If that
    happens, update this test and pin the new contract.
    """

    def test_truncation_passes_local_verify_integrity(self) -> None:
        chain = _build_chain()
        assert len(chain.events) == 5

        # Adversary drops the last event — say, the one that records a
        # bad execution outcome they'd rather not have on the record.
        dropped = chain.events.pop()
        assert dropped.event_type == EventType.EXECUTION_COMPLETED
        assert len(chain.events) == 4

        # This is the boundary: local integrity check PASSES.
        assert chain.verify_integrity() is True, (
            "CONTRACT CHANGE: verify_integrity() now detects truncation. "
            "Update this test and the threat model — this is a meaningful "
            "security improvement."
        )
        # And the artifact verifier also passes on the truncated chain,
        # because it sees a complete-looking 4-event chain.
        artifact = chain.to_artifact()
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is True
        assert result["events"] == 4

    def test_truncation_detectable_by_external_length_anchor(self) -> None:
        """Model the witness pattern: if an external store recorded the
        expected length (e.g. a merkle commitment) then truncation is
        trivially detectable.

        This is a mini-proof that the system has a path to close the gap,
        not a test of any specific witness module.
        """
        chain = _build_chain()
        # External witness snapshots the head hash + length before the attack.
        witnessed_length = len(chain.events)
        witnessed_head_hash = chain.latest_hash

        # Attacker truncates.
        chain.events.pop()

        # A verifier that consults the witness catches the mismatch.
        assert len(chain.events) != witnessed_length
        assert chain.latest_hash != witnessed_head_hash


# ── Parametrized smoke ─────────────────────────────────────────


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda c: c.events[0].payload.__setitem__("target", "/etc/passwd"),
            id="path-mutation-on-first-event",
        ),
        pytest.param(
            lambda c: setattr(c.events[4], "actor_id", "agent:ghost"),
            id="actor-substitution-on-last-event",
        ),
        pytest.param(
            lambda c: setattr(c.events[1], "prev_hash", "f" * 64),
            id="prev-hash-forgery",
        ),
        pytest.param(
            lambda c: c.events.insert(0, ChainEvent(
                chain_id=c.chain_id,
                event_type=EventType.INBOUND_INTENT,
                actor_id="agent:injected",
                role_used="proposer",
                payload={"injected": True},
                prev_hash=c.latest_hash,
                event_hash="a" * 64,
            )),
            id="event-injection-at-head",
        ),
    ],
)
def test_arbitrary_mutation_is_caught(mutation) -> None:
    """Any mutation we can describe must fail verify_integrity()."""
    chain = _build_chain()
    mutation(chain)
    assert chain.verify_integrity() is False
