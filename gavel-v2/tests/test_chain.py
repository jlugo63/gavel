"""Tests for Governance Chains — hash integrity, artifacts, verification."""

from __future__ import annotations

import copy
import hashlib

import pytest

from gavel.chain import (
    ChainEvent,
    ChainStatus,
    EventType,
    GovernanceChain,
)


class TestChainCreation:
    def test_new_chain_has_id(self, governance_chain):
        assert governance_chain.chain_id.startswith("c-")
        assert len(governance_chain.chain_id) > 4

    def test_custom_chain_id(self):
        chain = GovernanceChain(chain_id="c-custom-123")
        assert chain.chain_id == "c-custom-123"

    def test_initial_status_pending(self, governance_chain):
        assert governance_chain.status == ChainStatus.PENDING

    def test_empty_chain_integrity(self, governance_chain):
        assert governance_chain.verify_integrity() is True

    def test_genesis_hash(self, governance_chain):
        expected = hashlib.sha256(governance_chain.chain_id.encode()).hexdigest()
        assert governance_chain.latest_hash == expected


class TestChainAppend:
    def test_append_event(self, governance_chain):
        event = governance_chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id="agent:proposer",
            role_used="proposer",
            payload={"goal": "deploy v2"},
        )
        assert event.event_type == EventType.INBOUND_INTENT
        assert event.actor_id == "agent:proposer"
        assert event.chain_id == governance_chain.chain_id
        assert event.event_hash != ""
        assert event.prev_hash != ""

    def test_hash_chain_links(self, governance_chain):
        """Each event's prev_hash links to the previous event's hash."""
        genesis = hashlib.sha256(governance_chain.chain_id.encode()).hexdigest()

        e1 = governance_chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id="agent:a",
            role_used="proposer",
        )
        assert e1.prev_hash == genesis

        e2 = governance_chain.append(
            event_type=EventType.POLICY_EVAL,
            actor_id="system",
            role_used="evaluator",
        )
        assert e2.prev_hash == e1.event_hash

        e3 = governance_chain.append(
            event_type=EventType.APPROVAL_GRANTED,
            actor_id="agent:b",
            role_used="approver",
        )
        assert e3.prev_hash == e2.event_hash

    def test_event_hash_deterministic(self, governance_chain):
        """Same content produces same hash."""
        event = governance_chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id="agent:test",
            role_used="proposer",
            payload={"x": 1},
        )
        recomputed = event.compute_hash()
        assert event.event_hash == recomputed

    def test_actor_role_tracking(self, governance_chain):
        governance_chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id="agent:a",
            role_used="proposer",
        )
        governance_chain.append(
            event_type=EventType.REVIEW_ATTESTATION,
            actor_id="agent:b",
            role_used="reviewer",
        )
        assert governance_chain.get_actors_by_role("proposer") == ["agent:a"]
        assert governance_chain.get_actors_by_role("reviewer") == ["agent:b"]
        assert governance_chain.get_actors_by_role("approver") == []


class TestChainIntegrity:
    def _build_chain(self) -> GovernanceChain:
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer", {"goal": "test"})
        chain.append(EventType.POLICY_EVAL, "system", "evaluator", {"risk": 0.3})
        chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver", {"decision": "APPROVED"})
        return chain

    def test_intact_chain_verifies(self):
        chain = self._build_chain()
        assert chain.verify_integrity() is True

    def test_tampered_payload_detected(self):
        """Modifying a payload breaks the hash chain."""
        chain = self._build_chain()
        chain.events[1].payload["risk"] = 0.0  # tamper
        assert chain.verify_integrity() is False

    def test_tampered_actor_detected(self):
        chain = self._build_chain()
        chain.events[0].actor_id = "agent:evil"  # tamper
        assert chain.verify_integrity() is False

    def test_tampered_prev_hash_detected(self):
        chain = self._build_chain()
        chain.events[2].prev_hash = "0" * 64  # tamper
        assert chain.verify_integrity() is False

    def test_inserted_event_detected(self):
        """Inserting an event in the middle breaks the chain."""
        chain = self._build_chain()
        fake = ChainEvent(
            chain_id=chain.chain_id,
            event_type=EventType.ESCALATED,
            actor_id="agent:evil",
            role_used="attacker",
            prev_hash=chain.events[0].event_hash,
            event_hash="fake_hash",
        )
        chain.events.insert(1, fake)
        assert chain.verify_integrity() is False

    def test_deleted_event_detected(self):
        """Removing an event breaks the chain."""
        chain = self._build_chain()
        del chain.events[1]  # remove middle event
        assert chain.verify_integrity() is False


class TestChainArtifact:
    def test_artifact_structure(self, governance_chain):
        governance_chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        artifact = governance_chain.to_artifact()

        assert artifact["artifact_version"] == "1.0"
        assert artifact["chain_id"] == governance_chain.chain_id
        assert artifact["status"] == "PENDING"
        assert artifact["integrity"] is True
        assert artifact["event_count"] == 1
        assert len(artifact["events"]) == 1
        assert "roster" in artifact
        assert "genesis_hash" in artifact

    def test_artifact_independent_verification(self):
        """Artifact can be verified without the runtime."""
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer", {"goal": "test"})
        chain.append(EventType.POLICY_EVAL, "system", "evaluator", {"risk": 0.5})
        chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")
        chain.status = ChainStatus.APPROVED

        artifact = chain.to_artifact()
        result = GovernanceChain.verify_artifact(artifact)

        assert result["valid"] is True
        assert result["events"] == 3
        assert result["chain_id"] == chain.chain_id
        assert result["errors"] == []

    def test_tampered_artifact_fails_verification(self):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")

        artifact = chain.to_artifact()
        # Tamper with an event payload
        artifact["events"][0]["payload"]["injected"] = True

        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_empty_artifact_valid(self):
        artifact = {"chain_id": "c-empty", "events": []}
        result = GovernanceChain.verify_artifact(artifact)
        assert result["valid"] is True
        assert result["events"] == 0

    def test_roster_tracks_all_actors(self):
        chain = GovernanceChain()
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.REVIEW_ATTESTATION, "agent:b", "reviewer")
        chain.append(EventType.APPROVAL_GRANTED, "agent:c", "approver")

        artifact = chain.to_artifact()
        roster = artifact["roster"]
        assert "agent:a" in roster
        assert "proposer" in roster["agent:a"]
        assert "agent:b" in roster
        assert "reviewer" in roster["agent:b"]
        assert "agent:c" in roster
        assert "approver" in roster["agent:c"]


class TestChainHelpers:
    def test_get_event_by_type(self, governance_chain):
        governance_chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        governance_chain.append(EventType.POLICY_EVAL, "system", "evaluator")

        event = governance_chain.get_event(EventType.POLICY_EVAL)
        assert event is not None
        assert event.event_type == EventType.POLICY_EVAL

    def test_get_event_returns_latest(self, governance_chain):
        governance_chain.append(EventType.INBOUND_INTENT, "a", "proposer", {"v": 1})
        governance_chain.append(EventType.INBOUND_INTENT, "b", "proposer", {"v": 2})

        event = governance_chain.get_event(EventType.INBOUND_INTENT)
        assert event.payload["v"] == 2  # returns the latest

    def test_get_event_not_found(self, governance_chain):
        assert governance_chain.get_event(EventType.ROLLBACK_TRIGGERED) is None

    def test_timeline(self, governance_chain):
        governance_chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        governance_chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")

        timeline = governance_chain.to_timeline()
        assert len(timeline) == 2
        assert timeline[0]["event"] == "INBOUND_INTENT"
        assert timeline[1]["event"] == "APPROVAL_GRANTED"
        assert "hash" in timeline[0]
