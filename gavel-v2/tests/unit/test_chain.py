"""Unit tests for GovernanceChain — hash integrity, event linking, timeline."""

import hashlib
import json

from gavel.chain import GovernanceChain, ChainEvent, EventType, ChainStatus


class TestChainCreation:
    def test_chain_has_unique_id(self):
        c1 = GovernanceChain()
        c2 = GovernanceChain()
        assert c1.chain_id != c2.chain_id

    def test_chain_starts_pending(self):
        c = GovernanceChain()
        assert c.status == ChainStatus.PENDING

    def test_chain_starts_empty(self):
        c = GovernanceChain()
        assert len(c.events) == 0

    def test_custom_chain_id(self):
        c = GovernanceChain(chain_id="c-custom")
        assert c.chain_id == "c-custom"


class TestEventAppend:
    def test_append_returns_event(self, chain):
        event = chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id="agent:test",
            role_used="proposer",
            payload={"goal": "test"},
        )
        assert isinstance(event, ChainEvent)
        assert event.chain_id == chain.chain_id
        assert event.event_type == EventType.INBOUND_INTENT

    def test_append_increments_events(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.POLICY_EVAL, "system:pe", "system")
        assert len(chain.events) == 2

    def test_event_has_hash(self, chain):
        event = chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        assert event.event_hash != ""
        assert len(event.event_hash) == 64  # SHA-256 hex

    def test_event_has_prev_hash(self, chain):
        e1 = chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        e2 = chain.append(EventType.POLICY_EVAL, "system:pe", "system")
        assert e2.prev_hash == e1.event_hash

    def test_first_event_prev_hash_is_chain_genesis(self, chain):
        genesis = hashlib.sha256(chain.chain_id.encode()).hexdigest()
        e1 = chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        assert e1.prev_hash == genesis

    def test_tracks_actors(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:monitor", "proposer")
        chain.append(EventType.REVIEW_ATTESTATION, "agent:reviewer", "reviewer")
        assert chain.get_actors_by_role("proposer") == ["agent:monitor"]
        assert chain.get_actors_by_role("reviewer") == ["agent:reviewer"]


class TestHashIntegrity:
    def test_verify_empty_chain(self, chain):
        assert chain.verify_integrity() is True

    def test_verify_single_event(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        assert chain.verify_integrity() is True

    def test_verify_multi_event_chain(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.POLICY_EVAL, "system:pe", "system")
        chain.append(EventType.BLASTBOX_EVIDENCE, "system:bb", "system")
        chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")
        assert chain.verify_integrity() is True

    def test_tampered_hash_detected(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.POLICY_EVAL, "system:pe", "system")
        # Tamper with the first event's hash
        chain.events[0].event_hash = "tampered"
        assert chain.verify_integrity() is False

    def test_tampered_payload_detected(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer", {"goal": "safe"})
        chain.append(EventType.POLICY_EVAL, "system:pe", "system")
        # Tamper with payload but don't recompute hash
        chain.events[0].payload = {"goal": "malicious"}
        assert chain.verify_integrity() is False

    def test_inserted_event_detected(self, chain):
        e1 = chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        e3 = chain.append(EventType.APPROVAL_GRANTED, "agent:b", "approver")
        # Insert a fake event between e1 and e3
        fake = ChainEvent(
            chain_id=chain.chain_id,
            event_type=EventType.POLICY_EVAL,
            actor_id="attacker",
            role_used="system",
            prev_hash=e1.event_hash,
        )
        fake.event_hash = fake.compute_hash()
        chain.events.insert(1, fake)
        # e3's prev_hash still points to e1, but now the chain expects fake
        assert chain.verify_integrity() is False


class TestTimeline:
    def test_timeline_format(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.POLICY_EVAL, "system:pe", "system")
        timeline = chain.to_timeline()
        assert len(timeline) == 2
        assert timeline[0]["event"] == "INBOUND_INTENT"
        assert timeline[0]["actor"] == "agent:a"
        assert timeline[0]["role"] == "proposer"
        assert "hash" in timeline[0]

    def test_get_event_by_type(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        chain.append(EventType.POLICY_EVAL, "system:pe", "system", {"risk": 0.8})
        event = chain.get_event(EventType.POLICY_EVAL)
        assert event is not None
        assert event.payload["risk"] == 0.8

    def test_get_event_returns_none_for_missing(self, chain):
        chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
        assert chain.get_event(EventType.APPROVAL_GRANTED) is None
