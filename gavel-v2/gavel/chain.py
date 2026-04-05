"""
Governance Chains — the core abstraction Microsoft's toolkit lacks.

A chain is a linked sequence of governance events with cryptographic
hash integrity. Every proposal flows through: PROPOSE -> EVALUATE ->
EVIDENCE -> REVIEW -> APPROVE -> EXECUTE -> VERIFY. Each event
references the previous hash, creating a tamper-evident decision trail.

Microsoft's Agent OS evaluates actions individually. Gavel chains them
into auditable governance workflows where every decision is linked.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    INBOUND_INTENT = "INBOUND_INTENT"
    POLICY_EVAL = "POLICY_EVAL"
    BLASTBOX_EVIDENCE = "BLASTBOX_EVIDENCE"
    EVIDENCE_REVIEW = "EVIDENCE_REVIEW"
    REVIEW_ATTESTATION = "REVIEW_ATTESTATION"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    EXECUTION_TOKEN = "EXECUTION_TOKEN"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_COMPLETED = "EXECUTION_COMPLETED"
    POST_EXECUTION_VERIFICATION = "POST_EXECUTION_VERIFICATION"
    ESCALATED = "ESCALATED"
    AUTO_DENIED = "AUTO_DENIED"
    ROLLBACK_TRIGGERED = "ROLLBACK_TRIGGERED"


class ChainEvent(BaseModel):
    """A single event in a governance chain. Immutable once created."""

    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    chain_id: str
    event_type: EventType
    actor_id: str
    role_used: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    event_hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 hash of the event content + previous hash."""
        content = json.dumps(
            {
                "event_id": self.event_id,
                "chain_id": self.chain_id,
                "event_type": self.event_type.value,
                "actor_id": self.actor_id,
                "role_used": self.role_used,
                "timestamp": self.timestamp.isoformat(),
                "payload": self.payload,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()


class ChainStatus(str, Enum):
    PENDING = "PENDING"
    EVALUATING = "EVALUATING"
    ESCALATED = "ESCALATED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    ROLLED_BACK = "ROLLED_BACK"
    TIMED_OUT = "TIMED_OUT"


class GovernanceChain:
    """
    A hash-chained sequence of governance events.

    This is the core primitive that doesn't exist in Microsoft's toolkit.
    Their Agent OS evaluates "should this action happen?" — Gavel chains
    answer "who proposed it, who reviewed it, who approved it, what
    evidence was produced, and can we prove none of that was tampered with?"
    """

    def __init__(self, chain_id: str | None = None):
        self.chain_id = chain_id or f"c-{uuid.uuid4().hex[:8]}"
        self.events: list[ChainEvent] = []
        self.status = ChainStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self._actor_roles: dict[str, set[str]] = {}  # actor_id -> set of roles

    @property
    def latest_hash(self) -> str:
        if not self.events:
            return hashlib.sha256(self.chain_id.encode()).hexdigest()
        return self.events[-1].event_hash

    def append(
        self,
        event_type: EventType,
        actor_id: str,
        role_used: str,
        payload: dict[str, Any] | None = None,
    ) -> ChainEvent:
        """Append an event to the chain with hash linking."""
        event = ChainEvent(
            chain_id=self.chain_id,
            event_type=event_type,
            actor_id=actor_id,
            role_used=role_used,
            payload=payload or {},
            prev_hash=self.latest_hash,
        )
        event.event_hash = event.compute_hash()
        self._actor_roles.setdefault(actor_id, set()).add(role_used)
        self.events.append(event)
        return event

    def verify_integrity(self) -> bool:
        """Verify the entire hash chain is intact."""
        if not self.events:
            return True

        expected_prev = hashlib.sha256(self.chain_id.encode()).hexdigest()
        for event in self.events:
            if event.prev_hash != expected_prev:
                return False
            if event.event_hash != event.compute_hash():
                return False
            expected_prev = event.event_hash
        return True

    def get_actors_by_role(self, role: str) -> list[str]:
        return [aid for aid, roles in self._actor_roles.items() if role in roles]

    def get_event(self, event_type: EventType) -> ChainEvent | None:
        for event in reversed(self.events):
            if event.event_type == event_type:
                return event
        return None

    def to_artifact(self) -> dict:
        """Export chain as a portable decision artifact.

        Produces a self-contained, independently verifiable record
        of the entire governance decision. Can be passed between
        systems, stored externally, or verified without the runtime.
        """
        return {
            "artifact_version": "1.0",
            "chain_id": self.chain_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "integrity": self.verify_integrity(),
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type.value,
                    "actor_id": e.actor_id,
                    "role_used": e.role_used,
                    "timestamp": e.timestamp.isoformat(),
                    "payload": e.payload,
                    "prev_hash": e.prev_hash,
                    "event_hash": e.event_hash,
                }
                for e in self.events
            ],
            "roster": {
                aid: list(roles) for aid, roles in self._actor_roles.items()
            },
            "event_count": len(self.events),
            "genesis_hash": hashlib.sha256(self.chain_id.encode()).hexdigest(),
        }

    @classmethod
    def verify_artifact(cls, artifact: dict) -> dict:
        """Verify a decision artifact's integrity without the runtime.

        Takes a JSON artifact and re-computes every hash in the chain.
        Returns verification result.
        """
        events = artifact.get("events", [])
        if not events:
            return {"valid": True, "events": 0, "errors": []}

        errors = []
        genesis = hashlib.sha256(artifact["chain_id"].encode()).hexdigest()
        expected_prev = genesis

        for i, event in enumerate(events):
            # Check prev_hash links
            if event["prev_hash"] != expected_prev:
                errors.append(
                    f"Event {i}: prev_hash mismatch "
                    f"(expected {expected_prev[:16]}..., got {event['prev_hash'][:16]}...)"
                )

            # Recompute event hash
            content = json.dumps(
                {
                    "event_id": event["event_id"],
                    "chain_id": artifact["chain_id"],
                    "event_type": event["event_type"],
                    "actor_id": event["actor_id"],
                    "role_used": event["role_used"],
                    "timestamp": event["timestamp"],
                    "payload": event["payload"],
                    "prev_hash": event["prev_hash"],
                },
                sort_keys=True,
            )
            computed = hashlib.sha256(content.encode()).hexdigest()

            if event["event_hash"] != computed:
                errors.append(
                    f"Event {i}: hash mismatch "
                    f"(expected {computed[:16]}..., got {event['event_hash'][:16]}...)"
                )

            expected_prev = event["event_hash"]

        return {
            "valid": len(errors) == 0,
            "events": len(events),
            "chain_id": artifact["chain_id"],
            "genesis_hash": genesis,
            "errors": errors,
        }

    def to_timeline(self) -> list[dict[str, Any]]:
        """Return a human-readable timeline of the chain."""
        return [
            {
                "event": e.event_type.value,
                "actor": e.actor_id,
                "role": e.role_used,
                "time": e.timestamp.isoformat(),
                "hash": e.event_hash[:12] + "...",
            }
            for e in self.events
        ]
