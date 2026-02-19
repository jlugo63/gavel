"""
Evidence Packet Builder
Constitutional Reference: section I.1 -- Evidence Packets for tamper-evident execution records

Builds an EvidencePacket from a BlastBox execution result, computes a
SHA-256 evidence hash over canonical JSON, and logs it to the Audit Spine.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from governance.audit import AuditSpineManager
from governance.blastbox import BlastBoxConfig, BlastBoxResult


class EvidencePacket(BaseModel):
    proposal_id: str
    chain_id: str
    actor_id: str
    action_type: str
    command: str
    blast_box: dict[str, Any]
    environment: dict[str, Any]
    created_at: str
    evidence_hash: str


def create_evidence_packet(
    proposal_id: str,
    chain_id: str,
    actor_id: str,
    action_type: str,
    command: str,
    result: BlastBoxResult,
    config: BlastBoxConfig,
) -> EvidencePacket:
    """Build an EvidencePacket with a SHA-256 hash over canonical JSON."""
    blast_box = asdict(result)
    environment = {
        "image": config.image,
        "network_mode": config.network_mode,
        "memory_limit": config.memory_limit,
        "cpu_limit": config.cpu_limit,
        "timeout_seconds": config.timeout_seconds,
    }
    created_at = datetime.now(timezone.utc).isoformat()

    # All fields except evidence_hash, serialized to canonical JSON
    pre_hash = {
        "proposal_id": proposal_id,
        "chain_id": chain_id,
        "actor_id": actor_id,
        "action_type": action_type,
        "command": command,
        "blast_box": blast_box,
        "environment": environment,
        "created_at": created_at,
    }
    canonical = json.dumps(pre_hash, sort_keys=True)
    evidence_hash = hashlib.sha256(canonical.encode()).hexdigest()

    return EvidencePacket(
        proposal_id=proposal_id,
        chain_id=chain_id,
        actor_id=actor_id,
        action_type=action_type,
        command=command,
        blast_box=blast_box,
        environment=environment,
        created_at=created_at,
        evidence_hash=evidence_hash,
    )


def log_evidence_to_spine(
    audit: AuditSpineManager,
    packet: EvidencePacket,
) -> str:
    """Log an EVIDENCE_PACKET event to the Audit Spine. Returns event_id."""
    return audit.log_event(
        actor_id=packet.actor_id,
        action_type="EVIDENCE_PACKET",
        intent_payload=packet.model_dump(),
    )
