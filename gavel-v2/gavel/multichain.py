"""
Multi-chain governance — parallel approval chains for complex workflows.

Some governance decisions require multiple independent approval paths
(e.g., security review + compliance review + budget approval). This module
orchestrates multiple GovernanceChains that run in parallel and are joined
when all required chains reach a terminal state.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from gavel.chain import ChainStatus, EventType, GovernanceChain


class JoinPolicy(str, Enum):
    """How parallel chains are combined."""
    ALL = "ALL"             # All chains must approve (AND)
    MAJORITY = "MAJORITY"   # >50% must approve
    ANY = "ANY"             # At least one must approve (OR)
    QUORUM = "QUORUM"       # N-of-M must approve


class MultiChainStatus(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"       # At least one chain is running
    APPROVED = "APPROVED"   # Join policy satisfied
    DENIED = "DENIED"       # Join policy cannot be satisfied
    TIMED_OUT = "TIMED_OUT"


@dataclass
class ChainSlot:
    """A slot for a chain within a multi-chain workflow."""
    slot_id: str
    label: str              # e.g. "security-review", "compliance-check"
    chain: GovernanceChain
    required: bool = True   # If False, this chain is advisory-only
    weight: float = 1.0     # For weighted quorum


class MultiChainWorkflow:
    """Orchestrates parallel governance chains with join semantics.

    Usage:
        workflow = MultiChainWorkflow(join_policy=JoinPolicy.ALL)
        sec_chain = workflow.add_chain("security-review")
        comp_chain = workflow.add_chain("compliance-check")

        # Each chain progresses independently
        sec_chain.append(EventType.INBOUND_INTENT, ...)
        comp_chain.append(EventType.INBOUND_INTENT, ...)

        # Check if workflow is resolved
        result = workflow.evaluate()
    """

    def __init__(
        self,
        workflow_id: str | None = None,
        join_policy: JoinPolicy = JoinPolicy.ALL,
        quorum: int = 0,   # For QUORUM policy: minimum chains that must approve
        description: str = "",
    ) -> None:
        self.workflow_id = workflow_id or f"wf-{uuid.uuid4().hex[:8]}"
        self.join_policy = join_policy
        self.quorum = quorum
        self.description = description
        self.created_at = datetime.now(timezone.utc)
        self.slots: list[ChainSlot] = []
        self.status = MultiChainStatus.PENDING
        self._resolved_at: Optional[datetime] = None

    def add_chain(
        self,
        label: str,
        required: bool = True,
        weight: float = 1.0,
        chain_id: str | None = None,
    ) -> GovernanceChain:
        """Add a new parallel chain to the workflow."""
        chain = GovernanceChain(chain_id=chain_id)
        slot = ChainSlot(
            slot_id=f"slot-{uuid.uuid4().hex[:6]}",
            label=label,
            chain=chain,
            required=required,
            weight=weight,
        )
        self.slots.append(slot)
        if self.status == MultiChainStatus.PENDING:
            self.status = MultiChainStatus.ACTIVE
        return chain

    def get_chain(self, label: str) -> Optional[GovernanceChain]:
        """Get a chain by its label."""
        for slot in self.slots:
            if slot.label == label:
                return slot.chain
        return None

    def _count_by_status(self) -> dict[str, int]:
        """Count chains by their terminal status."""
        counts: dict[str, int] = {
            "approved": 0,
            "denied": 0,
            "pending": 0,
            "total": len(self.slots),
            "required": sum(1 for s in self.slots if s.required),
        }
        for slot in self.slots:
            if slot.chain.status in (ChainStatus.APPROVED, ChainStatus.COMPLETED):
                counts["approved"] += 1
            elif slot.chain.status in (ChainStatus.DENIED, ChainStatus.ROLLED_BACK):
                counts["denied"] += 1
            else:
                counts["pending"] += 1
        return counts

    def evaluate(self) -> MultiChainStatus:
        """Evaluate whether the join policy is satisfied.

        Returns the current workflow status. Once resolved (APPROVED/DENIED),
        the status is locked.
        """
        if self.status in (MultiChainStatus.APPROVED, MultiChainStatus.DENIED):
            return self.status

        counts = self._count_by_status()

        # Check required chains for denial
        for slot in self.slots:
            if slot.required and slot.chain.status in (
                ChainStatus.DENIED, ChainStatus.ROLLED_BACK
            ):
                if self.join_policy in (JoinPolicy.ALL, JoinPolicy.QUORUM):
                    self.status = MultiChainStatus.DENIED
                    self._resolved_at = datetime.now(timezone.utc)
                    return self.status

        if self.join_policy == JoinPolicy.ALL:
            if counts["approved"] == counts["total"]:
                self.status = MultiChainStatus.APPROVED
                self._resolved_at = datetime.now(timezone.utc)
            elif counts["denied"] > 0:
                self.status = MultiChainStatus.DENIED
                self._resolved_at = datetime.now(timezone.utc)

        elif self.join_policy == JoinPolicy.MAJORITY:
            if counts["approved"] > counts["total"] / 2:
                self.status = MultiChainStatus.APPROVED
                self._resolved_at = datetime.now(timezone.utc)
            elif counts["denied"] >= (counts["total"] + 1) / 2:
                self.status = MultiChainStatus.DENIED
                self._resolved_at = datetime.now(timezone.utc)

        elif self.join_policy == JoinPolicy.ANY:
            if counts["approved"] > 0:
                self.status = MultiChainStatus.APPROVED
                self._resolved_at = datetime.now(timezone.utc)
            elif counts["denied"] == counts["total"]:
                self.status = MultiChainStatus.DENIED
                self._resolved_at = datetime.now(timezone.utc)

        elif self.join_policy == JoinPolicy.QUORUM:
            needed = self.quorum if self.quorum > 0 else (counts["total"] // 2 + 1)
            if counts["approved"] >= needed:
                self.status = MultiChainStatus.APPROVED
                self._resolved_at = datetime.now(timezone.utc)
            elif counts["total"] - counts["denied"] < needed:
                # Not enough remaining chains to meet quorum
                self.status = MultiChainStatus.DENIED
                self._resolved_at = datetime.now(timezone.utc)

        return self.status

    def verify_integrity(self) -> dict[str, Any]:
        """Verify integrity of all chains in the workflow."""
        results = {}
        all_valid = True
        for slot in self.slots:
            valid = slot.chain.verify_integrity()
            results[slot.label] = {
                "chain_id": slot.chain.chain_id,
                "valid": valid,
                "events": len(slot.chain.events),
                "status": slot.chain.status.value,
            }
            if not valid:
                all_valid = False
        return {
            "workflow_id": self.workflow_id,
            "all_valid": all_valid,
            "join_policy": self.join_policy.value,
            "status": self.status.value,
            "chains": results,
        }

    def to_artifact(self) -> dict[str, Any]:
        """Export the entire multi-chain workflow as a portable artifact."""
        return {
            "artifact_version": "2.0",
            "type": "multi_chain",
            "workflow_id": self.workflow_id,
            "join_policy": self.join_policy.value,
            "quorum": self.quorum,
            "description": self.description,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self._resolved_at.isoformat() if self._resolved_at else None,
            "chains": [
                {
                    "slot_id": slot.slot_id,
                    "label": slot.label,
                    "required": slot.required,
                    "weight": slot.weight,
                    "artifact": slot.chain.to_artifact(),
                }
                for slot in self.slots
            ],
        }

    def summary(self) -> dict[str, Any]:
        """Brief status summary of the workflow."""
        counts = self._count_by_status()
        return {
            "workflow_id": self.workflow_id,
            "join_policy": self.join_policy.value,
            "status": self.status.value,
            "chains": counts["total"],
            "approved": counts["approved"],
            "denied": counts["denied"],
            "pending": counts["pending"],
        }
