"""
Policy distribution — push constitution updates to all endpoints.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Policy Distribution ──────────────────────────────────────

class PolicyVersion(BaseModel):
    """A versioned constitution/policy document distributed to endpoints."""
    version_id: str = Field(default_factory=lambda: f"pv-{uuid.uuid4().hex[:8]}")
    version_number: int
    policy_name: str
    content_hash: str = ""           # SHA-256 of the policy content
    content: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    target_scope: str = "all"        # "all", org_id, team_id, or endpoint_id


class PolicyDistributionRecord(BaseModel):
    """Tracks which endpoints have received which policy version."""
    endpoint_id: str
    version_id: str
    distributed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None


class PolicyDistributor:
    """Push constitution updates to all endpoints simultaneously."""

    def __init__(self):
        self._versions: list[PolicyVersion] = []
        self._distributions: list[PolicyDistributionRecord] = []
        self._endpoint_versions: dict[str, str] = {}  # endpoint_id -> latest version_id

    def publish(self, policy_name: str, content: dict[str, Any],
                created_by: str = "", target_scope: str = "all") -> PolicyVersion:
        version_number = len([v for v in self._versions if v.policy_name == policy_name]) + 1
        content_hash = hashlib.sha256(
            str(sorted(content.items())).encode()
        ).hexdigest()
        pv = PolicyVersion(
            version_number=version_number,
            policy_name=policy_name,
            content_hash=content_hash,
            content=content,
            created_by=created_by,
            target_scope=target_scope,
        )
        self._versions.append(pv)
        return pv

    def distribute(self, version_id: str, endpoint_ids: list[str]) -> list[PolicyDistributionRecord]:
        records = []
        for eid in endpoint_ids:
            rec = PolicyDistributionRecord(endpoint_id=eid, version_id=version_id)
            self._distributions.append(rec)
            self._endpoint_versions[eid] = version_id
            records.append(rec)
        return records

    def acknowledge(self, endpoint_id: str, version_id: str) -> bool:
        for rec in self._distributions:
            if rec.endpoint_id == endpoint_id and rec.version_id == version_id:
                rec.acknowledged = True
                rec.acknowledged_at = datetime.now(timezone.utc)
                return True
        return False

    def pending_endpoints(self, version_id: str) -> list[str]:
        """Endpoints that haven't acknowledged a specific version."""
        return [r.endpoint_id for r in self._distributions
                if r.version_id == version_id and not r.acknowledged]

    def latest_version(self, policy_name: str) -> Optional[PolicyVersion]:
        versions = [v for v in self._versions if v.policy_name == policy_name]
        return versions[-1] if versions else None

    def endpoint_version(self, endpoint_id: str) -> Optional[str]:
        return self._endpoint_versions.get(endpoint_id)
