"""Shared compliance types — frameworks, statuses, evidence, bundles."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ComplianceFramework(str, Enum):
    SOC2 = "soc2"
    ISO_42001 = "iso_42001"
    EU_AI_ACT = "eu_ai_act"


class ControlStatus(str, Enum):
    MET = "met"
    PARTIALLY_MET = "partially_met"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"


class ControlEvidence(BaseModel):
    """Evidence mapped to a specific compliance control."""
    control_id: str
    control_name: str
    description: str
    status: ControlStatus
    evidence_sources: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    gap_description: str = ""


class ComplianceBundle(BaseModel):
    """A complete compliance export bundle for one framework."""
    bundle_id: str = Field(default_factory=lambda: f"bundle-{uuid.uuid4().hex[:8]}")
    framework: ComplianceFramework
    framework_version: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scope: str = "Gavel AI Governance Platform"
    controls: list[ControlEvidence] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    bundle_hash: str = ""

    def compute_hash(self) -> str:
        content = json.dumps(
            {
                "bundle_id": self.bundle_id,
                "framework": self.framework.value,
                "controls": [c.model_dump(mode="json") for c in self.controls],
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def finalize(self) -> None:
        self.bundle_hash = self.compute_hash()
        met = sum(1 for c in self.controls if c.status == ControlStatus.MET)
        partial = sum(1 for c in self.controls if c.status == ControlStatus.PARTIALLY_MET)
        not_met = sum(1 for c in self.controls if c.status == ControlStatus.NOT_MET)
        na = sum(1 for c in self.controls if c.status == ControlStatus.NOT_APPLICABLE)
        total = len(self.controls)
        self.summary = {
            "total_controls": total,
            "met": met,
            "partially_met": partial,
            "not_met": not_met,
            "not_applicable": na,
            "coverage_pct": round((met + partial) / total * 100, 1) if total else 0.0,
        }
