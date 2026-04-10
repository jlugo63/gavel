"""
Compliance export bundles — Phase 8.

Auditors and certification bodies want a single tar-able directory
that, for a given scope and time window, contains:

  - a manifest describing the bundle contents and cryptographic hashes
  - the governance chain segment over that window
  - the enrollment ledger snapshot
  - incident records
  - Annex IV technical documentation (EU AI Act)
  - QMS manual (EU AI Act Art. 17)
  - the applicable multi-regulation compliance matrix
  - a FRIA packet if the agent requires one

This module builds a deterministic in-memory bundle representation
for three common targets:

  - SOC 2 (TSC 2017)            — auth, change mgmt, availability evidence
  - ISO 42001 (AI mgmt system)  — AIMS controls
  - EU AI Act                   — Annex IV + Art. 17 + Art. 27 + Art. 73

The bundle is a pure data object — callers can serialize it to
JSON, write it to disk, or hand it to an external archival system.
Every file entry carries a SHA-256 of its content so external
verifiers can compare against the bundle's manifest hash.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class BundleTarget(str, Enum):
    SOC2 = "soc2"
    ISO_42001 = "iso_42001"
    EU_AI_ACT = "eu_ai_act"


# ── Control catalogues ─────────────────────────────────────────

# These are the minimal control sets each target bundle must document.
# A real certification audit expects additional provider-supplied
# artifacts; Gavel's job is to supply the evidence it can prove
# automatically from its own modules.

_SOC2_CONTROLS = {
    "CC6.1": "Logical access controls",
    "CC6.2": "User access provisioning",
    "CC6.3": "Role-based access",
    "CC7.2": "System monitoring",
    "CC7.3": "Incident detection",
    "CC7.4": "Incident response",
    "CC8.1": "Change management",
    "A1.2": "Availability / capacity",
}

_ISO_42001_CONTROLS = {
    "A.6.1.1": "AI policy",
    "A.6.2.1": "AI roles and responsibilities",
    "A.7.2": "Impact assessment",
    "A.8.2": "Data quality for AI systems",
    "A.8.3": "Data for AI systems",
    "A.9.2": "Process for responsible AI design",
    "A.9.3": "Verification and validation",
    "A.9.4": "Deployment",
    "A.9.5": "Operation and monitoring",
    "A.10.2": "Supplier relationships",
}

_EU_AI_ACT_CONTROLS = {
    "Art. 9": "Risk management system",
    "Art. 10": "Data and data governance",
    "Art. 11": "Technical documentation (Annex IV)",
    "Art. 12": "Record-keeping",
    "Art. 13": "Transparency to deployers",
    "Art. 14": "Human oversight",
    "Art. 15": "Accuracy, robustness, cybersecurity",
    "Art. 17": "Quality management system",
    "Art. 27": "Fundamental Rights Impact Assessment",
    "Art. 72": "Post-market monitoring",
    "Art. 73": "Serious incident reporting",
}

_TARGET_CONTROLS: dict[BundleTarget, dict[str, str]] = {
    BundleTarget.SOC2: _SOC2_CONTROLS,
    BundleTarget.ISO_42001: _ISO_42001_CONTROLS,
    BundleTarget.EU_AI_ACT: _EU_AI_ACT_CONTROLS,
}


# ── Bundle data ────────────────────────────────────────────────

class BundleFile(BaseModel):
    """A logical file in the bundle — stored by its bytes, with a hash."""

    path: str                                # relative path inside the bundle
    content: str                             # UTF-8 text or base64 binary blob
    content_type: str = "application/json"
    sha256: str                              # over the content bytes
    bytes_len: int


class ControlEvidence(BaseModel):
    """One control → list of bundle file paths satisfying it."""

    control_id: str
    title: str
    file_paths: list[str] = Field(default_factory=list)
    gavel_module_refs: list[str] = Field(default_factory=list)
    notes: str = ""


class ComplianceBundle(BaseModel):
    """A complete bundle for one target, one scope, one window."""

    target: BundleTarget
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    window_start: datetime
    window_end: datetime
    scope: str                               # "tenant:acme" / "agent:x" / "all"
    files: list[BundleFile] = Field(default_factory=list)
    controls: list[ControlEvidence] = Field(default_factory=list)
    manifest_sha256: str = ""                # over sorted (path, sha256) pairs

    def compute_manifest_hash(self) -> str:
        items = sorted((f.path, f.sha256) for f in self.files)
        payload = json.dumps(items, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def coverage_summary(self) -> dict[str, int]:
        summary = {"covered": 0, "gap": 0}
        for c in self.controls:
            if c.file_paths or c.gavel_module_refs:
                summary["covered"] += 1
            else:
                summary["gap"] += 1
        return summary

    def gaps(self) -> list[ControlEvidence]:
        return [
            c for c in self.controls
            if not c.file_paths and not c.gavel_module_refs
        ]


# ── Builder ────────────────────────────────────────────────────

class BundleBuilder:
    """Assemble a ComplianceBundle file-by-file and finalize it."""

    def __init__(
        self,
        *,
        target: BundleTarget,
        scope: str,
        window_start: datetime,
        window_end: datetime,
    ):
        self._target = target
        self._scope = scope
        self._window_start = window_start
        self._window_end = window_end
        self._files: list[BundleFile] = []
        self._controls: dict[str, ControlEvidence] = {}
        for cid, title in _TARGET_CONTROLS[target].items():
            self._controls[cid] = ControlEvidence(control_id=cid, title=title)

    def add_json_file(
        self,
        path: str,
        payload: dict | list,
        *,
        evidence_for: Optional[list[str]] = None,
    ) -> BundleFile:
        content = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return self._add_file(
            path=path,
            content=content,
            content_type="application/json",
            evidence_for=evidence_for,
        )

    def add_text_file(
        self,
        path: str,
        text: str,
        *,
        content_type: str = "text/markdown",
        evidence_for: Optional[list[str]] = None,
    ) -> BundleFile:
        return self._add_file(
            path=path,
            content=text,
            content_type=content_type,
            evidence_for=evidence_for,
        )

    def attach_module_evidence(
        self, control_id: str, module_refs: list[str], notes: str = ""
    ) -> None:
        if control_id not in self._controls:
            raise KeyError(f"unknown control for {self._target.value}: {control_id}")
        ev = self._controls[control_id]
        ev.gavel_module_refs.extend(module_refs)
        if notes:
            ev.notes = (ev.notes + " " + notes).strip()

    def build(self) -> ComplianceBundle:
        bundle = ComplianceBundle(
            target=self._target,
            scope=self._scope,
            window_start=self._window_start,
            window_end=self._window_end,
            files=list(self._files),
            controls=list(self._controls.values()),
        )
        bundle.manifest_sha256 = bundle.compute_manifest_hash()
        return bundle

    # ---- internal ----

    def _add_file(
        self,
        *,
        path: str,
        content: str,
        content_type: str,
        evidence_for: Optional[list[str]],
    ) -> BundleFile:
        sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        bf = BundleFile(
            path=path,
            content=content,
            content_type=content_type,
            sha256=sha,
            bytes_len=len(content.encode("utf-8")),
        )
        self._files.append(bf)
        for cid in evidence_for or []:
            if cid not in self._controls:
                raise KeyError(
                    f"unknown control for {self._target.value}: {cid}"
                )
            self._controls[cid].file_paths.append(path)
        return bf


# ── Convenience assembler ──────────────────────────────────────

def build_eu_ai_act_bundle(
    *,
    scope: str,
    window_start: datetime,
    window_end: datetime,
    chain_events: list[dict],
    enrollment_records: list[dict],
    incidents: list[dict],
    annex_iv_markdown: str,
    qms_markdown: str,
    compliance_matrix: Optional[dict] = None,
    fria_packet: Optional[dict] = None,
) -> ComplianceBundle:
    """Assemble a ready-to-ship EU AI Act bundle from typical Gavel artifacts."""
    b = BundleBuilder(
        target=BundleTarget.EU_AI_ACT,
        scope=scope,
        window_start=window_start,
        window_end=window_end,
    )
    b.add_json_file(
        "chain/events.json",
        chain_events,
        evidence_for=["Art. 12"],
    )
    b.add_json_file(
        "enrollment/records.json",
        enrollment_records,
        evidence_for=["Art. 13"],
    )
    b.add_json_file(
        "incidents/registry.json",
        incidents,
        evidence_for=["Art. 72", "Art. 73"],
    )
    b.add_text_file(
        "technical-documentation/annex-iv.md",
        annex_iv_markdown,
        evidence_for=["Art. 11"],
    )
    b.add_text_file(
        "quality-management/qms-manual.md",
        qms_markdown,
        evidence_for=["Art. 17"],
    )
    if compliance_matrix is not None:
        b.add_json_file(
            "compliance/matrix.json",
            compliance_matrix,
            evidence_for=["Art. 9"],
        )
    if fria_packet is not None:
        b.add_json_file(
            "fria/packet.json",
            fria_packet,
            evidence_for=["Art. 27"],
        )

    # Attach module-level evidence for controls that come from structural
    # Gavel guarantees rather than files.
    b.attach_module_evidence(
        "Art. 14",
        ["gavel.separation", "gavel.tiers", "gateway.human_approval"],
    )
    b.attach_module_evidence(
        "Art. 15",
        ["tests/test_adversarial.py", "tests/test_adversarial_threat_model.py",
         "docs/threat-model.md"],
    )
    b.attach_module_evidence(
        "Art. 10",
        ["gavel.data_governance", "gavel.privacy"],
    )

    return b.build()
