"""
V10 — Offline Compliance Bundle Acceptance (Wave 1).

Goal: prove Gavel's compliance export bundles are (a) structurally complete
for all three supported frameworks (SOC 2, ISO 42001, EU AI Act),
(b) deterministic via a stable content hash, and (c) convincing enough to
an *independent* evaluator that has never seen Gavel's source code.

The independent evaluator is a local Ollama model (gemma4:26b by default)
acting as a "blind auditor". It receives each control's evidence_sources
and description — but NOT Gavel's own status verdict, gap_description, or
findings — and rates the evidence as SUFFICIENT / PARTIAL / INSUFFICIENT.
We then compare the blind rating to Gavel's internal ControlStatus and
require ≥50% agreement.

Why 50% and not 80%? The point of this test is not LLM accuracy: it's to
catch the failure mode where Gavel's export is so vague or circular that
an independent reader can't follow the reasoning AT ALL. A bundle where
the LLM agrees with 0-20% of controls would indicate evidence_sources
that don't actually describe the control. Anything above 50% means the
exported bundle carries real semantic content.

Structure:
  A  Structural completeness (no Ollama) — every framework bundle has
     the expected control count, summary block, and non-empty bundle_hash.
  B  Determinism (no Ollama) — same context → identical bundle_hash across
     two separate exports.
  C  Coverage floor (no Ollama) — with a fully-configured context, at
     least 60% of controls in each framework must be MET or PARTIALLY_MET.
  D  Blind audit (Ollama required) — gemma4:26b rates stripped evidence
     and agrees with Gavel ≥50% of the time. Skips cleanly if Ollama is
     unreachable.
"""

from __future__ import annotations

import json
import re

import pytest

from gavel.compliance_export import (
    ComplianceBundle,
    ComplianceExporter,
    ComplianceFramework,
    ControlStatus,
)


# ── Shared fully-configured context ──────────────────────────
#
# A customer deploying Gavel with every capability turned on. This is the
# "happy path" for compliance: no reason for a control to be unmet unless
# the bundle is actually broken.


_FULL_CONTEXT = {
    "chain_count": 25,
    "incident_count": 2,
    "has_rbac": True,
    "has_audit_trail": True,
    "has_enrollment": True,
    "has_separation_of_powers": True,
    "has_evidence_review": True,
    "has_monitoring": True,
    "has_killswitch": True,
    "has_fria": True,
    "has_qms": True,
    "has_data_governance": True,
}


_EXPECTED_CONTROL_COUNTS = {
    ComplianceFramework.SOC2: 16,
    ComplianceFramework.ISO_42001: 19,
    ComplianceFramework.EU_AI_ACT: 12,
}


@pytest.fixture
def full_exporter() -> ComplianceExporter:
    return ComplianceExporter(context=_FULL_CONTEXT)


# ── A: structural completeness ───────────────────────────────


class TestStructuralCompleteness:
    """The export pipeline must produce a well-formed bundle for every
    supported framework, with the expected control count, summary block,
    and a non-empty bundle_hash."""

    def test_all_three_frameworks_exported(self, full_exporter) -> None:
        bundles = full_exporter.export_all()
        assert len(bundles) == 3
        frameworks = {b.framework for b in bundles}
        assert frameworks == {
            ComplianceFramework.SOC2,
            ComplianceFramework.ISO_42001,
            ComplianceFramework.EU_AI_ACT,
        }

    @pytest.mark.parametrize(
        "framework", list(_EXPECTED_CONTROL_COUNTS.keys())
    )
    def test_bundle_shape(
        self, full_exporter, framework: ComplianceFramework
    ) -> None:
        bundle = full_exporter.export(framework)
        assert isinstance(bundle, ComplianceBundle)
        assert bundle.framework == framework
        assert bundle.framework_version  # non-empty
        assert bundle.bundle_hash, "bundle_hash must be populated after finalize()"
        assert len(bundle.bundle_hash) == 64  # SHA-256 hex

        # Control count matches the framework's registry.
        assert len(bundle.controls) == _EXPECTED_CONTROL_COUNTS[framework], (
            f"{framework.value} should have {_EXPECTED_CONTROL_COUNTS[framework]} "
            f"controls, got {len(bundle.controls)}"
        )

        # Every control has a non-empty description and a valid status.
        for ctrl in bundle.controls:
            assert ctrl.control_id
            assert ctrl.control_name
            assert ctrl.description
            assert ctrl.status in ControlStatus

        # Summary block is populated.
        summary = bundle.summary
        assert summary["total_controls"] == len(bundle.controls)
        assert "met" in summary
        assert "partially_met" in summary
        assert "not_met" in summary
        assert "coverage_pct" in summary
        assert 0.0 <= summary["coverage_pct"] <= 100.0

    def test_bundle_is_json_serializable(self, full_exporter) -> None:
        """Auditors receive the bundle as JSON, not as a Python object."""
        bundle = full_exporter.export(ComplianceFramework.EU_AI_ACT)
        blob = bundle.model_dump_json()
        reloaded = json.loads(blob)
        assert reloaded["framework"] == "eu_ai_act"
        assert len(reloaded["controls"]) == 12


# ── B: determinism of bundle_hash ────────────────────────────


class TestBundleHashDeterminism:
    """bundle_hash covers bundle_id + framework + controls. bundle_id is a
    random uuid, so two exports will have different bundle_hashes — but the
    *controls portion* of the hash must be identical for identical input.
    We prove this by hashing just the controls slice both times."""

    @staticmethod
    def _controls_fingerprint(bundle: ComplianceBundle) -> str:
        import hashlib
        payload = json.dumps(
            [c.model_dump(mode="json") for c in bundle.controls],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    @pytest.mark.parametrize(
        "framework", list(_EXPECTED_CONTROL_COUNTS.keys())
    )
    def test_same_context_same_controls(self, framework) -> None:
        a = ComplianceExporter(context=dict(_FULL_CONTEXT)).export(framework)
        b = ComplianceExporter(context=dict(_FULL_CONTEXT)).export(framework)
        assert self._controls_fingerprint(a) == self._controls_fingerprint(b), (
            f"{framework.value} control content differed across two exports "
            f"with identical context"
        )

    def test_context_change_changes_hash(self) -> None:
        """Flipping a capability flag must change the controls fingerprint —
        otherwise the context is being ignored."""
        with_evidence = ComplianceExporter(context=dict(_FULL_CONTEXT)).export(
            ComplianceFramework.EU_AI_ACT
        )
        ctx_no_evidence = dict(_FULL_CONTEXT)
        ctx_no_evidence["has_evidence_review"] = False
        without_evidence = ComplianceExporter(context=ctx_no_evidence).export(
            ComplianceFramework.EU_AI_ACT
        )
        assert (
            self._controls_fingerprint(with_evidence)
            != self._controls_fingerprint(without_evidence)
        ), "context changes should propagate into the controls fingerprint"


# ── C: coverage floor under full configuration ───────────────


class TestCoverageFloor:
    """With every capability flag set, each framework bundle must achieve
    at least 60% (met + partially_met) coverage. A bundle that still shows
    large gaps under full configuration indicates either broken context
    wiring or a control that's permanently unreachable — both of which are
    bugs the export pipeline must fail loud about."""

    @pytest.mark.parametrize(
        "framework,floor",
        [
            (ComplianceFramework.SOC2, 80.0),
            (ComplianceFramework.ISO_42001, 80.0),
            (ComplianceFramework.EU_AI_ACT, 80.0),
        ],
    )
    def test_full_context_meets_floor(
        self, full_exporter, framework: ComplianceFramework, floor: float
    ) -> None:
        bundle = full_exporter.export(framework)
        coverage = bundle.summary["coverage_pct"]
        assert coverage >= floor, (
            f"{framework.value} coverage {coverage}% is below floor {floor}% "
            f"under fully-configured context. Summary: {bundle.summary}"
        )


# ── D: blind auditor (Ollama) ────────────────────────────────
#
# The gemma4:26b model receives a stripped-down version of each control —
# only control_id, control_name, description, and evidence_sources.
# It does NOT see Gavel's own status or gap_description.
#
# We ask it to rate each control as SUFFICIENT / PARTIAL / INSUFFICIENT
# based only on whether the evidence sources plausibly demonstrate the
# control. Then we compare its ratings to Gavel's internal status with
# this mapping:
#   Gavel MET          ↔ LLM SUFFICIENT
#   Gavel PARTIALLY_MET ↔ LLM PARTIAL
#   Gavel NOT_MET      ↔ LLM INSUFFICIENT
#
# Required agreement floor: 50%. See module docstring for rationale.


_PROMPT_TEMPLATE = """You are an independent compliance auditor. You have
received a compliance bundle export for an AI governance platform called
Gavel. Your job is to rate each control's evidence as one of:

  SUFFICIENT  — the listed evidence sources plausibly satisfy the control
  PARTIAL     — the evidence is relevant but incomplete
  INSUFFICIENT — the evidence does not demonstrate the control

You will NOT see the platform's own verdict. Rate based solely on whether
the listed evidence_sources plausibly meet the control described.

Respond ONLY with a JSON object mapping control_id to rating, like:
{{"CC1.1": "SUFFICIENT", "CC1.2": "PARTIAL", ...}}

Do not include any prose before or after the JSON. Do not wrap the JSON
in markdown code fences. Do not include any control_id not present in
the input.

Framework: {framework}
Scope: Gavel AI Governance Platform

Controls:
{controls_json}

JSON:"""


def _strip_controls_for_blind_audit(bundle: ComplianceBundle) -> list[dict]:
    """Build the LLM-facing control list — status and gap_description
    removed so the model cannot simply echo Gavel's own verdict."""
    return [
        {
            "control_id": c.control_id,
            "control_name": c.control_name,
            "description": c.description,
            "evidence_sources": c.evidence_sources,
        }
        for c in bundle.controls
    ]


def _parse_llm_ratings(raw: str) -> dict[str, str]:
    """Parse the LLM response into {control_id: rating}. Tolerates a
    leading/trailing explanation paragraph by extracting the first JSON
    object in the response."""
    # Strip code fences if the model added them despite being asked not to.
    cleaned = raw.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    # Find the first {...} block.
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    # Normalize rating strings (uppercase, stripped).
    return {
        str(k): str(v).strip().upper()
        for k, v in parsed.items()
        if isinstance(v, str)
    }


_STATUS_TO_RATING = {
    ControlStatus.MET: "SUFFICIENT",
    ControlStatus.PARTIALLY_MET: "PARTIAL",
    ControlStatus.NOT_MET: "INSUFFICIENT",
    ControlStatus.NOT_APPLICABLE: None,  # skipped in comparison
}


class TestBlindAudit:
    """Ollama-backed tests. Each one calls the session-scoped `ollama_auditor`
    fixture which raises pytest.skip if the daemon is unreachable or the
    configured model is not installed. No mocking — we want this to exercise
    real local inference end-to-end."""

    @pytest.mark.parametrize(
        "framework",
        [
            ComplianceFramework.SOC2,
            ComplianceFramework.ISO_42001,
            ComplianceFramework.EU_AI_ACT,
        ],
    )
    def test_blind_auditor_agrees_with_gavel(
        self, full_exporter, ollama_auditor, framework: ComplianceFramework
    ) -> None:
        bundle = full_exporter.export(framework)
        stripped = _strip_controls_for_blind_audit(bundle)

        prompt = _PROMPT_TEMPLATE.format(
            framework=framework.value,
            controls_json=json.dumps(stripped, indent=2),
        )
        raw = ollama_auditor["generate"](prompt, timeout=600)
        ratings = _parse_llm_ratings(raw)
        assert ratings, (
            f"Blind auditor returned no parseable JSON for {framework.value}. "
            f"First 500 chars of raw response: {raw[:500]!r}"
        )

        # Compare ratings to Gavel's internal statuses.
        comparable = 0
        agreements = 0
        disagreements: list[tuple[str, str, str]] = []
        for ctrl in bundle.controls:
            gavel_rating = _STATUS_TO_RATING.get(ctrl.status)
            if gavel_rating is None:
                continue
            llm_rating = ratings.get(ctrl.control_id)
            if llm_rating is None:
                continue
            comparable += 1
            if llm_rating == gavel_rating:
                agreements += 1
            else:
                disagreements.append(
                    (ctrl.control_id, gavel_rating, llm_rating)
                )

        assert comparable >= max(3, len(bundle.controls) // 2), (
            f"Blind auditor rated too few controls for {framework.value}: "
            f"{comparable}/{len(bundle.controls)}. Ratings: {ratings}"
        )

        agreement_rate = agreements / comparable
        # 50% floor — see module docstring for why.
        assert agreement_rate >= 0.50, (
            f"Blind auditor agreement rate for {framework.value} is "
            f"{agreement_rate:.0%} ({agreements}/{comparable}), below the "
            f"50% floor. Disagreements: {disagreements}"
        )
