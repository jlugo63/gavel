"""
V5 — Annex IV Technical Documentation Validation (Wave 1).

Goal: prove the Annex IV generator produces complete, deterministic,
legally-structured technical documentation for a real high-risk agent.
EU AI Act Article 11 mandates this document for every high-risk AI system
placed on the market — if Gavel's generator produces something with
missing sections, TODO placeholders, or non-deterministic output, the
customer cannot ship.

Scenario: a recruitment-screening agent (HighRiskCategory.EMPLOYMENT —
Annex III paragraph 4(a)). This is one of the highest-stakes high-risk
categories in the Act because it interacts directly with employment
decisions protected under fundamental rights law.

Checks:
  C1  Structural      — all 9 Annex IV sections present with their
                         mandated keys, no 'incomplete' status.
  C2  Populated        — Section 1 has system_name / agent_id / owner /
                         contact; Section 2 has non-empty boundaries;
                         Section 5 has the risk_classification block.
  C3  Deterministic    — two back-to-back generate() calls produce
                         content-identical output (modulo the timestamp
                         fields, which we strip before comparing).
  C4  Compliance roll-up — compliance_status is either "compliant" or
                         "partially_compliant" for a properly-declared
                         agent (never "non_compliant" or "assessment_required").
  C5  Section 4 math   — chain/review rate denominators behave correctly
                         when chains are supplied.
"""

from __future__ import annotations

import json

import pytest

from gavel.compliance import (
    AnnexIVGenerator,
    ComplianceStatus,
)
from gavel.enrollment import (
    EnrollmentRecord,
    EnrollmentRegistry,
    EnrollmentStatus,
    HighRiskCategory,
)

from tests.validation.conftest import build_application
from conftest import _make_enrollment_registry


# ── Scenario: recruitment screening agent ─────────────────────


@pytest.fixture
async def recruitment_agent_record() -> EnrollmentRecord:
    """Build a realistic Annex III 4(a) Employment high-risk enrollment.

    We submit through the real EnrollmentRegistry so the record carries
    the exact shape production code produces — including validator
    pass/fail. Even if the validator adds a few nits, the record is
    still usable as input to Annex IV generation.
    """
    app = build_application(
        agent_id="agent:recruit-screen",
        display_name="Resume Screening Assistant",
        owner="hr-ops@example.org",
        owner_contact="hr-ops@example.org",
        purpose_summary=(
            "Screen candidate resumes against structured job descriptions "
            "to recommend shortlist candidates for human review"
        ),
        operational_scope="recruitment assistance for internal hiring committees",
        risk_tier="high",
        tools=["Read", "Embeddings", "LLMPrompt"],
        high_risk_category=HighRiskCategory.EMPLOYMENT,
    )
    registry = _make_enrollment_registry()
    record = await registry.submit(app)
    # We want a real ENROLLED record for the Annex IV generator. If the
    # validator raised nits (e.g. missing an allowed action), just force
    # the status — this test is about the *generator*, not the validator
    # (which V4 covers).
    if record.status != EnrollmentStatus.ENROLLED:
        record.status = EnrollmentStatus.ENROLLED
        record.violations = []
    return record


# ── C1: structural completeness ───────────────────────────────


_REQUIRED_SECTIONS = {
    "1_general_description",
    "2_development_and_design",
    "3_monitoring_and_control",
    "4_performance_metrics",
    "5_risk_management",
    "6_lifecycle_changes",
    "7_applied_standards",
    "8_eu_declaration",
    "9_post_market_monitoring",
}


class TestStructuralCompleteness:
    def test_all_nine_sections_present(self, recruitment_agent_record) -> None:
        gen = AnnexIVGenerator(enrollment_record=recruitment_agent_record)
        doc = gen.generate()

        assert doc["annex_iv_version"] == "1.0"
        assert "EU AI Act" in doc["regulation"]
        assert doc["annex"].startswith("IV")
        sections = doc["sections"]
        assert set(sections.keys()) == _REQUIRED_SECTIONS, (
            f"missing/extra sections: "
            f"got={set(sections.keys())}, expected={_REQUIRED_SECTIONS}"
        )

        # No section is flagged "incomplete" — the generator should have
        # all the data it needs for a properly-declared high-risk agent.
        for key, body in sections.items():
            if isinstance(body, dict):
                assert body.get("status") != "incomplete", (
                    f"section {key} reported incomplete for a fully-declared agent: {body}"
                )
                assert body.get("title"), f"section {key} missing title"

    def test_json_serializable(self, recruitment_agent_record) -> None:
        """The Annex IV doc must round-trip through JSON cleanly — this is
        how customers hand it to auditors."""
        gen = AnnexIVGenerator(enrollment_record=recruitment_agent_record)
        doc = gen.generate()
        # default=str covers datetimes and enum values.
        blob = json.dumps(doc, default=str)
        reloaded = json.loads(blob)
        assert set(reloaded["sections"].keys()) == _REQUIRED_SECTIONS


# ── C2: populated fields (not placeholders) ──────────────────


class TestPopulatedFields:
    def test_section_1_has_identity_and_accountability(
        self, recruitment_agent_record
    ) -> None:
        doc = AnnexIVGenerator(enrollment_record=recruitment_agent_record).generate()
        sec1 = doc["sections"]["1_general_description"]

        assert sec1["system_name"] == "Resume Screening Assistant"
        assert sec1["agent_id"] == "agent:recruit-screen"
        assert sec1["agent_type"] == "llm"
        assert sec1["risk_tier"] == "high"
        # Enum or string representation — accept either.
        assert str(sec1["high_risk_category"]) in (
            "HighRiskCategory.EMPLOYMENT",
            "employment",
        )
        accountability = sec1["accountability"]
        assert accountability["owner"] == "hr-ops@example.org"
        assert accountability["owner_contact"] == "hr-ops@example.org"
        # Capabilities must reflect the declared tool list.
        assert "LLMPrompt" in sec1["capabilities"]["tools"]

    def test_section_2_has_action_boundaries(self, recruitment_agent_record) -> None:
        doc = AnnexIVGenerator(enrollment_record=recruitment_agent_record).generate()
        sec2 = doc["sections"]["2_development_and_design"]
        boundaries = sec2["action_boundaries"]
        assert boundaries["allowed_actions"], "action boundaries must be non-empty"
        assert boundaries["max_risk_threshold"] > 0.0
        assert boundaries["max_actions_per_minute"] > 0

    def test_section_5_has_risk_classification(self, recruitment_agent_record) -> None:
        doc = AnnexIVGenerator(enrollment_record=recruitment_agent_record).generate()
        sec5 = doc["sections"]["5_risk_management"]
        rc = sec5["risk_classification"]
        assert rc["declared_risk_tier"] == "high"
        # Must mention employment / Annex III category somewhere.
        assert "employment" in rc["eu_ai_act_category"].lower()
        assert len(sec5["risk_factors_evaluated"]) >= 5
        assert len(sec5["risk_mitigation_measures"]) >= 5

    def test_section_8_declaration_has_provider(self, recruitment_agent_record) -> None:
        doc = AnnexIVGenerator(enrollment_record=recruitment_agent_record).generate()
        sec8 = doc["sections"]["8_eu_declaration"]
        assert sec8["provider"] == "hr-ops@example.org"
        assert sec8["system_name"] == "Resume Screening Assistant"
        assert "Annex VI" in sec8["conformity_procedure"]


# ── C3: determinism ──────────────────────────────────────────


class TestDeterminism:
    """Two back-to-back generate() calls must produce content-identical
    output, once the wall-clock timestamps are stripped. Any
    non-determinism in the generator (e.g. iterating an unsorted dict)
    would show up here and break reproducible audit trails."""

    @staticmethod
    def _strip_timestamps(obj):
        """Recursively remove ISO-format timestamps from dict values."""
        if isinstance(obj, dict):
            return {
                k: TestDeterminism._strip_timestamps(v)
                for k, v in obj.items()
                if k not in ("generated_at", "assessed_at", "snapshot_at", "reported_at")
            }
        if isinstance(obj, list):
            return [TestDeterminism._strip_timestamps(v) for v in obj]
        return obj

    def test_two_runs_produce_identical_content(self, recruitment_agent_record) -> None:
        gen = AnnexIVGenerator(enrollment_record=recruitment_agent_record)
        doc_a = self._strip_timestamps(gen.generate())
        doc_b = self._strip_timestamps(gen.generate())
        assert doc_a == doc_b, "generate() produced different content across runs"

    def test_two_generators_same_input_identical(
        self, recruitment_agent_record
    ) -> None:
        """Two separate generator instances over the same record should
        also produce the same content — this catches state leaking into
        the generator between instances."""
        doc_a = self._strip_timestamps(
            AnnexIVGenerator(enrollment_record=recruitment_agent_record).generate()
        )
        doc_b = self._strip_timestamps(
            AnnexIVGenerator(enrollment_record=recruitment_agent_record).generate()
        )
        assert doc_a == doc_b


# ── C4: compliance status roll-up ─────────────────────────────


class TestComplianceRollup:
    def test_properly_declared_agent_not_non_compliant(
        self, recruitment_agent_record
    ) -> None:
        doc = AnnexIVGenerator(enrollment_record=recruitment_agent_record).generate()
        status = doc["compliance_status"]
        # A properly-declared high-risk agent with owner_contact and
        # risk_tier='high' should land on COMPLIANT or PARTIALLY_COMPLIANT —
        # never NON_COMPLIANT.
        assert status["status"] in (
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.PARTIALLY_COMPLIANT,
        ), f"unexpected compliance status for well-declared agent: {status}"
        assert isinstance(status["issues"], list)


# ── C5: section 4 math ───────────────────────────────────────


class _FakeChain:
    """Minimal chain stand-in for section-4 rate calculations."""
    def __init__(self, status: str, integrity: bool = True):
        self.status = status
        self._integrity = integrity
        self.events = [None, None]  # length only
    def verify_integrity(self) -> bool:
        return self._integrity


class _FakeReview:
    def __init__(self, verdict: str):
        self.verdict = verdict


class TestSection4Math:
    def test_completion_rate_with_chains(self, recruitment_agent_record) -> None:
        chains = [
            _FakeChain("COMPLETED"),
            _FakeChain("COMPLETED"),
            _FakeChain("COMPLETED"),
            _FakeChain("DENIED"),
            _FakeChain("TIMED_OUT"),
        ]
        reviews = [_FakeReview("PASS"), _FakeReview("PASS"), _FakeReview("FAIL")]
        gen = AnnexIVGenerator(
            enrollment_record=recruitment_agent_record,
            chains=chains,
            review_results=reviews,
        )
        sec4 = gen.generate()["sections"]["4_performance_metrics"]
        assert sec4["governance_chains"]["total"] == 5
        assert sec4["governance_chains"]["completed"] == 3
        assert sec4["governance_chains"]["denied"] == 2
        assert sec4["governance_chains"]["completion_rate"] == pytest.approx(0.6)
        assert sec4["evidence_reviews"]["total"] == 3
        assert sec4["evidence_reviews"]["pass_rate"] == pytest.approx(2 / 3, abs=0.01)
        assert sec4["integrity"]["chain_integrity_verified"] is True

    def test_empty_chains_safe_denominators(self, recruitment_agent_record) -> None:
        gen = AnnexIVGenerator(
            enrollment_record=recruitment_agent_record,
            chains=[],
            review_results=[],
        )
        sec4 = gen.generate()["sections"]["4_performance_metrics"]
        # Zero-denominator case must not crash — completion_rate = 0.0.
        assert sec4["governance_chains"]["completion_rate"] == 0.0
        assert sec4["evidence_reviews"]["pass_rate"] == 0.0
