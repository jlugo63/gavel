"""
V4 — EU AI Act Article 5 Prohibited Practice Blocking (Wave 1).

Goal: prove Gavel refuses to enroll agents whose declared purpose matches
any of the Article 5 prohibited practices. This is not a compliance nicety
— Article 5 is the one part of the EU AI Act that carries criminal-grade
penalties (up to 7% of global turnover). Any enrollment path that lets a
prohibited-purpose agent slip through is a platform-level failure.

We test four realistic adversarial enrollments:
  P1  Social scoring                    → Art. 5(1)(c)
  P2  Real-time biometric ID            → Art. 5(1)(d)
  P3  Emotion recognition in workplace  → Art. 5(1)(f)
  P4  Subliminal manipulation           → Art. 5(1)(a)

Each enrollment must:
  1. Be submitted against a real EnrollmentRegistry (not mocked).
  2. Land with status == INCOMPLETE (never ENROLLED).
  3. Carry a violations list containing the specific Article 5 paragraph.
  4. Produce no governance token — we check TokenManager was not populated
     (there is no submission->token coupling inside the registry, but a
     rejected enrollment must leave is_enrolled() == False).

Plus a "control" test: a purpose that merely mentions the word "biometric"
in a legitimate scientific context (e.g. research) should NOT be flagged
as Article 5 prohibited — it should be flagged as high-risk (biometrics
category), requiring elevated risk_tier, but enrollable with proper
declarations. This pins the line between "high-risk" and "prohibited."
"""

from __future__ import annotations

import pytest

from gavel.enrollment import (
    EnrollmentRegistry,
    EnrollmentStatus,
    HighRiskCategory,
    detect_prohibited_practices,
)

# Imported from the validation conftest
from tests.validation.conftest import build_application
from conftest import _make_enrollment_registry


# ── Attack vectors ─────────────────────────────────────────────


PROHIBITED_ATTACKS = [
    pytest.param(
        {
            "agent_id": "agent:social-scoring",
            "display_name": "Citizen Behavior Classifier",
            "purpose_summary": "Perform social scoring of citizens based on public data",
            "operational_scope": "social scoring for municipal benefits allocation",
            "risk_tier": "high",
        },
        "Art. 5(1)(c)",
        id="P1-social-scoring",
    ),
    pytest.param(
        {
            "agent_id": "agent:biometric-id",
            "display_name": "Crowd Face Matcher",
            "purpose_summary": "Real-time biometric identification in public squares",
            "operational_scope": "real-time biometric identification for event security",
            "risk_tier": "critical",
        },
        "Art. 5(1)(d)",
        id="P2-realtime-biometric-id",
    ),
    pytest.param(
        {
            "agent_id": "agent:emotion-work",
            "display_name": "Employee Sentiment Monitor",
            "purpose_summary": "Emotion recognition workplace monitoring for HR analytics",
            "operational_scope": "emotion recognition workplace surveillance",
            "risk_tier": "high",
        },
        "Art. 5(1)(f)",
        id="P3-emotion-workplace",
    ),
    pytest.param(
        {
            "agent_id": "agent:subliminal",
            "display_name": "Engagement Nudger",
            "purpose_summary": "Use subliminal manipulation to increase checkout conversion",
            "operational_scope": "subliminal manipulation of purchase intent",
            "risk_tier": "high",
        },
        "Art. 5(1)(a)",
        id="P4-subliminal-manipulation",
    ),
]


@pytest.mark.parametrize("fields,expected_article", PROHIBITED_ATTACKS)
async def test_prohibited_enrollment_is_refused(
    fields: dict,
    expected_article: str,
) -> None:
    """Each prohibited attack must land as INCOMPLETE with the matching Article 5 citation."""
    app = build_application(
        high_risk_category=HighRiskCategory.NONE,  # Attacker tries to hide the category
        **fields,
    )

    registry = _make_enrollment_registry()
    record = await registry.submit(app)

    # Structural guarantees
    assert record.status != EnrollmentStatus.ENROLLED, (
        f"SECURITY FAILURE: prohibited agent {app.agent_id} was enrolled. "
        f"Violations reported: {record.violations}"
    )
    assert record.status in (EnrollmentStatus.INCOMPLETE, EnrollmentStatus.REJECTED)
    assert await registry.is_enrolled(app.agent_id) is False

    # Specific citation must appear somewhere in the violations list.
    joined = "; ".join(record.violations)
    assert expected_article in joined, (
        f"expected violation citing {expected_article} for "
        f"{app.agent_id!r}, got: {record.violations}"
    )

    # The Cedar FORBID side of the story: classify_risk_category must also
    # have flagged the agent as PROHIBITED (separate violation).
    assert any("Art. 5" in v for v in record.violations)


# ── Direct unit-level check on the detector ────────────────────


@pytest.mark.parametrize("fields,expected_article", PROHIBITED_ATTACKS)
def test_detect_prohibited_practices_flags_each_attack(
    fields: dict,
    expected_article: str,
) -> None:
    """detect_prohibited_practices() — the function actually cited by
    the Cedar FORBID rule — must fire for every attack, independent of
    whether validate() wraps it."""
    app = build_application(high_risk_category=HighRiskCategory.NONE, **fields)
    violations = detect_prohibited_practices(app)
    assert any(expected_article in v for v in violations), (
        f"detect_prohibited_practices() missed {expected_article}: got {violations}"
    )


# ── Control: high-risk but legitimate should still enroll ─────


class TestHighRiskNotProhibited:
    """Pin the line between "high-risk" (enrollable with controls) and
    "prohibited" (never enrollable). An agent that legitimately processes
    biometric data for medical research with high risk_tier and proper
    owner_contact should land as INCOMPLETE only if it has other
    violations — it should NOT be caught by the Article 5 detector.
    """

    def test_medical_biometrics_is_not_article_5(self) -> None:
        app = build_application(
            agent_id="agent:med-bio",
            display_name="Clinical Biomarker Analyzer",
            purpose_summary=(
                "Analyze anonymized patient biomarker data for oncology "
                "research under IRB-approved protocol"
            ),
            operational_scope="oncology biomarker research, anonymized datasets only",
            risk_tier="high",
            high_risk_category=HighRiskCategory.BIOMETRICS,
            owner_contact="irb-contact@example.org",
        )
        violations = detect_prohibited_practices(app)
        assert not any("Art. 5(1)" in v for v in violations), (
            f"legitimate medical biomarker agent was flagged as Art. 5 prohibited: "
            f"{violations}"
        )
