"""
Data Governance Policy Enforcement — EU AI Act Article 10.

Article 10 requires providers of high-risk AI systems to implement
data governance practices covering:

  10(2)(a)  Relevant design choices
  10(2)(b)  Data collection processes and origin
  10(2)(c)  Relevant data-preparation operations (annotation, labelling,
            cleaning, updating, enrichment, aggregation)
  10(2)(d)  Formulation of assumptions about what the data should measure
            and represent
  10(2)(e)  Assessment of the availability, quantity, and suitability of
            the data sets needed
  10(2)(f)  Examination in view of possible biases likely to affect health,
            safety, or fundamental rights, or lead to prohibited discrimination
  10(2)(g)  Appropriate measures to detect, prevent, and mitigate possible
            biases identified according to point (f)
  10(2)(h)  Identification of relevant data gaps or shortcomings and how
            those gaps can be addressed

Article 10(3) additionally requires datasets to be relevant, sufficiently
representative, free of errors, and complete in view of the intended
purpose.

Gavel does not hold training datasets itself, but it enforces the
governance policy surrounding them at enrollment time. A deployer must
attach a DataGovernancePolicy describing each Article 10 element before
a high-risk agent can be enrolled. The module provides:

  - DataGovernancePolicy: Pydantic schema for Art. 10(2)(a)–(h) + 10(3)
  - BiasCheck: lightweight detector of declared protected-class
    attributes and distributional summaries
  - validate_policy(): returns DataGovernanceReport with missing and
    shallow sections
  - DataGovernanceRegistry: per-agent attachment + gate function

The bias detector is deliberately conservative: it checks that the
deployer has enumerated the protected classes their data touches and
declared a mitigation plan for each. It does not try to compute bias
metrics on datasets it cannot see.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class DatasetRole(str, Enum):
    TRAINING = "training"
    VALIDATION = "validation"
    TEST = "test"
    REFERENCE = "reference"


class DatasetDescriptor(BaseModel):
    """Art. 10(2)(b): data origin + Art. 10(3) suitability evidence."""

    name: str
    role: DatasetRole
    origin: str                      # Provenance / sourcing
    collection_process: str = ""     # How it was collected
    size_rows: int = 0
    size_bytes: int = 0
    collection_period: str = ""
    license_terms: str = ""
    representativeness_note: str = ""  # Why this dataset is representative
    known_gaps: list[str] = Field(default_factory=list)  # Art. 10(2)(h)


class BiasMitigation(BaseModel):
    """Art. 10(2)(g): measures declared for a specific protected class."""

    protected_attribute: str         # e.g. "gender", "age", "ethnicity"
    detection_method: str            # e.g. "disparate impact ratio", "demographic parity"
    mitigation_action: str           # e.g. "reweighting at training time"
    monitoring_cadence: str = ""     # e.g. "quarterly review"


class DataGovernancePolicy(BaseModel):
    """Provider-declared policy per EU AI Act Article 10."""

    policy_id: str = Field(default_factory=lambda: f"dg-{datetime.now(timezone.utc).timestamp():.0f}")
    agent_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Art. 10(2)(a)
    design_choices: str = ""

    # Art. 10(2)(b)+(c) — dataset-level metadata
    datasets: list[DatasetDescriptor] = Field(default_factory=list)
    preparation_operations: list[str] = Field(default_factory=list)

    # Art. 10(2)(d)
    measurement_assumptions: str = ""

    # Art. 10(2)(e)
    availability_assessment: str = ""

    # Art. 10(2)(f)+(g)
    protected_attributes: list[str] = Field(default_factory=list)
    bias_examination: str = ""
    bias_mitigations: list[BiasMitigation] = Field(default_factory=list)

    # Art. 10(2)(h)
    data_gap_analysis: str = ""

    # Art. 10(3) — dataset qualities
    relevance_claim: str = ""
    representativeness_claim: str = ""
    error_rate_bound: Optional[float] = None
    completeness_claim: str = ""


class DataGovernanceReport(BaseModel):
    """Validation report for a DataGovernancePolicy."""

    passed: bool
    missing_sections: list[str] = Field(default_factory=list)
    shallow_sections: list[str] = Field(default_factory=list)
    bias_gaps: list[str] = Field(default_factory=list)
    article_references: list[str] = Field(default_factory=list)


_MIN_PROSE = 40


def _shallow(text: str) -> bool:
    return len(text.strip()) < _MIN_PROSE


def validate_policy(policy: DataGovernancePolicy) -> DataGovernanceReport:
    """Deterministically check Art. 10(2)(a)–(h) coverage."""
    missing: list[str] = []
    shallow: list[str] = []
    bias_gaps: list[str] = []

    # (a)
    if not policy.design_choices.strip():
        missing.append("Art. 10(2)(a): design choices")
    elif _shallow(policy.design_choices):
        shallow.append("Art. 10(2)(a): design choices too shallow")

    # (b)+(c)
    if not policy.datasets:
        missing.append("Art. 10(2)(b): at least one dataset descriptor required")
    else:
        for ds in policy.datasets:
            if not ds.origin.strip():
                missing.append(f"Art. 10(2)(b): dataset '{ds.name}' has no origin")
            if not ds.collection_process.strip():
                shallow.append(f"Art. 10(2)(b): dataset '{ds.name}' missing collection process")
    if not policy.preparation_operations:
        missing.append("Art. 10(2)(c): preparation operations (cleaning, labelling, etc.)")

    # (d)
    if not policy.measurement_assumptions.strip():
        missing.append("Art. 10(2)(d): measurement assumptions")
    elif _shallow(policy.measurement_assumptions):
        shallow.append("Art. 10(2)(d): measurement assumptions too shallow")

    # (e)
    if not policy.availability_assessment.strip():
        missing.append("Art. 10(2)(e): availability/suitability assessment")
    elif _shallow(policy.availability_assessment):
        shallow.append("Art. 10(2)(e): availability assessment too shallow")

    # (f)+(g) — bias
    if not policy.protected_attributes:
        missing.append("Art. 10(2)(f): protected attributes not enumerated")
    if not policy.bias_examination.strip():
        missing.append("Art. 10(2)(f): bias examination narrative")
    elif _shallow(policy.bias_examination):
        shallow.append("Art. 10(2)(f): bias examination too shallow")
    # Every protected attribute must have a mitigation
    mitigated_attrs = {m.protected_attribute for m in policy.bias_mitigations}
    for attr in policy.protected_attributes:
        if attr not in mitigated_attrs:
            bias_gaps.append(f"Art. 10(2)(g): no mitigation declared for protected attribute '{attr}'")

    # (h)
    if not policy.data_gap_analysis.strip():
        missing.append("Art. 10(2)(h): data gap analysis")

    # 10(3)
    if not policy.relevance_claim.strip():
        missing.append("Art. 10(3): relevance claim")
    if not policy.representativeness_claim.strip():
        missing.append("Art. 10(3): representativeness claim")
    if policy.error_rate_bound is None:
        missing.append("Art. 10(3): error rate bound")
    elif policy.error_rate_bound < 0 or policy.error_rate_bound > 1:
        shallow.append("Art. 10(3): error_rate_bound must be in [0, 1]")
    if not policy.completeness_claim.strip():
        missing.append("Art. 10(3): completeness claim")

    refs = [
        "Art. 10(2)(a)", "Art. 10(2)(b)", "Art. 10(2)(c)", "Art. 10(2)(d)",
        "Art. 10(2)(e)", "Art. 10(2)(f)", "Art. 10(2)(g)", "Art. 10(2)(h)",
        "Art. 10(3)",
    ]
    passed = not missing and not shallow and not bias_gaps

    return DataGovernanceReport(
        passed=passed,
        missing_sections=missing,
        shallow_sections=shallow,
        bias_gaps=bias_gaps,
        article_references=refs,
    )


class DataGovernanceRegistry:
    """Per-agent attachment point for DataGovernancePolicy."""

    def __init__(self):
        self._policies: dict[str, DataGovernancePolicy] = {}
        self._reports: dict[str, DataGovernanceReport] = {}

    def attach(self, policy: DataGovernancePolicy) -> DataGovernanceReport:
        report = validate_policy(policy)
        self._policies[policy.agent_id] = policy
        self._reports[policy.agent_id] = report
        return report

    def get(self, agent_id: str) -> Optional[DataGovernancePolicy]:
        return self._policies.get(agent_id)

    def report(self, agent_id: str) -> Optional[DataGovernanceReport]:
        return self._reports.get(agent_id)

    def is_compliant(self, agent_id: str) -> bool:
        r = self._reports.get(agent_id)
        return r is not None and r.passed
