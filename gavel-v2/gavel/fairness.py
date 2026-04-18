"""
Runtime fairness metrics — NIST AI RMF MAP 2.3 + EU AI Act Art. 10.

Tracks per-agent decision outcomes across protected attributes and
detects fairness drift over time.  Every enrolled agent accumulates a
rolling window of decision outcomes annotated with protected-attribute
group values.  The monitor computes demographic parity, equalized odds,
and disparate impact metrics — then compares against a frozen enrollment
baseline to detect fairness drift.

Design constraints:
- No LLM, no ML.  All metrics are deterministic arithmetic.
- Bounded memory: rolling window of N outcomes per agent.
- Self-contained: stdlib + pydantic only.
- Copy-free reads: snapshots are immutable Pydantic models.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from gavel.types import Severity

logger = logging.getLogger(__name__)


# ── Protected attributes ─────────────────────────────────────

class ProtectedAttribute(str, Enum):
    """Protected attributes aligned with EU AI Act Art. 10 + NIST AI RMF MAP 2.3."""

    RACE = "race"
    GENDER = "gender"
    AGE = "age"
    DISABILITY = "disability"
    NATIONALITY = "nationality"
    RELIGION = "religion"
    SEXUAL_ORIENTATION = "sexual_orientation"
    SOCIOECONOMIC_STATUS = "socioeconomic_status"


# ── Decision outcome ─────────────────────────────────────────

class DecisionOutcome(BaseModel):
    """A single observed decision outcome annotated with protected attributes."""

    agent_id: str
    chain_id: str = ""
    decision: str = "APPROVED"  # APPROVED, DENIED, ESCALATED
    protected_attributes: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH


# ── Computed metrics ──────────────────────────────────────────

class FairnessMetric(BaseModel):
    """Computed fairness metrics for one agent on one attribute."""

    agent_id: str
    attribute: str
    sample_size: int = 0
    group_counts: dict[str, int] = Field(default_factory=dict)
    group_approval_rates: dict[str, float] = Field(default_factory=dict)
    demographic_parity_ratio: Optional[float] = None
    min_parity_pair: tuple[str, str] = ("", "")
    equalized_odds_delta: float = 0.0
    disparate_impact_score: float = 0.0
    four_fifths_violated: bool = False
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def is_empty(self) -> bool:
        return self.sample_size == 0


# ── Baseline snapshot ─────────────────────────────────────────

class FairnessBaseline(BaseModel):
    """Frozen fairness snapshot at enrollment time."""

    agent_id: str
    metrics: dict[str, FairnessMetric] = Field(default_factory=dict)
    sample_size: int = 0
    snapshot_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def is_empty(self) -> bool:
        return self.sample_size == 0


# ── Drift report ──────────────────────────────────────────────

class FairnessDriftReport(BaseModel):
    """Comparison between enrollment fairness baseline and current metrics."""

    agent_id: str
    enrollment_sample_size: int = 0
    current_sample_size: int = 0
    parity_deltas: dict[str, float] = Field(default_factory=dict)
    disparate_impact_deltas: dict[str, float] = Field(default_factory=dict)
    drift_score: float = 0.0
    is_significant: bool = False
    reasons: list[str] = Field(default_factory=list)
    reported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Violation ─────────────────────────────────────────────────

# Use shared Severity; keep backward-compatible alias
FairnessViolationSeverity = Severity


class FairnessViolation(BaseModel):
    """A specific fairness threshold breach."""

    agent_id: str
    attribute: str
    metric_name: str
    value: float
    threshold: float
    severity: FairnessViolationSeverity
    detail: str = ""
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Summary ───────────────────────────────────────────────────

class FairnessSummary(BaseModel):
    """Overall fairness posture for one agent."""

    agent_id: str
    total_outcomes: int = 0
    attributes_tracked: list[str] = Field(default_factory=list)
    worst_parity_ratio: Optional[float] = None
    worst_attribute: str = ""
    violation_count: int = 0
    overall_disparate_impact: float = 0.0
    posture: str = "UNKNOWN"  # FAIR, AT_RISK, VIOLATION
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Constants ─────────────────────────────────────────────────

_DEFAULT_WINDOW = 1000
_FOUR_FIFTHS_LOW = 0.8
_FOUR_FIFTHS_HIGH = 1.25
_DRIFT_THRESHOLD = 0.15
_MIN_SAMPLES_FOR_SNAPSHOT = 20


# ── Monitor ───────────────────────────────────────────────────

class FairnessMonitor:
    """Rolling-window fairness monitor for per-agent decision outcomes.

    Memory is bounded: each agent keeps at most ``window`` recent
    outcomes.  An enrollment snapshot is frozen the first time an
    agent crosses the minimum-sample threshold, serving as the
    drift-detection anchor.
    """

    def __init__(
        self,
        window: int = _DEFAULT_WINDOW,
        min_samples_for_snapshot: int = _MIN_SAMPLES_FOR_SNAPSHOT,
    ):
        self._window = window
        self._min_snapshot = min_samples_for_snapshot
        self._outcomes: dict[str, deque[DecisionOutcome]] = {}
        self._enrollment_baselines: dict[str, FairnessBaseline] = {}

    # ---- writes ----

    def record_outcome(self, outcome: DecisionOutcome) -> None:
        """Append one outcome to the rolling window for its agent."""
        buf = self._outcomes.setdefault(
            outcome.agent_id, deque(maxlen=self._window)
        )
        buf.append(outcome)

        # Freeze enrollment baseline once agent reaches minimum sample size.
        if (
            outcome.agent_id not in self._enrollment_baselines
            and len(buf) >= self._min_snapshot
        ):
            metrics = self._compute_all_metrics_from_buf(outcome.agent_id, buf)
            self._enrollment_baselines[outcome.agent_id] = FairnessBaseline(
                agent_id=outcome.agent_id,
                metrics={m.attribute: m.model_copy(deep=True) for m in metrics},
                sample_size=len(buf),
            )
            logger.info(
                "Froze fairness baseline for %s at %d samples",
                outcome.agent_id,
                len(buf),
            )

    # ---- reads ----

    def compute_metrics(self, agent_id: str, attribute: str) -> FairnessMetric:
        """Compute current fairness metrics for one agent on one attribute."""
        buf = self._outcomes.get(agent_id)
        if not buf:
            return FairnessMetric(agent_id=agent_id, attribute=attribute)
        return self._compute_metric(agent_id, attribute, buf)

    def compute_all_metrics(self, agent_id: str) -> list[FairnessMetric]:
        """Compute fairness metrics across all observed attributes."""
        buf = self._outcomes.get(agent_id)
        if not buf:
            return []
        return self._compute_all_metrics_from_buf(agent_id, buf)

    def detect_drift(self, agent_id: str) -> Optional[FairnessDriftReport]:
        """Compare current fairness metrics against the enrollment baseline."""
        baseline = self._enrollment_baselines.get(agent_id)
        if baseline is None:
            return None
        buf = self._outcomes.get(agent_id)
        if not buf:
            return None
        current_metrics = self._compute_all_metrics_from_buf(agent_id, buf)
        return _score_fairness_drift(baseline, current_metrics, len(buf))

    def get_summary(self, agent_id: str) -> FairnessSummary:
        """Overall fairness posture for one agent."""
        buf = self._outcomes.get(agent_id)
        if not buf:
            return FairnessSummary(agent_id=agent_id)

        metrics = self._compute_all_metrics_from_buf(agent_id, buf)
        violations = self._find_violations_from_metrics(agent_id, metrics)

        worst_ratio: Optional[float] = None
        worst_attr = ""
        total_di = 0.0

        for m in metrics:
            if m.demographic_parity_ratio is not None:
                if worst_ratio is None or m.demographic_parity_ratio < worst_ratio:
                    worst_ratio = m.demographic_parity_ratio
                    worst_attr = m.attribute
            total_di += m.disparate_impact_score

        overall_di = round(total_di / max(1, len(metrics)), 4) if metrics else 0.0

        if violations:
            posture = "VIOLATION"
        elif worst_ratio is not None and worst_ratio < 0.9:
            posture = "AT_RISK"
        else:
            posture = "FAIR"

        return FairnessSummary(
            agent_id=agent_id,
            total_outcomes=len(buf),
            attributes_tracked=[m.attribute for m in metrics],
            worst_parity_ratio=worst_ratio,
            worst_attribute=worst_attr,
            violation_count=len(violations),
            overall_disparate_impact=overall_di,
            posture=posture,
        )

    def flag_violations(self) -> list[FairnessViolation]:
        """Return all current fairness violations across all tracked agents."""
        violations: list[FairnessViolation] = []
        for agent_id in self._outcomes:
            buf = self._outcomes[agent_id]
            if not buf:
                continue
            metrics = self._compute_all_metrics_from_buf(agent_id, buf)
            violations.extend(self._find_violations_from_metrics(agent_id, metrics))
        return violations

    def enrollment_baseline(self, agent_id: str) -> Optional[FairnessBaseline]:
        """Return the frozen enrollment baseline, if available."""
        return self._enrollment_baselines.get(agent_id)

    def reset_baseline(self, agent_id: str) -> None:
        """Drop the enrollment baseline so the next observation re-freezes it."""
        self._enrollment_baselines.pop(agent_id, None)

    # ---- internal ----

    def _compute_all_metrics_from_buf(
        self, agent_id: str, buf: deque[DecisionOutcome]
    ) -> list[FairnessMetric]:
        """Compute metrics for every attribute observed in the buffer."""
        attributes: set[str] = set()
        for o in buf:
            attributes.update(o.protected_attributes.keys())
        return [self._compute_metric(agent_id, attr, buf) for attr in sorted(attributes)]

    def _compute_metric(
        self, agent_id: str, attribute: str, buf: deque[DecisionOutcome]
    ) -> FairnessMetric:
        """Compute fairness metrics for a single attribute."""
        # Partition outcomes by group value for this attribute.
        group_total: dict[str, int] = defaultdict(int)
        group_approved: dict[str, int] = defaultdict(int)
        # For equalized odds: approval rate per group per risk level.
        group_risk_approved: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        group_risk_total: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        relevant = 0
        for o in buf:
            group = o.protected_attributes.get(attribute)
            if group is None:
                continue
            relevant += 1
            group_total[group] += 1
            if o.decision == "APPROVED":
                group_approved[group] += 1
            group_risk_total[group][o.risk_level] += 1
            if o.decision == "APPROVED":
                group_risk_approved[group][o.risk_level] += 1

        if not group_total:
            return FairnessMetric(agent_id=agent_id, attribute=attribute)

        # Approval rates per group.
        approval_rates: dict[str, float] = {}
        for g, total in group_total.items():
            approval_rates[g] = round(group_approved.get(g, 0) / total, 4) if total else 0.0

        # Demographic parity ratio: min(rate_A/rate_B) across all group pairs.
        parity_ratio: Optional[float] = None
        min_pair = ("", "")
        groups = sorted(group_total.keys())
        if len(groups) >= 2:
            parity_ratio = 1.0
            for i in range(len(groups)):
                for j in range(i + 1, len(groups)):
                    r_a = approval_rates[groups[i]]
                    r_b = approval_rates[groups[j]]
                    if r_a == 0.0 and r_b == 0.0:
                        ratio = 1.0
                    elif r_b == 0.0:
                        ratio = 0.0  # infinite disparity
                    elif r_a == 0.0:
                        ratio = 0.0
                    else:
                        ratio = min(r_a / r_b, r_b / r_a)
                    if ratio < parity_ratio:
                        parity_ratio = ratio
                        min_pair = (groups[i], groups[j])
            parity_ratio = round(parity_ratio, 4)

        # Four-fifths rule check.
        four_fifths_violated = False
        if parity_ratio is not None and parity_ratio < _FOUR_FIFTHS_LOW:
            four_fifths_violated = True

        # Equalized odds: max difference in approval rate across groups
        # conditioned on each risk level.
        eq_odds_delta = 0.0
        risk_levels = set()
        for g in groups:
            risk_levels.update(group_risk_total[g].keys())
        for rl in risk_levels:
            rates_at_rl: list[float] = []
            for g in groups:
                t = group_risk_total[g].get(rl, 0)
                a = group_risk_approved[g].get(rl, 0)
                if t > 0:
                    rates_at_rl.append(a / t)
            if len(rates_at_rl) >= 2:
                delta = max(rates_at_rl) - min(rates_at_rl)
                if delta > eq_odds_delta:
                    eq_odds_delta = delta
        eq_odds_delta = round(eq_odds_delta, 4)

        # Disparate impact score: 0.0 = perfect parity, 1.0 = maximum disparity.
        # We define it as 1 - min_parity_ratio (bounded [0, 1]).
        if parity_ratio is not None:
            di_score = round(min(1.0, max(0.0, 1.0 - parity_ratio)), 4)
        else:
            di_score = 0.0

        return FairnessMetric(
            agent_id=agent_id,
            attribute=attribute,
            sample_size=relevant,
            group_counts=dict(group_total),
            group_approval_rates=approval_rates,
            demographic_parity_ratio=parity_ratio,
            min_parity_pair=min_pair,
            equalized_odds_delta=eq_odds_delta,
            disparate_impact_score=di_score,
            four_fifths_violated=four_fifths_violated,
        )

    def _find_violations_from_metrics(
        self, agent_id: str, metrics: list[FairnessMetric]
    ) -> list[FairnessViolation]:
        """Extract violations from computed metrics."""
        violations: list[FairnessViolation] = []
        for m in metrics:
            if m.four_fifths_violated and m.demographic_parity_ratio is not None:
                severity = (
                    FairnessViolationSeverity.HIGH
                    if m.demographic_parity_ratio < 0.5
                    else FairnessViolationSeverity.MEDIUM
                )
                violations.append(
                    FairnessViolation(
                        agent_id=agent_id,
                        attribute=m.attribute,
                        metric_name="demographic_parity_ratio",
                        value=m.demographic_parity_ratio,
                        threshold=_FOUR_FIFTHS_LOW,
                        severity=severity,
                        detail=(
                            f"Four-fifths rule violated: parity ratio "
                            f"{m.demographic_parity_ratio:.4f} between groups "
                            f"{m.min_parity_pair[0]!r} and {m.min_parity_pair[1]!r}"
                        ),
                    )
                )
            if m.equalized_odds_delta > 0.2:
                violations.append(
                    FairnessViolation(
                        agent_id=agent_id,
                        attribute=m.attribute,
                        metric_name="equalized_odds_delta",
                        value=m.equalized_odds_delta,
                        threshold=0.2,
                        severity=FairnessViolationSeverity.MEDIUM,
                        detail=(
                            f"Equalized odds delta {m.equalized_odds_delta:.4f} "
                            f"exceeds threshold 0.2 for attribute {m.attribute!r}"
                        ),
                    )
                )
        return violations


# ── Drift scoring ─────────────────────────────────────────────

def _score_fairness_drift(
    baseline: FairnessBaseline,
    current_metrics: list[FairnessMetric],
    current_sample_size: int,
) -> FairnessDriftReport:
    """Deterministic fairness drift scoring.

    Compares current parity ratios and disparate impact scores
    against the enrollment baseline.  The aggregate drift_score is
    the mean of absolute deltas across all tracked attributes,
    clipped to [0, 1].
    """
    parity_deltas: dict[str, float] = {}
    di_deltas: dict[str, float] = {}
    reasons: list[str] = []

    for m in current_metrics:
        b = baseline.metrics.get(m.attribute)
        if b is None:
            continue
        # Parity ratio delta.
        if m.demographic_parity_ratio is not None and b.demographic_parity_ratio is not None:
            delta = round(m.demographic_parity_ratio - b.demographic_parity_ratio, 4)
            parity_deltas[m.attribute] = delta
            if abs(delta) > 0.1:
                reasons.append(
                    f"{m.attribute}: parity_ratio shifted {delta:+.4f} "
                    f"({b.demographic_parity_ratio:.4f} -> {m.demographic_parity_ratio:.4f})"
                )
        # Disparate impact delta.
        di_delta = round(m.disparate_impact_score - b.disparate_impact_score, 4)
        di_deltas[m.attribute] = di_delta
        if abs(di_delta) > 0.1:
            reasons.append(
                f"{m.attribute}: disparate_impact shifted {di_delta:+.4f}"
            )

    # Aggregate drift score: mean of absolute parity + DI deltas.
    all_deltas = [abs(v) for v in parity_deltas.values()] + [abs(v) for v in di_deltas.values()]
    if all_deltas:
        score = round(min(1.0, max(0.0, sum(all_deltas) / len(all_deltas))), 4)
    else:
        score = 0.0

    return FairnessDriftReport(
        agent_id=baseline.agent_id,
        enrollment_sample_size=baseline.sample_size,
        current_sample_size=current_sample_size,
        parity_deltas=parity_deltas,
        disparate_impact_deltas=di_deltas,
        drift_score=score,
        is_significant=score >= _DRIFT_THRESHOLD,
        reasons=reasons,
    )
