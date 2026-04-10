"""
Behavioral Baseline + Drift Detection — ATF B-3 + EU AI Act Tier 3.

Every enrolled agent accumulates a rolling behavioral baseline from its
governance chain history: which tools it uses, how often, at what risk
levels, on which paths, and with what success rate. The baseline is
deterministic, append-driven, and tamper-evident by reference (hashed
into each chain event).

Two things ride on top of the baseline:

1. ATF B-3 Behavioral Baseline — a per-agent rolling statistical
   profile ("what does normal look like for this agent?").

2. EU AI Act Tier 3 Behavioral Drift Detection — a comparison between
   a snapshot of the baseline taken at enrollment and the current
   rolling profile. Significant drift raises an incident-worthy signal.

Design constraints:
- No LLM in the loop. All drift scoring is deterministic arithmetic.
- Bounded memory: rolling window of N observations per agent.
- Copy-free reads: snapshots are immutable Pydantic models.
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


# ── Observation ────────────────────────────────────────────────

class BehavioralObservation(BaseModel):
    """A single observed governance chain outcome for one agent."""

    agent_id: str
    chain_id: str
    action_type: str = "UNKNOWN"
    tool: str = ""
    risk_score: float = 0.0
    touched_paths: list[str] = Field(default_factory=list)
    network: bool = False
    outcome: str = "UNKNOWN"  # APPROVED, DENIED, ESCALATED, TIMED_OUT, COMPLETED
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Baseline Snapshot ──────────────────────────────────────────

class BehavioralBaseline(BaseModel):
    """A rolling statistical profile of one agent's behavior."""

    agent_id: str
    sample_size: int = 0
    tool_frequencies: dict[str, float] = Field(default_factory=dict)
    action_frequencies: dict[str, float] = Field(default_factory=dict)
    mean_risk: float = 0.0
    max_risk: float = 0.0
    network_rate: float = 0.0
    approval_rate: float = 0.0
    denial_rate: float = 0.0
    escalation_rate: float = 0.0
    top_paths: list[str] = Field(default_factory=list)
    snapshot_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def is_empty(self) -> bool:
        return self.sample_size == 0


# ── Drift Report ───────────────────────────────────────────────

class DriftReport(BaseModel):
    """Comparison between an enrollment baseline and a current baseline."""

    agent_id: str
    enrollment_sample_size: int
    current_sample_size: int
    risk_delta: float = 0.0               # current.mean_risk - enrollment.mean_risk
    network_delta: float = 0.0            # current.network_rate - enrollment.network_rate
    denial_delta: float = 0.0
    escalation_delta: float = 0.0
    new_tools: list[str] = Field(default_factory=list)        # tools never seen at enrollment
    tool_distribution_shift: float = 0.0  # L1 distance between tool freq vectors (0..2)
    drift_score: float = 0.0              # Aggregate 0..1 score
    is_significant: bool = False
    reasons: list[str] = Field(default_factory=list)
    reported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Registry ───────────────────────────────────────────────────

_DEFAULT_WINDOW = 200
_DRIFT_THRESHOLD = 0.20


class BehavioralBaselineRegistry:
    """Accumulates observations and produces per-agent baselines + drift.

    Memory is bounded: each agent keeps at most `window` recent
    observations. An enrollment snapshot is frozen the first time an
    agent crosses the minimum-sample threshold, so subsequent drift
    comparisons always reference a stable anchor.
    """

    def __init__(self, window: int = _DEFAULT_WINDOW, min_samples_for_snapshot: int = 10):
        self._window = window
        self._min_snapshot = min_samples_for_snapshot
        self._observations: dict[str, deque[BehavioralObservation]] = {}
        self._enrollment_snapshots: dict[str, BehavioralBaseline] = {}

    # ---- writes ----

    def observe(self, obs: BehavioralObservation) -> BehavioralBaseline:
        """Record one observation and return the current baseline."""
        buf = self._observations.setdefault(obs.agent_id, deque(maxlen=self._window))
        buf.append(obs)

        baseline = self._compute_baseline(obs.agent_id)

        # Freeze enrollment snapshot once the agent reaches the minimum
        # sample size. This is the drift-detection anchor.
        if (
            obs.agent_id not in self._enrollment_snapshots
            and baseline.sample_size >= self._min_snapshot
        ):
            self._enrollment_snapshots[obs.agent_id] = baseline.model_copy(deep=True)

        return baseline

    # ---- reads ----

    def current_baseline(self, agent_id: str) -> BehavioralBaseline:
        return self._compute_baseline(agent_id)

    def enrollment_snapshot(self, agent_id: str) -> Optional[BehavioralBaseline]:
        return self._enrollment_snapshots.get(agent_id)

    def drift(self, agent_id: str) -> Optional[DriftReport]:
        """Compare current behavior against the frozen enrollment snapshot."""
        enrollment = self._enrollment_snapshots.get(agent_id)
        if enrollment is None:
            return None

        current = self._compute_baseline(agent_id)
        return _score_drift(enrollment, current)

    def reset_snapshot(self, agent_id: str) -> None:
        """Drop the enrollment snapshot so the next observation re-freezes it."""
        self._enrollment_snapshots.pop(agent_id, None)

    # ---- internal ----

    def _compute_baseline(self, agent_id: str) -> BehavioralBaseline:
        buf = self._observations.get(agent_id)
        if not buf:
            return BehavioralBaseline(agent_id=agent_id)

        n = len(buf)
        tool_counts: Counter[str] = Counter()
        action_counts: Counter[str] = Counter()
        path_counts: Counter[str] = Counter()
        risks: list[float] = []
        net_count = 0
        approved = denied = escalated = 0

        for o in buf:
            if o.tool:
                tool_counts[o.tool] += 1
            action_counts[o.action_type] += 1
            for p in o.touched_paths:
                path_counts[p] += 1
            risks.append(o.risk_score)
            if o.network:
                net_count += 1
            if o.outcome == "APPROVED" or o.outcome == "COMPLETED":
                approved += 1
            elif o.outcome == "DENIED" or o.outcome == "TIMED_OUT":
                denied += 1
            elif o.outcome == "ESCALATED":
                escalated += 1

        return BehavioralBaseline(
            agent_id=agent_id,
            sample_size=n,
            tool_frequencies={k: round(v / n, 4) for k, v in tool_counts.items()},
            action_frequencies={k: round(v / n, 4) for k, v in action_counts.items()},
            mean_risk=round(sum(risks) / n, 4),
            max_risk=round(max(risks), 4),
            network_rate=round(net_count / n, 4),
            approval_rate=round(approved / n, 4),
            denial_rate=round(denied / n, 4),
            escalation_rate=round(escalated / n, 4),
            top_paths=[p for p, _ in path_counts.most_common(5)],
        )


# ── Drift scoring ──────────────────────────────────────────────

def _score_drift(enrollment: BehavioralBaseline, current: BehavioralBaseline) -> DriftReport:
    """Deterministic drift scoring.

    The aggregate drift_score is a weighted sum of four signals,
    clipped to [0, 1]:

      - 0.35 * |risk_delta|   (risk inflation)
      - 0.25 * |network_delta|
      - 0.20 * tool_distribution_shift / 2
      - 0.10 * |denial_delta|
      - 0.10 * |escalation_delta|

    A drift_score above _DRIFT_THRESHOLD is flagged as significant.
    """
    reasons: list[str] = []

    risk_delta = round(current.mean_risk - enrollment.mean_risk, 4)
    network_delta = round(current.network_rate - enrollment.network_rate, 4)
    denial_delta = round(current.denial_rate - enrollment.denial_rate, 4)
    escalation_delta = round(current.escalation_rate - enrollment.escalation_rate, 4)

    # L1 distance between tool-frequency distributions, on the union
    # of keys. This is bounded at 2.0.
    keys = set(enrollment.tool_frequencies) | set(current.tool_frequencies)
    tool_shift = sum(
        abs(enrollment.tool_frequencies.get(k, 0.0) - current.tool_frequencies.get(k, 0.0))
        for k in keys
    )
    tool_shift = round(tool_shift, 4)

    new_tools = sorted(set(current.tool_frequencies) - set(enrollment.tool_frequencies))

    # Weighted aggregate
    score = (
        0.35 * abs(risk_delta)
        + 0.25 * abs(network_delta)
        + 0.20 * (tool_shift / 2.0)
        + 0.10 * abs(denial_delta)
        + 0.10 * abs(escalation_delta)
    )
    score = round(min(1.0, max(0.0, score)), 4)

    if abs(risk_delta) > 0.15:
        reasons.append(f"risk_delta={risk_delta:+.3f}")
    if abs(network_delta) > 0.10:
        reasons.append(f"network_delta={network_delta:+.3f}")
    if tool_shift > 0.30:
        reasons.append(f"tool_distribution_shift={tool_shift:.3f}")
    if new_tools:
        reasons.append(f"new_tools={new_tools}")
    if abs(denial_delta) > 0.10:
        reasons.append(f"denial_delta={denial_delta:+.3f}")
    if abs(escalation_delta) > 0.10:
        reasons.append(f"escalation_delta={escalation_delta:+.3f}")

    return DriftReport(
        agent_id=current.agent_id,
        enrollment_sample_size=enrollment.sample_size,
        current_sample_size=current.sample_size,
        risk_delta=risk_delta,
        network_delta=network_delta,
        denial_delta=denial_delta,
        escalation_delta=escalation_delta,
        new_tools=new_tools,
        tool_distribution_shift=tool_shift,
        drift_score=score,
        is_significant=score >= _DRIFT_THRESHOLD,
        reasons=reasons,
    )
