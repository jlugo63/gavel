"""
Oversight evasion detection — EU AI Act Tier 3.

Detects patterns that suggest an agent (or a human operator) is
circumventing the governance layer rather than operating inside it.
This is a *behavioral* check, not a policy check: the patterns here
describe "the agent is technically within policy, but the shape of
its activity is what you'd see if someone were trying to avoid
scrutiny."

Signals we score:

  E1  Fragmented actions — many small proposals with trivial risk
      that together would have triggered review as a single proposal.
  E2  Timing arbitrage — proposals submitted just outside declared
      oversight windows, or immediately before SLA timeouts.
  E3  Reviewer rotation abuse — same proposer consistently drawing
      reviewers from a narrow set while broader set is available.
  E4  Scope creep — cumulative paths touched over a rolling window
      exceeds the declared allowed_paths scope.
  E5  Heartbeat gap followed by burst — an agent goes quiet, then
      submits a flurry of proposals in a short window.
  E6  Kill-switch circumvention attempts — attempts to re-register
      under a new agent_id after suspension.

Every signal returns an EvasionFinding with severity and enough
detail for the incident reporter to file a report.

This module is deliberately stateful and bounded: it keeps rolling
activity windows per agent and discards old data.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Signal primitives ──────────────────────────────────────────

class EvasionSignal(str, Enum):
    FRAGMENTED_ACTIONS = "fragmented_actions"
    TIMING_ARBITRAGE = "timing_arbitrage"
    REVIEWER_ROTATION_ABUSE = "reviewer_rotation_abuse"
    SCOPE_CREEP = "scope_creep"
    HEARTBEAT_BURST = "heartbeat_burst"
    KILL_SWITCH_EVASION = "kill_switch_evasion"


class EvasionSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvasionFinding(BaseModel):
    """A single evasion pattern detection."""

    agent_id: str
    signal: EvasionSignal
    severity: EvasionSeverity
    detail: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    supporting_chain_ids: list[str] = Field(default_factory=list)


class ActivityRecord(BaseModel):
    """One unit of observed agent activity."""

    agent_id: str
    chain_id: str
    action_type: str
    risk_score: float
    touched_paths: list[str] = Field(default_factory=list)
    reviewer_id: str = ""
    submitted_at: datetime
    oversight_window_active: bool = True


# ── Detector ───────────────────────────────────────────────────

_FRAGMENT_WINDOW = timedelta(minutes=10)
_FRAGMENT_COUNT_THRESHOLD = 5
_FRAGMENT_INDIV_RISK = 0.15
_FRAGMENT_AGGREGATE_RISK = 0.6

_BURST_QUIET_MINUTES = 30
_BURST_COUNT = 5

_REVIEWER_DIVERSITY_MIN = 3


class OversightEvasionDetector:
    """Rolling-window detector for oversight-evasion patterns."""

    def __init__(self, window_minutes: int = 120):
        self._window = timedelta(minutes=window_minutes)
        self._activity: dict[str, deque[ActivityRecord]] = defaultdict(lambda: deque(maxlen=500))
        self._last_seen: dict[str, datetime] = {}
        self._suspended_agents: set[str] = set()
        self._suspended_signatures: dict[tuple, str] = {}  # (owner, display) -> old agent_id
        self._declared_scopes: dict[str, list[str]] = {}

    # ---- configuration ----

    def declare_scope(self, agent_id: str, allowed_paths: list[str]) -> None:
        self._declared_scopes[agent_id] = list(allowed_paths)

    def mark_suspended(self, agent_id: str, owner: str, display_name: str) -> None:
        self._suspended_agents.add(agent_id)
        self._suspended_signatures[(owner, display_name)] = agent_id

    # ---- ingestion ----

    def observe(self, record: ActivityRecord) -> list[EvasionFinding]:
        """Record activity and run all detectors. Returns any new findings."""
        buf = self._activity[record.agent_id]
        now = record.submitted_at
        # Evict old activity
        while buf and (now - buf[0].submitted_at) > self._window:
            buf.popleft()
        buf.append(record)
        self._last_seen[record.agent_id] = now

        findings: list[EvasionFinding] = []
        findings += self._detect_fragmentation(record.agent_id, buf)
        findings += self._detect_timing_arbitrage(record.agent_id, buf)
        findings += self._detect_reviewer_rotation_abuse(record.agent_id, buf)
        findings += self._detect_scope_creep(record.agent_id, buf)
        findings += self._detect_heartbeat_burst(record.agent_id, buf)
        return findings

    def observe_enrollment(self, agent_id: str, owner: str, display_name: str) -> list[EvasionFinding]:
        """Called by the enrollment gate to detect kill-switch circumvention."""
        key = (owner, display_name)
        prior = self._suspended_signatures.get(key)
        if prior and prior != agent_id and prior in self._suspended_agents:
            return [
                EvasionFinding(
                    agent_id=agent_id,
                    signal=EvasionSignal.KILL_SWITCH_EVASION,
                    severity=EvasionSeverity.HIGH,
                    detail=(
                        f"New enrollment matches owner/display of suspended agent "
                        f"{prior!r} — likely kill-switch evasion attempt"
                    ),
                )
            ]
        return []

    # ---- individual detectors ----

    def _detect_fragmentation(self, agent_id: str, buf: deque[ActivityRecord]) -> list[EvasionFinding]:
        recent = [
            r for r in buf
            if (buf[-1].submitted_at - r.submitted_at) <= _FRAGMENT_WINDOW
        ]
        low_risk = [r for r in recent if r.risk_score < _FRAGMENT_INDIV_RISK]
        if len(low_risk) < _FRAGMENT_COUNT_THRESHOLD:
            return []
        aggregate_risk = sum(r.risk_score for r in low_risk)
        if aggregate_risk < _FRAGMENT_AGGREGATE_RISK:
            return []
        return [
            EvasionFinding(
                agent_id=agent_id,
                signal=EvasionSignal.FRAGMENTED_ACTIONS,
                severity=EvasionSeverity.MEDIUM,
                detail=(
                    f"{len(low_risk)} low-risk proposals in {_FRAGMENT_WINDOW.seconds // 60}min "
                    f"summing to risk {aggregate_risk:.2f} — possible fragmentation"
                ),
                supporting_chain_ids=[r.chain_id for r in low_risk],
            )
        ]

    def _detect_timing_arbitrage(self, agent_id: str, buf: deque[ActivityRecord]) -> list[EvasionFinding]:
        out_of_window = [r for r in buf if not r.oversight_window_active]
        if len(out_of_window) < 3:
            return []
        # Require that out-of-window submissions dominate recent activity.
        if len(out_of_window) / max(1, len(buf)) < 0.6:
            return []
        return [
            EvasionFinding(
                agent_id=agent_id,
                signal=EvasionSignal.TIMING_ARBITRAGE,
                severity=EvasionSeverity.MEDIUM,
                detail=(
                    f"{len(out_of_window)}/{len(buf)} recent proposals submitted outside "
                    f"declared oversight window"
                ),
                supporting_chain_ids=[r.chain_id for r in out_of_window],
            )
        ]

    def _detect_reviewer_rotation_abuse(self, agent_id: str, buf: deque[ActivityRecord]) -> list[EvasionFinding]:
        reviewers = {r.reviewer_id for r in buf if r.reviewer_id}
        if len(buf) < 10:
            return []
        if len(reviewers) >= _REVIEWER_DIVERSITY_MIN:
            return []
        return [
            EvasionFinding(
                agent_id=agent_id,
                signal=EvasionSignal.REVIEWER_ROTATION_ABUSE,
                severity=EvasionSeverity.MEDIUM,
                detail=(
                    f"{len(buf)} proposals reviewed by only {len(reviewers)} distinct reviewers "
                    f"({sorted(reviewers)}) — possible reviewer capture"
                ),
            )
        ]

    def _detect_scope_creep(self, agent_id: str, buf: deque[ActivityRecord]) -> list[EvasionFinding]:
        declared = self._declared_scopes.get(agent_id)
        if not declared:
            return []
        touched: set[str] = set()
        for r in buf:
            touched.update(r.touched_paths)
        out_of_scope = sorted(
            p for p in touched
            if not any(p.startswith(d) for d in declared)
        )
        if not out_of_scope:
            return []
        return [
            EvasionFinding(
                agent_id=agent_id,
                signal=EvasionSignal.SCOPE_CREEP,
                severity=EvasionSeverity.HIGH,
                detail=(
                    f"Touched {len(out_of_scope)} paths outside declared scope: "
                    f"{out_of_scope[:5]}"
                ),
            )
        ]

    def _detect_heartbeat_burst(self, agent_id: str, buf: deque[ActivityRecord]) -> list[EvasionFinding]:
        if len(buf) < _BURST_COUNT + 1:
            return []
        latest = buf[-1]
        # Find the previous activity and measure the gap.
        prev = buf[-_BURST_COUNT - 1]
        gap = latest.submitted_at - prev.submitted_at
        if gap > timedelta(minutes=_BURST_QUIET_MINUTES):
            return []  # Not a burst — long gap between everything
        # But we want: quiet before, then burst
        if len(buf) < _BURST_COUNT + 2:
            return []
        pre_burst = buf[-_BURST_COUNT - 2]
        pre_gap = prev.submitted_at - pre_burst.submitted_at
        if pre_gap < timedelta(minutes=_BURST_QUIET_MINUTES):
            return []
        return [
            EvasionFinding(
                agent_id=agent_id,
                signal=EvasionSignal.HEARTBEAT_BURST,
                severity=EvasionSeverity.LOW,
                detail=(
                    f"{_BURST_COUNT} proposals in {int(gap.total_seconds() / 60)}min "
                    f"after {int(pre_gap.total_seconds() / 60)}min quiet period"
                ),
            )
        ]
