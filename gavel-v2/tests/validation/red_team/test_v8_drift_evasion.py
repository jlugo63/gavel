"""
V8 — Behavioral Drift + Oversight Evasion Detection (Wave 2).

Goal: prove both the "statistical" drift detector (ATF B-3 / EU AI Act
Tier 3) and the six "pattern" evasion detectors work end-to-end on
realistic synthetic activity trajectories. These are the two lagging
signals Gavel uses to catch agents that are technically within policy
but behaviorally going off-script.

Part A — Drift:
  A1  Risk inflation + network activation produces is_significant=True
      with drift_score >= 0.20, new_tools populated, reasons cited.
  A2  A stable baseline (same normal observations repeated) produces
      near-zero drift — the negative control that pins the false-positive
      rate.

Part B — Evasion signals (one sub-test per signal, fresh detector each):
  E1  FRAGMENTED_ACTIONS       — 5 low-risk proposals summing past 0.6
  E2  TIMING_ARBITRAGE         — >60% of recent window submitted outside
                                  declared oversight hours
  E3  REVIEWER_ROTATION_ABUSE  — 10+ proposals, ≤2 distinct reviewers
  E4  SCOPE_CREEP              — activity touches paths outside declared scope
  E5  HEARTBEAT_BURST          — 30min+ quiet then 5 proposals in 5min
  E6  KILL_SWITCH_EVASION      — re-enrollment matching a suspended agent's
                                  owner + display_name
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from gavel.baseline import (
    BehavioralBaselineRegistry,
    BehavioralObservation,
)
from gavel.evasion import (
    ActivityRecord,
    EvasionSignal,
    OversightEvasionDetector,
)


# ─────────────────────────────────────────────────────────────
# Part A — Behavioral Drift
# ─────────────────────────────────────────────────────────────


class TestBehavioralDrift:
    """The drift detector must catch meaningful shifts in an agent's
    operating profile, and NOT falsely alert on steady-state behavior."""

    def test_risk_inflation_and_network_activation_flagged(self) -> None:
        reg = BehavioralBaselineRegistry(window=200, min_samples_for_snapshot=10)
        agent = "agent:drifter"

        # 15 "normal" observations: low risk, no network, Read-only, all APPROVED.
        # At observation 10 the enrollment snapshot freezes.
        for i in range(15):
            reg.observe(BehavioralObservation(
                agent_id=agent,
                chain_id=f"c-norm-{i}",
                action_type="READ",
                tool="Read",
                risk_score=0.10,
                touched_paths=["/tmp/gavel-validation/inputs.json"],
                network=False,
                outcome="APPROVED",
            ))

        enrollment = reg.enrollment_snapshot(agent)
        assert enrollment is not None, "enrollment snapshot should freeze at sample 10"
        assert enrollment.mean_risk == pytest.approx(0.10, abs=0.02)
        assert enrollment.network_rate == 0.0

        # 30 "drifted" observations: high risk, network active, tools shift
        # toward Bash/HttpFetch. Some denied, some escalated.
        for i in range(30):
            outcome = "DENIED" if i % 4 == 0 else "APPROVED"
            reg.observe(BehavioralObservation(
                agent_id=agent,
                chain_id=f"c-drift-{i}",
                action_type="EXEC",
                tool="Bash" if i % 2 == 0 else "HttpFetch",
                risk_score=0.72,
                touched_paths=["/var/lib/prod/db.sqlite"],
                network=True,
                outcome=outcome,
            ))

        report = reg.drift(agent)
        assert report is not None
        assert report.is_significant is True, (
            f"drift should be significant — got score={report.drift_score} "
            f"(threshold 0.20), reasons={report.reasons}"
        )
        assert report.drift_score >= 0.20
        assert report.risk_delta > 0.30  # mean risk jumped from ~0.1 to ~0.7
        assert report.network_delta > 0.50
        assert set(report.new_tools) >= {"Bash", "HttpFetch"}
        # Reasons should cite both risk and network (the strongest signals).
        reasons_joined = " ".join(report.reasons)
        assert "risk_delta" in reasons_joined
        assert "network_delta" in reasons_joined

    def test_stable_baseline_no_drift(self) -> None:
        """Negative control: 50 identical observations must produce a drift
        score far below the 0.20 threshold."""
        reg = BehavioralBaselineRegistry(window=200, min_samples_for_snapshot=10)
        agent = "agent:stable"
        for i in range(50):
            reg.observe(BehavioralObservation(
                agent_id=agent,
                chain_id=f"c-stable-{i}",
                action_type="READ",
                tool="Read",
                risk_score=0.10,
                touched_paths=["/tmp/stable.json"],
                network=False,
                outcome="APPROVED",
            ))

        report = reg.drift(agent)
        assert report is not None
        assert report.is_significant is False, (
            f"stable baseline triggered false-positive drift: "
            f"score={report.drift_score}, reasons={report.reasons}"
        )
        assert report.drift_score < 0.20


# ─────────────────────────────────────────────────────────────
# Part B — Oversight Evasion Signals
# ─────────────────────────────────────────────────────────────


# Anchor time so all timestamps are deterministic within the 120-min window.
_T0 = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)


def _record(
    *,
    agent_id: str = "agent:sneak",
    chain_id: str,
    risk: float = 0.1,
    paths: list[str] | None = None,
    reviewer: str = "agent:R1",
    t: datetime,
    oversight: bool = True,
) -> ActivityRecord:
    return ActivityRecord(
        agent_id=agent_id,
        chain_id=chain_id,
        action_type="WRITE",
        risk_score=risk,
        touched_paths=paths or [],
        reviewer_id=reviewer,
        submitted_at=t,
        oversight_window_active=oversight,
    )


class TestE1Fragmentation:
    """E1 — Many small low-risk proposals in a short window that together
    would have been a single reviewable action."""

    def test_fragmented_burst_detected(self) -> None:
        det = OversightEvasionDetector(window_minutes=120)
        findings_all: list = []
        # 6 low-risk (0.125 each) proposals inside a 5-minute span.
        # 6 × 0.125 = 0.75 aggregate risk — above the 0.6 threshold.
        for i in range(6):
            rec = _record(
                chain_id=f"c-frag-{i}",
                risk=0.125,
                t=_T0 + timedelta(minutes=i),
            )
            findings_all.extend(det.observe(rec))

        frag = [f for f in findings_all if f.signal == EvasionSignal.FRAGMENTED_ACTIONS]
        assert frag, (
            f"FRAGMENTED_ACTIONS not detected. All findings: "
            f"{[f.signal for f in findings_all]}"
        )
        assert frag[0].agent_id == "agent:sneak"
        assert len(frag[0].supporting_chain_ids) >= 5


class TestE2TimingArbitrage:
    """E2 — Recent activity is dominated by submissions outside the declared
    oversight window."""

    def test_out_of_window_dominance_detected(self) -> None:
        det = OversightEvasionDetector(window_minutes=120)
        findings_all: list = []
        # 5 proposals, all submitted with oversight_window_active=False.
        # 5/5 = 100% out-of-window, well past the 60% threshold.
        for i in range(5):
            rec = _record(
                chain_id=f"c-timing-{i}",
                risk=0.3,
                t=_T0 + timedelta(minutes=i * 2),
                oversight=False,
            )
            findings_all.extend(det.observe(rec))

        timing = [f for f in findings_all if f.signal == EvasionSignal.TIMING_ARBITRAGE]
        assert timing, (
            f"TIMING_ARBITRAGE not detected. All findings: "
            f"{[f.signal for f in findings_all]}"
        )
        assert "outside" in timing[0].detail


class TestE3ReviewerRotationAbuse:
    """E3 — Proposer's many proposals are reviewed by only a handful of
    reviewers, well below the diversity threshold."""

    def test_narrow_reviewer_set_detected(self) -> None:
        det = OversightEvasionDetector(window_minutes=120)
        findings_all: list = []
        # 12 proposals, all reviewed by one of just 2 reviewers.
        for i in range(12):
            reviewer = "agent:R1" if i % 2 == 0 else "agent:R2"
            rec = _record(
                chain_id=f"c-rev-{i}",
                risk=0.3,
                reviewer=reviewer,
                t=_T0 + timedelta(minutes=i * 3),
            )
            findings_all.extend(det.observe(rec))

        rot = [f for f in findings_all if f.signal == EvasionSignal.REVIEWER_ROTATION_ABUSE]
        assert rot, (
            f"REVIEWER_ROTATION_ABUSE not detected. All findings: "
            f"{[f.signal for f in findings_all]}"
        )


class TestE4ScopeCreep:
    """E4 — Touching paths outside the declared allowed_paths scope."""

    def test_out_of_scope_paths_detected(self) -> None:
        det = OversightEvasionDetector(window_minutes=120)
        det.declare_scope("agent:sneak", ["/tmp/gavel-validation/"])

        rec = _record(
            chain_id="c-creep-1",
            paths=["/etc/passwd", "/var/lib/prod/db.sqlite"],
            t=_T0,
        )
        findings = det.observe(rec)
        creep = [f for f in findings if f.signal == EvasionSignal.SCOPE_CREEP]
        assert creep, (
            f"SCOPE_CREEP not detected. All findings: "
            f"{[f.signal for f in findings]}"
        )
        # Both out-of-scope paths should be reflected in the detail.
        assert "/etc/passwd" in creep[0].detail or "/var/lib/prod/db.sqlite" in creep[0].detail


class TestE5HeartbeatBurst:
    """E5 — Quiet period of >30 minutes followed by a flurry of proposals.
    Requires 7+ records: buf[-7] is pre-burst, buf[-6] is the moment the
    burst begins, buf[-1] is the most recent proposal, with
    gap(buf[-7], buf[-6]) > 30min and gap(buf[-6], buf[-1]) ≤ 30min."""

    def test_quiet_then_burst_detected(self) -> None:
        det = OversightEvasionDetector(window_minutes=120)

        # Schedule:
        #   t=0    : pre_burst anchor
        #   t=40   : prev (start of burst, 40min gap > 30min quiet threshold)
        #   t=41..45: 5 more proposals forming the burst (all within 5min)
        # Total: 7 records, last at t=45. Fits easily in 120-min window.
        schedule = [
            (0, "c-pre"),
            (40, "c-burst-0"),
            (41, "c-burst-1"),
            (42, "c-burst-2"),
            (43, "c-burst-3"),
            (44, "c-burst-4"),
            (45, "c-burst-5"),
        ]
        findings_all: list = []
        for mins, cid in schedule:
            findings_all.extend(det.observe(_record(
                chain_id=cid,
                risk=0.3,
                t=_T0 + timedelta(minutes=mins),
            )))

        burst = [f for f in findings_all if f.signal == EvasionSignal.HEARTBEAT_BURST]
        assert burst, (
            f"HEARTBEAT_BURST not detected. All findings: "
            f"{[f.signal for f in findings_all]}"
        )


class TestE6KillSwitchEvasion:
    """E6 — An enrollment whose (owner, display_name) matches a previously-
    suspended agent is flagged as a kill-switch evasion attempt.

    This path fires from `observe_enrollment`, called by the enrollment
    gate at submission time — not from the activity stream."""

    def test_re_enrollment_under_new_id_detected(self) -> None:
        det = OversightEvasionDetector(window_minutes=120)
        det.mark_suspended(
            agent_id="agent:original",
            owner="adversary@example.org",
            display_name="Crawler Bot",
        )

        findings = det.observe_enrollment(
            agent_id="agent:original-v2",  # new id
            owner="adversary@example.org",
            display_name="Crawler Bot",
        )

        kse = [f for f in findings if f.signal == EvasionSignal.KILL_SWITCH_EVASION]
        assert kse, (
            f"KILL_SWITCH_EVASION not detected. Findings: "
            f"{[f.signal for f in findings]}"
        )
        assert kse[0].severity.value == "high"
        assert "agent:original" in kse[0].detail


# ─────────────────────────────────────────────────────────────
# Summary check — all six signals must be producible
# ─────────────────────────────────────────────────────────────


def test_all_six_signals_are_reachable() -> None:
    """Meta-assertion: every EvasionSignal value defined by the enum has
    at least one test in this file. If someone adds a new signal to the
    enum, this test fails until the test coverage catches up."""
    covered = {
        EvasionSignal.FRAGMENTED_ACTIONS,
        EvasionSignal.TIMING_ARBITRAGE,
        EvasionSignal.REVIEWER_ROTATION_ABUSE,
        EvasionSignal.SCOPE_CREEP,
        EvasionSignal.HEARTBEAT_BURST,
        EvasionSignal.KILL_SWITCH_EVASION,
    }
    all_signals = set(EvasionSignal)
    missing = all_signals - covered
    assert missing == set(), (
        f"EvasionSignal additions not covered by V8: {missing}. "
        f"Add a test class for each."
    )
