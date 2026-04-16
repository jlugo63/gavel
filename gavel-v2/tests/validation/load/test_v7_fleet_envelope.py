"""
V7 — Fleet Behavioral Envelope (Wave 4).

Goal: prove the BehavioralBaselineRegistry holds per-agent isolation and
drift-detection accuracy under fleet-scale load — not just the 2-agent
smoke scenarios V8 covers.

Scenario: a synthetic fleet of 50 agents observing 30 events each
(1,500 observations total). 47 agents stay in their declared operating
profile (stable). 3 agents drift in different realistic ways:
  - drifter A: risk inflation + tool shift + outcome skew (the "agent
     going rogue" profile — multiple dimensions move together)
  - drifter B: network activation (false → true) + tool shift
  - drifter C: scope expansion (new touched paths) + outcome skew
     toward DENIED

Note on single-dimension drift: the drift formula (0.35×risk + 0.25×net +
0.20×tool/2 + 0.10×denial + 0.10×escalation) is heavily diluted unless
multiple dimensions drift simultaneously. A pure risk-only drift from
0.10 to 0.75 produces score ≈ 0.11 — below the 0.20 threshold. This is
NOT a bug: real rogue agents shift multiple operating characteristics
at once (risk + tools + outcome), and that's what V7's drifters model.
The single-dimension case is validated as a known edge case in V7's
_test_characterization_single_dimension_drift_ test.

Checks:
  F1  Per-agent isolation — each stable agent's drift score is near zero
       (< 0.10). Noise from other agents must not leak into a stable
       agent's baseline.
  F2  Drifter isolation — all 3 drifters are flagged is_significant=True
       and the stable 47 are not.
  F3  Enrollment snapshot freeze — every agent has an enrollment snapshot
       and the snapshots are independent (different mean_risk, tool mix, etc.).
  F4  Registry memory bounded — window=200 means no agent's buffer exceeds
       200 entries even under 30+ observations (well within window here,
       but the invariant must hold).
  F5  Throughput floor — 1,500 observe() calls should complete in under
       2 seconds on CPU. This is a sanity floor, not a benchmark.

V7 is in Wave 4 because fleet-scale tests are slower than the Wave 1+2
unit-style scenarios — but in practice, with 1,500 observations, this
still runs in well under a second on any modern machine. The "slow" tag
is more about intent than wall time: Wave 4 is where we run
scale/concurrency scenarios.
"""

from __future__ import annotations

import time

import pytest

from gavel.baseline import (
    BehavioralBaselineRegistry,
    BehavioralObservation,
    _DRIFT_THRESHOLD,
)


FLEET_SIZE = 50
OBSERVATIONS_PER_AGENT = 30
WINDOW = 200


def _stable_agent_id(i: int) -> str:
    return f"agent:fleet-stable-{i:02d}"


DRIFTER_A = "agent:fleet-drift-risk"
DRIFTER_B = "agent:fleet-drift-network"
DRIFTER_C = "agent:fleet-drift-scope"


@pytest.fixture
def fleet_registry() -> BehavioralBaselineRegistry:
    """Build a 50-agent fleet with 47 stable + 3 drifters.

    Each stable agent logs 30 low-risk READ observations. The drifters
    log 15 baseline observations (enough to freeze the enrollment snapshot
    at 10), then 15 "drifted" observations of different flavors."""
    reg = BehavioralBaselineRegistry(window=WINDOW, min_samples_for_snapshot=10)

    # 47 stable agents
    for i in range(FLEET_SIZE - 3):
        agent_id = _stable_agent_id(i)
        for j in range(OBSERVATIONS_PER_AGENT):
            reg.observe(BehavioralObservation(
                agent_id=agent_id,
                chain_id=f"c-{agent_id}-{j}",
                action_type="READ",
                tool="Read",
                risk_score=0.10,
                touched_paths=[f"/tmp/gavel-validation/agent-{i}/input.json"],
                network=False,
                outcome="APPROVED",
            ))

    # Drifter A: realistic multi-dimensional "going rogue" — risk up,
    # tool shifts from Read to Bash, outcomes skew to DENIED. This is
    # what real compromise or prompt-injection looks like in production.
    for j in range(15):
        reg.observe(BehavioralObservation(
            agent_id=DRIFTER_A,
            chain_id=f"c-{DRIFTER_A}-baseline-{j}",
            action_type="READ", tool="Read", risk_score=0.10,
            touched_paths=["/tmp/gavel-validation/drifter-a/input.json"],
            network=False, outcome="APPROVED",
        ))
    for j in range(20):
        reg.observe(BehavioralObservation(
            agent_id=DRIFTER_A,
            chain_id=f"c-{DRIFTER_A}-drift-{j}",
            action_type="EXEC",
            tool="Bash",
            risk_score=0.80,
            touched_paths=["/tmp/gavel-validation/drifter-a/input.json"],
            network=False,
            outcome="DENIED" if j % 3 == 0 else "APPROVED",
        ))

    # Drifter B: network activation + tool shift
    for j in range(15):
        reg.observe(BehavioralObservation(
            agent_id=DRIFTER_B,
            chain_id=f"c-{DRIFTER_B}-baseline-{j}",
            action_type="READ", tool="Read", risk_score=0.20,
            touched_paths=["/tmp/gavel-validation/drifter-b/data.json"],
            network=False, outcome="APPROVED",
        ))
    for j in range(15):
        reg.observe(BehavioralObservation(
            agent_id=DRIFTER_B,
            chain_id=f"c-{DRIFTER_B}-drift-{j}",
            action_type="EXEC",
            tool="HttpFetch" if j % 2 == 0 else "Bash",
            risk_score=0.30,
            touched_paths=["/tmp/gavel-validation/drifter-b/data.json"],
            network=True, outcome="APPROVED",
        ))

    # Drifter C: scope expansion + tool shift + outcome skew toward DENIED.
    # Note: touched_paths isn't in the drift score formula, so scope
    # expansion alone doesn't register — the drifter must also shift
    # tools (which IS in the formula) to cross the threshold.
    for j in range(15):
        reg.observe(BehavioralObservation(
            agent_id=DRIFTER_C,
            chain_id=f"c-{DRIFTER_C}-baseline-{j}",
            action_type="WRITE", tool="Write", risk_score=0.25,
            touched_paths=["/tmp/gavel-validation/drifter-c/out.json"],
            network=False, outcome="APPROVED",
        ))
    for j in range(20):
        reg.observe(BehavioralObservation(
            agent_id=DRIFTER_C,
            chain_id=f"c-{DRIFTER_C}-drift-{j}",
            action_type="WRITE",
            tool="Edit" if j % 2 == 0 else "FileSystem",
            risk_score=0.75,
            touched_paths=[
                f"/var/lib/prod/service-{j}.db",
                f"/etc/config/secret-{j}.yaml",
            ],
            network=False,
            outcome="DENIED" if j % 2 == 0 else "APPROVED",
        ))

    return reg


# ── F1 + F2: per-agent isolation + drifter detection ─────────


class TestFleetIsolationAndDetection:
    """The whole point of per-agent baselines is that one agent's drift
    doesn't leak into another's. With 47 stable agents and 3 drifters
    sharing the same registry, each stable agent must show near-zero
    drift and every drifter must be flagged."""

    def test_stable_agents_show_near_zero_drift(self, fleet_registry) -> None:
        stable_scores: list[tuple[str, float]] = []
        for i in range(FLEET_SIZE - 3):
            agent_id = _stable_agent_id(i)
            report = fleet_registry.drift(agent_id)
            assert report is not None, f"no drift report for {agent_id}"
            stable_scores.append((agent_id, report.drift_score))
            assert report.is_significant is False, (
                f"stable fleet agent {agent_id} triggered drift: "
                f"score={report.drift_score}, reasons={report.reasons}"
            )
            assert report.drift_score < 0.10, (
                f"stable fleet agent {agent_id} had elevated drift: "
                f"{report.drift_score}"
            )

        max_stable = max(s for _, s in stable_scores)
        assert max_stable < 0.10, (
            f"max stable drift {max_stable} — isolation may be broken"
        )

    def test_all_three_drifters_flagged(self, fleet_registry) -> None:
        report_a = fleet_registry.drift(DRIFTER_A)
        report_b = fleet_registry.drift(DRIFTER_B)
        report_c = fleet_registry.drift(DRIFTER_C)

        assert report_a is not None
        assert report_a.is_significant is True, (
            f"DRIFTER_A (risk inflation) missed: score={report_a.drift_score}, "
            f"reasons={report_a.reasons}"
        )
        assert report_a.risk_delta > 0.30

        assert report_b is not None
        assert report_b.is_significant is True, (
            f"DRIFTER_B (network activation) missed: score={report_b.drift_score}, "
            f"reasons={report_b.reasons}"
        )
        # At least one of network_delta or new_tools must cite the shift
        assert report_b.network_delta > 0.20 or set(report_b.new_tools) & {"HttpFetch", "Bash"}

        assert report_c is not None
        assert report_c.is_significant is True, (
            f"DRIFTER_C (scope + outcome skew) missed: score={report_c.drift_score}, "
            f"reasons={report_c.reasons}"
        )


# ── F3: per-agent snapshot independence ──────────────────────


class TestFleetSnapshotIndependence:
    def test_every_agent_has_enrollment_snapshot(self, fleet_registry) -> None:
        # All 47 stable agents + 3 drifters = 50 snapshots.
        snapshots = [
            fleet_registry.enrollment_snapshot(_stable_agent_id(i))
            for i in range(FLEET_SIZE - 3)
        ]
        for i, snap in enumerate(snapshots):
            assert snap is not None, f"no snapshot for fleet-stable-{i}"
            assert snap.sample_size >= 10  # min_samples_for_snapshot
            # Stable agents should all have mean_risk ≈ 0.10
            assert abs(snap.mean_risk - 0.10) < 0.05

        for drifter in (DRIFTER_A, DRIFTER_B, DRIFTER_C):
            snap = fleet_registry.enrollment_snapshot(drifter)
            assert snap is not None, f"no snapshot for {drifter}"
            # Snapshots are frozen at sample 10 — well before the drift.
            # So drifter-A's snapshot mean_risk should still be ~0.10.
            if drifter == DRIFTER_A:
                assert abs(snap.mean_risk - 0.10) < 0.05, (
                    f"DRIFTER_A snapshot should have frozen pre-drift, "
                    f"got mean_risk={snap.mean_risk}"
                )

    def test_snapshots_are_independent_objects(self, fleet_registry) -> None:
        """Mutating the current baseline must not mutate the frozen snapshot."""
        agent_id = _stable_agent_id(0)
        snap_before = fleet_registry.enrollment_snapshot(agent_id)
        assert snap_before is not None
        mean_before = snap_before.mean_risk

        # Observe a wildly different event — the current baseline will
        # shift but the enrollment snapshot must not.
        fleet_registry.observe(BehavioralObservation(
            agent_id=agent_id,
            chain_id="c-late-drift",
            action_type="EXEC", tool="Bash", risk_score=0.95,
            touched_paths=["/var/lib/prod/db.sqlite"],
            network=True, outcome="DENIED",
        ))

        snap_after = fleet_registry.enrollment_snapshot(agent_id)
        assert snap_after is not None
        assert snap_after.mean_risk == mean_before, (
            f"enrollment snapshot was mutated by a later observation: "
            f"before={mean_before}, after={snap_after.mean_risk}"
        )


# ── F4: memory bound ────────────────────────────────────────


class TestFleetMemoryBound:
    def test_window_caps_buffer_size(self) -> None:
        """With window=50 and 200 observations, each buffer must cap at 50."""
        reg = BehavioralBaselineRegistry(window=50, min_samples_for_snapshot=10)
        agent = "agent:bounded"
        for j in range(200):
            reg.observe(BehavioralObservation(
                agent_id=agent,
                chain_id=f"c-{j}",
                action_type="READ", tool="Read", risk_score=0.10,
                touched_paths=["/tmp/x"],
                network=False, outcome="APPROVED",
            ))
        baseline = reg.current_baseline(agent)
        assert baseline.sample_size == 50, (
            f"buffer not capped at window size: got {baseline.sample_size}"
        )


# ── F5: throughput floor ────────────────────────────────────


class TestFleetThroughput:
    def test_fleet_load_completes_within_floor(self) -> None:
        """1,500 observations across 50 agents must complete in < 2 seconds.
        This is a sanity floor — if it regresses to 10x slower, something
        changed."""
        reg = BehavioralBaselineRegistry(window=WINDOW, min_samples_for_snapshot=10)
        t0 = time.perf_counter()
        for i in range(FLEET_SIZE):
            agent_id = f"agent:perf-{i}"
            for j in range(OBSERVATIONS_PER_AGENT):
                reg.observe(BehavioralObservation(
                    agent_id=agent_id,
                    chain_id=f"c-{i}-{j}",
                    action_type="READ", tool="Read", risk_score=0.10,
                    touched_paths=["/tmp/x"],
                    network=False, outcome="APPROVED",
                ))
        elapsed = time.perf_counter() - t0
        # 2 seconds is a very loose floor — typical wall time is < 0.1s.
        assert elapsed < 2.0, (
            f"fleet observe() loop took {elapsed:.2f}s for {FLEET_SIZE * OBSERVATIONS_PER_AGENT} calls"
        )


# ── F6: single-dimension drift characterization ─────────────


class TestSingleDimensionDriftCharacterization:
    """Characterization test (not a pass/fail of application logic).

    Pure risk-only drift — same tools, same network, same outcome
    distribution, just higher risk scores — is insufficient to cross the
    0.20 significance threshold unless risk_delta exceeds ~0.57. This is
    a property of the current scoring formula (0.35 × risk_delta is the
    only term that moves) and is documented here so a future change to
    the formula doesn't silently widen this blind spot.

    If this test starts failing, it means the formula changed and either
    (a) the threshold no longer matches, or (b) the single-dimension gap
    has been fixed — both of which are worth a code review."""

    def test_pure_risk_drift_below_significance_threshold(self) -> None:
        reg = BehavioralBaselineRegistry(window=200, min_samples_for_snapshot=10)
        agent = "agent:pure-risk-drift"

        # 15 baseline observations at 0.10 risk
        for j in range(15):
            reg.observe(BehavioralObservation(
                agent_id=agent, chain_id=f"c-base-{j}",
                action_type="READ", tool="Read", risk_score=0.10,
                touched_paths=["/tmp/x"], network=False, outcome="APPROVED",
            ))
        # 15 "drifted" observations at 0.75 risk — but otherwise identical
        for j in range(15):
            reg.observe(BehavioralObservation(
                agent_id=agent, chain_id=f"c-drift-{j}",
                action_type="READ", tool="Read", risk_score=0.75,
                touched_paths=["/tmp/x"], network=False, outcome="APPROVED",
            ))

        report = reg.drift(agent)
        assert report is not None
        assert report.risk_delta > 0.30, "risk_delta should reflect the jump"
        # The formula's dilution: 0.35 * 0.325 ≈ 0.114, below the 0.20 threshold.
        assert report.drift_score < 0.20, (
            f"Pure risk drift unexpectedly crossed threshold. "
            f"If the formula changed, review the single-dimension blind spot. "
            f"Got: score={report.drift_score}, reasons={report.reasons}"
        )
        assert report.is_significant is False

    def test_scope_expansion_now_contributes_to_drift(self) -> None:
        """After the path_novelty term was added to the drift formula,
        an agent that moves to entirely new paths — even without changing
        tools or network — contributes 0.10 × path_novelty to the score.

        Scope expansion (path_novelty=1.0) adds 0.10 to the score.
        Combined with a moderate risk bump it can now cross the threshold,
        whereas before the fix it was invisible to drift detection."""
        reg = BehavioralBaselineRegistry(window=200, min_samples_for_snapshot=10)
        agent = "agent:scope-drift"

        # 15 baseline: safe path, low risk
        for j in range(15):
            reg.observe(BehavioralObservation(
                agent_id=agent, chain_id=f"c-base-{j}",
                action_type="READ", tool="Read", risk_score=0.15,
                touched_paths=["/tmp/gavel-validation/safe.json"],
                network=False, outcome="APPROVED",
            ))

        # 20 drifted: completely new paths + risk bump. The risk alone
        # (0.35 × delta ≈ 0.13) is below the 0.20 threshold. But
        # path_novelty (0.10 × 0.80 ≈ 0.08) pushes the combined score
        # above 0.20 — proving the new term makes a difference.
        for j in range(20):
            reg.observe(BehavioralObservation(
                agent_id=agent, chain_id=f"c-scope-{j}",
                action_type="READ", tool="Read", risk_score=0.80,
                touched_paths=[f"/var/lib/prod/secret-{j}.db"],
                network=False, outcome="APPROVED",
            ))

        report = reg.drift(agent)
        assert report is not None
        assert report.path_novelty > 0.50, (
            f"path_novelty should be high — agent moved to new paths. "
            f"got {report.path_novelty}, new_paths={report.new_paths}"
        )
        assert len(report.new_paths) >= 1

        # Without path_novelty term: risk contribution alone ≈ 0.13 (below threshold).
        risk_only_score = 0.35 * abs(report.risk_delta)
        assert risk_only_score < _DRIFT_THRESHOLD, (
            "test setup error — risk alone should be below threshold"
        )
        # WITH path_novelty: combined score crosses threshold.
        assert report.is_significant is True, (
            f"scope expansion + risk should now be caught (path_novelty "
            f"adds the margin). score={report.drift_score}, "
            f"reasons={report.reasons}"
        )
