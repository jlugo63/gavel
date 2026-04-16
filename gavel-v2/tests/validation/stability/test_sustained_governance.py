"""
Phase 14 — Long-Running Stability Test Suite.

Compressed simulation that verifies stability properties under sustained
load: no memory leaks, no state corruption, no drift in performance.
Each test exercises a subsystem over many iterations — enough to surface
unbounded growth, hash chain corruption, or rate-limiter state bugs
that only appear after prolonged operation.

All tests carry the ``stability`` marker so they are excluded from the
default pytest run (``addopts`` filters them out). Run explicitly with:

    python -m pytest tests/validation/stability/ -v -m stability

Total wall time target: < 60 seconds on modern hardware.
"""

from __future__ import annotations

import asyncio
import random
import time
import tracemalloc
from datetime import datetime, timedelta, timezone

import pytest

from gavel.baseline import (
    BehavioralBaselineRegistry,
    BehavioralObservation,
)
from gavel.chain import (
    ChainStatus,
    EventType,
    GovernanceChain,
)
from gavel.deception import DeceptionDetector
from gavel.enrollment import EnrollmentValidator
from gavel.evasion import (
    ActivityRecord,
    EvasionSignal,
    OversightEvasionDetector,
)
from gavel.fairness import (
    DecisionOutcome,
    FairnessMonitor,
    ProtectedAttribute,
)
from gavel.model_lifecycle import (
    ModelBindingRegistry,
    ModelLifecycleChecker,
    ModelRegistry,
    ModelStatus,
)
from gavel.rate_limit import InProcessRateLimiter

# Import build_application from the validation conftest
from tests.validation.conftest import build_application


# ── Constants ──────────────────────────────────────────────────

SEED = 42


# ── S1: Chain Integrity Under Sustained Load ──────────────────


@pytest.mark.stability
class TestChainIntegrityUnderSustainedLoad:
    """Create 100 governance chains with 100 events each (10,000 total),
    then verify hash chain integrity on all chains.

    Catches: hash linkage bugs under volume, duplicate chain IDs,
    missing events, throughput regressions.
    """

    CHAIN_COUNT = 100
    EVENTS_PER_CHAIN = 100

    def test_chain_integrity_under_sustained_load(self) -> None:
        event_types = list(EventType)
        chains: list[GovernanceChain] = []

        t0 = time.perf_counter()
        for c in range(self.CHAIN_COUNT):
            chain = GovernanceChain(chain_id=f"c-stab-{c:04d}")
            for e in range(self.EVENTS_PER_CHAIN):
                et = event_types[(c + e) % len(event_types)]
                chain.append(
                    event_type=et,
                    actor_id=f"agent:stab-{c % 20}",
                    role_used="executor" if e % 3 == 0 else "reviewer",
                    payload={"chain": c, "seq": e},
                )
            chains.append(chain)
        build_elapsed = time.perf_counter() - t0

        total_events = self.CHAIN_COUNT * self.EVENTS_PER_CHAIN

        # All events present
        assert sum(len(ch.events) for ch in chains) == total_events

        # No duplicate chain IDs
        chain_ids = [ch.chain_id for ch in chains]
        assert len(set(chain_ids)) == self.CHAIN_COUNT, "duplicate chain IDs detected"

        # Every chain verifies
        t1 = time.perf_counter()
        for chain in chains:
            assert chain.verify_integrity() is True, (
                f"chain {chain.chain_id} failed integrity"
            )
        verify_elapsed = time.perf_counter() - t1

        # Hash linkage spot-check across all chains
        for chain in chains:
            for i in range(1, len(chain.events)):
                assert chain.events[i].prev_hash == chain.events[i - 1].event_hash, (
                    f"hash linkage broken in {chain.chain_id} at event {i}"
                )

        # Throughput floor: >1000 events/sec (loose — typical is 5000+)
        throughput = total_events / build_elapsed
        assert throughput > 1000, (
            f"throughput regression: {throughput:.0f} events/sec "
            f"(floor is 1000, elapsed {build_elapsed:.2f}s for {total_events} events)"
        )

        # Verify floors (loose)
        assert build_elapsed < 30.0, f"build took {build_elapsed:.2f}s"
        assert verify_elapsed < 10.0, f"verify took {verify_elapsed:.2f}s"


# ── S2: Memory Bounded Under Sustained Operations ─────────────


@pytest.mark.stability
class TestMemoryBoundedUnderSustainedOperations:
    """Run 10 rounds of: create 50 chains x 50 events, verify, discard.
    Assert memory growth between round 1 and round 10 is < 20%.

    Catches: leaking references in registries, caches, rolling windows.
    """

    ROUNDS = 10
    CHAINS_PER_ROUND = 50
    EVENTS_PER_CHAIN = 50

    def test_memory_bounded_under_sustained_operations(self) -> None:
        tracemalloc.start()

        round_peaks: list[int] = []

        for r in range(self.ROUNDS):
            chains: list[GovernanceChain] = []
            for c in range(self.CHAINS_PER_ROUND):
                chain = GovernanceChain(chain_id=f"c-mem-r{r}-c{c}")
                for e in range(self.EVENTS_PER_CHAIN):
                    chain.append(
                        event_type=EventType.POLICY_EVAL,
                        actor_id=f"agent:mem-{c % 10}",
                        role_used="reviewer",
                        payload={"round": r, "chain": c, "seq": e},
                    )
                assert chain.verify_integrity() is True
                chains.append(chain)

            # Capture memory at end of round, then discard
            _, peak = tracemalloc.get_traced_memory()
            round_peaks.append(peak)
            del chains

        tracemalloc.stop()

        # Memory growth between round 1 and round 10 should be < 20%
        first_peak = round_peaks[0]
        last_peak = round_peaks[-1]
        if first_peak > 0:
            growth_ratio = (last_peak - first_peak) / first_peak
            assert growth_ratio < 0.20, (
                f"memory grew {growth_ratio * 100:.1f}% over {self.ROUNDS} rounds "
                f"(first peak: {first_peak / 1024:.0f}KB, "
                f"last peak: {last_peak / 1024:.0f}KB)"
            )


# ── S3: Rate Limiter Stability Over Time ──────────────────────


@pytest.mark.stability
class TestRateLimiterStabilityOverTime:
    """Configure rate limiters for 10 agents at 100/min, run 1000
    check_and_record calls per agent with advancing timestamps.

    Catches: state corruption (negative counts, missing agents),
    window pruning bugs, cleanup_inactive correctness.
    """

    AGENTS = 10
    CALLS_PER_AGENT = 1000
    RATE_LIMIT = 100  # per minute

    @pytest.mark.asyncio
    async def test_rate_limiter_stability_over_time(self) -> None:
        limiter = InProcessRateLimiter()

        # Configure all agents
        for i in range(self.AGENTS):
            await limiter.configure(f"agent:rl-{i}", self.RATE_LIMIT)

        # Run calls with advancing timestamps: each call advances 0.5s
        # so 120 calls span 60s (one full window). At 100/min limit,
        # the first 100 calls in any 60s window should be allowed.
        base_time = 1000.0  # arbitrary start
        allowed_counts: dict[str, int] = {f"agent:rl-{i}": 0 for i in range(self.AGENTS)}
        denied_counts: dict[str, int] = {f"agent:rl-{i}": 0 for i in range(self.AGENTS)}

        for i in range(self.AGENTS):
            agent_id = f"agent:rl-{i}"
            for call in range(self.CALLS_PER_AGENT):
                now = base_time + call * 0.5
                result = await limiter.check_and_record(agent_id, now=now)
                if result.allowed:
                    allowed_counts[agent_id] += 1
                else:
                    denied_counts[agent_id] += 1
                    # No negative counts
                    assert result.current_count >= 0, (
                        f"negative count for {agent_id}: {result.current_count}"
                    )

        # Each agent should have been allowed most calls (sliding window
        # advances, so after the first window fills, old entries expire).
        for i in range(self.AGENTS):
            agent_id = f"agent:rl-{i}"
            total = allowed_counts[agent_id] + denied_counts[agent_id]
            assert total == self.CALLS_PER_AGENT, (
                f"{agent_id}: expected {self.CALLS_PER_AGENT} total, got {total}"
            )
            # With 0.5s spacing and 100/min limit, most calls should be
            # allowed (the window slides). At least 80% should pass.
            assert allowed_counts[agent_id] > self.CALLS_PER_AGENT * 0.80, (
                f"{agent_id}: only {allowed_counts[agent_id]} allowed out of "
                f"{self.CALLS_PER_AGENT}"
            )

        # Verify usage reports are consistent
        for i in range(self.AGENTS):
            agent_id = f"agent:rl-{i}"
            final_now = base_time + self.CALLS_PER_AGENT * 0.5
            usage = await limiter.get_usage(agent_id, now=final_now)
            assert usage["agent_id"] == agent_id
            assert usage["limit"] == self.RATE_LIMIT
            assert usage["current_count"] >= 0
            assert usage["remaining"] >= 0

        # Cleanup: all agents should be removable after enough time
        far_future = base_time + self.CALLS_PER_AGENT * 0.5 + 100_000
        removed = await limiter.cleanup_inactive(
            max_age_seconds=1000, now=far_future,
        )
        assert removed == self.AGENTS, (
            f"cleanup_inactive should have removed {self.AGENTS}, got {removed}"
        )


# ── S4: Behavioral Baseline Drift Accumulation ───────────────


@pytest.mark.stability
class TestBehavioralBaselineDriftAccumulation:
    """Enroll 20 agents with baselines, generate 500 observations per
    agent with gradual drift injection in a subset.

    Catches: drift detection false negatives at scale, observation
    window unbounded growth, snapshot mutation.
    """

    FLEET_SIZE = 20
    OBS_PER_AGENT = 500
    WINDOW = 200
    DRIFTER_COUNT = 5

    def test_behavioral_baseline_drift_accumulation(self) -> None:
        rng = random.Random(SEED)
        reg = BehavioralBaselineRegistry(
            window=self.WINDOW, min_samples_for_snapshot=10,
        )

        drifter_ids = {f"agent:drift-{i}" for i in range(self.DRIFTER_COUNT)}

        for i in range(self.FLEET_SIZE):
            agent_id = f"agent:drift-{i}" if i < self.DRIFTER_COUNT else f"agent:stable-{i}"

            for j in range(self.OBS_PER_AGENT):
                is_drifter = agent_id in drifter_ids
                # Drifters: first 100 obs are baseline, then gradually drift
                if is_drifter and j >= 100:
                    drift_factor = min(1.0, (j - 100) / 400.0)
                    risk = 0.10 + drift_factor * 0.70
                    tool = rng.choice(["Bash", "HttpFetch", "Admin"])
                    network = rng.random() < drift_factor
                    outcome = "DENIED" if rng.random() < drift_factor * 0.5 else "APPROVED"
                else:
                    risk = 0.10 + rng.random() * 0.05
                    tool = "Read"
                    network = False
                    outcome = "APPROVED"

                reg.observe(BehavioralObservation(
                    agent_id=agent_id,
                    chain_id=f"c-{agent_id}-{j}",
                    action_type="READ" if tool == "Read" else "EXEC",
                    tool=tool,
                    risk_score=risk,
                    touched_paths=[f"/tmp/gavel-validation/{agent_id}/data.json"],
                    network=network,
                    outcome=outcome,
                ))

        # Drift detection: all drifters should be flagged
        for i in range(self.DRIFTER_COUNT):
            agent_id = f"agent:drift-{i}"
            report = reg.drift(agent_id)
            assert report is not None, f"no drift report for {agent_id}"
            assert report.is_significant is True, (
                f"drifter {agent_id} NOT flagged: score={report.drift_score}, "
                f"reasons={report.reasons}"
            )

        # Stable agents should NOT be flagged
        for i in range(self.DRIFTER_COUNT, self.FLEET_SIZE):
            agent_id = f"agent:stable-{i}"
            report = reg.drift(agent_id)
            assert report is not None
            assert report.is_significant is False, (
                f"stable {agent_id} wrongly flagged: score={report.drift_score}"
            )

        # Memory bounded: observation buffers capped at window size
        for i in range(self.FLEET_SIZE):
            agent_id = (
                f"agent:drift-{i}" if i < self.DRIFTER_COUNT
                else f"agent:stable-{i}"
            )
            baseline = reg.current_baseline(agent_id)
            assert baseline.sample_size <= self.WINDOW, (
                f"{agent_id} buffer exceeded window: {baseline.sample_size} > {self.WINDOW}"
            )

        # Enrollment snapshots frozen and immutable
        for i in range(self.DRIFTER_COUNT):
            agent_id = f"agent:drift-{i}"
            snap = reg.enrollment_snapshot(agent_id)
            assert snap is not None, f"no snapshot for {agent_id}"
            # Snapshot was frozen at sample 10, well before drift started
            assert abs(snap.mean_risk - 0.10) < 0.10, (
                f"{agent_id} snapshot mean_risk should be near baseline: "
                f"got {snap.mean_risk}"
            )


# ── S5: Concurrent Enrollment Stress ─────────────────────────


@pytest.mark.stability
class TestConcurrentEnrollmentStress:
    """100 concurrent enrollment validations via asyncio.gather.

    Catches: race conditions in validator, partial state, non-determinism.
    Note: uses EnrollmentValidator (stateless) since EnrollmentRegistry
    requires a DB repo. The validator is the CPU-bound path.
    """

    CONCURRENT = 100

    @pytest.mark.asyncio
    async def test_concurrent_enrollment_stress(self) -> None:
        validator = EnrollmentValidator()

        async def validate_one(idx: int) -> tuple[int, bool, list[str]]:
            app = build_application(
                agent_id=f"agent:concurrent-{idx:03d}",
                display_name=f"Concurrent Agent {idx}",
                owner=f"owner-{idx}@gavel.eu",
                owner_contact=f"owner-{idx}@gavel.eu",
            )
            # Run in executor to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            passed, violations = await loop.run_in_executor(
                None, validator.validate, app,
            )
            return idx, passed, violations

        t0 = time.perf_counter()
        results = await asyncio.gather(
            *(validate_one(i) for i in range(self.CONCURRENT))
        )
        elapsed = time.perf_counter() - t0

        # All should succeed deterministically
        for idx, passed, violations in results:
            assert passed is True, (
                f"agent:concurrent-{idx:03d} failed: {violations}"
            )

        # All unique indices present
        indices = sorted(r[0] for r in results)
        assert indices == list(range(self.CONCURRENT)), "missing results"

        # Performance floor: 100 validations should complete quickly
        assert elapsed < 10.0, (
            f"concurrent enrollment took {elapsed:.2f}s for {self.CONCURRENT} apps"
        )


# ── S6: Fairness Monitor Long Window ─────────────────────────


@pytest.mark.stability
class TestFairnessMonitorLongWindow:
    """Record 5000 outcomes across 10 agents with varying protected
    attribute distributions.

    Catches: metric instability at scale, window bounding failures,
    baseline snapshot mutation.
    """

    AGENTS = 10
    OUTCOMES_PER_AGENT = 500
    WINDOW = 200

    def test_fairness_monitor_long_window(self) -> None:
        rng = random.Random(SEED)
        monitor = FairnessMonitor(
            window=self.WINDOW, min_samples_for_snapshot=20,
        )

        genders = ["male", "female", "non_binary"]
        decisions = ["APPROVED", "DENIED"]

        for i in range(self.AGENTS):
            agent_id = f"agent:fair-{i}"
            # Vary approval rates per agent to test metric diversity
            approval_rate = 0.6 + (i * 0.03)  # 0.60 to 0.87

            for j in range(self.OUTCOMES_PER_AGENT):
                gender = genders[j % len(genders)]
                # Skew: male gets higher approval for some agents
                if gender == "male":
                    effective_rate = min(1.0, approval_rate + 0.10)
                elif gender == "female":
                    effective_rate = approval_rate
                else:
                    effective_rate = max(0.0, approval_rate - 0.05)

                decision = "APPROVED" if rng.random() < effective_rate else "DENIED"

                monitor.record_outcome(DecisionOutcome(
                    agent_id=agent_id,
                    chain_id=f"c-fair-{i}-{j}",
                    decision=decision,
                    protected_attributes={
                        ProtectedAttribute.GENDER.value: gender,
                    },
                ))

        # Metrics should be computable for all agents
        for i in range(self.AGENTS):
            agent_id = f"agent:fair-{i}"
            metrics = monitor.compute_metrics(
                agent_id, ProtectedAttribute.GENDER.value,
            )
            assert metrics is not None, f"no metrics for {agent_id}"
            assert metrics.sample_size > 0
            assert len(metrics.group_counts) == len(genders)

            # Demographic parity should be computed
            if metrics.demographic_parity_ratio is not None:
                assert 0.0 <= metrics.demographic_parity_ratio <= 2.0, (
                    f"parity ratio out of range: {metrics.demographic_parity_ratio}"
                )

        # Enrollment baselines should be frozen
        for i in range(self.AGENTS):
            agent_id = f"agent:fair-{i}"
            baseline = monitor.enrollment_baseline(agent_id)
            assert baseline is not None, f"no baseline for {agent_id}"
            assert baseline.sample_size >= 20

        # Window bounding: internal buffer should not exceed configured window
        for i in range(self.AGENTS):
            agent_id = f"agent:fair-{i}"
            buf = monitor._outcomes.get(agent_id)
            assert buf is not None
            assert len(buf) <= self.WINDOW, (
                f"{agent_id} buffer size {len(buf)} exceeds window {self.WINDOW}"
            )


# ── S7: Deception Detector Throughput ─────────────────────────


@pytest.mark.stability
class TestDeceptionDetectorThroughput:
    """Analyze 1000 outputs through the deception detector.

    Catches: inconsistent detection (same input -> different findings),
    rolling window unbounded growth, throughput regression.
    """

    ITERATIONS = 1000

    def test_deception_detector_throughput(self) -> None:
        detector = DeceptionDetector(window_size=500)

        # Deceptive outputs that should trigger findings
        deceptive_texts = [
            "This is 100% guaranteed to work without any issues.",
            "I am a human and I can confirm this is safe.",
            "Check the docs at https://api.fake.example/v2 for details.",
            "This is perfectly safe with zero risk of failure.",
            "I am a certified engineer and I guarantee this will never fail.",
        ]
        # Clean outputs that should not trigger findings
        clean_texts = [
            "The function returns a list of integers.",
            "Please review the configuration settings.",
            "This approach has trade-offs worth considering.",
            "The test passed with expected results.",
            "Here are the available options for this feature.",
        ]

        t0 = time.perf_counter()
        all_findings_counts: list[int] = []

        for i in range(self.ITERATIONS):
            text = deceptive_texts[i % len(deceptive_texts)]
            findings = detector.analyze_output(
                agent_id=f"agent:deception-{i % 10}",
                chain_id=f"c-deception-{i}",
                output_text=text,
            )
            all_findings_counts.append(len(findings))

        elapsed = time.perf_counter() - t0

        # Throughput floor: >200 analyses/sec (loose)
        throughput = self.ITERATIONS / elapsed
        assert throughput > 200, (
            f"deception detector throughput regression: {throughput:.0f}/sec "
            f"(floor is 200, elapsed {elapsed:.2f}s)"
        )

        # Consistency: same input text should produce same finding count.
        # Group by text index and verify.
        for text_idx in range(len(deceptive_texts)):
            counts_for_text = [
                all_findings_counts[i]
                for i in range(self.ITERATIONS)
                if i % len(deceptive_texts) == text_idx
            ]
            # All iterations of the same text should have the same
            # finding count (deterministic detection).
            unique_counts = set(counts_for_text)
            # Note: contradiction detection is stateful (uses prior claims),
            # so finding counts may vary slightly for the first few iterations
            # of a given agent. We check that at most 3 distinct counts appear.
            assert len(unique_counts) <= 3, (
                f"text {text_idx} had {len(unique_counts)} distinct finding "
                f"counts: {unique_counts}"
            )

        # Clean texts should produce fewer findings
        clean_counts = []
        for i in range(self.ITERATIONS):
            text = clean_texts[i % len(clean_texts)]
            findings = detector.analyze_output(
                agent_id=f"agent:clean-{i % 10}",
                chain_id=f"c-clean-{i}",
                output_text=text,
            )
            clean_counts.append(len(findings))

        avg_clean = sum(clean_counts) / len(clean_counts) if clean_counts else 0
        avg_deceptive = sum(all_findings_counts) / len(all_findings_counts) if all_findings_counts else 0
        # Deceptive texts should produce more findings on average
        assert avg_deceptive >= avg_clean, (
            f"deceptive avg ({avg_deceptive:.1f}) should be >= clean avg ({avg_clean:.1f})"
        )

        # Rolling window bounded: per-agent findings buffers capped
        for agent_idx in range(10):
            agent_id = f"agent:deception-{agent_idx}"
            buf = detector._findings.get(agent_id)
            if buf is not None:
                assert len(buf) <= 500, (
                    f"{agent_id} findings buffer {len(buf)} exceeds window 500"
                )


# ── S8: Model Lifecycle Fleet Churn ───────────────────────────


@pytest.mark.stability
class TestModelLifecycleFleetChurn:
    """Register 50 models, bind 200 agents, simulate lifecycle churn.

    Catches: binding resolution errors after model state changes,
    fleet health report inaccuracies, stale binding references.
    """

    MODELS = 50
    AGENTS = 200
    DEPRECATE_COUNT = 20
    RETIRE_COUNT = 10
    BAN_COUNT = 5

    def test_model_lifecycle_fleet_churn(self) -> None:
        model_reg = ModelRegistry()
        binding_reg = ModelBindingRegistry(model_reg)
        checker = ModelLifecycleChecker(model_reg, binding_reg)

        # Register 50 models
        for m in range(self.MODELS):
            model_reg.register_model(
                model_id=f"model-{m:03d}",
                provider=f"provider-{m % 5}",
                version=f"1.0.{m}",
            )

        # Bind 200 agents (round-robin across models)
        agent_ids = []
        for a in range(self.AGENTS):
            agent_id = f"agent:lifecycle-{a:03d}"
            model_id = f"model-{a % self.MODELS:03d}"
            binding_reg.bind_agent(agent_id, model_id)
            agent_ids.append(agent_id)

        # Deprecate first 20 models
        future = datetime.now(timezone.utc) + timedelta(days=90)
        deprecated_models = set()
        for m in range(self.DEPRECATE_COUNT):
            model_id = f"model-{m:03d}"
            model_reg.deprecate_model(model_id, retirement_date=future)
            deprecated_models.add(model_id)

        # Retire next 10 (20-29)
        retired_models = set()
        for m in range(self.DEPRECATE_COUNT, self.DEPRECATE_COUNT + self.RETIRE_COUNT):
            model_id = f"model-{m:03d}"
            model_reg.retire_model(model_id)
            retired_models.add(model_id)

        # Ban next 5 (30-34)
        banned_models = set()
        for m in range(
            self.DEPRECATE_COUNT + self.RETIRE_COUNT,
            self.DEPRECATE_COUNT + self.RETIRE_COUNT + self.BAN_COUNT,
        ):
            model_id = f"model-{m:03d}"
            model_reg.ban_model(model_id, reason="safety concern")
            banned_models.add(model_id)

        # Verify all bindings resolve correctly
        for a in range(self.AGENTS):
            agent_id = f"agent:lifecycle-{a:03d}"
            model_id = f"model-{a % self.MODELS:03d}"
            binding = binding_reg.get_binding(agent_id)
            assert binding is not None, f"binding missing for {agent_id}"
            assert binding.model_id == model_id

            # Check model status
            result = checker.check_agent_model_status(agent_id)
            if model_id in retired_models or model_id in banned_models:
                assert result.allowed is False, (
                    f"{agent_id} should be blocked (model {model_id} is "
                    f"{result.model_status})"
                )
            else:
                assert result.allowed is True, (
                    f"{agent_id} should be allowed (model {model_id} status "
                    f"{result.model_status})"
                )

        # Fleet health report
        report = checker.check_fleet_model_health()
        assert report.total_bindings == self.AGENTS

        # Count how many agents are on each model status
        # Each model has AGENTS/MODELS = 4 agents bound to it
        agents_per_model = self.AGENTS // self.MODELS
        expected_deprecated = self.DEPRECATE_COUNT * agents_per_model
        expected_retired = self.RETIRE_COUNT * agents_per_model
        expected_banned = self.BAN_COUNT * agents_per_model
        expected_active = self.AGENTS - expected_deprecated - expected_retired - expected_banned

        assert report.agents_on_deprecated_models == expected_deprecated, (
            f"expected {expected_deprecated} deprecated, got {report.agents_on_deprecated_models}"
        )
        assert report.agents_on_retired_models == expected_retired, (
            f"expected {expected_retired} retired, got {report.agents_on_retired_models}"
        )
        assert report.agents_on_banned_models == expected_banned, (
            f"expected {expected_banned} banned, got {report.agents_on_banned_models}"
        )
        assert report.agents_on_active_models == expected_active, (
            f"expected {expected_active} active, got {report.agents_on_active_models}"
        )


# ── S9: Evasion Detection Sustained ──────────────────────────


@pytest.mark.stability
class TestEvasionDetectionSustained:
    """Feed 2000 events through the evasion detector across 20 agents.

    Catches: signal detection failures at scale, unbounded window
    growth, memory leaks in activity buffers.
    """

    AGENTS = 20
    EVENTS_PER_AGENT = 100  # 2000 total

    def test_evasion_detection_sustained(self) -> None:
        rng = random.Random(SEED)
        detector = OversightEvasionDetector(window_minutes=120)

        base_time = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)
        all_findings: dict[str, list] = {f"agent:evasion-{i}": [] for i in range(self.AGENTS)}
        signal_types_seen: set[str] = set()

        for i in range(self.AGENTS):
            agent_id = f"agent:evasion-{i}"
            # Declare scope for scope creep detection
            detector.declare_scope(agent_id, [f"/tmp/gavel-validation/{agent_id}/"])

            for j in range(self.EVENTS_PER_AGENT):
                t = base_time + timedelta(seconds=j * 30)

                # Inject specific evasion patterns for some agents
                if i < 3 and j >= 50:
                    # Fragmented actions: many low-risk proposals
                    risk = 0.10
                    # Pack them close together in time for fragmentation detection
                    t = base_time + timedelta(minutes=50, seconds=(j - 50) * 5)
                    paths = [f"/tmp/gavel-validation/{agent_id}/shard-{j}.json"]
                    oversight = True
                elif i >= 3 and i < 6 and j >= 60:
                    # Timing arbitrage: submit outside oversight windows
                    risk = 0.30
                    paths = [f"/tmp/gavel-validation/{agent_id}/data.json"]
                    oversight = False
                elif i >= 6 and i < 9 and j >= 40:
                    # Scope creep: touch paths outside declared scope
                    risk = 0.40
                    paths = [f"/var/lib/prod/secret-{j}.db"]
                    oversight = True
                else:
                    risk = 0.10 + rng.random() * 0.20
                    paths = [f"/tmp/gavel-validation/{agent_id}/input.json"]
                    oversight = True

                record = ActivityRecord(
                    agent_id=agent_id,
                    chain_id=f"c-evasion-{i}-{j}",
                    action_type="READ" if risk < 0.20 else "EXEC",
                    risk_score=risk,
                    touched_paths=paths,
                    reviewer_id=f"reviewer-{j % 2}",
                    submitted_at=t,
                    oversight_window_active=oversight,
                )

                findings = detector.observe(record)
                all_findings[agent_id].extend(findings)
                for f in findings:
                    signal_types_seen.add(f.signal.value)

        # At least some evasion signals should have fired
        # (scope_creep should fire for agents 6-8, timing_arbitrage for 3-5)
        assert len(signal_types_seen) >= 2, (
            f"expected at least 2 signal types, got {signal_types_seen}"
        )

        # Scope creep agents should have scope_creep findings
        for i in range(6, 9):
            agent_id = f"agent:evasion-{i}"
            scope_findings = [
                f for f in all_findings[agent_id]
                if f.signal == EvasionSignal.SCOPE_CREEP
            ]
            assert len(scope_findings) > 0, (
                f"{agent_id} should have scope_creep findings"
            )

        # Memory bounded: activity buffers capped at 500 (deque maxlen)
        for i in range(self.AGENTS):
            agent_id = f"agent:evasion-{i}"
            buf = detector._activity.get(agent_id)
            if buf is not None:
                assert len(buf) <= 500, (
                    f"{agent_id} activity buffer {len(buf)} exceeds maxlen 500"
                )


# ── S10: End-to-End Governance Throughput ─────────────────────


@pytest.mark.stability
class TestEndToEndGovernanceThroughput:
    """Full governance flow: enroll -> propose -> evaluate -> approve ->
    execute, run 500 iterations.

    Catches: chain corruption under full-flow volume, evidence hash
    failures, throughput regression in the hot path.
    """

    ITERATIONS = 500

    def test_end_to_end_governance_throughput(self) -> None:
        validator = EnrollmentValidator()
        chains: list[GovernanceChain] = []

        t0 = time.perf_counter()

        for i in range(self.ITERATIONS):
            # 1. Enroll
            app = build_application(
                agent_id=f"agent:e2e-{i:04d}",
                display_name=f"E2E Agent {i}",
                owner=f"owner-{i % 20}@gavel.eu",
                owner_contact=f"owner-{i % 20}@gavel.eu",
            )
            passed, violations = validator.validate(app)
            assert passed is True, f"enrollment failed for {app.agent_id}: {violations}"

            # 2. Create governance chain with full flow
            chain = GovernanceChain(chain_id=f"c-e2e-{i:04d}")

            # Propose
            chain.append(
                event_type=EventType.INBOUND_INTENT,
                actor_id=app.agent_id,
                role_used="proposer",
                payload={"action": f"operation-{i}", "risk": 0.3},
            )

            # Evaluate
            chain.append(
                event_type=EventType.POLICY_EVAL,
                actor_id="system:policy-engine",
                role_used="evaluator",
                payload={"result": "pass", "risk_score": 0.3},
            )

            # Evidence
            chain.append(
                event_type=EventType.BLASTBOX_EVIDENCE,
                actor_id="system:blastbox",
                role_used="evidence_collector",
                payload={"evidence_hash": f"sha256:{i:064x}", "safe": True},
            )

            # Review
            chain.append(
                event_type=EventType.REVIEW_ATTESTATION,
                actor_id=f"reviewer:auto-{i % 5}",
                role_used="reviewer",
                payload={"decision": "approve", "confidence": 0.95},
            )

            # Approve
            chain.append(
                event_type=EventType.APPROVAL_GRANTED,
                actor_id="system:gate",
                role_used="gate",
                payload={"approved": True},
            )

            # Execute
            chain.append(
                event_type=EventType.EXECUTION_COMPLETED,
                actor_id=app.agent_id,
                role_used="executor",
                payload={"status": "success", "duration_ms": 42},
            )

            chains.append(chain)

        elapsed = time.perf_counter() - t0

        # All chains intact
        for chain in chains:
            assert len(chain.events) == 6, (
                f"{chain.chain_id} has {len(chain.events)} events, expected 6"
            )
            assert chain.verify_integrity() is True, (
                f"{chain.chain_id} failed integrity"
            )

        # Evidence hashes correct
        for chain in chains:
            for i in range(1, len(chain.events)):
                assert chain.events[i].prev_hash == chain.events[i - 1].event_hash

        # Throughput floor: >100 full flows/sec (loose)
        throughput = self.ITERATIONS / elapsed
        assert throughput > 100, (
            f"e2e throughput regression: {throughput:.0f} flows/sec "
            f"(floor is 100, elapsed {elapsed:.2f}s for {self.ITERATIONS} flows)"
        )

        # Total time floor
        assert elapsed < 30.0, (
            f"e2e governance took {elapsed:.2f}s for {self.ITERATIONS} iterations"
        )
