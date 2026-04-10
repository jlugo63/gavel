"""Tests for gavel.evasion — oversight evasion detection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gavel.evasion import (
    ActivityRecord,
    EvasionSignal,
    OversightEvasionDetector,
)


def _mk(agent: str, at: datetime, **kw) -> ActivityRecord:
    defaults = dict(
        chain_id=f"c-{int(at.timestamp())}",
        action_type="FILE_WRITE",
        risk_score=0.1,
        touched_paths=["src/app.py"],
        reviewer_id="agent:reviewer",
        oversight_window_active=True,
    )
    defaults.update(kw)
    return ActivityRecord(agent_id=agent, submitted_at=at, **defaults)


class TestFragmentation:
    def test_detects_fragmented_low_risk_burst(self):
        det = OversightEvasionDetector()
        start = datetime.now(timezone.utc)
        findings: list = []
        # 8 low-risk proposals within 10 min, total risk > 0.6
        for i in range(8):
            at = start + timedelta(minutes=i)
            findings += det.observe(_mk("agent:a", at, risk_score=0.1, chain_id=f"c-{i}"))
        frag = [f for f in findings if f.signal == EvasionSignal.FRAGMENTED_ACTIONS]
        assert frag, "expected fragmentation finding"
        assert frag[-1].supporting_chain_ids

    def test_no_fragmentation_when_under_threshold(self):
        det = OversightEvasionDetector()
        start = datetime.now(timezone.utc)
        findings: list = []
        for i in range(3):
            findings += det.observe(_mk("agent:a", start + timedelta(minutes=i)))
        assert not any(f.signal == EvasionSignal.FRAGMENTED_ACTIONS for f in findings)


class TestTimingArbitrage:
    def test_detects_out_of_window_dominance(self):
        det = OversightEvasionDetector()
        start = datetime.now(timezone.utc)
        findings: list = []
        for i in range(5):
            findings += det.observe(_mk(
                "agent:a",
                start + timedelta(minutes=i),
                oversight_window_active=False,
                chain_id=f"c-{i}",
            ))
        assert any(f.signal == EvasionSignal.TIMING_ARBITRAGE for f in findings)

    def test_in_window_does_not_trigger(self):
        det = OversightEvasionDetector()
        start = datetime.now(timezone.utc)
        findings: list = []
        for i in range(5):
            findings += det.observe(_mk("agent:a", start + timedelta(minutes=i)))
        assert not any(f.signal == EvasionSignal.TIMING_ARBITRAGE for f in findings)


class TestReviewerRotationAbuse:
    def test_detects_narrow_reviewer_pool(self):
        det = OversightEvasionDetector()
        start = datetime.now(timezone.utc)
        findings: list = []
        for i in range(12):
            findings += det.observe(_mk(
                "agent:a",
                start + timedelta(seconds=i * 10),
                reviewer_id="agent:only-reviewer",
                chain_id=f"c-{i}",
            ))
        assert any(f.signal == EvasionSignal.REVIEWER_ROTATION_ABUSE for f in findings)

    def test_diverse_reviewers_ok(self):
        det = OversightEvasionDetector()
        start = datetime.now(timezone.utc)
        findings: list = []
        reviewers = ["agent:r1", "agent:r2", "agent:r3", "agent:r4"]
        for i in range(12):
            findings += det.observe(_mk(
                "agent:a",
                start + timedelta(seconds=i * 10),
                reviewer_id=reviewers[i % 4],
                chain_id=f"c-{i}",
            ))
        assert not any(f.signal == EvasionSignal.REVIEWER_ROTATION_ABUSE for f in findings)


class TestScopeCreep:
    def test_detects_out_of_scope_paths(self):
        det = OversightEvasionDetector()
        det.declare_scope("agent:a", ["src/"])
        findings = det.observe(_mk(
            "agent:a",
            datetime.now(timezone.utc),
            touched_paths=["src/app.py", "/etc/passwd", "secrets/key.pem"],
        ))
        creep = [f for f in findings if f.signal == EvasionSignal.SCOPE_CREEP]
        assert creep
        assert "/etc/passwd" in creep[0].detail or "secrets" in creep[0].detail

    def test_no_scope_declaration_no_detection(self):
        det = OversightEvasionDetector()
        findings = det.observe(_mk(
            "agent:a",
            datetime.now(timezone.utc),
            touched_paths=["/etc/passwd"],
        ))
        assert not any(f.signal == EvasionSignal.SCOPE_CREEP for f in findings)


class TestKillSwitchEvasion:
    def test_reregister_under_new_id_flagged(self):
        det = OversightEvasionDetector()
        det.mark_suspended("agent:old", owner="ops-team", display_name="deploy-bot")
        findings = det.observe_enrollment(
            "agent:new", owner="ops-team", display_name="deploy-bot"
        )
        assert findings
        assert findings[0].signal == EvasionSignal.KILL_SWITCH_EVASION

    def test_legitimate_new_agent_ok(self):
        det = OversightEvasionDetector()
        det.mark_suspended("agent:old", owner="ops-team", display_name="deploy-bot")
        findings = det.observe_enrollment(
            "agent:legit", owner="different-team", display_name="different-bot"
        )
        assert not findings


class TestHeartbeatBurst:
    def test_detects_quiet_then_burst(self):
        det = OversightEvasionDetector()
        start = datetime.now(timezone.utc)
        findings: list = []
        # One old event
        findings += det.observe(_mk("agent:a", start, chain_id="c-0"))
        # Long quiet gap, then 6 events in a minute
        burst_start = start + timedelta(minutes=60)
        for i in range(6):
            findings += det.observe(_mk(
                "agent:a",
                burst_start + timedelta(seconds=i * 10),
                chain_id=f"c-burst-{i}",
            ))
        assert any(f.signal == EvasionSignal.HEARTBEAT_BURST for f in findings)
