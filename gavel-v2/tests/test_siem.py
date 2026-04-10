import pytest
from datetime import datetime, timedelta, timezone

from gavel.siem import (
    GovernanceEventCategory,
    GovernanceEvent,
    GovernanceEventStream,
    AnomalyDetector,
    AnomalyType,
    UnregisteredAgentMonitor,
    ComplianceScorer,
    TimelineReconstructor,
    SIEMForwarder,
    SIEMFormat,
)


def _make_event(category=GovernanceEventCategory.DECISION, event_type="test.event",
                endpoint_id="ep-1", agent_id="agent-1", severity="info",
                summary="test", timestamp=None, **details):
    return GovernanceEvent(
        category=category,
        event_type=event_type,
        endpoint_id=endpoint_id,
        agent_id=agent_id,
        severity=severity,
        summary=summary,
        timestamp=timestamp or datetime.now(timezone.utc),
        details=details,
    )


# ── GovernanceEventStream ──────────────────────────────────


class TestGovernanceEventStream:

    def test_emit_and_recent(self):
        stream = GovernanceEventStream()
        e = stream.emit(GovernanceEventCategory.ENROLLMENT, "agent.enrolled",
                        endpoint_id="ep-1", agent_id="a-1", summary="enrolled")
        assert e.category == GovernanceEventCategory.ENROLLMENT
        assert stream.total == 1
        assert stream.recent(10) == [e]

    def test_recent_limits_count(self):
        stream = GovernanceEventStream()
        for i in range(10):
            stream.emit(GovernanceEventCategory.HEARTBEAT, f"hb.{i}")
        assert len(stream.recent(3)) == 3

    def test_by_category(self):
        stream = GovernanceEventStream()
        stream.emit(GovernanceEventCategory.ENROLLMENT, "e1")
        stream.emit(GovernanceEventCategory.DECISION, "d1")
        stream.emit(GovernanceEventCategory.ENROLLMENT, "e2")
        assert len(stream.by_category(GovernanceEventCategory.ENROLLMENT)) == 2
        assert len(stream.by_category(GovernanceEventCategory.DECISION)) == 1

    def test_by_endpoint(self):
        stream = GovernanceEventStream()
        stream.emit(GovernanceEventCategory.DECISION, "x", endpoint_id="ep-A")
        stream.emit(GovernanceEventCategory.DECISION, "y", endpoint_id="ep-B")
        assert len(stream.by_endpoint("ep-A")) == 1

    def test_by_agent(self):
        stream = GovernanceEventStream()
        stream.emit(GovernanceEventCategory.DECISION, "x", agent_id="ag-1")
        stream.emit(GovernanceEventCategory.DECISION, "y", agent_id="ag-2")
        assert len(stream.by_agent("ag-1")) == 1

    def test_by_severity(self):
        stream = GovernanceEventStream()
        stream.emit(GovernanceEventCategory.VIOLATION, "v1", severity="critical")
        stream.emit(GovernanceEventCategory.DECISION, "d1", severity="info")
        assert len(stream.by_severity("critical")) == 1

    def test_in_window(self):
        stream = GovernanceEventStream()
        now = datetime.now(timezone.utc)
        stream.emit(GovernanceEventCategory.DECISION, "old")
        stream._events[-1].timestamp = now - timedelta(hours=2)
        stream.emit(GovernanceEventCategory.DECISION, "recent")
        stream._events[-1].timestamp = now
        start = now - timedelta(hours=1)
        assert len(stream.in_window(start, now)) == 1

    def test_subscribe_unsubscribe(self):
        stream = GovernanceEventStream()
        stream.subscribe("sub-1")
        stream.subscribe("sub-2")
        stream.subscribe("sub-1")  # duplicate
        assert stream.subscribers == ["sub-1", "sub-2"]
        stream.unsubscribe("sub-1")
        assert stream.subscribers == ["sub-2"]

    def test_max_events_cap(self):
        stream = GovernanceEventStream(max_events=5)
        for i in range(10):
            stream.emit(GovernanceEventCategory.HEARTBEAT, f"hb.{i}")
        assert stream.total == 5


# ── AnomalyDetector ────────────────────────────────────────


class TestAnomalyDetector:

    def test_detect_volume_anomaly_needs_history(self):
        detector = AnomalyDetector()
        events = [_make_event(agent_id="a1") for _ in range(3)]
        # First two calls build history, no findings yet
        assert detector.detect_volume_anomaly(events) == []
        assert detector.detect_volume_anomaly(events) == []

    def test_detect_volume_anomaly_triggers_on_spike(self):
        detector = AnomalyDetector(volume_threshold_sigma=1.5)
        detector.detect_volume_anomaly([_make_event(agent_id="a1") for _ in range(2)])
        detector.detect_volume_anomaly([_make_event(agent_id="a1") for _ in range(3)])
        detector.detect_volume_anomaly([_make_event(agent_id="a1") for _ in range(2)])
        spike = [_make_event(agent_id="a1") for _ in range(20)]
        findings = detector.detect_volume_anomaly(spike)
        assert len(findings) == 1
        assert findings[0].anomaly_type == AnomalyType.UNUSUAL_VOLUME
        assert findings[0].observed_value == 20.0

    def test_detect_volume_anomaly_no_trigger_on_stable(self):
        detector = AnomalyDetector()
        events = [_make_event(agent_id="a1") for _ in range(3)]
        for _ in range(5):
            detector.detect_volume_anomaly(events)
        # Stable counts should not trigger
        findings = detector.detect_volume_anomaly(events)
        assert findings == []

    def test_detect_denial_spike_triggers(self):
        detector = AnomalyDetector()
        events = []
        for i in range(6):
            events.append(_make_event(
                category=GovernanceEventCategory.DECISION,
                event_type="chain.denied" if i < 4 else "chain.allowed",
                agent_id="a1",
            ))
        findings = detector.detect_denial_spike(events)
        assert len(findings) == 1
        assert findings[0].anomaly_type == AnomalyType.DENIAL_SPIKE
        assert findings[0].evidence["denials"] == 4

    def test_detect_denial_spike_no_trigger_below_threshold(self):
        detector = AnomalyDetector()
        events = [
            _make_event(category=GovernanceEventCategory.DECISION,
                        event_type="chain.denied", agent_id="a1"),
            _make_event(category=GovernanceEventCategory.DECISION,
                        event_type="chain.allowed", agent_id="a1"),
        ]
        # Only 2 events, need >=5
        assert detector.detect_denial_spike(events) == []

    def test_detect_rapid_enrollment(self):
        detector = AnomalyDetector()
        events = [
            _make_event(category=GovernanceEventCategory.ENROLLMENT,
                        endpoint_id="ep-X")
            for _ in range(5)
        ]
        findings = detector.detect_rapid_enrollment(events)
        assert len(findings) == 1
        assert findings[0].anomaly_type == AnomalyType.RAPID_ENROLLMENT
        assert findings[0].endpoint_id == "ep-X"

    def test_detect_rapid_enrollment_below_threshold(self):
        detector = AnomalyDetector()
        events = [
            _make_event(category=GovernanceEventCategory.ENROLLMENT, endpoint_id="ep-Y")
            for _ in range(4)
        ]
        assert detector.detect_rapid_enrollment(events) == []

    def test_analyze_combines_all(self):
        detector = AnomalyDetector()
        enrollment_events = [
            _make_event(category=GovernanceEventCategory.ENROLLMENT, endpoint_id="ep-Z")
            for _ in range(6)
        ]
        denial_events = [
            _make_event(category=GovernanceEventCategory.DECISION,
                        event_type="action.denied", agent_id="b1")
            for _ in range(6)
        ]
        all_events = enrollment_events + denial_events
        findings = detector.analyze(all_events)
        types = {f.anomaly_type for f in findings}
        assert AnomalyType.RAPID_ENROLLMENT in types
        assert AnomalyType.DENIAL_SPIKE in types
        assert detector.all_findings == findings


# ── UnregisteredAgentMonitor ───────────────────────────────


class TestUnregisteredAgentMonitor:

    def test_set_baseline_and_scan_no_new(self):
        monitor = UnregisteredAgentMonitor()
        monitor.set_baseline("ep-1", ["copilot", "cursor"])
        alerts = monitor.scan("ep-1", ["copilot", "cursor"])
        assert alerts == []

    def test_scan_detects_new_tools(self):
        monitor = UnregisteredAgentMonitor()
        monitor.set_baseline("ep-1", ["copilot"])
        alerts = monitor.scan("ep-1", ["copilot", "cursor", "aider"], hostname="ws-01")
        assert len(alerts) == 2
        tool_names = {a.tool_name for a in alerts}
        assert tool_names == {"cursor", "aider"}
        assert alerts[0].hostname == "ws-01"

    def test_acknowledge(self):
        monitor = UnregisteredAgentMonitor()
        monitor.set_baseline("ep-1", [])
        alerts = monitor.scan("ep-1", ["newagent"])
        assert len(monitor.unacknowledged) == 1
        assert monitor.acknowledge(alerts[0].alert_id) is True
        assert len(monitor.unacknowledged) == 0
        assert monitor.acknowledge("nonexistent") is False


# ── ComplianceScorer ───────────────────────────────────────


class TestComplianceScorer:

    def test_score_machine_all_pass(self):
        scorer = ComplianceScorer()
        atf = {c: True for c in scorer.ATF_CHECKS}
        eu = {c: True for c in scorer.EU_AI_ACT_CHECKS}
        result = scorer.score_machine("ep-1", hostname="ws-1", atf_results=atf, eu_results=eu)
        assert result.atf_score == 1.0
        assert result.eu_ai_act_score == 1.0
        assert result.combined_score == 1.0
        assert len(result.checks) == len(scorer.ATF_CHECKS) + len(scorer.EU_AI_ACT_CHECKS)

    def test_score_machine_none_pass(self):
        scorer = ComplianceScorer()
        result = scorer.score_machine("ep-2")
        assert result.atf_score == 0.0
        assert result.eu_ai_act_score == 0.0

    def test_score_org(self):
        scorer = ComplianceScorer()
        m1 = scorer.score_machine("ep-1", atf_results={c: True for c in scorer.ATF_CHECKS},
                                  eu_results={c: True for c in scorer.EU_AI_ACT_CHECKS})
        m2 = scorer.score_machine("ep-2")
        org = scorer.score_org("org-1", [m1, m2])
        assert org.total_machines == 2
        assert org.compliant_machines == 1  # only m1 has combined >= 0.9
        assert org.atf_score == pytest.approx(0.5, abs=0.01)

    def test_score_org_empty(self):
        scorer = ComplianceScorer()
        org = scorer.score_org("org-empty", [])
        assert org.total_machines == 0
        assert org.combined_score == 0.0


# ── TimelineReconstructor ──────────────────────────────────


class TestTimelineReconstructor:

    def test_reconstruct_sorted_chronologically(self):
        recon = TimelineReconstructor()
        now = datetime.now(timezone.utc)
        events = [
            _make_event(endpoint_id="ep-2", agent_id="a2", summary="second",
                        timestamp=now + timedelta(seconds=10)),
            _make_event(endpoint_id="ep-1", agent_id="a1", summary="first",
                        timestamp=now),
            _make_event(endpoint_id="ep-1", agent_id="a3", summary="third",
                        timestamp=now + timedelta(seconds=20)),
        ]
        tl = recon.reconstruct(events, title="incident-1")
        assert tl.title == "incident-1"
        assert [e.summary for e in tl.entries] == ["first", "second", "third"]
        assert tl.endpoints_involved == ["ep-1", "ep-2"]
        assert tl.agents_involved == ["a1", "a2", "a3"]
        assert tl.start_time == now
        assert tl.end_time == now + timedelta(seconds=20)
        assert recon.all_timelines[0].timeline_id == tl.timeline_id


# ── SIEMForwarder ──────────────────────────────────────────


class TestSIEMForwarder:

    def test_add_remove_destination(self):
        fwd = SIEMForwarder()
        dest = fwd.add_destination("splunk", SIEMFormat.JSON, endpoint_url="https://splunk:8088")
        assert len(fwd.destinations) == 1
        assert fwd.remove_destination(dest.destination_id) is True
        assert len(fwd.destinations) == 0
        assert fwd.remove_destination("nonexistent") is False

    def test_format_cef(self):
        fwd = SIEMForwarder()
        event = _make_event(severity="high", summary="violation detected")
        cef = fwd.format_cef(event)
        assert cef.startswith("CEF:0|Gavel|GovernanceHub|1.0|")
        assert "|8|" in cef
        assert "violation detected" in cef

    def test_format_json(self):
        fwd = SIEMForwarder()
        event = _make_event(agent_id="ag-x", summary="test json")
        result = fwd.format_json(event)
        assert result["source"] == "gavel-hub"
        assert result["event"]["agent_id"] == "ag-x"
        assert result["event"]["summary"] == "test json"

    def test_format_syslog(self):
        fwd = SIEMForwarder()
        event = _make_event(severity="warning", summary="warn msg")
        syslog = fwd.format_syslog(event)
        assert syslog.startswith("<12>1 ")
        assert "warn msg" in syslog

    def test_forward_with_filter(self):
        fwd = SIEMForwarder()
        fwd.add_destination("filtered", SIEMFormat.JSON, event_filter=["agent.enrolled"])
        event_match = _make_event(event_type="agent.enrolled")
        event_miss = _make_event(event_type="chain.denied")
        assert len(fwd.forward(event_match)) == 1
        assert len(fwd.forward(event_miss)) == 0

    def test_forward_batch(self):
        fwd = SIEMForwarder()
        fwd.add_destination("all-events", SIEMFormat.CEF)
        fwd.add_destination("all-json", SIEMFormat.JSON)
        events = [_make_event() for _ in range(3)]
        count = fwd.forward_batch(events)
        assert count == 6  # 3 events * 2 destinations
        assert fwd.forwarded_count == 6
