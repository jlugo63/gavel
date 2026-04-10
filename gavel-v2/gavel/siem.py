"""
SIEM Integration & EDR-Style Monitoring — governance event stream, anomaly
detection, compliance scoring, incident timeline, and SIEM forwarding.

This module provides the monitoring and alerting layer for network-wide
agent governance:

  1. GovernanceEventStream — real-time feed of all governance events org-wide
  2. AnomalyDetector — unusual agent behavior patterns across the fleet
  3. ComplianceScorer — per-machine and org-wide ATF/EU AI Act compliance %
  4. IncidentTimeline — reconstruct what happened across multiple machines
  5. SIEMForwarder — forward governance events to Splunk, Sentinel, Elastic
  6. UnregisteredAgentMonitor — new AI tool detection + immediate notification

Design:
  - Deterministic anomaly scoring (z-score-like but without numpy)
  - SIEM output in CEF (Common Event Format) and JSON/Syslog
  - All state is in-memory + serializable via Pydantic
"""

from __future__ import annotations

import hashlib
import math
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Governance Event Stream ──────────────────────────────────

class GovernanceEventCategory(str, Enum):
    ENROLLMENT = "enrollment"
    DECISION = "decision"
    VIOLATION = "violation"
    HEARTBEAT = "heartbeat"
    POLICY = "policy"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    FLEET = "fleet"


class GovernanceEvent(BaseModel):
    """A single governance event in the org-wide stream."""
    event_id: str = Field(default_factory=lambda: f"ge-{uuid.uuid4().hex[:8]}")
    category: GovernanceEventCategory
    event_type: str                    # e.g. "agent.enrolled", "chain.denied"
    endpoint_id: str = ""
    agent_id: str = ""
    org_id: str = ""
    team_id: str = ""
    severity: str = "info"             # info, warning, high, critical
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GovernanceEventStream:
    """Real-time feed of all enrollments, decisions, violations org-wide."""

    def __init__(self, max_events: int = 10000):
        self._events: deque[GovernanceEvent] = deque(maxlen=max_events)
        self._subscribers: list[str] = []  # subscriber IDs for push notifications

    def emit(self, category: GovernanceEventCategory, event_type: str,
             endpoint_id: str = "", agent_id: str = "", org_id: str = "",
             team_id: str = "", severity: str = "info", summary: str = "",
             **details) -> GovernanceEvent:
        event = GovernanceEvent(
            category=category,
            event_type=event_type,
            endpoint_id=endpoint_id,
            agent_id=agent_id,
            org_id=org_id,
            team_id=team_id,
            severity=severity,
            summary=summary,
            details=details,
        )
        self._events.append(event)
        return event

    def recent(self, count: int = 100) -> list[GovernanceEvent]:
        items = list(self._events)
        return items[-count:]

    def by_category(self, category: GovernanceEventCategory) -> list[GovernanceEvent]:
        return [e for e in self._events if e.category == category]

    def by_endpoint(self, endpoint_id: str) -> list[GovernanceEvent]:
        return [e for e in self._events if e.endpoint_id == endpoint_id]

    def by_agent(self, agent_id: str) -> list[GovernanceEvent]:
        return [e for e in self._events if e.agent_id == agent_id]

    def by_severity(self, severity: str) -> list[GovernanceEvent]:
        return [e for e in self._events if e.severity == severity]

    def in_window(self, start: datetime, end: datetime) -> list[GovernanceEvent]:
        return [e for e in self._events if start <= e.timestamp <= end]

    def subscribe(self, subscriber_id: str) -> None:
        if subscriber_id not in self._subscribers:
            self._subscribers.append(subscriber_id)

    def unsubscribe(self, subscriber_id: str) -> None:
        if subscriber_id in self._subscribers:
            self._subscribers.remove(subscriber_id)

    @property
    def total(self) -> int:
        return len(self._events)

    @property
    def subscribers(self) -> list[str]:
        return list(self._subscribers)


# ── Anomaly Detection ────────────────────────────────────────

class AnomalyType(str, Enum):
    UNUSUAL_VOLUME = "unusual_volume"             # Spike in events from one agent/endpoint
    OFF_HOURS_ACTIVITY = "off_hours_activity"     # Activity outside normal working hours
    RAPID_ENROLLMENT = "rapid_enrollment"         # Many agents enrolling in burst
    DENIAL_SPIKE = "denial_spike"                 # Surge in denied actions
    NEW_TOOL_PATTERN = "new_tool_pattern"         # Agent using tools it hasn't used before
    CROSS_MACHINE_SPIKE = "cross_machine_spike"   # Agent suddenly active on many machines


class AnomalyFinding(BaseModel):
    """A detected anomaly in fleet-wide agent behavior."""
    finding_id: str = Field(default_factory=lambda: f"anom-{uuid.uuid4().hex[:8]}")
    anomaly_type: AnomalyType
    severity: str = "medium"
    agent_id: str = ""
    endpoint_id: str = ""
    description: str = ""
    score: float = 0.0               # Anomaly score (higher = more anomalous)
    baseline_value: float = 0.0      # Expected normal value
    observed_value: float = 0.0      # What we actually saw
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: dict[str, Any] = Field(default_factory=dict)


class AnomalyDetector:
    """Detect unusual agent behavior patterns across the fleet."""

    def __init__(self, volume_window_minutes: int = 60, volume_threshold_sigma: float = 2.0):
        self._findings: list[AnomalyFinding] = []
        self._volume_window = timedelta(minutes=volume_window_minutes)
        self._volume_threshold = volume_threshold_sigma
        # Rolling statistics per agent
        self._agent_event_counts: dict[str, list[int]] = defaultdict(list)  # agent_id -> [count per window]

    def _mean_std(self, values: list[int | float]) -> tuple[float, float]:
        """Compute mean and standard deviation without numpy."""
        if not values:
            return 0.0, 0.0
        n = len(values)
        mean = sum(values) / n
        if n < 2:
            return mean, 0.0
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        return mean, math.sqrt(variance)

    def detect_volume_anomaly(self, events: list[GovernanceEvent]) -> list[AnomalyFinding]:
        """Detect unusual event volume per agent."""
        findings = []
        # Count events per agent
        agent_counts: dict[str, int] = defaultdict(int)
        for e in events:
            if e.agent_id:
                agent_counts[e.agent_id] += 1

        for agent_id, count in agent_counts.items():
            self._agent_event_counts[agent_id].append(count)
            history = self._agent_event_counts[agent_id]
            if len(history) < 3:
                continue
            mean, std = self._mean_std(history[:-1])  # Compare against prior windows
            if std > 0 and (count - mean) / std > self._volume_threshold:
                score = (count - mean) / std
                finding = AnomalyFinding(
                    anomaly_type=AnomalyType.UNUSUAL_VOLUME,
                    severity="high" if score > 3.0 else "medium",
                    agent_id=agent_id,
                    description=f"Agent {agent_id} generated {count} events (baseline: {mean:.1f} ± {std:.1f})",
                    score=round(score, 2),
                    baseline_value=round(mean, 2),
                    observed_value=float(count),
                    evidence={"history": history[-10:]},
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def detect_denial_spike(self, events: list[GovernanceEvent]) -> list[AnomalyFinding]:
        """Detect surge in denied actions per agent."""
        findings = []
        agent_denials: dict[str, int] = defaultdict(int)
        agent_total: dict[str, int] = defaultdict(int)

        for e in events:
            if e.agent_id and e.category == GovernanceEventCategory.DECISION:
                agent_total[e.agent_id] += 1
                if e.event_type in ("chain.denied", "action.denied"):
                    agent_denials[e.agent_id] += 1

        for agent_id, denials in agent_denials.items():
            total = agent_total.get(agent_id, 0)
            if total >= 5 and denials / total > 0.5:
                denial_rate = denials / total
                finding = AnomalyFinding(
                    anomaly_type=AnomalyType.DENIAL_SPIKE,
                    severity="high",
                    agent_id=agent_id,
                    description=f"Agent {agent_id}: {denials}/{total} actions denied ({denial_rate:.0%})",
                    score=round(denial_rate * 10, 2),
                    baseline_value=0.1,
                    observed_value=round(denial_rate, 3),
                    evidence={"denials": denials, "total": total},
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def detect_rapid_enrollment(self, events: list[GovernanceEvent],
                                 threshold: int = 5) -> list[AnomalyFinding]:
        """Detect burst of agent enrollments on a single endpoint."""
        findings = []
        endpoint_enrollments: dict[str, int] = defaultdict(int)

        for e in events:
            if e.category == GovernanceEventCategory.ENROLLMENT:
                endpoint_enrollments[e.endpoint_id] += 1

        for endpoint_id, count in endpoint_enrollments.items():
            if count >= threshold:
                finding = AnomalyFinding(
                    anomaly_type=AnomalyType.RAPID_ENROLLMENT,
                    severity="high",
                    endpoint_id=endpoint_id,
                    description=f"Endpoint {endpoint_id}: {count} agents enrolled in window",
                    score=float(count),
                    baseline_value=1.0,
                    observed_value=float(count),
                    evidence={"enrollment_count": count},
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def analyze(self, events: list[GovernanceEvent]) -> list[AnomalyFinding]:
        """Run all anomaly detectors."""
        results = []
        results.extend(self.detect_volume_anomaly(events))
        results.extend(self.detect_denial_spike(events))
        results.extend(self.detect_rapid_enrollment(events))
        return results

    @property
    def all_findings(self) -> list[AnomalyFinding]:
        return list(self._findings)


# ── Unregistered Agent Monitor ───────────────────────────────

class UnregisteredAgentAlert(BaseModel):
    """Alert for a new AI tool detected on a machine that isn't enrolled in Gavel."""
    alert_id: str = Field(default_factory=lambda: f"ura-{uuid.uuid4().hex[:8]}")
    endpoint_id: str
    hostname: str = ""
    tool_name: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    resolved: bool = False


class UnregisteredAgentMonitor:
    """New AI tool installed on a machine → immediate notification."""

    def __init__(self):
        self._known_tools: dict[str, set[str]] = defaultdict(set)  # endpoint_id -> {tool_names}
        self._alerts: list[UnregisteredAgentAlert] = []

    def set_baseline(self, endpoint_id: str, tools: list[str]) -> None:
        self._known_tools[endpoint_id] = set(tools)

    def scan(self, endpoint_id: str, current_tools: list[str],
             hostname: str = "") -> list[UnregisteredAgentAlert]:
        known = self._known_tools.get(endpoint_id, set())
        new_tools = set(current_tools) - known
        alerts = []
        for tool in new_tools:
            alert = UnregisteredAgentAlert(
                endpoint_id=endpoint_id,
                hostname=hostname,
                tool_name=tool,
            )
            alerts.append(alert)
            self._alerts.append(alert)
        # Update known set
        self._known_tools[endpoint_id] = set(current_tools)
        return alerts

    def acknowledge(self, alert_id: str) -> bool:
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    @property
    def unacknowledged(self) -> list[UnregisteredAgentAlert]:
        return [a for a in self._alerts if not a.acknowledged]

    @property
    def all_alerts(self) -> list[UnregisteredAgentAlert]:
        return list(self._alerts)


# ── Compliance Scoring ───────────────────────────────────────

class ComplianceFramework(str, Enum):
    ATF = "atf"                  # Agentic Trust Framework
    EU_AI_ACT = "eu_ai_act"
    COMBINED = "combined"


class ComplianceCheckResult(BaseModel):
    """Result of a single compliance check."""
    check_name: str
    framework: ComplianceFramework
    passed: bool
    weight: float = 1.0
    details: str = ""


class MachineComplianceScore(BaseModel):
    """Compliance score for a single machine."""
    endpoint_id: str
    hostname: str = ""
    checks: list[ComplianceCheckResult] = Field(default_factory=list)
    atf_score: float = 0.0          # 0.0 - 1.0
    eu_ai_act_score: float = 0.0
    combined_score: float = 0.0
    scored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OrgComplianceScore(BaseModel):
    """Org-wide compliance aggregate."""
    org_id: str
    machine_scores: list[MachineComplianceScore] = Field(default_factory=list)
    atf_score: float = 0.0
    eu_ai_act_score: float = 0.0
    combined_score: float = 0.0
    total_machines: int = 0
    compliant_machines: int = 0
    scored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceScorer:
    """Per-machine and org-wide ATF/EU AI Act compliance percentage."""

    ATF_CHECKS = [
        "I-1_agent_identity", "I-2_did_binding", "I-3_enrollment_validation",
        "I-4_purpose_declaration", "I-5_capability_manifest",
        "S-1_resource_allowlist", "S-2_action_boundaries", "S-3_default_deny",
        "B-1_governance_chain", "B-2_approval_flow", "B-3_behavioral_baseline",
        "D-1_audit_ledger", "D-2_evidence_packets", "D-3_pii_protection",
        "R-1_kill_switch", "R-2_drift_detection", "R-3_escalation", "R-4_rollback",
        "T-1_separation_of_powers", "T-2_tamper_detection", "T-3_hash_chain",
        "T-4_witness", "T-5_artifact_export",
        "G-1_constitution", "G-2_policy_engine",
    ]

    EU_AI_ACT_CHECKS = [
        "art9_risk_management", "art10_data_governance", "art11_documentation",
        "art12_record_keeping", "art13_transparency", "art14_human_oversight",
        "art15_accuracy_robustness", "art17_qms", "art27_fria",
        "art5_prohibited_practices", "art72_post_market", "art73_incidents",
    ]

    def score_machine(self, endpoint_id: str, hostname: str = "",
                      atf_results: dict[str, bool] | None = None,
                      eu_results: dict[str, bool] | None = None) -> MachineComplianceScore:
        checks = []
        atf_results = atf_results or {}
        eu_results = eu_results or {}

        # ATF checks
        atf_passed = 0
        for check_name in self.ATF_CHECKS:
            passed = atf_results.get(check_name, False)
            checks.append(ComplianceCheckResult(
                check_name=check_name, framework=ComplianceFramework.ATF, passed=passed
            ))
            if passed:
                atf_passed += 1

        # EU AI Act checks
        eu_passed = 0
        for check_name in self.EU_AI_ACT_CHECKS:
            passed = eu_results.get(check_name, False)
            checks.append(ComplianceCheckResult(
                check_name=check_name, framework=ComplianceFramework.EU_AI_ACT, passed=passed
            ))
            if passed:
                eu_passed += 1

        atf_score = atf_passed / len(self.ATF_CHECKS) if self.ATF_CHECKS else 0.0
        eu_score = eu_passed / len(self.EU_AI_ACT_CHECKS) if self.EU_AI_ACT_CHECKS else 0.0
        combined = (atf_score + eu_score) / 2

        return MachineComplianceScore(
            endpoint_id=endpoint_id,
            hostname=hostname,
            checks=checks,
            atf_score=round(atf_score, 3),
            eu_ai_act_score=round(eu_score, 3),
            combined_score=round(combined, 3),
        )

    def score_org(self, org_id: str,
                  machine_scores: list[MachineComplianceScore]) -> OrgComplianceScore:
        if not machine_scores:
            return OrgComplianceScore(org_id=org_id)

        atf_avg = sum(m.atf_score for m in machine_scores) / len(machine_scores)
        eu_avg = sum(m.eu_ai_act_score for m in machine_scores) / len(machine_scores)
        combined_avg = sum(m.combined_score for m in machine_scores) / len(machine_scores)
        compliant = len([m for m in machine_scores if m.combined_score >= 0.9])

        return OrgComplianceScore(
            org_id=org_id,
            machine_scores=machine_scores,
            atf_score=round(atf_avg, 3),
            eu_ai_act_score=round(eu_avg, 3),
            combined_score=round(combined_avg, 3),
            total_machines=len(machine_scores),
            compliant_machines=compliant,
        )


# ── Incident Timeline ────────────────────────────────────────

class TimelineEntry(BaseModel):
    """A single entry in a cross-machine incident timeline."""
    entry_id: str = Field(default_factory=lambda: f"tle-{uuid.uuid4().hex[:8]}")
    timestamp: datetime
    endpoint_id: str = ""
    agent_id: str = ""
    event_type: str = ""
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"


class IncidentTimeline(BaseModel):
    """Reconstructed timeline of what happened across multiple machines."""
    timeline_id: str = Field(default_factory=lambda: f"tl-{uuid.uuid4().hex[:8]}")
    title: str = ""
    entries: list[TimelineEntry] = Field(default_factory=list)
    endpoints_involved: list[str] = Field(default_factory=list)
    agents_involved: list[str] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TimelineReconstructor:
    """Reconstruct exactly what happened across multiple machines."""

    def __init__(self):
        self._timelines: list[IncidentTimeline] = []

    def reconstruct(self, events: list[GovernanceEvent],
                    title: str = "") -> IncidentTimeline:
        """Build a timeline from governance events, sorted chronologically."""
        entries = []
        endpoints = set()
        agents = set()

        for event in sorted(events, key=lambda e: e.timestamp):
            entry = TimelineEntry(
                timestamp=event.timestamp,
                endpoint_id=event.endpoint_id,
                agent_id=event.agent_id,
                event_type=event.event_type,
                summary=event.summary,
                details=event.details,
                severity=event.severity,
            )
            entries.append(entry)
            if event.endpoint_id:
                endpoints.add(event.endpoint_id)
            if event.agent_id:
                agents.add(event.agent_id)

        timeline = IncidentTimeline(
            title=title,
            entries=entries,
            endpoints_involved=sorted(endpoints),
            agents_involved=sorted(agents),
            start_time=entries[0].timestamp if entries else None,
            end_time=entries[-1].timestamp if entries else None,
        )
        self._timelines.append(timeline)
        return timeline

    def get(self, timeline_id: str) -> Optional[IncidentTimeline]:
        for tl in self._timelines:
            if tl.timeline_id == timeline_id:
                return tl
        return None

    @property
    def all_timelines(self) -> list[IncidentTimeline]:
        return list(self._timelines)


# ── SIEM Integration ─────────────────────────────────────────

class SIEMFormat(str, Enum):
    CEF = "cef"                  # Common Event Format (ArcSight, QRadar)
    JSON = "json"                # JSON (Splunk HEC, Elastic)
    SYSLOG = "syslog"            # RFC 5424 Syslog (generic)


class SIEMDestination(BaseModel):
    """A configured SIEM destination for event forwarding."""
    destination_id: str = Field(default_factory=lambda: f"siem-{uuid.uuid4().hex[:8]}")
    name: str
    format: SIEMFormat
    endpoint_url: str = ""           # e.g. https://splunk.corp:8088/services/collector
    api_key: str = ""                # Redacted in output
    enabled: bool = True
    event_filter: list[str] = Field(default_factory=list)  # Empty = all events
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SIEMForwarder:
    """Forward governance events to Splunk, Sentinel, Elastic."""

    SEVERITY_MAP = {"info": 1, "warning": 5, "high": 8, "critical": 10}

    def __init__(self):
        self._destinations: dict[str, SIEMDestination] = {}
        self._forwarded: list[dict[str, Any]] = []  # Log of forwarded events

    def add_destination(self, name: str, format: SIEMFormat,
                        endpoint_url: str = "", api_key: str = "",
                        event_filter: list[str] | None = None) -> SIEMDestination:
        dest = SIEMDestination(
            name=name,
            format=format,
            endpoint_url=endpoint_url,
            api_key=api_key,
            event_filter=event_filter or [],
        )
        self._destinations[dest.destination_id] = dest
        return dest

    def remove_destination(self, destination_id: str) -> bool:
        return self._destinations.pop(destination_id, None) is not None

    def format_cef(self, event: GovernanceEvent) -> str:
        """Format as CEF (Common Event Format)."""
        severity = self.SEVERITY_MAP.get(event.severity, 1)
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        extensions = f"src={event.endpoint_id} duser={event.agent_id} msg={event.summary}"
        return f"CEF:0|Gavel|GovernanceHub|1.0|{event.event_type}|{event.summary or event.event_type}|{severity}|{extensions}"

    def format_json(self, event: GovernanceEvent) -> dict[str, Any]:
        """Format as JSON for Splunk HEC / Elastic."""
        return {
            "timestamp": event.timestamp.isoformat(),
            "source": "gavel-hub",
            "sourcetype": "gavel:governance",
            "event": {
                "event_id": event.event_id,
                "category": event.category.value,
                "event_type": event.event_type,
                "endpoint_id": event.endpoint_id,
                "agent_id": event.agent_id,
                "org_id": event.org_id,
                "severity": event.severity,
                "summary": event.summary,
                "details": event.details,
            },
        }

    def format_syslog(self, event: GovernanceEvent) -> str:
        """Format as RFC 5424 syslog."""
        pri = 14 if event.severity == "info" else (12 if event.severity == "warning" else 10)
        ts = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return f"<{pri}>1 {ts} gavel-hub gavel - {event.event_id} - {event.event_type}: {event.summary}"

    def forward(self, event: GovernanceEvent) -> list[dict[str, Any]]:
        """Forward an event to all matching destinations. Returns formatted payloads."""
        results = []
        for dest in self._destinations.values():
            if not dest.enabled:
                continue
            if dest.event_filter and event.event_type not in dest.event_filter:
                continue

            if dest.format == SIEMFormat.CEF:
                payload = {"destination_id": dest.destination_id, "format": "cef",
                           "data": self.format_cef(event)}
            elif dest.format == SIEMFormat.JSON:
                payload = {"destination_id": dest.destination_id, "format": "json",
                           "data": self.format_json(event)}
            else:
                payload = {"destination_id": dest.destination_id, "format": "syslog",
                           "data": self.format_syslog(event)}

            results.append(payload)
            self._forwarded.append(payload)
        return results

    def forward_batch(self, events: list[GovernanceEvent]) -> int:
        """Forward multiple events. Returns count of forwarded payloads."""
        count = 0
        for event in events:
            count += len(self.forward(event))
        return count

    @property
    def destinations(self) -> list[SIEMDestination]:
        return list(self._destinations.values())

    @property
    def forwarded_count(self) -> int:
        return len(self._forwarded)

    @property
    def forwarded_log(self) -> list[dict[str, Any]]:
        return list(self._forwarded)
