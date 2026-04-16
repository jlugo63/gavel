"""
Cross-machine correlation — detect agents coordinating across machines.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

import uuid
from datetime import datetime, timezone

from gavel.hub.governance import OrgChainEvent


# ── Cross-Machine Correlation ────────────────────────────────

class CorrelationSignal(str, Enum):
    COORDINATED_TIMING = "coordinated_timing"       # Agents on different machines acting in sync
    SHARED_TARGET = "shared_target"                  # Agents on different machines targeting same resource
    DATA_EXFIL_PATTERN = "data_exfil_pattern"        # One agent reads, another on different machine sends
    SYNCHRONIZED_ENROLLMENT = "synchronized_enrollment"  # Agents enrolling in lockstep


class CorrelationFinding(BaseModel):
    """A detected cross-machine correlation pattern."""
    finding_id: str = Field(default_factory=lambda: f"corr-{uuid.uuid4().hex[:8]}")
    signal: CorrelationSignal
    agents: list[str]                # Agent IDs involved
    endpoints: list[str]             # Endpoint IDs involved
    evidence: dict[str, Any] = Field(default_factory=dict)
    severity: str = "medium"         # low, medium, high, critical
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""


class CrossMachineCorrelator:
    """Detect if agents on different machines are coordinating."""

    def __init__(self, timing_window_seconds: int = 30, shared_target_threshold: int = 3):
        self._findings: list[CorrelationFinding] = []
        self._timing_window = timedelta(seconds=timing_window_seconds)
        self._shared_target_threshold = shared_target_threshold

    def analyze_timing(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Detect agents on different endpoints acting within a tight time window."""
        findings = []
        # Group events by time buckets
        by_bucket: dict[str, list[OrgChainEvent]] = defaultdict(list)
        for e in events:
            bucket = e.timestamp.strftime("%Y-%m-%dT%H:%M")  # 1-minute buckets
            by_bucket[bucket].append(e)

        for bucket, bucket_events in by_bucket.items():
            # Find events from different endpoints in same bucket
            endpoint_agents: dict[str, set[str]] = defaultdict(set)
            for e in bucket_events:
                endpoint_agents[e.endpoint_id].add(e.agent_id)

            if len(endpoint_agents) >= 2:
                all_agents = []
                all_endpoints = list(endpoint_agents.keys())
                for agents in endpoint_agents.values():
                    all_agents.extend(agents)

                if len(set(all_agents)) >= 2:
                    finding = CorrelationFinding(
                        signal=CorrelationSignal.COORDINATED_TIMING,
                        agents=list(set(all_agents)),
                        endpoints=all_endpoints,
                        evidence={"time_bucket": bucket, "event_count": len(bucket_events)},
                        severity="medium",
                        description=f"Agents on {len(all_endpoints)} endpoints acted within same minute window",
                    )
                    findings.append(finding)
                    self._findings.append(finding)
        return findings

    def analyze_shared_targets(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Detect agents on different machines targeting the same resource."""
        findings = []
        # Group by target resource (from payload)
        target_accesses: dict[str, list[OrgChainEvent]] = defaultdict(list)
        for e in events:
            target = e.payload.get("target", "")
            if target:
                target_accesses[target].append(e)

        for target, access_events in target_accesses.items():
            endpoints = set(e.endpoint_id for e in access_events)
            if len(endpoints) >= 2 and len(access_events) >= self._shared_target_threshold:
                agents = list(set(e.agent_id for e in access_events))
                finding = CorrelationFinding(
                    signal=CorrelationSignal.SHARED_TARGET,
                    agents=agents,
                    endpoints=list(endpoints),
                    evidence={"target": target, "access_count": len(access_events)},
                    severity="high",
                    description=f"Agents on {len(endpoints)} endpoints accessed '{target}' {len(access_events)} times",
                )
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def analyze_data_exfil(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Detect read-on-A, send-on-B patterns suggesting data exfiltration."""
        findings = []
        reads: dict[str, list[OrgChainEvent]] = defaultdict(list)  # target -> events
        sends: list[OrgChainEvent] = []

        for e in events:
            action = e.payload.get("action", "")
            if action in ("read", "file_read", "db_query"):
                target = e.payload.get("target", "")
                if target:
                    reads[target].append(e)
            elif action in ("send", "network_send", "api_call", "upload"):
                sends.append(e)

        for send_event in sends:
            send_target = send_event.payload.get("target", "")
            for read_target, read_events in reads.items():
                for read_event in read_events:
                    if (read_event.endpoint_id != send_event.endpoint_id and
                            read_event.timestamp < send_event.timestamp):
                        finding = CorrelationFinding(
                            signal=CorrelationSignal.DATA_EXFIL_PATTERN,
                            agents=[read_event.agent_id, send_event.agent_id],
                            endpoints=[read_event.endpoint_id, send_event.endpoint_id],
                            evidence={
                                "read_target": read_target,
                                "send_target": send_target,
                                "read_time": read_event.timestamp.isoformat(),
                                "send_time": send_event.timestamp.isoformat(),
                            },
                            severity="critical",
                            description=f"Agent {read_event.agent_id} read '{read_target}' on {read_event.endpoint_id}, then {send_event.agent_id} sent data from {send_event.endpoint_id}",
                        )
                        findings.append(finding)
                        self._findings.append(finding)
        return findings

    def correlate(self, events: list[OrgChainEvent]) -> list[CorrelationFinding]:
        """Run all correlation analyses."""
        results = []
        results.extend(self.analyze_timing(events))
        results.extend(self.analyze_shared_targets(events))
        results.extend(self.analyze_data_exfil(events))
        return results

    @property
    def all_findings(self) -> list[CorrelationFinding]:
        return list(self._findings)
