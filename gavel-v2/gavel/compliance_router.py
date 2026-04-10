"""EU AI Act Compliance API — Annex IV documentation, incident management, compliance status.

Endpoints for generating technical documentation per Article 11,
managing incidents per Article 73, and monitoring overall compliance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from gavel.compliance import (
    AnnexIVGenerator,
    ComplianceStatus,
    IncidentClassifier,
    IncidentRegistry,
    IncidentReport,
    IncidentSeverity,
    IncidentStatus,
)
from gavel.events import DashboardEvent, EventBus

router = APIRouter(tags=["compliance"])

# Shared state — injected via init_compliance_router()
_incident_registry: Optional[IncidentRegistry] = None
_enrollment_registry = None  # EnrollmentRegistry
_chains: Optional[dict] = None
_review_results: Optional[dict] = None
_constitution = None  # Constitution
_tier_policy = None  # TierPolicy
_event_bus: Optional[EventBus] = None


def init_compliance_router(
    incidents: IncidentRegistry,
    enrollments,
    chains: dict,
    review_results: dict,
    constitution,
    tier_policy,
    event_bus: EventBus,
):
    """Inject shared state from gateway."""
    global _incident_registry, _enrollment_registry, _chains, _review_results
    global _constitution, _tier_policy, _event_bus
    _incident_registry = incidents
    _enrollment_registry = enrollments
    _chains = chains
    _review_results = review_results
    _constitution = constitution
    _tier_policy = tier_policy
    _event_bus = event_bus


# ── Request/Response Models ──────────────────────────────────


class CreateIncidentRequest(BaseModel):
    agent_id: str
    title: str
    description: str
    severity: Optional[IncidentSeverity] = None
    event_type: str = ""
    chain_ids: list[str] = Field(default_factory=list)


class IncidentResponse(BaseModel):
    incident_id: str
    agent_id: str
    severity: IncidentSeverity
    status: IncidentStatus
    title: str
    description: str
    detected_at: datetime
    reported_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    deadline: Optional[datetime] = None
    is_overdue: bool = False
    days_remaining: float = 0.0
    chain_ids: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    regulatory_references: list[str] = Field(default_factory=list)


class ComplianceStatusSummary(BaseModel):
    total_agents: int = 0
    enrolled_agents: int = 0
    total_incidents: int = 0
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    overdue_incidents: int = 0
    total_chains: int = 0
    completed_chains: int = 0
    denied_chains: int = 0


def _to_response(incident: IncidentReport) -> IncidentResponse:
    """Convert IncidentReport to IncidentResponse with computed fields."""
    return IncidentResponse(
        incident_id=incident.incident_id,
        agent_id=incident.agent_id,
        severity=incident.severity,
        status=incident.status,
        title=incident.title,
        description=incident.description,
        detected_at=incident.detected_at,
        reported_at=incident.reported_at,
        resolved_at=incident.resolved_at,
        deadline=incident.deadline,
        is_overdue=incident.is_overdue,
        days_remaining=incident.days_remaining,
        chain_ids=incident.chain_ids,
        findings=incident.findings,
        regulatory_references=incident.regulatory_references,
    )


# ── Incident Endpoints ───────────────────────────────────────


@router.get("/api/v1/incidents/overdue", response_model=list[IncidentResponse])
async def get_overdue_incidents():
    """List incidents that have exceeded their reporting deadline."""
    overdue = _incident_registry.get_overdue()
    return [_to_response(i) for i in overdue]


@router.get("/api/v1/incidents", response_model=list[IncidentResponse])
async def list_incidents(
    severity: Optional[IncidentSeverity] = Query(None),
    status: Optional[IncidentStatus] = Query(None),
    agent_id: Optional[str] = Query(None),
):
    """List all incidents with optional filters."""
    incidents = _incident_registry.get_all()
    if severity:
        incidents = [i for i in incidents if i.severity == severity]
    if status:
        incidents = [i for i in incidents if i.status == status]
    if agent_id:
        incidents = [i for i in incidents if i.agent_id == agent_id]
    return [_to_response(i) for i in incidents]


@router.get("/api/v1/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str):
    """Get a specific incident by ID."""
    incident = _incident_registry.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _to_response(incident)


@router.post("/api/v1/incidents", response_model=IncidentResponse, status_code=201)
async def create_incident(req: CreateIncidentRequest):
    """Create a new incident report."""
    incident = _incident_registry.report(
        agent_id=req.agent_id,
        title=req.title,
        description=req.description,
        severity=req.severity,
        event_type=req.event_type,
        chain_ids=req.chain_ids,
    )
    if _event_bus:
        await _event_bus.publish(DashboardEvent(
            event_type="incident_created",
            agent_id=req.agent_id,
            payload={"incident_id": incident.incident_id, "severity": incident.severity.value, "title": req.title},
        ))
    return _to_response(incident)


@router.patch("/api/v1/incidents/{incident_id}/report", response_model=IncidentResponse)
async def mark_incident_reported(incident_id: str):
    """Mark an incident as reported to regulatory authorities."""
    incident = _incident_registry.mark_reported(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if _event_bus:
        await _event_bus.publish(DashboardEvent(
            event_type="incident_reported",
            agent_id=incident.agent_id,
            payload={"incident_id": incident_id},
        ))
    return _to_response(incident)


@router.patch("/api/v1/incidents/{incident_id}/resolve", response_model=IncidentResponse)
async def mark_incident_resolved(incident_id: str):
    """Mark an incident as resolved."""
    incident = _incident_registry.mark_resolved(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if _event_bus:
        await _event_bus.publish(DashboardEvent(
            event_type="incident_resolved",
            agent_id=incident.agent_id,
            payload={"incident_id": incident_id},
        ))
    return _to_response(incident)


# ── Annex IV Documentation ───────────────────────────────────


@router.get("/api/v1/agents/{agent_id}/compliance/annex-iv")
async def generate_annex_iv(agent_id: str):
    """Generate EU AI Act Annex IV technical documentation for an agent."""
    # Find enrollment record
    enrollment_record = _enrollment_registry.get(agent_id) if _enrollment_registry else None
    if not enrollment_record:
        raise HTTPException(status_code=404, detail=f"No enrollment record for agent {agent_id}")

    # Gather chains for this agent
    agent_chains = []
    if _chains:
        for chain in _chains.values():
            if chain.events and chain.events[0].actor_id == agent_id:
                agent_chains.append(chain)

    # Gather review results
    agent_reviews = list(_review_results.values()) if _review_results else []

    # Gather incidents
    agent_incidents = _incident_registry.get_by_agent(agent_id) if _incident_registry else []

    generator = AnnexIVGenerator(
        enrollment_record=enrollment_record,
        chains=agent_chains,
        review_results=agent_reviews,
        constitution=_constitution,
        tier_policy=_tier_policy,
        incidents=agent_incidents,
    )
    return generator.generate()


# ── Compliance Status ─────────────────────────────────────────


@router.get("/api/v1/compliance/status", response_model=ComplianceStatusSummary)
async def get_compliance_status():
    """Get overall compliance status summary."""
    # Agents
    enrollments = _enrollment_registry.get_all() if _enrollment_registry else []
    enrolled = [e for e in enrollments if e.status.value in ("ENROLLED", "enrolled")]

    # Incidents
    all_incidents = _incident_registry.get_all() if _incident_registry else []
    by_severity = {}
    for sev in IncidentSeverity:
        count = sum(1 for i in all_incidents if i.severity == sev)
        if count > 0:
            by_severity[sev.value] = count
    overdue = len(_incident_registry.get_overdue()) if _incident_registry else 0

    # Chains
    total_chains = len(_chains) if _chains else 0
    completed = sum(1 for c in (_chains or {}).values() if c.status.value in ("COMPLETED", "completed"))
    denied = sum(1 for c in (_chains or {}).values() if c.status.value in ("DENIED", "denied", "TIMED_OUT", "timed_out"))

    return ComplianceStatusSummary(
        total_agents=len(enrollments),
        enrolled_agents=len(enrolled),
        total_incidents=len(all_incidents),
        incidents_by_severity=by_severity,
        overdue_incidents=overdue,
        total_chains=total_chains,
        completed_chains=completed,
        denied_chains=denied,
    )
