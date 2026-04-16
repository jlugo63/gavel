"""EU AI Act Compliance API — Annex IV documentation, incident management, compliance status.

Endpoints for generating technical documentation per Article 11,
managing incidents per Article 73, and monitoring overall compliance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
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
from gavel.constitution import Constitution
from gavel.dependencies import (
    get_chain_repo,
    get_constitution,
    get_enrollment_registry,
    get_event_bus,
    get_incident_registry,
    get_review_repo,
    get_tier_policy,
)
from gavel.db.repositories import ChainRepository, ReviewRepository
from gavel.enrollment import EnrollmentRegistry
from gavel.events import DashboardEvent, EventBus
from gavel.tiers import TierPolicy

router = APIRouter(tags=["compliance"])


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


@router.get("/incidents/overdue", response_model=list[IncidentResponse])
async def get_overdue_incidents(
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
):
    """List incidents that have exceeded their reporting deadline."""
    overdue = await incident_registry.get_overdue()
    return [_to_response(i) for i in overdue]


@router.get("/incidents", response_model=list[IncidentResponse])
async def list_incidents(
    severity: Optional[IncidentSeverity] = Query(None),
    status: Optional[IncidentStatus] = Query(None),
    agent_id: Optional[str] = Query(None),
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
):
    """List all incidents with optional filters."""
    incidents = await incident_registry.get_all()
    if severity:
        incidents = [i for i in incidents if i.severity == severity]
    if status:
        incidents = [i for i in incidents if i.status == status]
    if agent_id:
        incidents = [i for i in incidents if i.agent_id == agent_id]
    return [_to_response(i) for i in incidents]


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
):
    """Get a specific incident by ID."""
    incident = await incident_registry.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _to_response(incident)


@router.post("/incidents", response_model=IncidentResponse, status_code=201)
async def create_incident(
    req: CreateIncidentRequest,
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
    event_bus: EventBus = Depends(get_event_bus),
):
    """Create a new incident report."""
    incident = await incident_registry.report(
        agent_id=req.agent_id,
        title=req.title,
        description=req.description,
        severity=req.severity,
        event_type=req.event_type,
        chain_ids=req.chain_ids,
    )
    if event_bus:
        await event_bus.publish(DashboardEvent(
            event_type="incident_created",
            agent_id=req.agent_id,
            payload={"incident_id": incident.incident_id, "severity": incident.severity.value, "title": req.title},
        ))
    return _to_response(incident)


@router.patch("/incidents/{incident_id}/report", response_model=IncidentResponse)
async def mark_incident_reported(
    incident_id: str,
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
    event_bus: EventBus = Depends(get_event_bus),
):
    """Mark an incident as reported to regulatory authorities."""
    incident = await incident_registry.mark_reported(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if event_bus:
        await event_bus.publish(DashboardEvent(
            event_type="incident_reported",
            agent_id=incident.agent_id,
            payload={"incident_id": incident_id},
        ))
    return _to_response(incident)


@router.patch("/incidents/{incident_id}/resolve", response_model=IncidentResponse)
async def mark_incident_resolved(
    incident_id: str,
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
    event_bus: EventBus = Depends(get_event_bus),
):
    """Mark an incident as resolved."""
    incident = await incident_registry.mark_resolved(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if event_bus:
        await event_bus.publish(DashboardEvent(
            event_type="incident_resolved",
            agent_id=incident.agent_id,
            payload={"incident_id": incident_id},
        ))
    return _to_response(incident)


# ── Annex IV Documentation ───────────────────────────────────


@router.get("/agents/{agent_id}/compliance/annex-iv")
async def generate_annex_iv(
    agent_id: str,
    enrollment_registry: EnrollmentRegistry = Depends(get_enrollment_registry),
    chain_repo: ChainRepository = Depends(get_chain_repo),
    review_repo: ReviewRepository = Depends(get_review_repo),
    constitution: Constitution = Depends(get_constitution),
    tier_policy: TierPolicy = Depends(get_tier_policy),
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
):
    """Generate EU AI Act Annex IV technical documentation for an agent."""
    enrollment_record = await enrollment_registry.get(agent_id)
    if not enrollment_record:
        raise HTTPException(status_code=404, detail=f"No enrollment record for agent {agent_id}")

    all_chains = await chain_repo.list_all()
    agent_chains = [
        c for c in all_chains
        if c.events and c.events[0].actor_id == agent_id
    ]

    agent_reviews: list = []
    for chain in agent_chains:
        review = await review_repo.get(chain.chain_id)
        if review is not None:
            agent_reviews.append(review)

    agent_incidents = await incident_registry.get_by_agent(agent_id)

    generator = AnnexIVGenerator(
        enrollment_record=enrollment_record,
        chains=agent_chains,
        review_results=agent_reviews,
        constitution=constitution,
        tier_policy=tier_policy,
        incidents=agent_incidents,
    )
    return generator.generate()


# ── Compliance Status ─────────────────────────────────────────


@router.get("/compliance/status", response_model=ComplianceStatusSummary)
async def get_compliance_status(
    enrollment_registry: EnrollmentRegistry = Depends(get_enrollment_registry),
    incident_registry: IncidentRegistry = Depends(get_incident_registry),
    chain_repo: ChainRepository = Depends(get_chain_repo),
):
    """Get overall compliance status summary."""
    enrollments = await enrollment_registry.get_all()
    enrolled = [e for e in enrollments if e.status.value in ("ENROLLED", "enrolled")]

    all_incidents = await incident_registry.get_all()
    by_severity = {}
    for sev in IncidentSeverity:
        count = sum(1 for i in all_incidents if i.severity == sev)
        if count > 0:
            by_severity[sev.value] = count
    overdue = len(await incident_registry.get_overdue())

    all_chains = await chain_repo.list_all()
    total_chains = len(all_chains)
    completed = sum(1 for c in all_chains if c.status.value in ("COMPLETED", "completed"))
    denied = sum(1 for c in all_chains if c.status.value in ("DENIED", "denied", "TIMED_OUT", "timed_out"))

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
