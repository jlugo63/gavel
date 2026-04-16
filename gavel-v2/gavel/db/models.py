"""SQLAlchemy ORM rows for Gavel's persistent entities.

Each row class mirrors a Pydantic/dataclass model that is the source of
truth in the in-memory code paths:

* :class:`ChainEventRow`        ↔ :class:`gavel.chain.ChainEvent`
* :class:`GovernanceChainRow`   ↔ :class:`gavel.chain.GovernanceChain`
* :class:`AgentRecordRow`       ↔ :class:`gavel.agents.AgentRecord`
* :class:`EnrollmentTokenRow`   ↔ :class:`gavel.enrollment.GovernanceToken`
* :class:`IncidentRow`          ↔ :class:`gavel.compliance.IncidentReport`
* :class:`EvidencePacketRow`    ↔ :class:`gavel.blastbox.EvidencePacket`
* :class:`ReviewResultRow`      ↔ :class:`gavel.evidence.ReviewResult`
* :class:`ExecutionTokenRow`    ↔ the dict stored in ``get_execution_tokens()``

Wave 1 decisions baked in here:

* ``JSON`` column type (SQLAlchemy's generic ``JSON``) used for free-form
  payload/metadata columns. On Postgres SQLAlchemy renders ``JSON``, not
  ``JSONB``; a later migration can switch critical columns to ``JSONB``
  when needed for indexing. Sticking with generic ``JSON`` keeps the
  SQLite dev/test path and Postgres prod path identical.
* Timestamps use ``DateTime(timezone=True)``. SQLite will store naive
  but the Python side always produces aware ``datetime`` objects.
* Primary keys are the natural keys from the domain models
  (``chain_id``, ``agent_id``, etc.) rather than synthetic integer IDs.
* ``ChainEventRow`` uses a composite PK ``(chain_id, sequence)`` so
  order and uniqueness-per-chain are schema-enforced.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from gavel.db.base import Base


# ── Governance Chains ─────────────────────────────────────────────


class GovernanceChainRow(Base):
    """One row per ``GovernanceChain`` — chain-level metadata only.

    Hash-chained events live in ``chain_events`` and reference this row.
    """

    __tablename__ = "governance_chains"

    chain_id: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Flat roster cache: {actor_id: [role, ...]}. Stored here because the
    # in-memory GovernanceChain tracks it alongside events.
    actor_roles: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Eager-loadable relationship for ChainRepository.get() / list_all().
    # Event rows are ordered by ``sequence`` — the same order the in-memory
    # chain appends them. ``selectinload`` on this attribute replaces the
    # two-query form.
    events: Mapped[list["ChainEventRow"]] = relationship(
        "ChainEventRow",
        order_by="ChainEventRow.sequence",
        lazy="select",
    )


class ChainEventRow(Base):
    """One row per ``ChainEvent``.

    Composite PK ``(chain_id, sequence)`` enforces ordering and uniqueness
    within a chain. ``event_id`` is indexed for lookup but is not the PK
    because chain + sequence is the natural addressing scheme.

    ``request_id`` is stored for observability only — it is *not* part of
    the tamper seal (``event_hash`` is computed without it, matching the
    existing Pydantic model behavior).
    """

    __tablename__ = "chain_events"

    chain_id: Mapped[str] = mapped_column(
        String, ForeignKey("governance_chains.chain_id"), primary_key=True
    )
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)

    event_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    actor_id: Mapped[str] = mapped_column(String, nullable=False)
    role_used: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    prev_hash: Mapped[str] = mapped_column(Text, nullable=False, default="")
    event_hash: Mapped[str] = mapped_column(Text, nullable=False, default="")

    request_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)


# ── Agent Registry ────────────────────────────────────────────────


class AgentRecordRow(Base):
    """Mirror of :class:`gavel.agents.AgentRecord`."""

    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    agent_type: Mapped[str] = mapped_column(String, nullable=False)
    did: Mapped[str] = mapped_column(String, nullable=False, default="")
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False, default=500)
    autonomy_tier: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String, nullable=False, default="ACTIVE")
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_interval_s: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    chains_proposed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    chains_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    violations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful_actions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    session_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    current_activity: Mapped[str] = mapped_column(String, nullable=False, default="Idle")


# ── Enrollment Tokens ─────────────────────────────────────────────


class EnrollmentTokenRow(Base):
    """Mirror of :class:`gavel.enrollment.GovernanceToken`.

    The token string itself is the PK — it is already a SHA-256-derived
    unique identifier, so no synthetic key is needed.
    """

    __tablename__ = "enrollment_tokens"

    token: Mapped[str] = mapped_column(String, primary_key=True)
    agent_did: Mapped[str] = mapped_column(String, nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scope: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)


# ── Enrollment Records ────────────────────────────────────────────


class EnrollmentRecordRow(Base):
    """Mirror of :class:`gavel.enrollment.EnrollmentRecord`.

    The ``application`` Pydantic model is persisted as JSON — it is
    read-together with the parent record and is not queried on its own
    fields in existing call sites.
    """

    __tablename__ = "enrollment_records"

    agent_id: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING")
    application: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enrolled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    violations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


# ── Incidents ─────────────────────────────────────────────────────


class IncidentRow(Base):
    """Mirror of :class:`gavel.compliance.IncidentReport`."""

    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="open")
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reported_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    chain_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    findings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    regulatory_references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


# ── Evidence Packets ──────────────────────────────────────────────


class EvidencePacketRow(Base):
    """Mirror of :class:`gavel.blastbox.EvidencePacket`.

    ``scope`` is a dataclass on the Python side; we persist it as JSON
    (it's small, read-together, and not queried independently).
    """

    __tablename__ = "evidence_packets"

    packet_id: Mapped[str] = mapped_column(String, primary_key=True)
    chain_id: Mapped[str] = mapped_column(String, nullable=False, index=True, default="")
    intent_event_id: Mapped[str] = mapped_column(String, nullable=False, default="")

    command_argv: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    exit_code: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    stdout_hash: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stderr_hash: Mapped[str] = mapped_column(Text, nullable=False, default="")
    diff_hash: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stdout_preview: Mapped[str] = mapped_column(Text, nullable=False, default="")

    files_modified: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    files_created: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    files_deleted: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    image: Mapped[str] = mapped_column(String, nullable=False, default="")
    image_digest: Mapped[str] = mapped_column(String, nullable=False, default="")
    network_mode: Mapped[str] = mapped_column(String, nullable=False, default="none")
    cpu: Mapped[str] = mapped_column(String, nullable=False, default="1")
    memory: Mapped[str] = mapped_column(String, nullable=False, default="512m")

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# ── Review Results ────────────────────────────────────────────────


class ReviewResultRow(Base):
    """Mirror of :class:`gavel.evidence.ReviewResult`.

    The in-memory dataclass has no natural key of its own (it lives in a
    dict keyed by the reviewer on the caller side). We add ``packet_id``
    as the PK since one review result maps to one evidence packet in the
    current code paths. If the mapping becomes many-to-one later, Wave 2
    can migrate to a synthetic PK.
    """

    __tablename__ = "review_results"

    packet_id: Mapped[str] = mapped_column(String, primary_key=True)
    chain_id: Mapped[str] = mapped_column(String, nullable=False, index=True, default="")

    verdict: Mapped[str] = mapped_column(String, nullable=False, default="PASS")
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    risk_delta: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    scope_compliance: Mapped[str] = mapped_column(String, nullable=False, default="FULL")
    review_hash: Mapped[str] = mapped_column(Text, nullable=False, default="")

    redacted_stdout: Mapped[str] = mapped_column(Text, nullable=False, default="")
    redacted_stderr: Mapped[str] = mapped_column(Text, nullable=False, default="")
    privacy_findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)


# ── Execution Tokens ──────────────────────────────────────────────


class ExecutionTokenRow(Base):
    """Mirror of the dict stored in ``gavel.dependencies.get_execution_tokens()``.

    The existing dict shape is::

        {
            "token_id": "exec-t-xxxxxxxx",
            "chain_id": "c-...",
            "expires_at": "2024-01-01T00:00:00+00:00",
            "used": False,
        }

    We store ``expires_at`` as a proper ``DateTime`` column (the in-memory
    code uses an ISO string, but storage can and should be typed).
    """

    __tablename__ = "execution_tokens"

    token_id: Mapped[str] = mapped_column(String, primary_key=True)
    chain_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


__all__ = [
    "GovernanceChainRow",
    "ChainEventRow",
    "AgentRecordRow",
    "EnrollmentRecordRow",
    "EnrollmentTokenRow",
    "IncidentRow",
    "EvidencePacketRow",
    "ReviewResultRow",
    "ExecutionTokenRow",
]
