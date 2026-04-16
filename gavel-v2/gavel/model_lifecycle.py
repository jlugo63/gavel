"""
Model Lifecycle Management — ISO 42001 Clause 8 compliance.

Tracks AI model versions used by governed agents, enforces version
pinning and deprecation gates, and emits retirement events on the
governance chain.

Lifecycle states:
  ACTIVE       → model is available for new agent bindings
  DEPRECATED   → model still usable but scheduled for retirement
  RETIRED      → model blocked; agents must migrate
  BANNED       → model blocked immediately (safety/compliance)

Design constraints:
- In-memory first (dict-based registries, same as agents/baseline).
- Deterministic, no external calls.
- Self-contained module, no circular imports.
- Bounded, auditable state transitions.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ── Enums ─────────────────────────────────────────────────────

class ModelStatus(str, Enum):
    """Lifecycle status of a registered model."""
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"
    BANNED = "BANNED"


class ModelGovernanceEventType(str, Enum):
    """Event types emitted for governance chain integration."""
    MODEL_REGISTERED = "MODEL_REGISTERED"
    MODEL_DEPRECATED = "MODEL_DEPRECATED"
    MODEL_RETIRED = "MODEL_RETIRED"
    MODEL_BANNED = "MODEL_BANNED"
    AGENT_MODEL_BOUND = "AGENT_MODEL_BOUND"
    AGENT_MODEL_UNBOUND = "AGENT_MODEL_UNBOUND"
    VERSION_DRIFT_DETECTED = "VERSION_DRIFT_DETECTED"


# ── Data Models ───────────────────────────────────────────────

class ModelRecord(BaseModel):
    """A registered AI model tracked by Gavel governance."""

    model_id: str
    provider: str
    version: str
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: ModelStatus = ModelStatus.ACTIVE
    deprecated_at: Optional[datetime] = None
    retirement_date: Optional[datetime] = None
    replacement_model_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentModelBinding(BaseModel):
    """Tracks which model an agent is bound to."""

    agent_id: str
    model_id: str
    pinned_version: Optional[str] = None
    bound_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VersionDriftReport(BaseModel):
    """Report when an agent's pinned version diverges from the model's current version."""

    agent_id: str
    model_id: str
    pinned_version: str
    current_version: str
    drift_detected: bool = False
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelCheckResult(BaseModel):
    """Result of checking an agent's model status."""

    agent_id: str
    model_id: Optional[str] = None
    model_status: Optional[ModelStatus] = None
    allowed: bool = False
    reason: str = ""
    version_drift: Optional[VersionDriftReport] = None


class FleetModelHealthReport(BaseModel):
    """Summary of model health across all bound agents."""

    report_id: str = Field(default_factory=lambda: f"fleet-{uuid.uuid4().hex[:8]}")
    total_bindings: int = 0
    agents_on_active_models: int = 0
    agents_on_deprecated_models: int = 0
    agents_on_retired_models: int = 0
    agents_on_banned_models: int = 0
    agents_with_version_drift: int = 0
    agents_unbound: int = 0
    details: list[ModelCheckResult] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Governance Event Factory ──────────────────────────────────

def create_governance_event(
    event_type: ModelGovernanceEventType,
    *,
    model_id: str = "",
    agent_id: str = "",
    reason: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce an event payload compatible with GovernanceChain.append().

    Returns a dict with event_type, actor_id, role_used, and payload
    keys matching the chain's append signature.
    """
    payload: dict[str, Any] = {}
    if model_id:
        payload["model_id"] = model_id
    if agent_id:
        payload["agent_id"] = agent_id
    if reason:
        payload["reason"] = reason
    if metadata:
        payload.update(metadata)

    return {
        "event_type": event_type.value,
        "actor_id": agent_id or "system",
        "role_used": "model_lifecycle",
        "payload": payload,
    }


# ── Model Registry ────────────────────────────────────────────

class ModelRegistry:
    """Manages the roster of known AI models.

    In-memory dict-based registry following the same pattern as
    AgentRegistry and BehavioralBaselineRegistry.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelRecord] = {}

    def register_model(
        self,
        model_id: str,
        provider: str,
        version: str,
        metadata: dict[str, Any] | None = None,
    ) -> ModelRecord:
        """Register a new model. Overwrites if model_id already exists."""
        record = ModelRecord(
            model_id=model_id,
            provider=provider,
            version=version,
            metadata=metadata or {},
        )
        self._models[model_id] = record
        logger.info("Model registered: %s (provider=%s, version=%s)", model_id, provider, version)
        return record

    def get_model(self, model_id: str) -> ModelRecord | None:
        """Return the model record or None if not found."""
        return self._models.get(model_id)

    def list_models(
        self,
        status: ModelStatus | None = None,
        provider: str | None = None,
    ) -> list[ModelRecord]:
        """List models, optionally filtered by status and/or provider."""
        result = list(self._models.values())
        if status is not None:
            result = [m for m in result if m.status == status]
        if provider is not None:
            result = [m for m in result if m.provider == provider]
        return result

    def deprecate_model(
        self,
        model_id: str,
        retirement_date: datetime,
        replacement_model_id: str | None = None,
    ) -> ModelRecord:
        """Mark a model as DEPRECATED with a scheduled retirement date.

        Raises KeyError if model_id is not registered.
        Raises ValueError if model is already RETIRED or BANNED.
        """
        record = self._models.get(model_id)
        if record is None:
            raise KeyError(f"Model not found: {model_id}")
        if record.status in (ModelStatus.RETIRED, ModelStatus.BANNED):
            raise ValueError(
                f"Cannot deprecate model in {record.status.value} status"
            )

        record.status = ModelStatus.DEPRECATED
        record.deprecated_at = datetime.now(timezone.utc)
        record.retirement_date = retirement_date
        if replacement_model_id is not None:
            record.replacement_model_id = replacement_model_id

        logger.info(
            "Model deprecated: %s (retirement=%s, replacement=%s)",
            model_id, retirement_date.isoformat(), replacement_model_id,
        )
        return record

    def retire_model(self, model_id: str) -> ModelRecord:
        """Set a model to RETIRED status, blocking new enrollments.

        Raises KeyError if model_id is not registered.
        """
        record = self._models.get(model_id)
        if record is None:
            raise KeyError(f"Model not found: {model_id}")

        record.status = ModelStatus.RETIRED
        logger.info("Model retired: %s", model_id)
        return record

    def ban_model(self, model_id: str, reason: str = "") -> ModelRecord:
        """Immediately ban a model (safety/compliance block).

        Raises KeyError if model_id is not registered.
        """
        record = self._models.get(model_id)
        if record is None:
            raise KeyError(f"Model not found: {model_id}")

        record.status = ModelStatus.BANNED
        record.metadata["ban_reason"] = reason
        logger.info("Model banned: %s (reason=%s)", model_id, reason)
        return record

    def check_retirement_due(self, now: datetime | None = None) -> list[ModelRecord]:
        """Return models past their retirement_date still in DEPRECATED status."""
        now = now or datetime.now(timezone.utc)
        return [
            m for m in self._models.values()
            if m.status == ModelStatus.DEPRECATED
            and m.retirement_date is not None
            and m.retirement_date <= now
        ]

    def is_model_allowed(self, model_id: str) -> bool:
        """True if the model is ACTIVE or DEPRECATED (still usable).

        Returns False for RETIRED, BANNED, or unknown models.
        """
        record = self._models.get(model_id)
        if record is None:
            return False
        return record.status in (ModelStatus.ACTIVE, ModelStatus.DEPRECATED)


# ── Model Binding Registry ────────────────────────────────────

class ModelBindingRegistry:
    """Tracks which agent uses which model, with optional version pinning.

    Each agent has at most one binding. Rebinding replaces the previous one.
    """

    def __init__(self, model_registry: ModelRegistry) -> None:
        self._bindings: dict[str, AgentModelBinding] = {}
        self._model_registry = model_registry

    def bind_agent(
        self,
        agent_id: str,
        model_id: str,
        pin_version: str | None = None,
    ) -> AgentModelBinding:
        """Bind an agent to a model.

        Raises KeyError if the model is not registered.
        Raises ValueError if the model is not allowed (RETIRED/BANNED).
        """
        record = self._model_registry.get_model(model_id)
        if record is None:
            raise KeyError(f"Model not found: {model_id}")
        if not self._model_registry.is_model_allowed(model_id):
            raise ValueError(
                f"Cannot bind agent to model in {record.status.value} status"
            )

        binding = AgentModelBinding(
            agent_id=agent_id,
            model_id=model_id,
            pinned_version=pin_version,
        )
        self._bindings[agent_id] = binding
        logger.info(
            "Agent %s bound to model %s (pinned=%s)",
            agent_id, model_id, pin_version,
        )
        return binding

    def unbind_agent(self, agent_id: str) -> AgentModelBinding | None:
        """Remove an agent's model binding. Returns the old binding or None."""
        binding = self._bindings.pop(agent_id, None)
        if binding:
            logger.info("Agent %s unbound from model %s", agent_id, binding.model_id)
        return binding

    def get_binding(self, agent_id: str) -> AgentModelBinding | None:
        """Return the binding for an agent, or None."""
        return self._bindings.get(agent_id)

    def agents_using_model(self, model_id: str) -> list[str]:
        """Return list of agent_ids currently bound to the given model."""
        return [
            b.agent_id for b in self._bindings.values()
            if b.model_id == model_id
        ]

    def check_version_drift(self, agent_id: str) -> VersionDriftReport | None:
        """Compare an agent's pinned version against the model's current version.

        Returns None if no binding, no pin, or model not found.
        """
        binding = self._bindings.get(agent_id)
        if binding is None or binding.pinned_version is None:
            return None

        record = self._model_registry.get_model(binding.model_id)
        if record is None:
            return None

        drift = binding.pinned_version != record.version
        return VersionDriftReport(
            agent_id=agent_id,
            model_id=binding.model_id,
            pinned_version=binding.pinned_version,
            current_version=record.version,
            drift_detected=drift,
        )

    def all_bindings(self) -> list[AgentModelBinding]:
        """Return all current bindings."""
        return list(self._bindings.values())


# ── Model Lifecycle Checker ───────────────────────────────────

class ModelLifecycleChecker:
    """Readiness-check-style validation of agent model health.

    Plugs into the same pattern as ReadinessChecker — structured
    results suitable for dashboards and automated gates.
    """

    def __init__(
        self,
        model_registry: ModelRegistry,
        binding_registry: ModelBindingRegistry,
    ) -> None:
        self._models = model_registry
        self._bindings = binding_registry

    def check_agent_model_status(self, agent_id: str) -> ModelCheckResult:
        """Check whether an agent's bound model is still allowed."""
        binding = self._bindings.get_binding(agent_id)
        if binding is None:
            return ModelCheckResult(
                agent_id=agent_id,
                allowed=False,
                reason="No model binding found",
            )

        record = self._models.get_model(binding.model_id)
        if record is None:
            return ModelCheckResult(
                agent_id=agent_id,
                model_id=binding.model_id,
                allowed=False,
                reason="Bound model not found in registry",
            )

        allowed = self._models.is_model_allowed(binding.model_id)
        reason = f"Model status is {record.status.value}"
        if record.status == ModelStatus.DEPRECATED and record.retirement_date:
            reason += f" (retirement scheduled: {record.retirement_date.isoformat()})"
        if record.replacement_model_id:
            reason += f" — replacement: {record.replacement_model_id}"

        drift = self._bindings.check_version_drift(agent_id)

        return ModelCheckResult(
            agent_id=agent_id,
            model_id=binding.model_id,
            model_status=record.status,
            allowed=allowed,
            reason=reason,
            version_drift=drift,
        )

    def check_fleet_model_health(
        self,
        agent_ids: list[str] | None = None,
    ) -> FleetModelHealthReport:
        """Summary of model health across all (or specified) agents.

        If agent_ids is None, checks all currently bound agents.
        """
        if agent_ids is None:
            agent_ids = [b.agent_id for b in self._bindings.all_bindings()]

        details: list[ModelCheckResult] = []
        active = deprecated = retired = banned = drifted = unbound = 0

        for aid in agent_ids:
            result = self.check_agent_model_status(aid)
            details.append(result)

            if result.model_id is None:
                unbound += 1
            elif result.model_status == ModelStatus.ACTIVE:
                active += 1
            elif result.model_status == ModelStatus.DEPRECATED:
                deprecated += 1
            elif result.model_status == ModelStatus.RETIRED:
                retired += 1
            elif result.model_status == ModelStatus.BANNED:
                banned += 1

            if result.version_drift and result.version_drift.drift_detected:
                drifted += 1

        return FleetModelHealthReport(
            total_bindings=len(agent_ids),
            agents_on_active_models=active,
            agents_on_deprecated_models=deprecated,
            agents_on_retired_models=retired,
            agents_on_banned_models=banned,
            agents_with_version_drift=drifted,
            agents_unbound=unbound,
            details=details,
        )
