"""Tests for gavel.model_lifecycle — Model Lifecycle Management (ISO 42001 Clause 8)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from gavel.model_lifecycle import (
    AgentModelBinding,
    FleetModelHealthReport,
    ModelBindingRegistry,
    ModelCheckResult,
    ModelGovernanceEventType,
    ModelLifecycleChecker,
    ModelRecord,
    ModelRegistry,
    ModelStatus,
    VersionDriftReport,
    create_governance_event,
)


# ── Helpers ───────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _future(days: int = 30) -> datetime:
    return _now() + timedelta(days=days)


def _past(days: int = 30) -> datetime:
    return _now() - timedelta(days=days)


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry()


@pytest.fixture
def populated_registry(registry: ModelRegistry) -> ModelRegistry:
    """Registry with three models pre-registered."""
    registry.register_model("gpt-4o-2024-08-06", "openai", "2024-08-06")
    registry.register_model("claude-sonnet-4-20250514", "anthropic", "20250514")
    registry.register_model("llama3:8b", "ollama", "3.0")
    return registry


@pytest.fixture
def binding_registry(populated_registry: ModelRegistry) -> ModelBindingRegistry:
    return ModelBindingRegistry(populated_registry)


# ── ModelRegistry — registration ──────────────────────────────

class TestModelRegistration:
    def test_register_model_basic(self, registry: ModelRegistry) -> None:
        record = registry.register_model("gpt-4o", "openai", "2024-08-06")
        assert record.model_id == "gpt-4o"
        assert record.provider == "openai"
        assert record.version == "2024-08-06"
        assert record.status == ModelStatus.ACTIVE
        assert record.deprecated_at is None
        assert record.retirement_date is None
        assert record.replacement_model_id is None

    def test_register_model_with_metadata(self, registry: ModelRegistry) -> None:
        meta = {"context_window": 128000, "modality": "text+vision"}
        record = registry.register_model("gpt-4o", "openai", "2024-08-06", metadata=meta)
        assert record.metadata["context_window"] == 128000

    def test_register_overwrites_existing(self, registry: ModelRegistry) -> None:
        registry.register_model("gpt-4o", "openai", "v1")
        record = registry.register_model("gpt-4o", "openai", "v2")
        assert record.version == "v2"
        assert registry.get_model("gpt-4o") is not None
        assert registry.get_model("gpt-4o").version == "v2"  # type: ignore[union-attr]

    def test_get_model_not_found(self, registry: ModelRegistry) -> None:
        assert registry.get_model("nonexistent") is None


# ── ModelRegistry — listing ───────────────────────────────────

class TestModelListing:
    def test_list_all(self, populated_registry: ModelRegistry) -> None:
        models = populated_registry.list_models()
        assert len(models) == 3

    def test_list_by_status(self, populated_registry: ModelRegistry) -> None:
        populated_registry.deprecate_model(
            "llama3:8b", retirement_date=_future(30)
        )
        active = populated_registry.list_models(status=ModelStatus.ACTIVE)
        deprecated = populated_registry.list_models(status=ModelStatus.DEPRECATED)
        assert len(active) == 2
        assert len(deprecated) == 1

    def test_list_by_provider(self, populated_registry: ModelRegistry) -> None:
        ollama = populated_registry.list_models(provider="ollama")
        assert len(ollama) == 1
        assert ollama[0].model_id == "llama3:8b"

    def test_list_by_status_and_provider(self, populated_registry: ModelRegistry) -> None:
        result = populated_registry.list_models(
            status=ModelStatus.ACTIVE, provider="anthropic"
        )
        assert len(result) == 1
        assert result[0].model_id == "claude-sonnet-4-20250514"


# ── ModelRegistry — deprecation ───────────────────────────────

class TestModelDeprecation:
    def test_deprecate_model(self, populated_registry: ModelRegistry) -> None:
        retire_at = _future(60)
        record = populated_registry.deprecate_model("gpt-4o-2024-08-06", retire_at)
        assert record.status == ModelStatus.DEPRECATED
        assert record.deprecated_at is not None
        assert record.retirement_date == retire_at

    def test_deprecate_with_replacement(self, populated_registry: ModelRegistry) -> None:
        record = populated_registry.deprecate_model(
            "gpt-4o-2024-08-06",
            retirement_date=_future(30),
            replacement_model_id="claude-sonnet-4-20250514",
        )
        assert record.replacement_model_id == "claude-sonnet-4-20250514"

    def test_deprecate_nonexistent_raises(self, registry: ModelRegistry) -> None:
        with pytest.raises(KeyError, match="Model not found"):
            registry.deprecate_model("nope", _future())

    def test_deprecate_retired_raises(self, populated_registry: ModelRegistry) -> None:
        populated_registry.retire_model("llama3:8b")
        with pytest.raises(ValueError, match="RETIRED"):
            populated_registry.deprecate_model("llama3:8b", _future())

    def test_deprecate_banned_raises(self, populated_registry: ModelRegistry) -> None:
        populated_registry.ban_model("llama3:8b", "unsafe")
        with pytest.raises(ValueError, match="BANNED"):
            populated_registry.deprecate_model("llama3:8b", _future())


# ── ModelRegistry — retirement ────────────────────────────────

class TestModelRetirement:
    def test_retire_model(self, populated_registry: ModelRegistry) -> None:
        record = populated_registry.retire_model("llama3:8b")
        assert record.status == ModelStatus.RETIRED

    def test_retire_nonexistent_raises(self, registry: ModelRegistry) -> None:
        with pytest.raises(KeyError):
            registry.retire_model("nope")

    def test_check_retirement_due(self, populated_registry: ModelRegistry) -> None:
        populated_registry.deprecate_model(
            "gpt-4o-2024-08-06", retirement_date=_past(1)
        )
        populated_registry.deprecate_model(
            "llama3:8b", retirement_date=_future(30)
        )
        due = populated_registry.check_retirement_due()
        assert len(due) == 1
        assert due[0].model_id == "gpt-4o-2024-08-06"

    def test_check_retirement_due_none(self, populated_registry: ModelRegistry) -> None:
        due = populated_registry.check_retirement_due()
        assert due == []


# ── ModelRegistry — banning ───────────────────────────────────

class TestModelBanning:
    def test_ban_model(self, populated_registry: ModelRegistry) -> None:
        record = populated_registry.ban_model("llama3:8b", "safety concern")
        assert record.status == ModelStatus.BANNED
        assert record.metadata["ban_reason"] == "safety concern"

    def test_ban_nonexistent_raises(self, registry: ModelRegistry) -> None:
        with pytest.raises(KeyError):
            registry.ban_model("nope")


# ── ModelRegistry — allowed status ────────────────────────────

class TestModelAllowed:
    def test_active_is_allowed(self, populated_registry: ModelRegistry) -> None:
        assert populated_registry.is_model_allowed("gpt-4o-2024-08-06") is True

    def test_deprecated_is_allowed(self, populated_registry: ModelRegistry) -> None:
        populated_registry.deprecate_model("gpt-4o-2024-08-06", _future())
        assert populated_registry.is_model_allowed("gpt-4o-2024-08-06") is True

    def test_retired_is_not_allowed(self, populated_registry: ModelRegistry) -> None:
        populated_registry.retire_model("llama3:8b")
        assert populated_registry.is_model_allowed("llama3:8b") is False

    def test_banned_is_not_allowed(self, populated_registry: ModelRegistry) -> None:
        populated_registry.ban_model("llama3:8b")
        assert populated_registry.is_model_allowed("llama3:8b") is False

    def test_unknown_is_not_allowed(self, populated_registry: ModelRegistry) -> None:
        assert populated_registry.is_model_allowed("unknown-model") is False


# ── ModelBindingRegistry ──────────────────────────────────────

class TestModelBinding:
    def test_bind_agent(self, binding_registry: ModelBindingRegistry) -> None:
        binding = binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        assert binding.agent_id == "agent-1"
        assert binding.model_id == "gpt-4o-2024-08-06"
        assert binding.pinned_version is None

    def test_bind_agent_with_pin(self, binding_registry: ModelBindingRegistry) -> None:
        binding = binding_registry.bind_agent(
            "agent-1", "gpt-4o-2024-08-06", pin_version="2024-08-06"
        )
        assert binding.pinned_version == "2024-08-06"

    def test_bind_to_nonexistent_model_raises(self, binding_registry: ModelBindingRegistry) -> None:
        with pytest.raises(KeyError, match="Model not found"):
            binding_registry.bind_agent("agent-1", "nonexistent")

    def test_bind_to_retired_model_raises(
        self, populated_registry: ModelRegistry, binding_registry: ModelBindingRegistry
    ) -> None:
        populated_registry.retire_model("llama3:8b")
        with pytest.raises(ValueError, match="RETIRED"):
            binding_registry.bind_agent("agent-1", "llama3:8b")

    def test_bind_to_banned_model_raises(
        self, populated_registry: ModelRegistry, binding_registry: ModelBindingRegistry
    ) -> None:
        populated_registry.ban_model("llama3:8b")
        with pytest.raises(ValueError, match="BANNED"):
            binding_registry.bind_agent("agent-1", "llama3:8b")

    def test_rebind_replaces(self, binding_registry: ModelBindingRegistry) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        binding_registry.bind_agent("agent-1", "claude-sonnet-4-20250514")
        binding = binding_registry.get_binding("agent-1")
        assert binding is not None
        assert binding.model_id == "claude-sonnet-4-20250514"

    def test_unbind_agent(self, binding_registry: ModelBindingRegistry) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        old = binding_registry.unbind_agent("agent-1")
        assert old is not None
        assert old.model_id == "gpt-4o-2024-08-06"
        assert binding_registry.get_binding("agent-1") is None

    def test_unbind_nonexistent_returns_none(self, binding_registry: ModelBindingRegistry) -> None:
        assert binding_registry.unbind_agent("ghost") is None

    def test_agents_using_model(self, binding_registry: ModelBindingRegistry) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        binding_registry.bind_agent("agent-2", "gpt-4o-2024-08-06")
        binding_registry.bind_agent("agent-3", "claude-sonnet-4-20250514")
        agents = binding_registry.agents_using_model("gpt-4o-2024-08-06")
        assert sorted(agents) == ["agent-1", "agent-2"]


# ── Version Drift ─────────────────────────────────────────────

class TestVersionDrift:
    def test_no_drift_when_versions_match(
        self, binding_registry: ModelBindingRegistry
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06", pin_version="2024-08-06")
        report = binding_registry.check_version_drift("agent-1")
        assert report is not None
        assert report.drift_detected is False

    def test_drift_when_versions_differ(
        self, populated_registry: ModelRegistry, binding_registry: ModelBindingRegistry
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06", pin_version="2024-05-01")
        report = binding_registry.check_version_drift("agent-1")
        assert report is not None
        assert report.drift_detected is True
        assert report.pinned_version == "2024-05-01"
        assert report.current_version == "2024-08-06"

    def test_no_drift_without_pin(self, binding_registry: ModelBindingRegistry) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        assert binding_registry.check_version_drift("agent-1") is None

    def test_no_drift_without_binding(self, binding_registry: ModelBindingRegistry) -> None:
        assert binding_registry.check_version_drift("ghost") is None


# ── Governance Events ─────────────────────────────────────────

class TestGovernanceEvents:
    def test_model_registered_event(self) -> None:
        event = create_governance_event(
            ModelGovernanceEventType.MODEL_REGISTERED,
            model_id="gpt-4o",
        )
        assert event["event_type"] == "MODEL_REGISTERED"
        assert event["payload"]["model_id"] == "gpt-4o"
        assert event["role_used"] == "model_lifecycle"

    def test_model_banned_event_with_reason(self) -> None:
        event = create_governance_event(
            ModelGovernanceEventType.MODEL_BANNED,
            model_id="bad-model",
            reason="safety violation",
        )
        assert event["payload"]["reason"] == "safety violation"

    def test_agent_bound_event(self) -> None:
        event = create_governance_event(
            ModelGovernanceEventType.AGENT_MODEL_BOUND,
            model_id="gpt-4o",
            agent_id="agent-1",
        )
        assert event["actor_id"] == "agent-1"
        assert event["payload"]["model_id"] == "gpt-4o"
        assert event["payload"]["agent_id"] == "agent-1"

    def test_version_drift_event_with_metadata(self) -> None:
        event = create_governance_event(
            ModelGovernanceEventType.VERSION_DRIFT_DETECTED,
            model_id="gpt-4o",
            agent_id="agent-1",
            metadata={"pinned": "v1", "current": "v2"},
        )
        assert event["payload"]["pinned"] == "v1"
        assert event["payload"]["current"] == "v2"

    def test_event_defaults_actor_to_system(self) -> None:
        event = create_governance_event(
            ModelGovernanceEventType.MODEL_RETIRED,
            model_id="old-model",
        )
        assert event["actor_id"] == "system"


# ── ModelLifecycleChecker ─────────────────────────────────────

class TestModelLifecycleChecker:
    @pytest.fixture
    def checker(
        self, populated_registry: ModelRegistry, binding_registry: ModelBindingRegistry
    ) -> ModelLifecycleChecker:
        return ModelLifecycleChecker(populated_registry, binding_registry)

    def test_check_active_model(
        self, binding_registry: ModelBindingRegistry, checker: ModelLifecycleChecker
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        result = checker.check_agent_model_status("agent-1")
        assert result.allowed is True
        assert result.model_status == ModelStatus.ACTIVE

    def test_check_deprecated_model(
        self,
        populated_registry: ModelRegistry,
        binding_registry: ModelBindingRegistry,
        checker: ModelLifecycleChecker,
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        populated_registry.deprecate_model(
            "gpt-4o-2024-08-06",
            retirement_date=_future(30),
            replacement_model_id="claude-sonnet-4-20250514",
        )
        result = checker.check_agent_model_status("agent-1")
        assert result.allowed is True
        assert result.model_status == ModelStatus.DEPRECATED
        assert "replacement" in result.reason

    def test_check_unbound_agent(self, checker: ModelLifecycleChecker) -> None:
        result = checker.check_agent_model_status("ghost")
        assert result.allowed is False
        assert "No model binding" in result.reason

    def test_check_with_version_drift(
        self, binding_registry: ModelBindingRegistry, checker: ModelLifecycleChecker
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06", pin_version="old-ver")
        result = checker.check_agent_model_status("agent-1")
        assert result.version_drift is not None
        assert result.version_drift.drift_detected is True

    def test_fleet_health_report(
        self,
        populated_registry: ModelRegistry,
        binding_registry: ModelBindingRegistry,
        checker: ModelLifecycleChecker,
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        binding_registry.bind_agent("agent-2", "claude-sonnet-4-20250514")
        binding_registry.bind_agent("agent-3", "llama3:8b")
        populated_registry.deprecate_model("llama3:8b", _future(30))

        report = checker.check_fleet_model_health()
        assert report.total_bindings == 3
        assert report.agents_on_active_models == 2
        assert report.agents_on_deprecated_models == 1
        assert report.agents_on_retired_models == 0
        assert len(report.details) == 3

    def test_fleet_health_with_subset(
        self, binding_registry: ModelBindingRegistry, checker: ModelLifecycleChecker
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06")
        binding_registry.bind_agent("agent-2", "claude-sonnet-4-20250514")
        report = checker.check_fleet_model_health(agent_ids=["agent-1"])
        assert report.total_bindings == 1
        assert len(report.details) == 1

    def test_fleet_health_includes_unbound(
        self, checker: ModelLifecycleChecker
    ) -> None:
        report = checker.check_fleet_model_health(agent_ids=["ghost"])
        assert report.agents_unbound == 1

    def test_fleet_health_counts_drift(
        self, binding_registry: ModelBindingRegistry, checker: ModelLifecycleChecker
    ) -> None:
        binding_registry.bind_agent("agent-1", "gpt-4o-2024-08-06", pin_version="old")
        binding_registry.bind_agent("agent-2", "gpt-4o-2024-08-06", pin_version="2024-08-06")
        report = checker.check_fleet_model_health()
        assert report.agents_with_version_drift == 1


# ── Status transitions (edge cases) ──────────────────────────

class TestStatusTransitions:
    def test_active_to_deprecated_to_retired(self, registry: ModelRegistry) -> None:
        registry.register_model("m1", "provider", "v1")
        assert registry.get_model("m1").status == ModelStatus.ACTIVE  # type: ignore[union-attr]

        registry.deprecate_model("m1", _future(30))
        assert registry.get_model("m1").status == ModelStatus.DEPRECATED  # type: ignore[union-attr]
        assert registry.is_model_allowed("m1") is True

        registry.retire_model("m1")
        assert registry.get_model("m1").status == ModelStatus.RETIRED  # type: ignore[union-attr]
        assert registry.is_model_allowed("m1") is False

    def test_active_to_banned(self, registry: ModelRegistry) -> None:
        registry.register_model("m1", "provider", "v1")
        registry.ban_model("m1", "emergency")
        assert registry.get_model("m1").status == ModelStatus.BANNED  # type: ignore[union-attr]
        assert registry.is_model_allowed("m1") is False

    def test_deprecated_model_still_bindable(
        self, populated_registry: ModelRegistry
    ) -> None:
        populated_registry.deprecate_model("gpt-4o-2024-08-06", _future(30))
        br = ModelBindingRegistry(populated_registry)
        binding = br.bind_agent("agent-1", "gpt-4o-2024-08-06")
        assert binding.model_id == "gpt-4o-2024-08-06"
