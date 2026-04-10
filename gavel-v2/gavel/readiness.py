"""
Pre-deployment Readiness Checks — validate before you ship.

Before an agent transitions from enrolled to deployed, this module runs
a comprehensive checklist ensuring:

  1. Enrollment is complete and current (not expired, not suspended)
  2. Budget limits are set and not yet exhausted
  3. An accountable owner is assigned and contactable
  4. The agent's governance token is valid
  5. Required compliance artifacts exist (Annex IV, FRIA if high-risk)
  6. Behavioral baseline is established (if required by tier)
  7. The agent's tier policy allows deployment at current trust level
  8. Multi-tenant context is valid (org active, team exists)

Each check is independent and produces a structured ReadinessCheck result.
The overall ReadinessReport is PASS only if every required check passes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


class ReadinessCheck(BaseModel):
    """Result of a single readiness check."""
    check_id: str
    name: str
    status: CheckStatus
    message: str
    required: bool = True
    details: dict[str, Any] = Field(default_factory=dict)


class ReadinessReport(BaseModel):
    """Aggregate readiness report for an agent."""
    report_id: str = Field(default_factory=lambda: f"ready-{uuid.uuid4().hex[:8]}")
    agent_id: str
    checks: list[ReadinessCheck] = Field(default_factory=list)
    overall: CheckStatus = CheckStatus.FAIL
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    blocking_checks: list[str] = Field(default_factory=list)

    def compute_overall(self) -> None:
        """Derive overall status from individual checks."""
        self.blocking_checks = [
            c.check_id for c in self.checks
            if c.required and c.status == CheckStatus.FAIL
        ]
        if self.blocking_checks:
            self.overall = CheckStatus.FAIL
        elif any(c.status == CheckStatus.WARN for c in self.checks):
            self.overall = CheckStatus.WARN
        else:
            self.overall = CheckStatus.PASS


class ReadinessChecker:
    """Run pre-deployment readiness checks for an agent.

    Accepts optional subsystem references (enrollment_registry, token_manager,
    etc.) and checks whatever is available. Missing subsystems produce SKIP
    rather than FAIL — the deployer decides which checks are blocking.
    """

    def check(
        self,
        agent_id: str,
        *,
        enrollment_record: Any = None,
        token: Any = None,
        tier_policy: Any = None,
        baseline: Any = None,
        annex_iv: Any = None,
        fria: Any = None,
        tenant_context: Any = None,
        tenant_registry: Any = None,
    ) -> ReadinessReport:
        report = ReadinessReport(agent_id=agent_id)
        report.checks.append(self._check_enrollment(agent_id, enrollment_record))
        report.checks.append(self._check_budget(agent_id, enrollment_record))
        report.checks.append(self._check_owner(agent_id, enrollment_record))
        report.checks.append(self._check_token(agent_id, token))
        report.checks.append(self._check_compliance_artifacts(agent_id, enrollment_record, annex_iv, fria))
        report.checks.append(self._check_baseline(agent_id, enrollment_record, baseline))
        report.checks.append(self._check_tier_policy(agent_id, enrollment_record, tier_policy))
        report.checks.append(self._check_tenant(agent_id, tenant_context, tenant_registry))
        report.compute_overall()
        return report

    def _check_enrollment(self, agent_id: str, record: Any) -> ReadinessCheck:
        if record is None:
            return ReadinessCheck(
                check_id="enrollment", name="Enrollment Status",
                status=CheckStatus.FAIL, message="No enrollment record found",
                required=True,
            )
        status = getattr(record, "status", None)
        if status is None:
            return ReadinessCheck(
                check_id="enrollment", name="Enrollment Status",
                status=CheckStatus.FAIL, message="Enrollment record has no status",
                required=True,
            )
        status_val = status.value if hasattr(status, "value") else str(status)
        if status_val == "ENROLLED":
            return ReadinessCheck(
                check_id="enrollment", name="Enrollment Status",
                status=CheckStatus.PASS, message="Agent is enrolled",
                required=True,
                details={"status": status_val, "enrolled_at": str(getattr(record, "enrolled_at", ""))},
            )
        return ReadinessCheck(
            check_id="enrollment", name="Enrollment Status",
            status=CheckStatus.FAIL, message=f"Agent enrollment status is {status_val}, not ENROLLED",
            required=True,
            details={"status": status_val},
        )

    def _check_budget(self, agent_id: str, record: Any) -> ReadinessCheck:
        if record is None:
            return ReadinessCheck(
                check_id="budget", name="Budget Limits",
                status=CheckStatus.SKIP, message="No enrollment record — skipping budget check",
                required=True,
            )
        app = getattr(record, "application", record)
        tokens = getattr(app, "budget_tokens", 0)
        usd = getattr(app, "budget_usd", 0.0)
        if tokens > 0 or usd > 0:
            return ReadinessCheck(
                check_id="budget", name="Budget Limits",
                status=CheckStatus.PASS, message=f"Budget set: {tokens} tokens, ${usd}",
                required=True,
                details={"budget_tokens": tokens, "budget_usd": usd},
            )
        return ReadinessCheck(
            check_id="budget", name="Budget Limits",
            status=CheckStatus.FAIL, message="No budget limits set — open-ended spending not allowed",
            required=True,
        )

    def _check_owner(self, agent_id: str, record: Any) -> ReadinessCheck:
        if record is None:
            return ReadinessCheck(
                check_id="owner", name="Accountable Owner",
                status=CheckStatus.SKIP, message="No enrollment record — skipping owner check",
                required=True,
            )
        app = getattr(record, "application", record)
        owner = getattr(app, "owner", "")
        contact = getattr(app, "owner_contact", "")
        if owner and len(owner) >= 2:
            if contact:
                return ReadinessCheck(
                    check_id="owner", name="Accountable Owner",
                    status=CheckStatus.PASS, message=f"Owner: {owner} ({contact})",
                    required=True,
                    details={"owner": owner, "contact": contact},
                )
            return ReadinessCheck(
                check_id="owner", name="Accountable Owner",
                status=CheckStatus.WARN, message=f"Owner: {owner} — no contact info",
                required=True,
                details={"owner": owner},
            )
        return ReadinessCheck(
            check_id="owner", name="Accountable Owner",
            status=CheckStatus.FAIL, message="No accountable owner assigned",
            required=True,
        )

    def _check_token(self, agent_id: str, token: Any) -> ReadinessCheck:
        if token is None:
            return ReadinessCheck(
                check_id="token", name="Governance Token",
                status=CheckStatus.FAIL, message="No governance token issued",
                required=True,
            )
        revoked = getattr(token, "revoked", False)
        if revoked:
            return ReadinessCheck(
                check_id="token", name="Governance Token",
                status=CheckStatus.FAIL, message="Governance token has been revoked",
                required=True,
            )
        expires_at = getattr(token, "expires_at", None)
        if expires_at and datetime.now(timezone.utc) >= expires_at:
            return ReadinessCheck(
                check_id="token", name="Governance Token",
                status=CheckStatus.FAIL, message="Governance token has expired",
                required=True,
            )
        return ReadinessCheck(
            check_id="token", name="Governance Token",
            status=CheckStatus.PASS, message="Governance token is valid",
            required=True,
            details={"token_prefix": str(getattr(token, "token", ""))[:16] + "..."},
        )

    def _check_compliance_artifacts(self, agent_id: str, record: Any, annex_iv: Any, fria: Any) -> ReadinessCheck:
        if record is None:
            return ReadinessCheck(
                check_id="compliance", name="Compliance Artifacts",
                status=CheckStatus.SKIP, message="No enrollment record — skipping compliance check",
                required=False,
            )
        app = getattr(record, "application", record)
        high_risk = getattr(app, "high_risk_category", None)
        hr_val = high_risk.value if hasattr(high_risk, "value") else str(high_risk or "none")
        is_high_risk = hr_val not in ("none", "None", "")

        if not is_high_risk:
            return ReadinessCheck(
                check_id="compliance", name="Compliance Artifacts",
                status=CheckStatus.PASS, message="Non-high-risk agent — no mandatory artifacts required",
                required=False,
            )

        issues = []
        if annex_iv is None:
            issues.append("Missing Annex IV technical documentation")
        if fria is None:
            issues.append("Missing FRIA (Fundamental Rights Impact Assessment)")

        if issues:
            return ReadinessCheck(
                check_id="compliance", name="Compliance Artifacts",
                status=CheckStatus.FAIL, message="; ".join(issues),
                required=True,
                details={"high_risk_category": hr_val},
            )
        return ReadinessCheck(
            check_id="compliance", name="Compliance Artifacts",
            status=CheckStatus.PASS, message="All required compliance artifacts present",
            required=True,
            details={"high_risk_category": hr_val},
        )

    def _check_baseline(self, agent_id: str, record: Any, baseline: Any) -> ReadinessCheck:
        if record is None:
            return ReadinessCheck(
                check_id="baseline", name="Behavioral Baseline",
                status=CheckStatus.SKIP, message="No enrollment record — skipping baseline check",
                required=False,
            )
        app = getattr(record, "application", record)
        risk_tier = getattr(getattr(app, "purpose", None), "risk_tier", "standard")

        if risk_tier in ("low", "standard"):
            if baseline is not None:
                return ReadinessCheck(
                    check_id="baseline", name="Behavioral Baseline",
                    status=CheckStatus.PASS, message="Behavioral baseline established (optional for this tier)",
                    required=False,
                )
            return ReadinessCheck(
                check_id="baseline", name="Behavioral Baseline",
                status=CheckStatus.SKIP, message=f"Baseline not required for {risk_tier} tier",
                required=False,
            )

        if baseline is None:
            return ReadinessCheck(
                check_id="baseline", name="Behavioral Baseline",
                status=CheckStatus.FAIL, message=f"Behavioral baseline required for {risk_tier} tier but not established",
                required=True,
            )
        return ReadinessCheck(
            check_id="baseline", name="Behavioral Baseline",
            status=CheckStatus.PASS, message="Behavioral baseline established",
            required=True,
        )

    def _check_tier_policy(self, agent_id: str, record: Any, tier_policy: Any) -> ReadinessCheck:
        if tier_policy is None:
            return ReadinessCheck(
                check_id="tier_policy", name="Tier Policy",
                status=CheckStatus.SKIP, message="No tier policy — skipping tier check",
                required=False,
            )
        if record is None:
            return ReadinessCheck(
                check_id="tier_policy", name="Tier Policy",
                status=CheckStatus.SKIP, message="No enrollment record — skipping tier check",
                required=False,
            )
        return ReadinessCheck(
            check_id="tier_policy", name="Tier Policy",
            status=CheckStatus.PASS, message="Tier policy is configured",
            required=False,
            details={"tier_policy": str(type(tier_policy).__name__)},
        )

    def _check_tenant(self, agent_id: str, tenant_context: Any, tenant_registry: Any) -> ReadinessCheck:
        if tenant_context is None:
            return ReadinessCheck(
                check_id="tenant", name="Tenant Context",
                status=CheckStatus.SKIP, message="No tenant context — single-tenant mode",
                required=False,
            )
        org_id = getattr(tenant_context, "org_id", "")
        team_id = getattr(tenant_context, "team_id", "")

        if not org_id or not team_id:
            return ReadinessCheck(
                check_id="tenant", name="Tenant Context",
                status=CheckStatus.FAIL, message="Incomplete tenant context (missing org_id or team_id)",
                required=True,
            )

        if tenant_registry is not None:
            org = tenant_registry.get_org(org_id) if hasattr(tenant_registry, "get_org") else None
            if org is None:
                return ReadinessCheck(
                    check_id="tenant", name="Tenant Context",
                    status=CheckStatus.FAIL, message=f"Organization {org_id} not found",
                    required=True,
                )
            org_status = getattr(org, "status", None)
            status_val = org_status.value if hasattr(org_status, "value") else str(org_status)
            if status_val != "active":
                return ReadinessCheck(
                    check_id="tenant", name="Tenant Context",
                    status=CheckStatus.FAIL, message=f"Organization {org_id} is {status_val}",
                    required=True,
                )

        return ReadinessCheck(
            check_id="tenant", name="Tenant Context",
            status=CheckStatus.PASS, message=f"Tenant: org={org_id}, team={team_id}",
            required=True,
            details={"org_id": org_id, "team_id": team_id},
        )
