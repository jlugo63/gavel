"""Tests for gavel.readiness — pre-deployment readiness checks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from gavel.readiness import CheckStatus, ReadinessChecker, ReadinessReport


def _enrolled_record():
    return SimpleNamespace(
        status=SimpleNamespace(value="ENROLLED"),
        enrolled_at=datetime.now(timezone.utc),
        application=SimpleNamespace(
            budget_tokens=50000,
            budget_usd=25.0,
            owner="dev@acme.com",
            owner_contact="dev@acme.com",
            high_risk_category=SimpleNamespace(value="none"),
            purpose=SimpleNamespace(risk_tier="standard"),
        ),
    )


def _valid_token():
    return SimpleNamespace(
        token="gvl_tok_abc123",
        revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


class TestReadinessChecker:
    def test_all_pass_with_full_context(self):
        checker = ReadinessChecker()
        report = checker.check(
            "agent:test",
            enrollment_record=_enrolled_record(),
            token=_valid_token(),
        )
        assert report.overall == CheckStatus.PASS
        assert len(report.blocking_checks) == 0

    def test_fail_without_enrollment(self):
        checker = ReadinessChecker()
        report = checker.check("agent:test")
        assert report.overall == CheckStatus.FAIL
        assert "enrollment" in report.blocking_checks

    def test_fail_without_token(self):
        checker = ReadinessChecker()
        report = checker.check(
            "agent:test",
            enrollment_record=_enrolled_record(),
        )
        assert report.overall == CheckStatus.FAIL
        assert "token" in report.blocking_checks

    def test_fail_with_revoked_token(self):
        checker = ReadinessChecker()
        token = _valid_token()
        token.revoked = True
        report = checker.check(
            "agent:test",
            enrollment_record=_enrolled_record(),
            token=token,
        )
        assert report.overall == CheckStatus.FAIL
        assert "token" in report.blocking_checks

    def test_fail_with_expired_token(self):
        checker = ReadinessChecker()
        token = _valid_token()
        token.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        report = checker.check(
            "agent:test",
            enrollment_record=_enrolled_record(),
            token=token,
        )
        assert report.overall == CheckStatus.FAIL

    def test_warn_with_no_owner_contact(self):
        checker = ReadinessChecker()
        record = _enrolled_record()
        record.application.owner_contact = ""
        report = checker.check(
            "agent:test",
            enrollment_record=record,
            token=_valid_token(),
        )
        # No blocking failures for owner warn, but overall might be WARN
        owner_check = next(c for c in report.checks if c.check_id == "owner")
        assert owner_check.status == CheckStatus.WARN

    def test_eight_checks_generated(self):
        checker = ReadinessChecker()
        report = checker.check("agent:test")
        assert len(report.checks) == 8

    def test_high_risk_requires_compliance_artifacts(self):
        checker = ReadinessChecker()
        record = _enrolled_record()
        record.application.high_risk_category = SimpleNamespace(value="employment")
        report = checker.check(
            "agent:test",
            enrollment_record=record,
            token=_valid_token(),
        )
        compliance_check = next(c for c in report.checks if c.check_id == "compliance")
        assert compliance_check.status == CheckStatus.FAIL

    def test_high_risk_passes_with_artifacts(self):
        checker = ReadinessChecker()
        record = _enrolled_record()
        record.application.high_risk_category = SimpleNamespace(value="employment")
        report = checker.check(
            "agent:test",
            enrollment_record=record,
            token=_valid_token(),
            annex_iv={"exists": True},
            fria={"exists": True},
        )
        compliance_check = next(c for c in report.checks if c.check_id == "compliance")
        assert compliance_check.status == CheckStatus.PASS

    def test_high_tier_requires_baseline(self):
        checker = ReadinessChecker()
        record = _enrolled_record()
        record.application.purpose.risk_tier = "high"
        report = checker.check(
            "agent:test",
            enrollment_record=record,
            token=_valid_token(),
        )
        baseline_check = next(c for c in report.checks if c.check_id == "baseline")
        assert baseline_check.status == CheckStatus.FAIL

    def test_report_id_unique(self):
        checker = ReadinessChecker()
        r1 = checker.check("a")
        r2 = checker.check("b")
        assert r1.report_id != r2.report_id


class TestReadinessWithTenant:
    def test_tenant_check_pass(self):
        checker = ReadinessChecker()
        from gavel.tenants import TenantContext, TenantRegistry
        reg = TenantRegistry()
        org = reg.create_org("Acme", billing_owner="x")
        team = reg.create_team(org.org_id, "Eng", owner="y")
        ctx = TenantContext(org_id=org.org_id, team_id=team.team_id, operator_id="op")
        report = checker.check(
            "agent:test",
            enrollment_record=_enrolled_record(),
            token=_valid_token(),
            tenant_context=ctx,
            tenant_registry=reg,
        )
        tenant_check = next(c for c in report.checks if c.check_id == "tenant")
        assert tenant_check.status == CheckStatus.PASS

    def test_tenant_check_fails_for_suspended_org(self):
        checker = ReadinessChecker()
        from gavel.tenants import TenantContext, TenantRegistry
        reg = TenantRegistry()
        org = reg.create_org("Acme", billing_owner="x")
        team = reg.create_team(org.org_id, "Eng", owner="y")
        reg.suspend_org(org.org_id)
        ctx = TenantContext(org_id=org.org_id, team_id=team.team_id, operator_id="op")
        report = checker.check(
            "agent:test",
            enrollment_record=_enrolled_record(),
            token=_valid_token(),
            tenant_context=ctx,
            tenant_registry=reg,
        )
        tenant_check = next(c for c in report.checks if c.check_id == "tenant")
        assert tenant_check.status == CheckStatus.FAIL
