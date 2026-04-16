"""Tests for gavel.supply_chain — OWASP ASI06, CSA AICM Supply Chain."""

from datetime import datetime, timedelta, timezone

import pytest

from gavel.supply_chain import (
    DependencyRecord,
    SBOM,
    SupplyChainPolicy,
    SupplyChainRegistry,
    SupplyChainValidator,
    ToolAttestation,
    ValidationResult,
)

NOW = datetime.now(timezone.utc)


# ── Helpers ───────────────────────────────────────────────────

def _make_attestation(
    name: str = "tool-a",
    version: str = "1.0.0",
    signed: bool = True,
    expired: bool = False,
) -> ToolAttestation:
    return ToolAttestation(
        tool_name=name,
        tool_version=version,
        publisher="acme-corp",
        content_hash="sha256:abc123" + name,
        signature="sig-valid" if signed else None,
        attested_at=NOW - timedelta(days=30),
        expires_at=(NOW - timedelta(hours=1)) if expired else (NOW + timedelta(days=365)),
    )


def _make_dependency(
    name: str = "requests",
    source: str = "pypi",
    vulns: list[str] | None = None,
) -> DependencyRecord:
    return DependencyRecord(
        package_name=name,
        version="2.31.0",
        source=source,
        content_hash="sha256:dep-" + name,
        license="MIT",
        known_vulnerabilities=vulns or [],
        last_checked=NOW,
    )


# ── ToolAttestation ───────────────────────────────────────────

class TestToolAttestation:
    def test_create_valid(self):
        att = _make_attestation()
        assert att.tool_name == "tool-a"
        assert att.signature is not None
        assert not att.is_expired()

    def test_expired(self):
        att = _make_attestation(expired=True)
        assert att.is_expired()

    def test_no_expiry_never_expires(self):
        att = _make_attestation()
        att.expires_at = None
        assert not att.is_expired()

    def test_unsigned(self):
        att = _make_attestation(signed=False)
        assert att.signature is None


# ── DependencyRecord ──────────────────────────────────────────

class TestDependencyRecord:
    def test_no_vulns(self):
        dep = _make_dependency()
        assert dep.known_vulnerabilities == []

    def test_with_vulns(self):
        dep = _make_dependency(vulns=["CVE-2024-1234 CRITICAL"])
        assert len(dep.known_vulnerabilities) == 1


# ── SBOM ──────────────────────────────────────────────────────

class TestSBOM:
    def test_computed_fields(self):
        sbom = SBOM(
            agent_id="agent-1",
            generated_at=NOW,
            dependencies=[_make_dependency(), _make_dependency("flask")],
            tools=[_make_attestation(), _make_attestation("tool-b", signed=False)],
        )
        assert sbom.total_dependencies == 2
        assert sbom.unattested_count == 1  # tool-b is unsigned
        assert sbom.vulnerable_count == 0

    def test_vulnerable_count(self):
        sbom = SBOM(
            agent_id="agent-2",
            generated_at=NOW,
            dependencies=[
                _make_dependency(vulns=["CVE-2024-001 HIGH"]),
                _make_dependency("safe-lib"),
            ],
            tools=[],
        )
        assert sbom.vulnerable_count == 1

    def test_empty_sbom(self):
        sbom = SBOM(agent_id="agent-empty", generated_at=NOW)
        assert sbom.total_dependencies == 0
        assert sbom.unattested_count == 0
        assert sbom.vulnerable_count == 0

    def test_all_unattested(self):
        sbom = SBOM(
            agent_id="agent-3",
            generated_at=NOW,
            tools=[
                _make_attestation("t1", signed=False),
                _make_attestation("t2", signed=False),
            ],
        )
        assert sbom.unattested_count == 2

    def test_expired_attestation_counted(self):
        sbom = SBOM(
            agent_id="agent-4",
            generated_at=NOW,
            tools=[_make_attestation("t1", expired=True)],
        )
        assert sbom.unattested_count == 1  # expired counts as unattested


# ── SupplyChainValidator ──────────────────────────────────────

class TestSupplyChainValidator:
    def test_validate_tool_valid(self):
        v = SupplyChainValidator(SupplyChainPolicy())
        result = v.validate_tool(_make_attestation())
        assert result.valid
        assert result.violations == []

    def test_validate_tool_no_signature(self):
        v = SupplyChainValidator(SupplyChainPolicy(require_attestation=True))
        result = v.validate_tool(_make_attestation(signed=False))
        assert not result.valid
        assert any("no signature" in v for v in result.violations)

    def test_validate_tool_expired(self):
        v = SupplyChainValidator(SupplyChainPolicy())
        result = v.validate_tool(_make_attestation(expired=True))
        assert not result.valid
        assert any("expired" in v for v in result.violations)

    def test_validate_tool_attestation_not_required(self):
        v = SupplyChainValidator(SupplyChainPolicy(require_attestation=False))
        result = v.validate_tool(_make_attestation(signed=False))
        assert result.valid  # no signature is OK when not required

    def test_check_dependency_clean(self):
        v = SupplyChainValidator(SupplyChainPolicy())
        violations = v.check_dependency(_make_dependency())
        assert violations == []

    def test_check_dependency_blocked_package(self):
        v = SupplyChainValidator(SupplyChainPolicy(blocked_packages=["evil-lib"]))
        violations = v.check_dependency(_make_dependency("evil-lib"))
        assert any("blocked" in v for v in violations)

    def test_check_dependency_disallowed_source(self):
        v = SupplyChainValidator(SupplyChainPolicy(allowed_sources=["pypi"]))
        violations = v.check_dependency(_make_dependency(source="unknown-registry"))
        assert any("disallowed source" in v for v in violations)

    def test_check_dependency_critical_vuln_blocked(self):
        v = SupplyChainValidator(SupplyChainPolicy(max_vulnerability_severity="HIGH"))
        violations = v.check_dependency(
            _make_dependency(vulns=["CVE-2024-9999 CRITICAL RCE"])
        )
        assert any("CRITICAL" in v for v in violations)

    def test_check_dependency_high_vuln_allowed(self):
        v = SupplyChainValidator(SupplyChainPolicy(max_vulnerability_severity="HIGH"))
        violations = v.check_dependency(
            _make_dependency(vulns=["CVE-2024-1111 HIGH buffer overflow"])
        )
        assert violations == []  # HIGH is within threshold

    def test_validate_sbom_all_clean(self):
        v = SupplyChainValidator(SupplyChainPolicy())
        sbom = SBOM(
            agent_id="agent-ok",
            generated_at=NOW,
            dependencies=[_make_dependency()],
            tools=[_make_attestation()],
        )
        result = v.validate_sbom(sbom)
        assert result.valid

    def test_validate_sbom_unattested_ratio_exceeded(self):
        v = SupplyChainValidator(SupplyChainPolicy(max_unattested_ratio=0.0))
        sbom = SBOM(
            agent_id="agent-bad",
            generated_at=NOW,
            tools=[_make_attestation(signed=False)],
        )
        result = v.validate_sbom(sbom)
        assert not result.valid
        assert any("Unattested tool ratio" in v for v in result.violations)

    def test_validate_sbom_empty_is_valid(self):
        v = SupplyChainValidator(SupplyChainPolicy())
        sbom = SBOM(agent_id="agent-empty", generated_at=NOW)
        result = v.validate_sbom(sbom)
        assert result.valid

    def test_generate_sbom(self):
        v = SupplyChainValidator(SupplyChainPolicy())
        sbom = v.generate_sbom(
            "agent-gen",
            dependencies=[_make_dependency()],
            tools=[_make_attestation()],
        )
        assert sbom.agent_id == "agent-gen"
        assert sbom.total_dependencies == 1
        assert sbom.sbom_id  # UUID was generated


# ── SupplyChainRegistry ──────────────────────────────────────

class TestSupplyChainRegistry:
    def test_register_and_get(self):
        reg = SupplyChainRegistry()
        sbom = SBOM(
            agent_id="agent-r1",
            generated_at=NOW,
            tools=[_make_attestation()],
        )
        reg.register_sbom(sbom)
        assert reg.get_sbom("agent-r1") is sbom

    def test_get_missing(self):
        reg = SupplyChainRegistry()
        assert reg.get_sbom("nonexistent") is None

    def test_get_unattested_tools(self):
        reg = SupplyChainRegistry()
        sbom = SBOM(
            agent_id="agent-u",
            generated_at=NOW,
            tools=[
                _make_attestation("signed-tool"),
                _make_attestation("unsigned-tool", signed=False),
            ],
        )
        reg.register_sbom(sbom)
        unattested = reg.get_unattested_tools("agent-u")
        assert "unsigned-tool" in unattested
        assert "signed-tool" not in unattested

    def test_get_unattested_tools_missing_agent(self):
        reg = SupplyChainRegistry()
        assert reg.get_unattested_tools("ghost") == []

    def test_get_vulnerable_dependencies(self):
        reg = SupplyChainRegistry()
        vuln_dep = _make_dependency("vuln-pkg", vulns=["CVE-2024-0001 HIGH"])
        safe_dep = _make_dependency("safe-pkg")
        sbom = SBOM(
            agent_id="agent-v",
            generated_at=NOW,
            dependencies=[vuln_dep, safe_dep],
        )
        reg.register_sbom(sbom)
        vulns = reg.get_vulnerable_dependencies("agent-v")
        assert len(vulns) == 1
        assert vulns[0].package_name == "vuln-pkg"

    def test_get_vulnerable_dependencies_missing_agent(self):
        reg = SupplyChainRegistry()
        assert reg.get_vulnerable_dependencies("ghost") == []

    def test_audit_all(self):
        reg = SupplyChainRegistry()
        sbom1 = SBOM(
            agent_id="agent-a1",
            generated_at=NOW,
            tools=[_make_attestation()],
            dependencies=[_make_dependency()],
        )
        sbom2 = SBOM(
            agent_id="agent-a2",
            generated_at=NOW,
            tools=[_make_attestation(signed=False)],
        )
        reg.register_sbom(sbom1)
        reg.register_sbom(sbom2)
        results = reg.audit_all()
        assert "agent-a1" in results
        assert "agent-a2" in results
        assert results["agent-a1"].valid
        assert not results["agent-a2"].valid  # unsigned tool + attestation required

    def test_audit_all_empty(self):
        reg = SupplyChainRegistry()
        assert reg.audit_all() == {}

    def test_replace_sbom(self):
        reg = SupplyChainRegistry()
        sbom_v1 = SBOM(agent_id="agent-rep", generated_at=NOW, tools=[])
        sbom_v2 = SBOM(agent_id="agent-rep", generated_at=NOW, tools=[_make_attestation()])
        reg.register_sbom(sbom_v1)
        reg.register_sbom(sbom_v2)
        assert reg.get_sbom("agent-rep") is sbom_v2


# ── ValidationResult ──────────────────────────────────────────

class TestValidationResult:
    def test_defaults(self):
        vr = ValidationResult(valid=True)
        assert vr.violations == []
        assert vr.warnings == []
        assert vr.checked_at is not None

    def test_with_violations(self):
        vr = ValidationResult(valid=False, violations=["bad thing"])
        assert not vr.valid
        assert len(vr.violations) == 1
