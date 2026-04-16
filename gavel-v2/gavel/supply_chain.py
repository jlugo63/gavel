"""
Supply Chain Provenance — OWASP ASI06, CSA AICM Supply Chain.

Tracks and validates the provenance, integrity, and attestation status
of tools, plugins, and dependencies used by agents.

Standards coverage:
  OWASP ASI06  Supply Chain Compromise     — tool attestation, SBOM generation
  CSA AICM     Supply Chain Management     — dependency tracking, vulnerability checks
  NIST MANAGE  Supply Chain Risk Management — policy enforcement, audit trail
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field

log = logging.getLogger("gavel.supply_chain")


# ── Attestation & Dependency Models ───────────────────────────

class ToolAttestation(BaseModel):
    """Cryptographic attestation record for a tool or plugin."""
    tool_name: str
    tool_version: str
    publisher: str
    content_hash: str                          # SHA-256 of tool binary/source
    signature: Optional[str] = None            # Publisher's cryptographic signature
    attested_at: datetime
    expires_at: Optional[datetime] = None
    attestation_url: Optional[str] = None      # Where to verify externally

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Check whether this attestation has expired."""
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at


class DependencyRecord(BaseModel):
    """A single dependency in an agent's software supply chain."""
    package_name: str
    version: str
    source: str                                # e.g. "pypi", "npm", "github"
    content_hash: str                          # SHA-256 of package artifact
    license: str
    known_vulnerabilities: list[str] = Field(default_factory=list)
    last_checked: datetime


class ValidationResult(BaseModel):
    """Outcome of a supply-chain validation check."""
    valid: bool
    violations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Software Bill of Materials ────────────────────────────────

class SBOM(BaseModel):
    """Software Bill of Materials for a governed agent."""
    sbom_id: str = Field(default_factory=lambda: uuid4().hex)
    agent_id: str
    generated_at: datetime
    format_version: str = "1.0"
    dependencies: list[DependencyRecord] = Field(default_factory=list)
    tools: list[ToolAttestation] = Field(default_factory=list)

    @computed_field  # type: ignore[misc]
    @property
    def total_dependencies(self) -> int:
        return len(self.dependencies)

    @computed_field  # type: ignore[misc]
    @property
    def unattested_count(self) -> int:
        """Tools without a valid (non-expired) attestation."""
        now = datetime.now(timezone.utc)
        return sum(1 for t in self.tools if t.signature is None or t.is_expired(now))

    @computed_field  # type: ignore[misc]
    @property
    def vulnerable_count(self) -> int:
        return sum(1 for d in self.dependencies if d.known_vulnerabilities)


# ── Supply Chain Policy ───────────────────────────────────────

class SupplyChainPolicy(BaseModel):
    """Configurable policy governing supply-chain requirements."""
    require_attestation: bool = True                       # All tools must have attestations
    max_vulnerability_severity: str = "HIGH"               # Block CRITICAL vulns
    allowed_sources: list[str] = Field(default_factory=lambda: ["pypi", "npm", "github"])
    blocked_packages: list[str] = Field(default_factory=list)
    max_unattested_ratio: float = 0.1                      # Max 10% unattested deps


# ── Validator ─────────────────────────────────────────────────

class SupplyChainValidator:
    """Validates tools, dependencies, and SBOMs against a SupplyChainPolicy."""

    def __init__(self, policy: SupplyChainPolicy) -> None:
        self.policy = policy

    def validate_tool(self, attestation: ToolAttestation) -> ValidationResult:
        """Validate a single tool attestation against policy."""
        violations: list[str] = []
        warnings: list[str] = []
        now = datetime.now(timezone.utc)

        # Signature check
        if self.policy.require_attestation and attestation.signature is None:
            violations.append(f"Tool '{attestation.tool_name}' has no signature")

        # Expiry check
        if attestation.is_expired(now):
            violations.append(
                f"Tool '{attestation.tool_name}' attestation expired at {attestation.expires_at}"
            )

        # Content hash sanity
        if not attestation.content_hash:
            violations.append(f"Tool '{attestation.tool_name}' missing content_hash")

        # Publisher trust (warn if empty)
        if not attestation.publisher:
            warnings.append(f"Tool '{attestation.tool_name}' has no publisher declared")

        return ValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    def check_dependency(self, dep: DependencyRecord) -> list[str]:
        """Check a single dependency against policy. Returns list of violations."""
        violations: list[str] = []

        # Source allowlist
        if dep.source not in self.policy.allowed_sources:
            violations.append(
                f"Dependency '{dep.package_name}' from disallowed source '{dep.source}'"
            )

        # Blocked packages
        if dep.package_name in self.policy.blocked_packages:
            violations.append(
                f"Dependency '{dep.package_name}' is on the blocked packages list"
            )

        # Vulnerability check — block if any vuln contains "CRITICAL"
        # when policy max_vulnerability_severity is below CRITICAL
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        max_idx = severity_order.index(self.policy.max_vulnerability_severity) \
            if self.policy.max_vulnerability_severity in severity_order else 2

        for vuln in dep.known_vulnerabilities:
            vuln_upper = vuln.upper()
            for idx, sev in enumerate(severity_order):
                if sev in vuln_upper and idx > max_idx:
                    violations.append(
                        f"Dependency '{dep.package_name}' has vulnerability exceeding "
                        f"policy threshold ({sev} > {self.policy.max_vulnerability_severity}): {vuln}"
                    )

        return violations

    def validate_sbom(self, sbom: SBOM) -> ValidationResult:
        """Validate an entire SBOM against policy."""
        violations: list[str] = []
        warnings: list[str] = []

        # Validate each tool
        for tool in sbom.tools:
            result = self.validate_tool(tool)
            violations.extend(result.violations)
            warnings.extend(result.warnings)

        # Validate each dependency
        for dep in sbom.dependencies:
            dep_violations = self.check_dependency(dep)
            violations.extend(dep_violations)

        # Unattested ratio check
        total_tools = len(sbom.tools)
        if total_tools > 0:
            unattested_ratio = sbom.unattested_count / total_tools
            if unattested_ratio > self.policy.max_unattested_ratio:
                violations.append(
                    f"Unattested tool ratio {unattested_ratio:.0%} exceeds "
                    f"policy limit {self.policy.max_unattested_ratio:.0%}"
                )

        return ValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    def generate_sbom(
        self,
        agent_id: str,
        dependencies: list[DependencyRecord],
        tools: list[ToolAttestation],
    ) -> SBOM:
        """Create a new SBOM for an agent."""
        sbom = SBOM(
            agent_id=agent_id,
            generated_at=datetime.now(timezone.utc),
            dependencies=dependencies,
            tools=tools,
        )
        log.info(
            "SBOM generated for agent %s: %d deps, %d tools, %d unattested, %d vulnerable",
            agent_id, sbom.total_dependencies, len(tools),
            sbom.unattested_count, sbom.vulnerable_count,
        )
        return sbom


# ── Registry ──────────────────────────────────────────────────

class SupplyChainRegistry:
    """In-memory registry of agent SBOMs for governance and audit."""

    def __init__(self, policy: Optional[SupplyChainPolicy] = None) -> None:
        self._sboms: dict[str, SBOM] = {}
        self._validator = SupplyChainValidator(policy or SupplyChainPolicy())

    def register_sbom(self, sbom: SBOM) -> None:
        """Store (or replace) the SBOM for an agent."""
        self._sboms[sbom.agent_id] = sbom
        log.info("SBOM registered for agent %s (id: %s)", sbom.agent_id, sbom.sbom_id)

    def get_sbom(self, agent_id: str) -> Optional[SBOM]:
        """Retrieve the SBOM for an agent."""
        return self._sboms.get(agent_id)

    def get_unattested_tools(self, agent_id: str) -> list[str]:
        """List tool names without a valid (non-expired, signed) attestation."""
        sbom = self._sboms.get(agent_id)
        if sbom is None:
            return []
        now = datetime.now(timezone.utc)
        return [
            t.tool_name for t in sbom.tools
            if t.signature is None or t.is_expired(now)
        ]

    def get_vulnerable_dependencies(self, agent_id: str) -> list[DependencyRecord]:
        """Return dependencies with known vulnerabilities for an agent."""
        sbom = self._sboms.get(agent_id)
        if sbom is None:
            return []
        return [d for d in sbom.dependencies if d.known_vulnerabilities]

    def audit_all(self) -> dict[str, ValidationResult]:
        """Validate all registered SBOMs and return results keyed by agent_id."""
        results: dict[str, ValidationResult] = {}
        for agent_id, sbom in self._sboms.items():
            results[agent_id] = self._validator.validate_sbom(sbom)
        return results
