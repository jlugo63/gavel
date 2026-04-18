"""
Evidence Reviewer — deterministic review of blast box output.

Microsoft's toolkit evaluates "is this action allowed?" (policy).
Gavel's evidence reviewer evaluates "did the speculative execution
prove this action is safe?" (evidence).

This is a deterministic, non-LLM review. No model in the loop.
It checks scope compliance, diff analysis, secret detection, and
risk delta computation. The output is a ReviewResult that feeds
into the governance chain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from gavel.blastbox import EvidencePacket, ScopeDeclaration
from gavel.privacy import scan_text


class ReviewVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class Finding:
    """A single finding from the evidence review."""

    check: str
    passed: bool
    detail: str
    severity: str = "info"  # info, warn, fail


@dataclass
class ReviewResult:
    """The output of a deterministic evidence review."""

    verdict: ReviewVerdict = ReviewVerdict.PASS
    findings: list[Finding] = field(default_factory=list)
    risk_delta: float = 0.0
    scope_compliance: str = "FULL"
    review_hash: str = ""
    # D-3 Privacy: redacted outputs carry no PII/PHI; originals are dropped.
    redacted_stdout: str = ""
    redacted_stderr: str = ""
    privacy_findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.verdict == ReviewVerdict.PASS


# Patterns that should never appear in stdout/stderr
SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
]


class EvidenceReviewer:
    """
    Deterministic evidence review engine.

    Runs a series of checks against an evidence packet and produces
    a ReviewResult. Every check is deterministic — no LLM, no
    probability, no ambiguity.

    Checks performed:
    1. Exit code == 0
    2. All modified files within declared scope
    3. No forbidden paths touched
    4. Network mode matches declaration
    5. No secrets in stdout/stderr
    6. No unexpected file deletions
    7. Risk delta computation
    """

    def __init__(self, forbidden_paths: list[str] | None = None):
        self.forbidden_paths = forbidden_paths or [
            "/etc/shadow",
            "/etc/passwd",
            ".env",
            "credentials",
            "secrets",
            "*.pem",
            "*.key",
        ]

    def review(
        self,
        packet: EvidencePacket,
        declared_scope: ScopeDeclaration,
        stdout_content: str = "",
        stderr_content: str = "",
    ) -> ReviewResult:
        """Run all deterministic checks against the evidence packet."""
        findings: list[Finding] = []
        risk_delta = 0.0

        # Check 1: Exit code
        findings.append(Finding(
            check="exit_code",
            passed=packet.exit_code == 0,
            detail=f"Exit code: {packet.exit_code}",
            severity="fail" if packet.exit_code != 0 else "info",
        ))

        # Check 2: Files within declared scope
        scope_ok = True
        for f in packet.files_modified + packet.files_created:
            in_scope = any(f.startswith(p) for p in declared_scope.allow_paths)
            if not in_scope:
                scope_ok = False
                risk_delta += 0.3
                findings.append(Finding(
                    check="scope_compliance",
                    passed=False,
                    detail=f"File '{f}' outside declared allow_paths",
                    severity="fail",
                ))
        if scope_ok:
            findings.append(Finding(
                check="scope_compliance",
                passed=True,
                detail="All files within declared scope",
            ))

        # Check 3: Forbidden paths
        for f in packet.files_modified + packet.files_created + packet.files_deleted:
            for forbidden in self.forbidden_paths:
                if forbidden in f:
                    risk_delta += 0.5
                    findings.append(Finding(
                        check="forbidden_path",
                        passed=False,
                        detail=f"Forbidden path pattern '{forbidden}' found in '{f}'",
                        severity="fail",
                    ))

        # Check 4: Network mode
        if not declared_scope.allow_network and packet.network_mode != "none":
            risk_delta += 0.4
            findings.append(Finding(
                check="network_mode",
                passed=False,
                detail=f"Network mode '{packet.network_mode}' but scope declares no network",
                severity="fail",
            ))
        else:
            findings.append(Finding(
                check="network_mode",
                passed=True,
                detail=f"Network mode: {packet.network_mode}",
            ))

        # Check 5: Secrets in output
        for content, label in [(stdout_content, "stdout"), (stderr_content, "stderr")]:
            for pattern in SECRET_PATTERNS:
                if pattern.search(content):
                    risk_delta += 0.5
                    findings.append(Finding(
                        check="secret_detection",
                        passed=False,
                        detail=f"Potential secret detected in {label}",
                        severity="fail",
                    ))
                    break
            else:
                findings.append(Finding(
                    check="secret_detection",
                    passed=True,
                    detail=f"No secrets detected in {label}",
                ))

        # Check 5b: D-3 PII/PHI scan with redaction
        stdout_scan = scan_text(stdout_content)
        stderr_scan = scan_text(stderr_content)
        privacy_findings_dict: list[dict[str, Any]] = []
        for scan, label in [(stdout_scan, "stdout"), (stderr_scan, "stderr")]:
            if scan.findings:
                # PII and PHI both contribute to risk; PHI is weighted heavier.
                risk_delta += 0.3 * scan.pii_count + 0.5 * scan.phi_count
                for f in scan.findings:
                    privacy_findings_dict.append({
                        "stream": label,
                        "category": f.category.value,
                        "type": f.type,
                        "span": list(f.span),
                        "redacted": f.redacted,
                    })
                findings.append(Finding(
                    check="pii_phi_scan",
                    passed=False,
                    detail=(
                        f"{label}: {scan.pii_count} PII + {scan.phi_count} PHI "
                        f"matches (redacted in artifact)"
                    ),
                    severity="fail" if scan.phi_count else "warn",
                ))
            else:
                findings.append(Finding(
                    check="pii_phi_scan",
                    passed=True,
                    detail=f"{label}: no PII/PHI detected",
                ))

        # Check 6: Unexpected deletions
        if packet.files_deleted:
            for f in packet.files_deleted:
                in_scope = any(f.startswith(p) for p in declared_scope.allow_paths)
                if not in_scope:
                    risk_delta += 0.3
                    findings.append(Finding(
                        check="file_deletion",
                        passed=False,
                        detail=f"File deletion '{f}' outside declared scope",
                        severity="fail",
                    ))

        has_failures = any(f.severity == "fail" and not f.passed for f in findings)
        has_warnings = any(f.severity == "warn" and not f.passed for f in findings)

        if has_failures:
            verdict = ReviewVerdict.FAIL
            scope_compliance = "VIOLATION"
        elif has_warnings:
            verdict = ReviewVerdict.WARN
            scope_compliance = "PARTIAL"
        else:
            verdict = ReviewVerdict.PASS
            scope_compliance = "FULL"

        return ReviewResult(
            verdict=verdict,
            findings=findings,
            risk_delta=risk_delta,
            scope_compliance=scope_compliance,
            redacted_stdout=stdout_scan.redacted_text,
            redacted_stderr=stderr_scan.redacted_text,
            privacy_findings=privacy_findings_dict,
        )
