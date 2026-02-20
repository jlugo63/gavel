"""
Deterministic Evidence Review
Constitutional Reference: §II — Automated analysis of Evidence Packets

Runs deterministic checks on Blast Box evidence: scope compliance,
forbidden path detection, secret exposure scanning, and dependency
change detection. Produces a ReviewResult with findings and risk delta.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from governance.audit import AuditSpineManager
from governance.evidence import EvidencePacket


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ReviewFinding:
    category: str  # scope_violation, forbidden_path, secret_exposure, dependency_change, network_attempt
    severity: str  # critical, high, medium, low
    description: str
    file_path: str | None = None
    matched_pattern: str | None = None


@dataclass
class ReviewResult:
    passed: bool
    findings: list[ReviewFinding] = field(default_factory=list)
    risk_delta: float = 0.0
    scope_compliant: bool = True
    reviewed_at: str = ""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FORBIDDEN_PATHS = [
    re.compile(r"CONSTITUTION\.md", re.IGNORECASE),
    re.compile(r"governance[/\\]", re.IGNORECASE),
    re.compile(r"policy[/\\]", re.IGNORECASE),
    re.compile(r"\.env", re.IGNORECASE),
    re.compile(r"\.git[/\\]", re.IGNORECASE),
    re.compile(r".*\.key$", re.IGNORECASE),
    re.compile(r".*\.pem$", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
]

DEPENDENCY_FILES = {
    "package-lock.json",
    "package.json",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "Gemfile.lock",
    "go.sum",
    "Cargo.lock",
}

NETWORK_PATTERNS = [
    ("Network command", re.compile(r"\b(?:curl|wget|fetch|http\.get|requests\.get|urllib)\b")),
    ("URL reference", re.compile(r"(?:https?|ftp)://")),
    ("DNS operation", re.compile(r"\b(?:getaddrinfo|resolve|nslookup|dig)\b")),
    ("Socket operation", re.compile(r"(?:connect\(\)|socket\(|SOCK_STREAM)")),
    ("Network error (blocked)", re.compile(
        r"(?:Network is unreachable|Could not resolve host|Connection refused|Name or service not known)"
    )),
]

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"gh[posrt]_[A-Za-z0-9_]{36,}")),
    ("Generic API Key", re.compile(r"[Aa]pi[_\-]?[Kk]ey\s*[:=]\s*\S+")),
    ("Private Key Header", re.compile(r"-----BEGIN.*PRIVATE KEY-----")),
]

RISK_DELTA_MAP = {
    "scope_violation": 0.3,
    "forbidden_path": 0.5,
    "secret_exposure": 0.5,
    "dependency_change": 0.1,
    "network_attempt": 0.2,
}

RISK_MAP_VERSION_HASH = hashlib.sha256(
    json.dumps(RISK_DELTA_MAP, sort_keys=True).encode()
).hexdigest()


# ---------------------------------------------------------------------------
# Review functions
# ---------------------------------------------------------------------------

def review_scope(workspace_diff: dict, allow_paths: list[str]) -> list[ReviewFinding]:
    """Check that all added/modified files fall under allowed path prefixes."""
    findings: list[ReviewFinding] = []
    for file_path in list(workspace_diff.get("added", {}).keys()) + list(workspace_diff.get("modified", {}).keys()):
        if not any(file_path.startswith(prefix) for prefix in allow_paths):
            findings.append(ReviewFinding(
                category="scope_violation",
                severity="high",
                description=f"File '{file_path}' is outside allowed paths",
                file_path=file_path,
            ))
    return findings


def review_forbidden_paths(workspace_diff: dict) -> list[ReviewFinding]:
    """Detect touches to forbidden paths (governance, constitution, secrets)."""
    findings: list[ReviewFinding] = []
    all_files = (
        list(workspace_diff.get("added", {}).keys())
        + list(workspace_diff.get("modified", {}).keys())
        + list(workspace_diff.get("deleted", {}).keys())
    )
    for file_path in all_files:
        for pattern in FORBIDDEN_PATHS:
            if pattern.search(file_path):
                findings.append(ReviewFinding(
                    category="forbidden_path",
                    severity="critical",
                    description=f"Forbidden path touched: '{file_path}'",
                    file_path=file_path,
                    matched_pattern=pattern.pattern,
                ))
                break  # one finding per file is enough
    return findings


def review_secrets(stdout: str, stderr: str) -> list[ReviewFinding]:
    """Scan command output for leaked secrets."""
    findings: list[ReviewFinding] = []
    seen: set[tuple[str, str]] = set()  # (pattern_name, stream)
    for stream_name, stream_text in [("stdout", stdout), ("stderr", stderr)]:
        for name, regex in SECRET_PATTERNS:
            key = (name, stream_name)
            if key not in seen and regex.search(stream_text):
                seen.add(key)
                findings.append(ReviewFinding(
                    category="secret_exposure",
                    severity="critical",
                    description=f"{name} detected in output",
                    matched_pattern=regex.pattern,
                ))
    return findings


def review_dependencies(workspace_diff: dict) -> list[ReviewFinding]:
    """Flag changes to dependency / lock files."""
    findings: list[ReviewFinding] = []
    all_files = (
        list(workspace_diff.get("added", {}).keys())
        + list(workspace_diff.get("modified", {}).keys())
    )
    for file_path in all_files:
        if os.path.basename(file_path) in DEPENDENCY_FILES:
            findings.append(ReviewFinding(
                category="dependency_change",
                severity="medium",
                description=f"Dependency file changed: '{file_path}'",
                file_path=file_path,
            ))
    return findings


def review_network_attempts(stdout: str, stderr: str) -> list[ReviewFinding]:
    """Scan command output for signs of network access attempts."""
    findings: list[ReviewFinding] = []
    seen: set[tuple[str, str]] = set()  # (pattern_name, stream)
    for stream_name, stream_text in [("stdout", stdout), ("stderr", stderr)]:
        for name, regex in NETWORK_PATTERNS:
            key = (name, stream_name)
            if key not in seen and regex.search(stream_text):
                seen.add(key)
                findings.append(ReviewFinding(
                    category="network_attempt",
                    severity="medium",
                    description=f"{name} detected in {stream_name}",
                    matched_pattern=regex.pattern,
                ))
    return findings


def _compute_risk_delta(findings: list[ReviewFinding]) -> float:
    """Sum risk deltas for all findings, capped at 1.0."""
    total = sum(RISK_DELTA_MAP.get(f.category, 0.0) for f in findings)
    return min(total, 1.0)


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

def review_evidence(
    packet: EvidencePacket,
    allow_paths: list[str] | None = None,
) -> ReviewResult:
    """Run all deterministic checks on an Evidence Packet."""
    workspace_diff = packet.blast_box.get("workspace_diff", {})
    stdout = packet.blast_box.get("stdout", "")
    stderr = packet.blast_box.get("stderr", "")

    findings: list[ReviewFinding] = []

    if allow_paths is not None:
        findings.extend(review_scope(workspace_diff, allow_paths))

    findings.extend(review_forbidden_paths(workspace_diff))
    findings.extend(review_secrets(stdout, stderr))
    findings.extend(review_dependencies(workspace_diff))
    findings.extend(review_network_attempts(stdout, stderr))

    passed = len([f for f in findings if f.severity in ("critical", "high")]) == 0
    scope_compliant = len([f for f in findings if f.category == "scope_violation"]) == 0
    risk_delta = _compute_risk_delta(findings)
    reviewed_at = datetime.now(timezone.utc).isoformat()

    return ReviewResult(
        passed=passed,
        findings=findings,
        risk_delta=risk_delta,
        scope_compliant=scope_compliant,
        reviewed_at=reviewed_at,
    )


def log_review_to_spine(
    audit: AuditSpineManager,
    packet: EvidencePacket,
    result: ReviewResult,
) -> str:
    """Log an EVIDENCE_REVIEW_DETERMINISTIC event to the Audit Spine. Returns event_id."""
    payload = {
        "proposal_id": packet.proposal_id,
        "chain_id": packet.chain_id,
        "evidence_hash": packet.evidence_hash,
        "passed": result.passed,
        "findings_count": len(result.findings),
        "risk_delta": result.risk_delta,
        "scope_compliant": result.scope_compliant,
        "findings_summary": [asdict(f) for f in result.findings],
        "risk_map_version_hash": RISK_MAP_VERSION_HASH,
        "reviewed_at": result.reviewed_at,
    }
    return audit.log_event(
        actor_id="system:evidence_review",
        action_type="EVIDENCE_REVIEW_DETERMINISTIC",
        intent_payload=payload,
    )
