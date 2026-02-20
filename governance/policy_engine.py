"""
Deterministic Policy Engine
Constitutional References: §I.2 (Authority Decoupling), §II (Operational Constraints)

Evaluates proposed agent actions against hard constitutional invariants.
Every evaluation is logged to the Audit Spine as an immutable record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from governance.audit import AuditSpineManager
from governance.evidence_review import ReviewResult

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CONSTITUTION_PATH = Path(__file__).resolve().parent.parent / "CONSTITUTION.md"

# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    ESCALATED = "ESCALATED"


@dataclass
class Violation:
    rule: str          # e.g. "§I.2", "§II"
    description: str


@dataclass
class PolicyResult:
    decision: Decision
    risk_score: float                       # 0.0 (safe) to 1.0 (critical)
    violations: list[Violation] = field(default_factory=list)
    proposal: Optional[dict] = None
    rationale: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.decision == Decision.APPROVED

    def summary(self) -> str:
        lines = [
            f"Decision:   {self.decision.value}",
            f"Risk Score: {self.risk_score:.2f}",
        ]
        if self.violations:
            lines.append("Violations:")
            for v in self.violations:
                lines.append(f"  [{v.rule}] {v.description}")
        if self.rationale:
            lines.append("Rationale:")
            for r in self.rationale:
                lines.append(f"  - {r}")
        if self.matched_rules:
            lines.append(f"Matched Rules: {', '.join(self.matched_rules)}")
        if self.signals:
            lines.append(f"Signals: {', '.join(self.signals)}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Constitutional parser
# ---------------------------------------------------------------------------

@dataclass
class ConstitutionRule:
    section: str       # "I" or "II"
    ref: str           # "§I.1", "§II"
    text: str          # raw rule text


def parse_constitution(path: Path) -> list[ConstitutionRule]:
    """Extract rules from CONSTITUTION.md by section."""
    content = path.read_text(encoding="utf-8")
    rules: list[ConstitutionRule] = []
    current_section = ""

    for line in content.splitlines():
        line = line.strip()

        # Detect section headers: "## I. Governance Invariants"
        header_match = re.match(r"^##\s+(I{1,3}V?)\.\s+", line)
        if header_match:
            current_section = header_match.group(1)
            continue

        # Numbered invariants: "1. **Name:** description"
        numbered = re.match(r"^(\d+)\.\s+\*\*(.+?)\*\*", line)
        if numbered and current_section:
            num = numbered.group(1)
            rules.append(ConstitutionRule(
                section=current_section,
                ref=f"§{current_section}.{num}",
                text=line,
            ))
            continue

        # Bullet constraints: "- No command shall..."
        if line.startswith("- ") and current_section:
            rules.append(ConstitutionRule(
                section=current_section,
                ref=f"§{current_section}",
                text=line.lstrip("- "),
            ))

    return rules


# ---------------------------------------------------------------------------
# Hard-coded invariant checks
# ---------------------------------------------------------------------------

# §I.2 — protected paths (governance files and constitution itself)
# Note: use [/\\] to match both Unix and Windows path separators
PROTECTED_PATHS = [
    re.compile(r"(^|[/\\])governance[/\\]", re.IGNORECASE),
    re.compile(r"(^|[/\\])policy[/\\]", re.IGNORECASE),
    re.compile(r"(^|[/\\])CONSTITUTION\.md$", re.IGNORECASE),
]

# §II — forbidden shell patterns
FORBIDDEN_COMMANDS = [
    (re.compile(r"\bsudo\b"), "Use of 'sudo' is prohibited (§II)"),
    (re.compile(r"\bchmod\s+777\b"), "chmod 777 is prohibited (§II)"),
    (re.compile(r"\brm\s+-rf\s+/"), "Destructive 'rm -rf /' is prohibited (§II)"),
    (re.compile(r"\brm\s+-rf\s+\*"), "Destructive 'rm -rf *' is prohibited (§II)"),
    (re.compile(r"\bmkfs\b"), "Filesystem format command is prohibited (§II)"),
    (re.compile(r"\bdd\s+.+of=/dev/"), "Raw disk write via dd is prohibited (§II)"),
]

# Action types that involve shell execution
SHELL_ACTION_TYPES = {"bash", "shell", "command", "exec", "terminal"}

# Action types that involve file mutations
FILE_ACTION_TYPES = {"file_write", "file_edit", "file_delete", "file_move", "write", "edit", "delete"}


def _check_authority_decoupling(proposal: dict) -> list[Violation]:
    """§I.2 — Agents cannot modify governance/, policy/, or CONSTITUTION.md."""
    violations: list[Violation] = []
    action_type = proposal.get("action_type", "").lower()

    if action_type not in FILE_ACTION_TYPES:
        return violations

    content = proposal.get("content", "")
    target = proposal.get("target_path", content)

    for pattern in PROTECTED_PATHS:
        if pattern.search(target):
            violations.append(Violation(
                rule="§I.2",
                description=(
                    f"Authority Decoupling: modification of protected path "
                    f"'{target}' is prohibited."
                ),
            ))
            break

    return violations


def _check_operational_constraints(proposal: dict) -> list[Violation]:
    """§II — Scan shell actions for forbidden commands."""
    violations: list[Violation] = []
    action_type = proposal.get("action_type", "").lower()

    if action_type not in SHELL_ACTION_TYPES:
        return violations

    content = proposal.get("content", "")
    for pattern, description in FORBIDDEN_COMMANDS:
        if pattern.search(content):
            violations.append(Violation(
                rule="§II",
                description=description,
            ))

    return violations


def _check_unproxied_api_calls(proposal: dict) -> list[Violation]:
    """§II — External API calls must go through the Governance Gateway."""
    violations: list[Violation] = []
    action_type = proposal.get("action_type", "").lower()
    content = proposal.get("content", "")

    is_shell = action_type in SHELL_ACTION_TYPES
    has_curl = re.search(r"\bcurl\b", content)
    has_wget = re.search(r"\bwget\b", content)

    if is_shell and (has_curl or has_wget):
        violations.append(Violation(
            rule="§II",
            description=(
                "External API calls must be proxied through the "
                "Governance Gateway for intent-logging."
            ),
        ))

    return violations


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _compute_risk_score(violations: list[Violation]) -> float:
    """
    Deterministic risk score.
      - No violations:  0.0
      - §II violations: 0.6 each (operational)
      - §I  violations: 0.9 each (governance invariant)
    Capped at 1.0.
    """
    if not violations:
        return 0.0

    WEIGHTS = {"§I": 0.9, "§II": 0.6}
    score = 0.0
    for v in violations:
        # Extract section number (e.g. "§I.2" -> "§I", "§II" -> "§II")
        section = v.rule.split(".")[0]
        score += WEIGHTS.get(section, 0.5)

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Deterministic governance engine.

    Loads the Constitution, evaluates proposals against hard invariants,
    and logs every decision to the Audit Spine.
    """

    def __init__(self, constitution_path: Path = CONSTITUTION_PATH,
                 audit: AuditSpineManager | None = None):
        self.constitution_path = constitution_path
        self.rules = parse_constitution(constitution_path)
        self.audit = audit or AuditSpineManager()

    def evaluate_proposal(self, proposal: dict) -> tuple[PolicyResult, str]:
        """
        Evaluate a proposed action against all constitutional checks.

        Args:
            proposal: dict with keys:
                - actor_id:    str — who is proposing the action
                - action_type: str — category (bash, file_write, etc.)
                - content:     str — the command or payload
                - target_path: str (optional) — file path for mutations

        Returns:
            (PolicyResult, event_id) — the result and its Audit Spine UUID.
        """
        violations: list[Violation] = []
        rationale: list[str] = []
        matched_rules: list[str] = []
        signals: list[str] = []

        # Run all hard-coded checks and collect structured output
        auth_violations = _check_authority_decoupling(proposal)
        for v in auth_violations:
            target = proposal.get("target_path", proposal.get("content", ""))
            signals.append("protected_path_write")
            matched_rules.append("§I.2")
            rationale.append(
                f"Action targets protected governance path: {target}"
            )
        violations.extend(auth_violations)

        ops_violations = _check_operational_constraints(proposal)
        for v in ops_violations:
            signals.append("destructive_command")
            matched_rules.append("§II")
            rationale.append(f"Forbidden command detected: {v.description}")
        violations.extend(ops_violations)

        proxy_violations = _check_unproxied_api_calls(proposal)
        for v in proxy_violations:
            signals.append("external_network_access")
            matched_rules.append("§II")
            rationale.append(
                "External network access must use governance gateway"
            )
        violations.extend(proxy_violations)

        risk_score = _compute_risk_score(violations)

        # Decision logic
        if not violations:
            decision = Decision.APPROVED
            signals.append("standard_operation")
            rationale.append("No policy violations detected")
        elif risk_score >= 0.8:
            decision = Decision.DENIED
        else:
            decision = Decision.ESCALATED

        # De-duplicate matched_rules while preserving order
        seen: set[str] = set()
        unique_rules: list[str] = []
        for rule in matched_rules:
            if rule not in seen:
                seen.add(rule)
                unique_rules.append(rule)
        matched_rules = unique_rules

        result = PolicyResult(
            decision=decision,
            risk_score=risk_score,
            violations=violations,
            proposal=proposal,
            rationale=rationale,
            matched_rules=matched_rules,
            signals=signals,
        )

        # Log to Audit Spine — every evaluation, pass or fail
        event_id = self.audit.log_event(
            actor_id=proposal.get("actor_id", "unknown"),
            action_type=f"POLICY_EVAL:{proposal.get('action_type', 'unknown').upper()}",
            intent_payload={
                "decision": result.decision.value,
                "risk_score": result.risk_score,
                "violations": [
                    {"rule": v.rule, "description": v.description}
                    for v in result.violations
                ],
                "rationale": result.rationale,
                "matched_rules": result.matched_rules,
                "signals": result.signals,
                "proposal": result.proposal,
            },
        )

        return result, event_id


# ---------------------------------------------------------------------------
# Evidence-based auto-approve
# ---------------------------------------------------------------------------

def evaluate_evidence_for_auto_approve(review_result: ReviewResult, tier: int) -> tuple[bool, str]:
    """Evaluate evidence review results for automatic post-execution approval.

    Only Tier 1 agents with clean evidence can be auto-approved.
    """
    if tier == 0:
        return (False, "Tier 0: no execution, no auto-approve")
    if tier == 1:
        if review_result.passed and review_result.risk_delta <= 0.2:
            return (True, "Tier 1: evidence review passed, auto-approved")
        findings_count = len(review_result.findings)
        return (False, f"Tier 1: evidence review failed -- {findings_count} findings, risk_delta={review_result.risk_delta}")
    if tier == 2:
        return (False, "Tier 2: requires attestation (not yet implemented)")
    if tier == 3:
        return (False, "Tier 3: requires human approval regardless of evidence")
    return (False, f"Unknown tier {tier}: no auto-approve")
