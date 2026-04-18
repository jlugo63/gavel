"""Compliance scoring — per-machine and org-wide ATF/EU AI Act compliance percentage."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from gavel.compliance_exports.types import ComplianceFramework


class ComplianceCheckResult(BaseModel):
    """Result of a single compliance check."""
    check_name: str
    framework: ComplianceFramework
    passed: bool
    weight: float = 1.0
    details: str = ""


class MachineComplianceScore(BaseModel):
    """Compliance score for a single machine."""
    endpoint_id: str
    hostname: str = ""
    checks: list[ComplianceCheckResult] = Field(default_factory=list)
    atf_score: float = 0.0          # 0.0 - 1.0
    eu_ai_act_score: float = 0.0
    combined_score: float = 0.0
    scored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OrgComplianceScore(BaseModel):
    """Org-wide compliance aggregate."""
    org_id: str
    machine_scores: list[MachineComplianceScore] = Field(default_factory=list)
    atf_score: float = 0.0
    eu_ai_act_score: float = 0.0
    combined_score: float = 0.0
    total_machines: int = 0
    compliant_machines: int = 0
    scored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceScorer:
    """Per-machine and org-wide ATF/EU AI Act compliance percentage."""

    ATF_CHECKS = [
        "I-1_agent_identity", "I-2_did_binding", "I-3_enrollment_validation",
        "I-4_purpose_declaration", "I-5_capability_manifest",
        "S-1_resource_allowlist", "S-2_action_boundaries", "S-3_default_deny",
        "B-1_governance_chain", "B-2_approval_flow", "B-3_behavioral_baseline",
        "D-1_audit_ledger", "D-2_evidence_packets", "D-3_pii_protection",
        "R-1_kill_switch", "R-2_drift_detection", "R-3_escalation", "R-4_rollback",
        "T-1_separation_of_powers", "T-2_tamper_detection", "T-3_hash_chain",
        "T-4_witness", "T-5_artifact_export",
        "G-1_constitution", "G-2_policy_engine",
    ]

    EU_AI_ACT_CHECKS = [
        "art9_risk_management", "art10_data_governance", "art11_documentation",
        "art12_record_keeping", "art13_transparency", "art14_human_oversight",
        "art15_accuracy_robustness", "art17_qms", "art27_fria",
        "art5_prohibited_practices", "art72_post_market", "art73_incidents",
    ]

    def score_machine(self, endpoint_id: str, hostname: str = "",
                      atf_results: dict[str, bool] | None = None,
                      eu_results: dict[str, bool] | None = None) -> MachineComplianceScore:
        checks = []
        atf_results = atf_results or {}
        eu_results = eu_results or {}

        # ATF checks
        atf_passed = 0
        for check_name in self.ATF_CHECKS:
            passed = atf_results.get(check_name, False)
            checks.append(ComplianceCheckResult(
                check_name=check_name, framework=ComplianceFramework.ATF, passed=passed
            ))
            if passed:
                atf_passed += 1

        # EU AI Act checks
        eu_passed = 0
        for check_name in self.EU_AI_ACT_CHECKS:
            passed = eu_results.get(check_name, False)
            checks.append(ComplianceCheckResult(
                check_name=check_name, framework=ComplianceFramework.EU_AI_ACT, passed=passed
            ))
            if passed:
                eu_passed += 1

        atf_score = atf_passed / len(self.ATF_CHECKS) if self.ATF_CHECKS else 0.0
        eu_score = eu_passed / len(self.EU_AI_ACT_CHECKS) if self.EU_AI_ACT_CHECKS else 0.0
        combined = (atf_score + eu_score) / 2

        return MachineComplianceScore(
            endpoint_id=endpoint_id,
            hostname=hostname,
            checks=checks,
            atf_score=round(atf_score, 3),
            eu_ai_act_score=round(eu_score, 3),
            combined_score=round(combined, 3),
        )

    def score_org(self, org_id: str,
                  machine_scores: list[MachineComplianceScore]) -> OrgComplianceScore:
        if not machine_scores:
            return OrgComplianceScore(org_id=org_id)

        atf_avg = sum(m.atf_score for m in machine_scores) / len(machine_scores)
        eu_avg = sum(m.eu_ai_act_score for m in machine_scores) / len(machine_scores)
        combined_avg = sum(m.combined_score for m in machine_scores) / len(machine_scores)
        compliant = len([m for m in machine_scores if m.combined_score >= 0.9])

        return OrgComplianceScore(
            org_id=org_id,
            machine_scores=machine_scores,
            atf_score=round(atf_avg, 3),
            eu_ai_act_score=round(eu_avg, 3),
            combined_score=round(combined_avg, 3),
            total_machines=len(machine_scores),
            compliant_machines=compliant,
        )
