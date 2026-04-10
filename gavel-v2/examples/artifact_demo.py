"""
GovernanceArtifact and PolicyDecision adapter demo.

Shows the full lifecycle: governance chain -> evidence review ->
portable artifact -> AGT PolicyDecision -> tamper detection.

No external dependencies needed. Run from the gavel-v2 directory:

    python examples/artifact_demo.py
"""

import sys
import json
sys.path.insert(0, ".")

from gavel.chain import GovernanceChain, EventType, ChainStatus
from gavel.artifact import from_chain, verify_artifact, PolicyDecisionAdapter, GovernanceArtifact
from gavel.evidence import EvidenceReviewer, ReviewResult
from gavel.blastbox import EvidencePacket, ScopeDeclaration


def header(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def main():
    # 1. Build a governance chain
    header("1. Create Governance Chain")
    chain = GovernanceChain()
    print(f"Chain ID: {chain.chain_id}")

    chain.append(EventType.INBOUND_INTENT, "agent-alpha", "proposer",
                 {"action": "deploy model v2.1", "target": "staging"})
    chain.append(EventType.POLICY_EVAL, "policy-engine", "evaluator",
                 {"tier": 2, "rules_checked": 11, "result": "requires_evidence"})
    chain.append(EventType.BLASTBOX_EVIDENCE, "blast-box-01", "executor",
                 {"exit_code": 0, "files_modified": ["src/model.py"]})
    chain.append(EventType.EVIDENCE_REVIEW, "det-reviewer", "reviewer",
                 {"verdict": "PASS", "checks_passed": 5, "checks_total": 5})
    chain.append(EventType.APPROVAL_GRANTED, "human-ops-1", "approver",
                 {"reason": "Evidence clean, scope compliant"})

    chain.status = ChainStatus.APPROVED
    print(f"Status: {chain.status.value}")
    print(f"Events: {len(chain.events)}")
    print(f"Integrity: {chain.verify_integrity()}")

    # 2. Run evidence review on a mock packet
    header("2. Evidence Review")
    scope = ScopeDeclaration(allow_paths=["src/"], allow_commands=["python"])
    packet = EvidencePacket(
        chain_id=chain.chain_id,
        command_argv=["python", "deploy.py"],
        exit_code=0,
        files_modified=["src/model.py"],
        network_mode="none",
    )

    reviewer = EvidenceReviewer()
    evidence_result = reviewer.review(packet, scope)
    print(f"Verdict: {evidence_result.verdict.value}")
    print(f"Risk delta: {evidence_result.risk_delta}")
    print(f"Scope compliance: {evidence_result.scope_compliance}")
    print(f"Findings: {len(evidence_result.findings)} checks run")
    for f in evidence_result.findings:
        status = "PASS" if f.passed else "FAIL"
        print(f"  [{status}] {f.check}: {f.detail}")

    # 3. Convert chain to GovernanceArtifact
    header("3. GovernanceArtifact")
    artifact = from_chain(chain, evidence_result)
    print(f"Artifact ID: {artifact.artifact_id}")
    print(f"Chain ID: {artifact.chain_id}")
    print(f"Action: {artifact.action} (allowed={artifact.allowed})")
    print(f"Status: {artifact.status}")
    print(f"Principals: {len(artifact.principals)}")
    for p in artifact.principals:
        print(f"  {p.actor_id} ({p.role})")
    print(f"Evidence: {artifact.evidence.checks_passed}/{artifact.evidence.checks_total} passed")
    print(f"Artifact hash: {artifact.artifact_hash[:32]}...")

    # 4. Convert to AGT PolicyDecision
    header("4. AGT PolicyDecision")
    decision = PolicyDecisionAdapter.to_policy_decision(artifact)
    print(json.dumps(decision, indent=2))

    # 5. Verify the artifact
    header("5. Artifact Verification (clean)")
    artifact_json = artifact.model_dump(mode="json")
    result = verify_artifact(artifact_json)
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")

    # 6. Tamper and re-verify
    header("6. Artifact Verification (tampered)")
    artifact_json["status"] = "DENIED"
    tampered_result = verify_artifact(artifact_json)
    print(f"Valid: {tampered_result['valid']}")
    print(f"Errors:")
    for err in tampered_result["errors"]:
        print(f"  - {err}")

    header("Demo Complete")
    print("The governance artifact is a portable, self-verifying record.")
    print("Any system can verify it without the Gavel runtime.\n")


if __name__ == "__main__":
    main()
