"""
Gavel Governance Chains — quickstart demo.

Shows the full lifecycle: create governance events -> build artifact ->
convert to AGT PolicyDecision -> verify tamper detection.

No external dependencies beyond pydantic. Run from the gavel-governance
package directory:

    python examples/quickstart.py
"""

import hashlib
import json
import sys
from datetime import datetime, timezone

sys.path.insert(0, "src")

from gavel_governance import (
    from_governance_chain,
    verify_artifact,
    PolicyDecisionAdapter,
)


def header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def main() -> None:
    now = datetime.now(timezone.utc).isoformat()

    # 1. Define governance chain events
    header("1. Governance Chain Events")
    events = [
        {
            "event_id": "evt-001",
            "event_type": "INBOUND_INTENT",
            "actor_id": "agent:planner",
            "role": "proposer",
            "timestamp": now,
            "event_hash": hashlib.sha256(b"evt-001-genesis").hexdigest(),
        },
        {
            "event_id": "evt-002",
            "event_type": "POLICY_EVAL",
            "actor_id": "system:policy-engine",
            "role": "evaluator",
            "timestamp": now,
            "event_hash": hashlib.sha256(b"evt-002-eval").hexdigest(),
        },
        {
            "event_id": "evt-003",
            "event_type": "EVIDENCE_REVIEW",
            "actor_id": "agent:det-reviewer",
            "role": "reviewer",
            "timestamp": now,
            "event_hash": hashlib.sha256(b"evt-003-review").hexdigest(),
        },
        {
            "event_id": "evt-004",
            "event_type": "APPROVAL_GRANTED",
            "actor_id": "human:ops-lead",
            "role": "approver",
            "timestamp": now,
            "event_hash": hashlib.sha256(b"evt-004-approval").hexdigest(),
        },
    ]

    for e in events:
        print(f"  [{e['event_type']}] {e['actor_id']} ({e['role']})")

    # 2. Build GovernanceArtifact
    header("2. GovernanceArtifact")
    artifact = from_governance_chain(
        chain_id="gc-demo-deploy-v2",
        status="APPROVED",
        created_at=now,
        events=events,
        integrity=True,
        evidence={
            "checks_total": 5,
            "checks_passed": 5,
            "risk_delta": 0.08,
            "scope_compliance": "FULL",
            "review_verdict": "PASS",
        },
    )

    print(f"  Artifact ID:  {artifact.artifact_id}")
    print(f"  Chain ID:     {artifact.chain_id}")
    print(f"  Action:       {artifact.action} (allowed={artifact.allowed})")
    print(f"  Principals:   {len(artifact.principals)}")
    for p in artifact.principals:
        print(f"    - {p.actor_id} ({p.role})")
    print(f"  Evidence:     {artifact.evidence.checks_passed}/{artifact.evidence.checks_total} passed")
    print(f"  Artifact hash: {artifact.artifact_hash[:32]}...")

    # 3. Convert to AGT PolicyDecision
    header("3. AGT PolicyDecision")
    decision = PolicyDecisionAdapter.to_policy_decision(artifact)
    print(json.dumps(decision, indent=2))

    # 4. Verify artifact integrity
    header("4. Verification (clean)")
    artifact_json = artifact.model_dump(mode="json")
    result = verify_artifact(artifact_json)
    print(f"  Valid:  {result['valid']}")
    print(f"  Errors: {result['errors']}")

    # 5. Tamper detection
    header("5. Verification (tampered)")
    artifact_json["status"] = "DENIED"
    tampered_result = verify_artifact(artifact_json)
    print(f"  Valid:  {tampered_result['valid']}")
    for err in tampered_result["errors"]:
        print(f"  Error: {err}")

    header("Demo Complete")
    print("  GovernanceArtifacts are portable, self-verifying records.")
    print("  Any system can verify them with only hashlib and json.\n")


if __name__ == "__main__":
    main()
