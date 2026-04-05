"""Shared fixtures for Gavel test suite."""

import pytest

from gavel.chain import GovernanceChain, EventType
from gavel.constitution import Constitution
from gavel.separation import SeparationOfPowers, ChainRole
from gavel.blastbox import BlastBox, ScopeDeclaration, EvidencePacket
from gavel.evidence import EvidenceReviewer
from gavel.tiers import TierPolicy, RiskFactors
from gavel.liveness import LivenessMonitor


@pytest.fixture
def chain():
    """A fresh governance chain."""
    return GovernanceChain()


@pytest.fixture
def populated_chain():
    """A chain with a proposal already logged."""
    c = GovernanceChain()
    c.append(
        event_type=EventType.INBOUND_INTENT,
        actor_id="agent:monitor",
        role_used="proposer",
        payload={"goal": "Scale payments-service", "action_type": "INFRA_SCALE"},
    )
    c.append(
        event_type=EventType.POLICY_EVAL,
        actor_id="system:policy-engine",
        role_used="system",
        payload={"risk": 0.65, "tier": 2},
    )
    return c


@pytest.fixture
def constitution():
    return Constitution()


@pytest.fixture
def separation():
    return SeparationOfPowers()


@pytest.fixture
def blastbox():
    return BlastBox()


@pytest.fixture
def scope():
    return ScopeDeclaration(
        allow_paths=["k8s/deployments/payments-service.yaml"],
        allow_commands=["kubectl scale deployment payments-service --replicas=6"],
        allow_network=False,
    )


@pytest.fixture
def evidence_reviewer():
    return EvidenceReviewer()


@pytest.fixture
def tier_policy():
    return TierPolicy()


@pytest.fixture
def liveness():
    return LivenessMonitor()


@pytest.fixture
def clean_evidence_packet():
    """An evidence packet that passes all checks."""
    return EvidencePacket(
        chain_id="c-test1234",
        intent_event_id="evt-test1234",
        command_argv=["kubectl", "scale", "deployment", "payments-service", "--replicas=6"],
        exit_code=0,
        stdout_hash="sha256:abc123",
        stderr_hash="sha256:000000",
        diff_hash="sha256:def456",
        stdout_preview="deployment.apps/payments-service scaled",
        files_modified=["k8s/deployments/payments-service.yaml"],
        network_mode="none",
    )


@pytest.fixture
def dirty_evidence_packet():
    """An evidence packet with scope violations."""
    return EvidencePacket(
        chain_id="c-test1234",
        intent_event_id="evt-test1234",
        command_argv=["kubectl", "apply", "-f", "malicious.yaml"],
        exit_code=0,
        stdout_hash="sha256:abc123",
        stderr_hash="sha256:000000",
        diff_hash="sha256:def456",
        files_modified=["/etc/shadow", "k8s/deployments/payments-service.yaml"],
        files_created=["backdoor.sh"],
        network_mode="bridge",
    )
