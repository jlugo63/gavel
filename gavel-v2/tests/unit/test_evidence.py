"""Unit tests for EvidenceReviewer — all 7 deterministic checks."""

from gavel.blastbox import EvidencePacket, ScopeDeclaration
from gavel.evidence import EvidenceReviewer, ReviewVerdict


class TestCleanEvidence:
    def test_clean_packet_passes(self, evidence_reviewer, clean_evidence_packet, scope):
        result = evidence_reviewer.review(clean_evidence_packet, scope)
        assert result.verdict == ReviewVerdict.PASS
        assert result.scope_compliance == "FULL"
        assert result.risk_delta == 0.0

    def test_clean_packet_has_findings(self, evidence_reviewer, clean_evidence_packet, scope):
        result = evidence_reviewer.review(clean_evidence_packet, scope)
        assert len(result.findings) > 0
        assert all(f.passed for f in result.findings)


class TestExitCodeCheck:
    def test_nonzero_exit_code_fails(self, evidence_reviewer, scope):
        packet = EvidencePacket(exit_code=1, files_modified=[], network_mode="none")
        result = evidence_reviewer.review(packet, scope)
        exit_findings = [f for f in result.findings if f.check == "exit_code"]
        assert any(not f.passed for f in exit_findings)

    def test_zero_exit_code_passes(self, evidence_reviewer, scope):
        packet = EvidencePacket(exit_code=0, files_modified=[], network_mode="none")
        result = evidence_reviewer.review(packet, scope)
        exit_findings = [f for f in result.findings if f.check == "exit_code"]
        assert all(f.passed for f in exit_findings)


class TestScopeCompliance:
    def test_file_outside_scope_fails(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=["/var/log/secret.txt"],
            network_mode="none",
        )
        result = evidence_reviewer.review(packet, scope)
        assert result.verdict == ReviewVerdict.FAIL
        assert result.risk_delta > 0

    def test_file_inside_scope_passes(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=["k8s/deployments/payments-service.yaml"],
            network_mode="none",
        )
        result = evidence_reviewer.review(packet, scope)
        scope_findings = [f for f in result.findings if f.check == "scope_compliance"]
        assert all(f.passed for f in scope_findings)


class TestForbiddenPaths:
    def test_etc_shadow_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=["/etc/shadow"],
            network_mode="none",
        )
        result = evidence_reviewer.review(packet, scope)
        assert result.verdict == ReviewVerdict.FAIL
        assert any("forbidden" in f.check.lower() or "shadow" in f.detail for f in result.findings if not f.passed)

    def test_env_file_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=["app/.env"],
            network_mode="none",
        )
        result = evidence_reviewer.review(packet, scope)
        forbidden_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in forbidden_findings)

    def test_credentials_file_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=["config/credentials.json"],
            network_mode="none",
        )
        result = evidence_reviewer.review(packet, scope)
        forbidden_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in forbidden_findings)


class TestNetworkMode:
    def test_network_when_disallowed_fails(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=[],
            network_mode="bridge",
        )
        result = evidence_reviewer.review(packet, scope)
        net_findings = [f for f in result.findings if f.check == "network_mode"]
        assert any(not f.passed for f in net_findings)

    def test_no_network_passes(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=[],
            network_mode="none",
        )
        result = evidence_reviewer.review(packet, scope)
        net_findings = [f for f in result.findings if f.check == "network_mode"]
        assert all(f.passed for f in net_findings)


class TestSecretDetection:
    def test_api_key_in_stdout_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(exit_code=0, files_modified=[], network_mode="none")
        result = evidence_reviewer.review(
            packet, scope,
            stdout_content="config loaded: api_key=sk-12345abcdef",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_bearer_token_in_stderr_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(exit_code=0, files_modified=[], network_mode="none")
        result = evidence_reviewer.review(
            packet, scope,
            stderr_content="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_private_key_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(exit_code=0, files_modified=[], network_mode="none")
        result = evidence_reviewer.review(
            packet, scope,
            stdout_content="-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_aws_key_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(exit_code=0, files_modified=[], network_mode="none")
        result = evidence_reviewer.review(
            packet, scope,
            stdout_content="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_clean_output_passes(self, evidence_reviewer, scope):
        packet = EvidencePacket(exit_code=0, files_modified=[], network_mode="none")
        result = evidence_reviewer.review(
            packet, scope,
            stdout_content="deployment.apps/payments-service scaled",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert all(f.passed for f in secret_findings)


class TestFileDeletion:
    def test_deletion_outside_scope_detected(self, evidence_reviewer, scope):
        packet = EvidencePacket(
            exit_code=0,
            files_modified=[],
            files_deleted=["/var/lib/important.db"],
            network_mode="none",
        )
        result = evidence_reviewer.review(packet, scope)
        del_findings = [f for f in result.findings if f.check == "file_deletion"]
        assert any(not f.passed for f in del_findings)


class TestRiskDelta:
    def test_multiple_violations_compound(self, evidence_reviewer, scope, dirty_evidence_packet):
        result = evidence_reviewer.review(dirty_evidence_packet, scope)
        assert result.risk_delta > 0.5  # Multiple violations should compound
        assert result.verdict == ReviewVerdict.FAIL
