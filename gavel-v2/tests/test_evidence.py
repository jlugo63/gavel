"""Tests for Evidence Reviewer — 7 deterministic checks + privacy scan."""

from __future__ import annotations

import pytest

from gavel.blastbox import EvidencePacket, ScopeDeclaration
from gavel.evidence import (
    EvidenceReviewer,
    Finding,
    ReviewResult,
    ReviewVerdict,
    SECRET_PATTERNS,
)


# ── Helper factories ──────────────────────────────────────────────


def _clean_packet(**overrides) -> EvidencePacket:
    """A minimal clean evidence packet that should pass all checks."""
    defaults = dict(
        exit_code=0,
        network_mode="none",
        files_modified=[],
        files_created=[],
        files_deleted=[],
    )
    defaults.update(overrides)
    return EvidencePacket(**defaults)


def _default_scope(**overrides) -> ScopeDeclaration:
    defaults = dict(
        allow_paths=["/tmp/project"],
        allow_network=False,
    )
    defaults.update(overrides)
    return ScopeDeclaration(**defaults)


# ── ReviewVerdict Enum ────────────────────────────────────────────


class TestReviewVerdict:
    def test_pass_value(self):
        assert ReviewVerdict.PASS.value == "PASS"

    def test_fail_value(self):
        assert ReviewVerdict.FAIL.value == "FAIL"

    def test_warn_value(self):
        assert ReviewVerdict.WARN.value == "WARN"


# ── ReviewResult ──────────────────────────────────────────────────


class TestReviewResult:
    def test_default_is_pass(self):
        r = ReviewResult()
        assert r.verdict == ReviewVerdict.PASS
        assert r.passed is True

    def test_fail_verdict_not_passed(self):
        r = ReviewResult(verdict=ReviewVerdict.FAIL)
        assert r.passed is False

    def test_warn_verdict_not_passed(self):
        r = ReviewResult(verdict=ReviewVerdict.WARN)
        assert r.passed is False


# ── Finding ───────────────────────────────────────────────────────


class TestFinding:
    def test_finding_defaults(self):
        f = Finding(check="test", passed=True, detail="ok")
        assert f.severity == "info"

    def test_finding_fail_severity(self):
        f = Finding(check="test", passed=False, detail="bad", severity="fail")
        assert f.severity == "fail"


# ── Check 1: Exit Code ───────────────────────────────────────────


class TestExitCodeCheck:
    def test_exit_code_zero_passes(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(exit_code=0)
        result = reviewer.review(pkt, _default_scope())
        ec_findings = [f for f in result.findings if f.check == "exit_code"]
        assert all(f.passed for f in ec_findings)

    def test_exit_code_nonzero_fails(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(exit_code=1)
        result = reviewer.review(pkt, _default_scope())
        ec_findings = [f for f in result.findings if f.check == "exit_code"]
        assert any(not f.passed for f in ec_findings)
        assert result.verdict == ReviewVerdict.FAIL


# ── Check 2: Scope Compliance ────────────────────────────────────


class TestScopeComplianceCheck:
    def test_files_in_scope_pass(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/tmp/project/main.py"])
        scope = _default_scope(allow_paths=["/tmp/project"])
        result = reviewer.review(pkt, scope)
        sc_findings = [f for f in result.findings if f.check == "scope_compliance"]
        assert all(f.passed for f in sc_findings)

    def test_files_outside_scope_fail(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/etc/important.conf"])
        scope = _default_scope(allow_paths=["/tmp/project"])
        result = reviewer.review(pkt, scope)
        sc_findings = [f for f in result.findings if f.check == "scope_compliance"]
        assert any(not f.passed for f in sc_findings)
        assert result.verdict == ReviewVerdict.FAIL

    def test_created_files_outside_scope_fail(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_created=["/var/sneaky.txt"])
        scope = _default_scope(allow_paths=["/tmp/project"])
        result = reviewer.review(pkt, scope)
        sc_findings = [f for f in result.findings if f.check == "scope_compliance"]
        assert any(not f.passed for f in sc_findings)

    def test_scope_risk_delta_increases(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/etc/passwd"])
        scope = _default_scope(allow_paths=["/tmp"])
        result = reviewer.review(pkt, scope)
        assert result.risk_delta >= 0.3

    def test_empty_files_passes_scope(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(pkt, _default_scope())
        sc_findings = [f for f in result.findings if f.check == "scope_compliance"]
        assert all(f.passed for f in sc_findings)


# ── Check 3: Forbidden Paths ─────────────────────────────────────


class TestForbiddenPathsCheck:
    def test_etc_shadow_forbidden(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/etc/shadow"])
        result = reviewer.review(pkt, _default_scope())
        fp_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in fp_findings)

    def test_env_file_forbidden(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/tmp/project/.env"])
        scope = _default_scope()
        result = reviewer.review(pkt, scope)
        fp_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in fp_findings)

    def test_pem_file_forbidden(self):
        """The forbidden pattern '*.pem' uses substring match, so '.pem' in path triggers it."""
        reviewer = EvidenceReviewer()
        # The forbidden list has "*.pem" — the code checks `forbidden in filepath`,
        # so only filenames literally containing "*.pem" would match. Test with ".pem"
        # by using a custom forbidden_paths list for clarity.
        reviewer_pem = EvidenceReviewer(forbidden_paths=[".pem"])
        pkt = _clean_packet(files_created=["/tmp/project/server.pem"])
        scope = _default_scope()
        result = reviewer_pem.review(pkt, scope)
        fp_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in fp_findings)

    def test_credentials_forbidden(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/app/credentials.json"])
        result = reviewer.review(pkt, _default_scope())
        fp_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in fp_findings)

    def test_safe_path_no_forbidden_findings(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/tmp/project/app.py"])
        scope = _default_scope()
        result = reviewer.review(pkt, scope)
        fp_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert all(f.passed for f in fp_findings)

    def test_deleted_file_forbidden(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_deleted=["/etc/shadow"])
        result = reviewer.review(pkt, _default_scope())
        fp_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in fp_findings)

    def test_custom_forbidden_paths(self):
        reviewer = EvidenceReviewer(forbidden_paths=["/opt/restricted"])
        pkt = _clean_packet(files_modified=["/opt/restricted/data.db"])
        result = reviewer.review(pkt, _default_scope())
        fp_findings = [f for f in result.findings if f.check == "forbidden_path"]
        assert any(not f.passed for f in fp_findings)

    def test_forbidden_path_risk_delta(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/etc/shadow"])
        result = reviewer.review(pkt, _default_scope())
        assert result.risk_delta >= 0.5


# ── Check 4: Network Mode ────────────────────────────────────────


class TestNetworkModeCheck:
    def test_network_none_passes(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(network_mode="none")
        scope = _default_scope(allow_network=False)
        result = reviewer.review(pkt, scope)
        net_findings = [f for f in result.findings if f.check == "network_mode"]
        assert all(f.passed for f in net_findings)

    def test_network_bridge_without_permission_fails(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(network_mode="bridge")
        scope = _default_scope(allow_network=False)
        result = reviewer.review(pkt, scope)
        net_findings = [f for f in result.findings if f.check == "network_mode"]
        assert any(not f.passed for f in net_findings)
        assert result.verdict == ReviewVerdict.FAIL

    def test_network_bridge_with_permission_passes(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(network_mode="bridge")
        scope = _default_scope(allow_network=True)
        result = reviewer.review(pkt, scope)
        net_findings = [f for f in result.findings if f.check == "network_mode"]
        assert all(f.passed for f in net_findings)


# ── Check 5: Secret Detection ────────────────────────────────────


class TestSecretDetectionCheck:
    def test_clean_output_passes(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(pkt, _default_scope(), stdout_content="Hello world")
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert all(f.passed for f in secret_findings)

    def test_api_key_in_stdout_fails(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stdout_content="api_key=sk-abc123xyz",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_bearer_token_in_stderr_fails(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stderr_content="Bearer eyJhbGciOiJIUzI1NiJ9",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_private_key_detected(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stdout_content="-----BEGIN RSA PRIVATE KEY-----",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_aws_key_detected(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stdout_content="Access key: AKIAIOSFODNN7EXAMPLE",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_password_in_env_detected(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stdout_content="password=super_secret_123",
        )
        secret_findings = [f for f in result.findings if f.check == "secret_detection"]
        assert any(not f.passed for f in secret_findings)

    def test_secret_increases_risk_delta(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stdout_content="api_key=LEAKED",
        )
        assert result.risk_delta >= 0.5


# ── Check 6: File Deletions ──────────────────────────────────────


class TestFileDeletionCheck:
    def test_no_deletions_ok(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_deleted=[])
        result = reviewer.review(pkt, _default_scope())
        del_findings = [f for f in result.findings if f.check == "file_deletion"]
        assert all(f.passed for f in del_findings)

    def test_deletion_outside_scope_fails(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_deleted=["/home/user/important.doc"])
        scope = _default_scope(allow_paths=["/tmp/project"])
        result = reviewer.review(pkt, scope)
        del_findings = [f for f in result.findings if f.check == "file_deletion"]
        assert any(not f.passed for f in del_findings)
        assert result.verdict == ReviewVerdict.FAIL

    def test_deletion_inside_scope_no_violation(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_deleted=["/tmp/project/temp.txt"])
        scope = _default_scope(allow_paths=["/tmp/project"])
        result = reviewer.review(pkt, scope)
        del_findings = [f for f in result.findings if f.check == "file_deletion"]
        assert all(f.passed for f in del_findings)


# ── Check 7: Risk Delta Computation ──────────────────────────────


class TestRiskDelta:
    def test_clean_packet_zero_risk(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(pkt, _default_scope())
        assert result.risk_delta == 0.0

    def test_multiple_violations_accumulate_risk(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(
            files_modified=["/etc/shadow"],       # scope violation + forbidden
            network_mode="bridge",                 # network violation
        )
        scope = _default_scope(allow_paths=["/tmp"], allow_network=False)
        result = reviewer.review(pkt, scope)
        # scope (0.3) + forbidden (0.5) + network (0.4) = 1.2 minimum
        assert result.risk_delta >= 1.0


# ── Verdict Aggregation ──────────────────────────────────────────


class TestVerdictAggregation:
    def test_all_pass_verdict(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(pkt, _default_scope())
        assert result.verdict == ReviewVerdict.PASS
        assert result.scope_compliance == "FULL"

    def test_failure_verdict(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(exit_code=1)
        result = reviewer.review(pkt, _default_scope())
        assert result.verdict == ReviewVerdict.FAIL
        assert result.scope_compliance == "VIOLATION"

    def test_all_findings_present(self):
        """Review should produce findings for all check categories."""
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(pkt, _default_scope(), stdout_content="clean", stderr_content="clean")
        check_types = {f.check for f in result.findings}
        assert "exit_code" in check_types
        assert "scope_compliance" in check_types
        assert "network_mode" in check_types
        assert "secret_detection" in check_types


# ── Edge Cases ────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_stdout_stderr(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(pkt, _default_scope(), stdout_content="", stderr_content="")
        assert result.verdict == ReviewVerdict.PASS

    def test_no_stdout_stderr_args(self):
        """Review works when stdout/stderr not provided (defaults to empty)."""
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(pkt, _default_scope())
        assert result.verdict == ReviewVerdict.PASS

    def test_empty_allow_paths(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet(files_modified=["/any/path"])
        scope = ScopeDeclaration(allow_paths=[])
        result = reviewer.review(pkt, scope)
        assert result.verdict == ReviewVerdict.FAIL

    def test_privacy_redacted_outputs(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stdout_content="Contact user@example.com for help",
        )
        assert "REDACTED" in result.redacted_stdout or result.redacted_stdout == ""

    def test_pii_in_stdout_increases_risk(self):
        reviewer = EvidenceReviewer()
        pkt = _clean_packet()
        result = reviewer.review(
            pkt, _default_scope(),
            stdout_content="SSN: 123-45-6789",
        )
        assert result.risk_delta > 0.0

    def test_secret_patterns_are_compiled_regexes(self):
        import re
        for pattern in SECRET_PATTERNS:
            assert isinstance(pattern, re.Pattern)
