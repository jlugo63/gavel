"""Tests for gavel.privacy — PII/PHI scanner + redaction (ATF D-3)."""

from __future__ import annotations

from gavel.privacy import PrivacyCategory, scan_text
from gavel.blastbox import EvidencePacket, ScopeDeclaration
from gavel.evidence import EvidenceReviewer


class TestPrivacyScanner:
    def test_empty_input(self):
        r = scan_text("")
        assert r.findings == []
        assert r.redacted_text == ""
        assert r.passed

    def test_clean_text_passes(self):
        r = scan_text("This is an ordinary log line with no sensitive data.")
        assert r.passed
        assert r.redacted_text == "This is an ordinary log line with no sensitive data."

    def test_detects_email(self):
        r = scan_text("Contact: alice@example.com please.")
        assert not r.passed
        assert r.pii_count == 1
        assert "alice@example.com" not in r.redacted_text
        assert "[REDACTED:EMAIL]" in r.redacted_text
        assert r.findings[0].category == PrivacyCategory.PII
        assert r.findings[0].type == "email"

    def test_detects_ssn(self):
        r = scan_text("SSN on file: 123-45-6789")
        assert any(f.type == "ssn" for f in r.findings)
        assert "123-45-6789" not in r.redacted_text

    def test_detects_phone(self):
        r = scan_text("Call 415-555-1234 for support")
        assert any(f.type == "phone" for f in r.findings)
        assert "415-555-1234" not in r.redacted_text

    def test_detects_luhn_valid_credit_card(self):
        # Test CC that passes Luhn (this is a commonly-used test number)
        r = scan_text("Card: 4111 1111 1111 1111")
        assert any(f.type == "credit_card" for f in r.findings)

    def test_rejects_luhn_invalid_cc(self):
        # 16 digits, wrong checksum
        r = scan_text("Not a card: 1234 5678 9012 3456")
        assert not any(f.type == "credit_card" for f in r.findings)

    def test_detects_ipv4(self):
        r = scan_text("Source IP 192.168.1.42")
        assert any(f.type == "ipv4" for f in r.findings)

    def test_detects_dob(self):
        r = scan_text("Patient DOB: 01/15/1985")
        assert any(f.type == "date_of_birth" for f in r.findings)
        assert r.phi_count >= 1

    def test_detects_mrn_context(self):
        r = scan_text("MRN: ABC-12345 in the system")
        assert any(f.type == "mrn" for f in r.findings)

    def test_icd10_only_with_clinical_context(self):
        # No clinical context — should not fire
        r = scan_text("The code A01 is assigned to storage unit A01")
        assert not any(f.type == "icd10" for f in r.findings)
        # With clinical context — should fire
        r2 = scan_text("Patient diagnosis: A01.1 typhoid fever")
        assert any(f.type == "icd10" for f in r2.findings)

    def test_multiple_findings_all_redacted(self):
        text = "Contact alice@example.com or 415-555-1234, SSN 123-45-6789"
        r = scan_text(text)
        assert len(r.findings) >= 3
        assert "alice@example.com" not in r.redacted_text
        assert "415-555-1234" not in r.redacted_text
        assert "123-45-6789" not in r.redacted_text


class TestEvidenceReviewerIntegration:
    def _mk_packet(self) -> tuple[EvidencePacket, ScopeDeclaration]:
        scope = ScopeDeclaration(allow_paths=["src/"], allow_network=False)
        packet = EvidencePacket(
            chain_id="c-1",
            command_argv=["cat", "log.txt"],
            scope=scope,
            exit_code=0,
            files_modified=["src/app.py"],
            network_mode="none",
        )
        return packet, scope

    def test_clean_output_passes(self):
        packet, scope = self._mk_packet()
        reviewer = EvidenceReviewer()
        result = reviewer.review(packet, scope, stdout_content="build ok", stderr_content="")
        assert result.passed
        assert result.privacy_findings == []
        assert result.redacted_stdout == "build ok"

    def test_pii_detected_and_redacted(self):
        packet, scope = self._mk_packet()
        reviewer = EvidenceReviewer()
        result = reviewer.review(
            packet,
            scope,
            stdout_content="user: alice@example.com",
            stderr_content="",
        )
        assert not result.passed
        assert len(result.privacy_findings) >= 1
        assert "alice@example.com" not in result.redacted_stdout
        assert "[REDACTED:EMAIL]" in result.redacted_stdout

    def test_phi_weighted_as_fail(self):
        packet, scope = self._mk_packet()
        reviewer = EvidenceReviewer()
        result = reviewer.review(
            packet,
            scope,
            stdout_content="Patient DOB: 01/15/1985",
            stderr_content="",
        )
        assert not result.passed
        assert any(f["category"] == "phi" for f in result.privacy_findings)
        assert "01/15/1985" not in result.redacted_stdout
