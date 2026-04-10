"""Tests for gavel.qms — EU AI Act Art. 17 Quality Management System."""

from __future__ import annotations

from gavel.qms import QmsCoverage, QmsGenerator, QmsManual


class TestQmsManual:
    def test_generator_produces_13_clauses(self):
        manual = QmsGenerator("Acme AI", "CreditScorer").generate()
        assert isinstance(manual, QmsManual)
        assert len(manual.clauses) == 13
        # Every clause has a unique Art. 17(1) letter reference.
        refs = {c.article_ref for c in manual.clauses}
        assert len(refs) == 13
        for letter in "abcdefghijklm":
            assert any(f"(1)({letter})" in r for r in refs)

    def test_coverage_summary_sums_to_13(self):
        manual = QmsGenerator("Acme AI", "CreditScorer").generate()
        summary = manual.coverage_summary()
        assert sum(summary.values()) == 13
        assert summary[QmsCoverage.AUTOMATED.value] >= 3
        assert summary[QmsCoverage.PROVIDER_DOCUMENTED.value] >= 1

    def test_automated_clauses_reference_gavel_modules(self):
        manual = QmsGenerator("Acme AI", "CreditScorer").generate()
        for clause in manual.clauses:
            if clause.coverage == QmsCoverage.AUTOMATED:
                assert clause.gavel_evidence, f"{clause.article_ref} automated but no evidence"
                # Every automated clause should cite at least one concrete artefact.
                joined = " ".join(clause.gavel_evidence).lower()
                assert any(k in joined for k in ("gavel", "chain", "tests/", "incident"))

    def test_provider_documented_lists_provider_requirements(self):
        manual = QmsGenerator("Acme AI", "CreditScorer").generate()
        for clause in manual.clauses:
            if clause.coverage == QmsCoverage.PROVIDER_DOCUMENTED:
                assert clause.provider_required_input, f"{clause.article_ref} missing provider inputs"

    def test_markdown_export_contains_all_clauses(self):
        manual = QmsGenerator("Acme AI", "CreditScorer").generate()
        md = manual.to_markdown()
        assert "# QMS Manual — CreditScorer" in md
        assert "Acme AI" in md
        assert "prEN 18286" in md
        for letter in "abcdefghijklm":
            assert f"(1)({letter})" in md

    def test_incidents_feed_clause_g(self):
        class FakeIncident:
            status = "open"
        manual = QmsGenerator(
            "Acme AI",
            "CreditScorer",
            incidents=[FakeIncident(), FakeIncident()],
        ).generate()
        clause_g = next(c for c in manual.clauses if "(g)" in c.article_ref)
        assert any("2" in e for e in clause_g.gavel_evidence)
