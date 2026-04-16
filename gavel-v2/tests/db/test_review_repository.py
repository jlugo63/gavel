"""Tests for ``ReviewRepository`` (Wave 2A)."""

from __future__ import annotations

import pytest

from gavel.db.repositories.reviews import ReviewRepository
from gavel.evidence import Finding, ReviewResult, ReviewVerdict


async def test_save_get_delete_roundtrip(sessionmaker):
    repo = ReviewRepository(sessionmaker)

    assert await repo.get("c-missing") is None

    result = ReviewResult(
        verdict=ReviewVerdict.PASS,
        findings=[
            Finding(check="exit_code", passed=True, detail="ok", severity="info"),
            Finding(check="scope", passed=True, detail="all paths in scope"),
        ],
        risk_delta=0.1,
        scope_compliance="FULL",
        review_hash="d" * 64,
        redacted_stdout="hi",
        redacted_stderr="",
        privacy_findings=[],
    )

    await repo.save("c-1", result)
    loaded = await repo.get("c-1")
    assert loaded is not None
    assert loaded.verdict == ReviewVerdict.PASS
    assert loaded.scope_compliance == "FULL"
    assert loaded.risk_delta == 0.1
    assert loaded.review_hash == "d" * 64
    assert loaded.redacted_stdout == "hi"
    assert len(loaded.findings) == 2
    assert loaded.findings[0].check == "exit_code"
    assert loaded.findings[0].passed is True
    assert loaded.findings[0].severity == "info"

    await repo.delete("c-1")
    assert await repo.get("c-1") is None


async def test_save_upsert_replaces_prior(sessionmaker):
    repo = ReviewRepository(sessionmaker)

    first = ReviewResult(verdict=ReviewVerdict.PASS, risk_delta=0.0)
    await repo.save("c-upsert", first)

    second = ReviewResult(
        verdict=ReviewVerdict.FAIL,
        findings=[Finding(check="x", passed=False, detail="boom", severity="fail")],
        risk_delta=0.9,
        scope_compliance="VIOLATION",
    )
    await repo.save("c-upsert", second)

    loaded = await repo.get("c-upsert")
    assert loaded is not None
    assert loaded.verdict == ReviewVerdict.FAIL
    assert loaded.scope_compliance == "VIOLATION"
    assert loaded.risk_delta == 0.9
    assert len(loaded.findings) == 1
    assert loaded.findings[0].severity == "fail"


async def test_privacy_findings_roundtrip(sessionmaker):
    repo = ReviewRepository(sessionmaker)
    result = ReviewResult(
        verdict=ReviewVerdict.WARN,
        privacy_findings=[
            {"stream": "stdout", "category": "PII", "type": "email", "redacted": True},
        ],
    )
    await repo.save("c-pf", result)
    loaded = await repo.get("c-pf")
    assert loaded is not None
    assert loaded.privacy_findings == [
        {"stream": "stdout", "category": "PII", "type": "email", "redacted": True},
    ]


async def test_delete_missing_is_noop(sessionmaker):
    repo = ReviewRepository(sessionmaker)
    await repo.delete("c-never")
