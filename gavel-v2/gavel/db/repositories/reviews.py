"""ReviewRepository — persistence for ReviewResult rows.

Current in-memory semantics (``get_review_results()`` returns a
``dict[chain_id, ReviewResult]``):

* ``get(chain_id)``       → ``review_results.get(chain_id)``
* ``save(cid, result)``   → ``review_results[cid] = result``  (upsert)
* ``delete(cid)``         → ``review_results.pop(cid, None)``

Per the Wave 2A spec: ``get()`` returns ``None`` when absent — do NOT
bake the default ``ReviewResult()`` into the repo. Callers that need
the default (e.g. ``governance_router.py:230``) handle it themselves.

``Finding`` is a dataclass; we serialise findings as a list of dicts
via ``dataclasses.asdict`` and rehydrate on load. The storage row
keys by ``packet_id``; we upsert keyed on ``chain_id`` to match the
dict semantics (one review per chain today).
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Optional

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from gavel.db.models import ReviewResultRow
from gavel.evidence import Finding, ReviewResult, ReviewVerdict


class ReviewRepository:
    """Async repository for review results keyed by ``chain_id``."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]):
        self._sessionmaker = sessionmaker

    async def get(self, chain_id: str) -> Optional[ReviewResult]:
        async with self._sessionmaker() as session:
            stmt = select(ReviewResultRow).where(
                ReviewResultRow.chain_id == chain_id
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None
            return _row_to_result(row)

    async def save(self, chain_id: str, result: ReviewResult) -> None:
        """Upsert: one review per chain. Replaces any prior row."""
        async with self._sessionmaker() as session:
            async with session.begin():
                await session.execute(
                    sa_delete(ReviewResultRow).where(
                        ReviewResultRow.chain_id == chain_id
                    )
                )
                session.add(_result_to_row(chain_id, result))

    async def delete(self, chain_id: str) -> None:
        async with self._sessionmaker() as session:
            async with session.begin():
                await session.execute(
                    sa_delete(ReviewResultRow).where(
                        ReviewResultRow.chain_id == chain_id
                    )
                )


# ── helpers ───────────────────────────────────────────────────────


def _result_to_row(chain_id: str, result: ReviewResult) -> ReviewResultRow:
    # ReviewResult has no packet_id of its own. The ORM row's PK is
    # ``packet_id`` — for the dict-style single-review-per-chain flow
    # we synthesize one when the caller didn't hand us a packet-linked
    # result. Chain_id is indexed and is how we look rows up.
    packet_id = f"rev-{uuid.uuid4().hex[:8]}"
    return ReviewResultRow(
        packet_id=packet_id,
        chain_id=chain_id,
        verdict=result.verdict.value
        if isinstance(result.verdict, ReviewVerdict)
        else str(result.verdict),
        findings=[asdict(f) if isinstance(f, Finding) else dict(f) for f in result.findings],
        risk_delta=float(result.risk_delta),
        scope_compliance=result.scope_compliance,
        review_hash=result.review_hash,
        redacted_stdout=result.redacted_stdout,
        redacted_stderr=result.redacted_stderr,
        privacy_findings=list(result.privacy_findings or []),
    )


def _row_to_result(row: ReviewResultRow) -> ReviewResult:
    findings: list[Finding] = []
    for f in row.findings or []:
        if isinstance(f, dict):
            findings.append(
                Finding(
                    check=f.get("check", ""),
                    passed=bool(f.get("passed", False)),
                    detail=f.get("detail", ""),
                    severity=f.get("severity", "info"),
                )
            )
    return ReviewResult(
        verdict=ReviewVerdict(row.verdict),
        findings=findings,
        risk_delta=float(row.risk_delta),
        scope_compliance=row.scope_compliance,
        review_hash=row.review_hash,
        redacted_stdout=row.redacted_stdout,
        redacted_stderr=row.redacted_stderr,
        privacy_findings=list(row.privacy_findings or []),
    )
