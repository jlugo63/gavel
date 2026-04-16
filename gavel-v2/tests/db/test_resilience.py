"""Tests for gavel.db.resilience — retry + circuit breaker."""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

from gavel.db import resilience
from gavel.db.resilience import (
    DatabaseCircuitOpenError,
    db_retry,
    get_breaker,
    reset_breaker,
)


@pytest.fixture(autouse=True)
def _fast_sleep_and_fresh_breaker(monkeypatch):
    async def _noop(_seconds):
        return None

    monkeypatch.setattr(resilience.asyncio, "sleep", _noop)
    reset_breaker()
    yield
    reset_breaker()


def _operational_error() -> OperationalError:
    return OperationalError("SELECT 1", {}, Exception("connection reset"))


def _integrity_error() -> IntegrityError:
    return IntegrityError("INSERT", {}, Exception("dup key"))


async def test_retries_operational_error_then_succeeds(caplog):
    calls = {"n": 0}

    @db_retry
    async def op():
        calls["n"] += 1
        if calls["n"] <= 2:
            raise _operational_error()
        return "ok"

    caplog.set_level(logging.WARNING, logger="gavel.db.resilience")
    result = await op()

    assert result == "ok"
    assert calls["n"] == 3
    # Two retry warnings (attempts 1 and 2), third call succeeds.
    retry_records = [r for r in caplog.records if "db retry" in r.getMessage()]
    assert len(retry_records) == 2
    assert all(r.levelno == logging.WARNING for r in retry_records)


async def test_integrity_error_is_not_retried():
    calls = {"n": 0}

    @db_retry
    async def op():
        calls["n"] += 1
        raise _integrity_error()

    with pytest.raises(IntegrityError):
        await op()
    assert calls["n"] == 1


async def test_exhaust_retries_raises_last_exception():
    @db_retry
    async def op():
        raise _operational_error()

    with pytest.raises(OperationalError):
        await op()


async def test_circuit_breaker_trips_after_threshold_and_short_circuits():
    calls = {"n": 0}

    @db_retry
    async def op():
        calls["n"] += 1
        raise _operational_error()

    # First call exhausts 5 attempts -> 5 consecutive failures -> OPEN.
    with pytest.raises(OperationalError):
        await op()
    assert calls["n"] == 5

    breaker = get_breaker()
    state = breaker.get_state("db")
    assert state is not None
    assert state.state.value == "OPEN"

    # Second call must short-circuit without invoking the wrapped op.
    before = calls["n"]
    with pytest.raises(DatabaseCircuitOpenError):
        await op()
    assert calls["n"] == before


async def test_half_open_allows_trial_after_recovery_timeout(monkeypatch):
    from datetime import datetime, timedelta, timezone

    @db_retry
    async def always_fail():
        raise _operational_error()

    with pytest.raises(OperationalError):
        await always_fail()

    breaker = get_breaker()
    state = breaker.get_state("db")
    assert state.state.value == "OPEN"

    # Rewind last_state_change by 61s so the breaker moves to HALF_OPEN.
    state.last_state_change = datetime.now(timezone.utc) - timedelta(seconds=61)

    calls = {"n": 0}

    @db_retry
    async def succeed():
        calls["n"] += 1
        return "ok"

    result = await succeed()
    assert result == "ok"
    assert calls["n"] == 1
    assert breaker.get_state("db").state.value == "CLOSED"
