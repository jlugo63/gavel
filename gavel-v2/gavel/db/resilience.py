"""DB resilience: retry with backoff + circuit breaker for transient failures.

Transient errors (``OperationalError``, generic ``DBAPIError`` connection
blips) are retried with exponential backoff. Logical errors
(``IntegrityError``, ``ProgrammingError``, etc.) propagate immediately.

A process-wide circuit breaker trips after ``_FAILURE_THRESHOLD`` consecutive
transient failures and short-circuits subsequent calls until the recovery
window elapses.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Awaitable, Callable, TypeVar

from sqlalchemy.exc import DBAPIError, OperationalError

from gavel.circuit_breaker import CircuitBreaker, CircuitBreakerConfig

logger = logging.getLogger("gavel.db.resilience")

_BACKOFF_SCHEDULE: tuple[int, ...] = (1, 2, 4, 8, 16)
_MAX_ATTEMPTS = len(_BACKOFF_SCHEDULE)
_FAILURE_THRESHOLD = 5
_RECOVERY_TIMEOUT_SECONDS = 60
_DB_KEY = "db"

T = TypeVar("T")


class DatabaseCircuitOpenError(RuntimeError):
    """Raised when the DB circuit breaker is open and short-circuits a call."""


_breaker = CircuitBreaker(
    default_config=CircuitBreakerConfig(
        failure_threshold=_FAILURE_THRESHOLD,
        recovery_timeout_seconds=_RECOVERY_TIMEOUT_SECONDS,
        half_open_max_requests=1,
        success_threshold=1,
    )
)


def get_breaker() -> CircuitBreaker:
    return _breaker


def reset_breaker() -> None:
    _breaker.reset(_DB_KEY)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, OperationalError):
        return True
    if isinstance(exc, DBAPIError):
        # ``connection_invalidated`` is set by SA when the pool detects a
        # dead connection; treat those as transient.
        return bool(getattr(exc, "connection_invalidated", False))
    return False


def db_retry(
    func: Callable[..., Awaitable[T]],
) -> Callable[..., Awaitable[T]]:
    """Decorate an async callable with retry + circuit-breaker semantics."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> T:
        if not _breaker.allow_request(_DB_KEY):
            raise DatabaseCircuitOpenError(
                "gavel.db circuit breaker is OPEN; refusing call"
            )

        last_exc: BaseException | None = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                result = await func(*args, **kwargs)
            except BaseException as exc:
                if not _is_retryable(exc):
                    raise
                last_exc = exc
                _breaker.record_failure(_DB_KEY)
                if attempt >= _MAX_ATTEMPTS:
                    break
                delay = _BACKOFF_SCHEDULE[attempt - 1]
                logger.warning(
                    "db retry attempt=%d delay=%ds exc=%s",
                    attempt,
                    delay,
                    type(exc).__name__,
                )
                if not _breaker.allow_request(_DB_KEY):
                    raise DatabaseCircuitOpenError(
                        "gavel.db circuit breaker tripped mid-retry"
                    ) from exc
                await asyncio.sleep(delay)
            else:
                _breaker.record_success(_DB_KEY)
                return result

        assert last_exc is not None
        raise last_exc

    return wrapper


__all__ = [
    "DatabaseCircuitOpenError",
    "db_retry",
    "get_breaker",
    "reset_breaker",
]
