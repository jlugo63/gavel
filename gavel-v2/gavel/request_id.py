"""Request ID correlation: contextvar-backed propagation across the gateway."""

from __future__ import annotations

import contextvars
import logging
import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id_var", default=None
)

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def get_request_id() -> str | None:
    return request_id_var.get()


def set_request_id(value: str) -> contextvars.Token:
    return request_id_var.set(value)


def _normalize(raw: str | None) -> str:
    if raw and _REQUEST_ID_PATTERN.match(raw):
        return raw
    return uuid.uuid4().hex


class RequestIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id() or "-"
        return True


def configure_request_id_logging(logger_name: str | None = None) -> None:
    logger = logging.getLogger(logger_name)
    for existing in logger.filters:
        if isinstance(existing, RequestIDFilter):
            return
    logger.addFilter(RequestIDFilter())


configure_request_id_logging("gavel")


class RequestIDMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get("x-request-id")
        rid = _normalize(incoming)
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response
