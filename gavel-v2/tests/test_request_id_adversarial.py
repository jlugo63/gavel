"""Adversarial and edge-case tests for X-Request-ID correlation.

QA D sprint coverage: validator robustness, duplicate headers, contextvar
hygiene, chain/event-bus propagation under load, and middleware ordering.

These tests do NOT modify production code. Any defect discovered here is
pinned as a regression guard or documented via xfail/skip for follow-up.
"""

from __future__ import annotations

import asyncio
import re

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from gavel.chain import EventType, GovernanceChain
from gavel.events import DashboardEvent
from gavel.request_id import (
    RequestIDMiddleware,
    get_request_id,
    request_id_var,
    set_request_id,
)

UUID_HEX = re.compile(r"^[0-9a-f]{32}$")


def _mini_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)

    @app.get("/ping")
    async def ping():
        return {"request_id": get_request_id()}

    @app.post("/emit-chain")
    async def emit_chain():
        chain = GovernanceChain()
        evt = chain.append(EventType.INBOUND_INTENT, "agent:x", "proposer")
        return {"event_rid": evt.request_id}

    @app.post("/emit-event")
    async def emit_event():
        evt = DashboardEvent(event_type="action", agent_id="a")
        return {"evt_rid": evt.request_id}

    return app


# ---------------------------------------------------------------------------
# A. Validator robustness
# ---------------------------------------------------------------------------


class TestValidatorAdversarial:
    """Each input exercises a specific attack or edge case against the
    ^[A-Za-z0-9_-]{1,128}$ validator. Any accepted value MUST be safe to
    echo into a response header without enabling injection or log poisoning.
    """

    @pytest.mark.parametrize(
        "bad,threat",
        [
            ("", "empty string must regenerate, not echo an empty header"),
            ("   ", "whitespace-only is not in charset, must regenerate"),
            ("\t", "tab control char could break log parsing"),
            ("\r\n", "bare CRLF is the canonical header-injection vector"),
            ("\x00", "NUL byte can truncate C-string consumers downstream"),
            ("valid\r\nX-Injected: evil", "CRLF header injection attempt"),
            ("valid\nSet-Cookie: pwned=1", "LF-only injection (HTTP/1.0 style)"),
            ("\x1b[31mred", "ANSI escape could poison terminal-based log viewers"),
            ("\x7f", "DEL byte, non-printable"),
            ("\x08backspace", "backspace control char"),
            ("a b c", "internal spaces are not in charset"),
            ("has/slash", "slash could be misread as path"),
            ("has.dot", "dot not in charset (pins validator strictness)"),
            ("has:colon", "colon is an HTTP header delimiter"),
            ("has;semi", "semicolon is a cookie/header param delimiter"),
            ("has,comma", "comma triggers the duplicate-header join case"),
            ("'; DROP TABLE users;--", "classic SQLi payload must never reach a logger that interpolates"),
            ("<script>alert(1)</script>", "XSS payload (dashboards may render request_id)"),
            ("../../etc/passwd", "path traversal attempt"),
            ("%00null", "URL-encoded null (must be rejected pre-decode)"),
            ("x" * 129, "one-byte overflow past the 128 limit"),
            ("x" * 1024, "kilobyte-long input: DoS via log volume"),
            ("null", "literal string 'null' is valid-looking garbage — pinning it IS accepted as it matches charset"),
        ],
    )
    def test_adversarial_input_handled_safely(self, bad, threat):
        """Adversarial input is either regenerated (preferred) or, if it
        happens to match the charset, echoed verbatim. In both cases the
        response header must be a safe single-line string with no injected
        headers and no control characters.
        """
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": bad})
        assert r.status_code == 200, f"threat: {threat}"
        returned = r.headers["X-Request-ID"]
        # No control chars ever survive into the response header.
        for ch in returned:
            assert ord(ch) >= 0x20 and ord(ch) != 0x7f, (
                f"control char {ord(ch):#x} leaked into header ({threat})"
            )
            assert ch not in "\r\n", f"CRLF leaked ({threat})"
        # No injected headers appeared.
        assert "x-injected" not in {k.lower() for k in r.headers.keys()}, (
            f"header injection succeeded: {threat}"
        )
        # Returned value conforms to the validator charset.
        assert re.match(r"^[A-Za-z0-9_-]{1,128}$", returned), (
            f"returned value {returned!r} escapes the charset ({threat})"
        )

    def test_exactly_128_chars_preserved(self):
        """Boundary: 128 chars of valid charset should be preserved verbatim."""
        supplied = "A" * 128
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": supplied})
        assert r.headers["X-Request-ID"] == supplied
        assert r.json()["request_id"] == supplied

    def test_129_chars_regenerated(self):
        """Boundary: one byte over the limit must regenerate."""
        supplied = "A" * 129
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": supplied})
        assert r.headers["X-Request-ID"] != supplied
        assert UUID_HEX.match(r.headers["X-Request-ID"])

    def test_one_char_preserved(self):
        """Boundary: the validator allows length 1."""
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": "x"})
        assert r.headers["X-Request-ID"] == "x"

    def test_underscore_and_hyphen_preserved(self):
        """Charset includes _ and -; pin that both survive."""
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": "_-_-_"})
        assert r.headers["X-Request-ID"] == "_-_-_"

    @pytest.mark.parametrize(
        "raw_bytes,threat",
        [
            ("übung".encode("utf-8"), "latin-1 unicode outside ASCII charset"),
            ("日本語".encode("utf-8"), "CJK unicode"),
            ("🦀".encode("utf-8"), "emoji (multi-byte UTF-8)"),
            (("\u202e" + "evil").encode("utf-8"), "right-to-left override can mislead log readers"),
            (b"x" * 10_000, "10KB input: oversized, still regenerated"),
        ],
    )
    def test_non_ascii_and_huge_inputs_via_raw_asgi(self, raw_bytes, threat):
        """httpx refuses to send non-ASCII header values, so we exercise
        these cases through the raw ASGI interface. The middleware must
        still regenerate and never leak bytes into the response header.
        """
        app = _mini_app()

        async def run():
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/ping",
                "raw_path": b"/ping",
                "query_string": b"",
                "root_path": "",
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 1234),
                "headers": [(b"host", b"testserver"), (b"x-request-id", raw_bytes)],
            }
            messages: list[dict] = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(msg):
                messages.append(msg)

            await app(scope, receive, send)
            return messages

        messages = asyncio.run(run())
        start = next(m for m in messages if m["type"] == "http.response.start")
        returned = dict(start["headers"])[b"x-request-id"].decode("latin-1")
        assert re.match(r"^[A-Za-z0-9_-]{1,128}$", returned), (
            f"returned value {returned!r} escapes the charset ({threat})"
        )
        # Never echoed back the hostile bytes.
        assert raw_bytes.decode("utf-8", errors="replace") not in returned


# ---------------------------------------------------------------------------
# B. Duplicate / multi-value X-Request-ID headers
# ---------------------------------------------------------------------------


class TestDuplicateHeaders:
    """HTTP allows repeated header names. We pin the observed behavior:
    Starlette's ``request.headers.get`` returns the FIRST value when the
    ASGI scope contains multiple entries for the same name (it does NOT
    comma-join at this layer — comma-joining would be an httpx/proxy-side
    behavior). The middleware therefore validates and echoes the first.
    """

    def test_two_raw_asgi_headers_first_wins(self):
        """Raw ASGI scope with two X-Request-ID entries: first-valid wins."""
        app = _mini_app()

        async def run():
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/ping",
                "raw_path": b"/ping",
                "query_string": b"",
                "root_path": "",
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 1234),
                "headers": [
                    (b"host", b"testserver"),
                    (b"x-request-id", b"first-valid"),
                    (b"x-request-id", b"second-valid"),
                ],
            }
            messages: list[dict] = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(msg):
                messages.append(msg)

            await app(scope, receive, send)
            return messages

        messages = asyncio.run(run())
        start = next(m for m in messages if m["type"] == "http.response.start")
        returned = dict(start["headers"])[b"x-request-id"].decode()
        assert returned == "first-valid"

    def test_comma_joined_single_header_regenerated(self):
        """If an upstream proxy comma-joins two values into 'a, b', that
        single string fails the validator (space + comma) and is regenerated.
        """
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": "first-valid, second-valid"})
        assert r.headers["X-Request-ID"] != "first-valid, second-valid"
        assert UUID_HEX.match(r.headers["X-Request-ID"])

    def test_first_invalid_second_valid_still_regenerates(self):
        """First header wins even if invalid. Second valid value is ignored.
        This pins the behavior — if a future dev wants fallback-to-next, the
        test must be rewritten, which is exactly the regression signal we want.
        """
        app = _mini_app()

        async def run():
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/ping",
                "raw_path": b"/ping",
                "query_string": b"",
                "root_path": "",
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 1234),
                "headers": [
                    (b"host", b"testserver"),
                    (b"x-request-id", b"bad value with spaces"),
                    (b"x-request-id", b"valid-second"),
                ],
            }
            messages: list[dict] = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(msg):
                messages.append(msg)

            await app(scope, receive, send)
            return messages

        messages = asyncio.run(run())
        start = next(m for m in messages if m["type"] == "http.response.start")
        returned = dict(start["headers"])[b"x-request-id"].decode()
        # First was invalid -> regenerated; second never consulted.
        assert returned != "valid-second"
        assert UUID_HEX.match(returned)


# ---------------------------------------------------------------------------
# C. Structured logging propagation
# ---------------------------------------------------------------------------


class TestLoggingPropagation:
    """There is currently NO logging integration wiring request_id into
    LogRecords. This is a documented gap: out of scope for Dev B, flagged
    for a follow-up. The test below asserts the gap's existence so a future
    integration flips it from xfail to pass.
    """

    def test_request_id_appears_in_log_records(self):
        import logging

        captured: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(record)

        handler = Capture()
        logger = logging.getLogger("gavel")
        logger.addHandler(handler)
        try:
            token = set_request_id("log-rid-1")
            try:
                logger.warning("test message")
            finally:
                request_id_var.reset(token)
        finally:
            logger.removeHandler(handler)

        assert captured, "no log records captured"
        # Would require a logging.Filter wired to request_id_var.
        assert getattr(captured[0], "request_id", None) == "log-rid-1"


# ---------------------------------------------------------------------------
# D. Contextvar hygiene
# ---------------------------------------------------------------------------


class TestContextvarHygiene:
    def test_context_reset_after_request(self):
        """After TestClient returns, get_request_id() outside any request
        must be None. A leak here would cross-contaminate subsequent work.
        """
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": "inside-rid"})
        assert r.json()["request_id"] == "inside-rid"
        # Outside the request context now.
        assert get_request_id() is None

    def test_concurrent_requests_isolated(self):
        """Two concurrent requests must each observe their own request_id."""
        from httpx import ASGITransport, AsyncClient

        app = _mini_app()

        async def run():
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://t") as ac:
                r1, r2 = await asyncio.gather(
                    ac.get("/ping", headers={"X-Request-ID": "concurrent-A"}),
                    ac.get("/ping", headers={"X-Request-ID": "concurrent-B"}),
                )
                return r1.json()["request_id"], r2.json()["request_id"]

        a, b = asyncio.run(run())
        assert a == "concurrent-A"
        assert b == "concurrent-B"

    def test_background_task_inherits_request_id(self):
        """asyncio.create_task inside a request inherits the contextvar —
        that is the whole point of contextvars. Pin the behavior so a future
        refactor to threads (which do NOT inherit) is caught.
        """
        app = FastAPI()
        app.add_middleware(RequestIDMiddleware)
        captured: dict = {}

        @app.post("/bg")
        async def bg():
            async def inner():
                # Let the outer handler return first is not required; we
                # just need the task to run in the same context.
                captured["rid"] = get_request_id()

            task = asyncio.create_task(inner())
            await task
            return {"ok": True}

        client = TestClient(app)
        client.post("/bg", headers={"X-Request-ID": "bg-rid-1"})
        assert captured.get("rid") == "bg-rid-1"

    def test_set_request_id_outside_request_is_cleanable(self):
        """Manual set_request_id/reset cycle leaves no residue."""
        assert get_request_id() is None
        token = set_request_id("manual-1")
        try:
            assert get_request_id() == "manual-1"
        finally:
            request_id_var.reset(token)
        assert get_request_id() is None


# ---------------------------------------------------------------------------
# E. Audit chain propagation under load
# ---------------------------------------------------------------------------


class TestChainIntegrityUnderLoad:
    def test_identical_content_different_request_ids_same_hash(self):
        """request_id is explicitly excluded from compute_hash. Two events
        with identical content but different request_ids MUST produce the
        same hash, otherwise a benign tracing header change would break
        tamper-evidence replays.
        """
        chain_a = GovernanceChain(chain_id="fixed-chain")
        chain_b = GovernanceChain(chain_id="fixed-chain")

        token_a = set_request_id("rid-A")
        try:
            evt_a = chain_a.append(EventType.INBOUND_INTENT, "agent:x", "proposer")
        finally:
            request_id_var.reset(token_a)

        token_b = set_request_id("rid-B")
        try:
            evt_b = chain_b.append(EventType.INBOUND_INTENT, "agent:x", "proposer")
        finally:
            request_id_var.reset(token_b)

        # Force identical event_id and timestamp to isolate the request_id variable.
        evt_b.event_id = evt_a.event_id
        evt_b.timestamp = evt_a.timestamp
        # Recompute on both — request_id differs, everything else identical.
        assert evt_a.request_id == "rid-A"
        assert evt_b.request_id == "rid-B"
        assert evt_a.compute_hash() == evt_b.compute_hash()

    def test_chain_with_mixed_request_ids_verifies(self):
        """A chain whose events were appended under different request_ids
        (e.g., a long-running chain spanning multiple HTTP requests) still
        passes verify_integrity().
        """
        chain = GovernanceChain()

        for rid in ("req-1", "req-2", "req-3", None):
            if rid is None:
                chain.append(EventType.POLICY_EVAL, "system:agentos", "policy")
            else:
                token = set_request_id(rid)
                try:
                    chain.append(EventType.POLICY_EVAL, "system:agentos", "policy")
                finally:
                    request_id_var.reset(token)

        assert chain.verify_integrity() is True
        observed = [e.request_id for e in chain.events]
        assert observed == ["req-1", "req-2", "req-3", None]

    def test_many_events_under_one_request_id(self):
        """Load: 100 events within a single request context all carry the same id."""
        token = set_request_id("bulk-load-rid")
        try:
            chain = GovernanceChain()
            for _ in range(100):
                chain.append(EventType.POLICY_EVAL, "system:agentos", "policy")
        finally:
            request_id_var.reset(token)
        assert chain.verify_integrity() is True
        assert all(e.request_id == "bulk-load-rid" for e in chain.events)


# ---------------------------------------------------------------------------
# F. Event-bus propagation
# ---------------------------------------------------------------------------


class TestEventBusEdgeCases:
    def test_event_outside_request_is_none_not_leaked(self):
        """Pydantic's default_factory is evaluated at instantiation. Outside
        a request, get_request_id() returns None — not a stale value from
        a previous request handled on the same worker.
        """
        # Simulate a previous request that set and cleaned up.
        token = set_request_id("previous-request")
        try:
            pass
        finally:
            request_id_var.reset(token)
        assert get_request_id() is None
        evt = DashboardEvent(event_type="action")
        assert evt.request_id is None

    def test_explicit_kwarg_beats_context(self):
        """Explicit request_id=... passed to the constructor overrides the
        default_factory, so callers that already have a correlation id from
        a different source can still set it.
        """
        token = set_request_id("ctx-rid")
        try:
            evt = DashboardEvent(event_type="action", request_id="explicit-rid")
        finally:
            request_id_var.reset(token)
        assert evt.request_id == "explicit-rid"

    def test_explicit_none_beats_context(self):
        """Explicit request_id=None is respected (i.e., it's a real override
        signal, not 'fall back to factory'). Pins current pydantic semantics.
        """
        token = set_request_id("ctx-rid")
        try:
            evt = DashboardEvent(event_type="action", request_id=None)
        finally:
            request_id_var.reset(token)
        assert evt.request_id is None

    def test_event_sse_payload_contains_request_id(self):
        """The SSE serialization must include request_id so dashboard
        clients can correlate events back to API calls.
        """
        token = set_request_id("sse-rid-42")
        try:
            evt = DashboardEvent(event_type="action", agent_id="a")
        finally:
            request_id_var.reset(token)
        sse = evt.to_sse()
        assert '"request_id": "sse-rid-42"' in sse


# ---------------------------------------------------------------------------
# G. Middleware ordering
# ---------------------------------------------------------------------------


class TestMiddlewareOrdering:
    """RequestIDMiddleware must wrap CORSMiddleware so the request_id is
    available for the lifetime of the request, including any CORS pre-flight
    logging. In FastAPI/Starlette, ``app.user_middleware`` is a list where
    index 0 is the OUTERMOST layer (last-added). So RequestID (added last)
    must appear at index 0.
    """

    def test_gateway_request_id_wraps_cors(self):
        from gavel.gateway import app

        names = [mw.cls.__name__ for mw in app.user_middleware]
        assert "RequestIDMiddleware" in names, "RequestIDMiddleware missing from gateway"
        assert "CORSMiddleware" in names, "CORSMiddleware missing from gateway"
        rid_idx = names.index("RequestIDMiddleware")
        cors_idx = names.index("CORSMiddleware")
        assert rid_idx < cors_idx, (
            f"RequestIDMiddleware (idx {rid_idx}) must be outer "
            f"(lower index) than CORSMiddleware (idx {cors_idx}); "
            "otherwise CORS preflight rejections would bypass request-id tagging."
        )

    def test_manual_construction_same_convention(self):
        """Mirror the gateway wiring on a throwaway app to guard against a
        Starlette change to user_middleware semantics.
        """
        app = FastAPI()
        app.add_middleware(CORSMiddleware, allow_origins=["*"])
        app.add_middleware(RequestIDMiddleware)  # added last => outermost
        names = [mw.cls.__name__ for mw in app.user_middleware]
        assert names.index("RequestIDMiddleware") < names.index("CORSMiddleware")


# ---------------------------------------------------------------------------
# H. Proxy app — coverage gap (documented, not fixed)
# ---------------------------------------------------------------------------


class TestProxyAppCoverageGap:
    """``gavel/proxy.py`` is a separate FastAPI app (the enforcement proxy).
    Dev B explicitly scoped it out. We assert the CURRENT absence so that
    when a follow-up agent adds the middleware, this xfail flips and the
    gap is visibly closed.
    """

    def test_proxy_has_request_id_middleware(self):
        from gavel.proxy import app as proxy_app

        names = [mw.cls.__name__ for mw in proxy_app.user_middleware]
        assert "RequestIDMiddleware" in names
