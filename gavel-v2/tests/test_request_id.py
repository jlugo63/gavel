"""Request ID correlation tests: generation, validation, propagation."""

from __future__ import annotations

import asyncio
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gavel.chain import EventType, GovernanceChain
from gavel.events import DashboardEvent, EventBus
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

    return app


class TestRequestIDValidation:
    def test_generated_when_header_absent(self):
        client = TestClient(_mini_app())
        r = client.get("/ping")
        assert r.status_code == 200
        rid = r.headers["X-Request-ID"]
        assert UUID_HEX.match(rid)
        assert r.json()["request_id"] == rid

    def test_preserved_when_valid(self):
        client = TestClient(_mini_app())
        supplied = "abc-123_DEF"
        r = client.get("/ping", headers={"X-Request-ID": supplied})
        assert r.headers["X-Request-ID"] == supplied
        assert r.json()["request_id"] == supplied

    @pytest.mark.parametrize(
        "bad",
        [
            "'; DROP TABLE;--",
            "has spaces",
            "has/slash",
            "x" * 129,
            "",
            "contains\nnewline",
        ],
    )
    def test_regenerated_when_malformed(self, bad):
        client = TestClient(_mini_app())
        r = client.get("/ping", headers={"X-Request-ID": bad})
        rid = r.headers["X-Request-ID"]
        assert rid != bad
        assert UUID_HEX.match(rid)


class TestGatewayIntegration:
    def test_real_gateway_route_emits_header(self):
        from gavel.gateway import app

        with TestClient(app) as client:
            r = client.get("/v1/status")
            assert r.status_code == 200
            assert "X-Request-ID" in r.headers
            assert UUID_HEX.match(r.headers["X-Request-ID"])

    def test_real_gateway_preserves_supplied(self):
        from gavel.gateway import app

        with TestClient(app) as client:
            supplied = "trace-42_abc"
            r = client.get("/v1/status", headers={"X-Request-ID": supplied})
            assert r.headers["X-Request-ID"] == supplied


class TestChainPropagation:
    def test_chain_event_carries_request_id(self):
        token = set_request_id("rid-chain-test_1")
        try:
            chain = GovernanceChain()
            event = chain.append(
                event_type=EventType.INBOUND_INTENT,
                actor_id="agent:a",
                role_used="proposer",
            )
        finally:
            request_id_var.reset(token)
        assert event.request_id == "rid-chain-test_1"

    def test_chain_event_none_outside_request(self):
        chain = GovernanceChain()
        event = chain.append(
            event_type=EventType.INBOUND_INTENT,
            actor_id="agent:a",
            role_used="proposer",
        )
        assert event.request_id is None

    def test_chain_integrity_unaffected_by_request_id(self):
        token = set_request_id("rid-integrity")
        try:
            chain = GovernanceChain()
            chain.append(EventType.INBOUND_INTENT, "agent:a", "proposer")
            chain.append(EventType.POLICY_EVAL, "system:agentos", "policy")
        finally:
            request_id_var.reset(token)
        assert chain.verify_integrity() is True

    def test_chain_propagates_via_http_request(self):
        from gavel.chain import GovernanceChain
        from gavel.request_id import RequestIDMiddleware

        captured: dict = {}
        app = FastAPI()
        app.add_middleware(RequestIDMiddleware)

        @app.post("/make-chain")
        async def make_chain():
            chain = GovernanceChain()
            event = chain.append(
                EventType.INBOUND_INTENT, "agent:x", "proposer"
            )
            captured["request_id"] = event.request_id
            return {"event_rid": event.request_id}

        client = TestClient(app)
        r = client.post("/make-chain", headers={"X-Request-ID": "http-chain-1"})
        assert r.json()["event_rid"] == "http-chain-1"
        assert captured["request_id"] == "http-chain-1"


class TestEventBusPropagation:
    def test_event_defaults_request_id_from_context(self):
        token = set_request_id("bus-rid-xyz")
        try:
            event = DashboardEvent(event_type="action")
        finally:
            request_id_var.reset(token)
        assert event.request_id == "bus-rid-xyz"

    def test_event_explicit_override(self):
        token = set_request_id("ctx-rid")
        try:
            event = DashboardEvent(event_type="action", request_id="override")
        finally:
            request_id_var.reset(token)
        assert event.request_id == "override"

    def test_event_none_outside_context(self):
        event = DashboardEvent(event_type="action")
        assert event.request_id is None

    def test_bus_subscriber_sees_request_id_from_request(self):
        bus = EventBus()
        app = FastAPI()
        app.add_middleware(RequestIDMiddleware)

        received: list[DashboardEvent] = []

        @app.post("/emit")
        async def emit():
            event = DashboardEvent(event_type="action", agent_id="a")
            await bus.publish(event)
            return {"ok": True}

        async def run() -> DashboardEvent | None:
            sub_task_event: asyncio.Event = asyncio.Event()
            found: dict = {}

            async def listener():
                async for evt in bus.subscribe():
                    found["evt"] = evt
                    sub_task_event.set()
                    break

            listener_task = asyncio.create_task(listener())
            await asyncio.sleep(0.05)

            client = TestClient(app)
            client.post("/emit", headers={"X-Request-ID": "bus-http-7"})

            await asyncio.wait_for(sub_task_event.wait(), timeout=2.0)
            listener_task.cancel()
            return found.get("evt")

        evt = asyncio.run(run())
        assert evt is not None
        received.append(evt)
        assert received[0].request_id == "bus-http-7"
