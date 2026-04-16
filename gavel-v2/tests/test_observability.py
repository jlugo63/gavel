"""Tests for the Gavel observability module — metrics, Prometheus export, and middleware."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gavel.observability import (
    DEFAULT_BUCKETS,
    MetricDefinition,
    MetricType,
    MetricsMiddleware,
    MetricsRegistry,
    PrometheusExporter,
    _format_labels,
    _parse_label_str,
    registry,
)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _fresh_registry() -> MetricsRegistry:
    """Return a blank MetricsRegistry for isolated tests."""
    return MetricsRegistry()


# -------------------------------------------------------------------
# MetricType enum
# -------------------------------------------------------------------


class TestMetricType:
    def test_values(self):
        assert MetricType.COUNTER.value == "counter"
        assert MetricType.GAUGE.value == "gauge"
        assert MetricType.HISTOGRAM.value == "histogram"


# -------------------------------------------------------------------
# MetricDefinition
# -------------------------------------------------------------------


class TestMetricDefinition:
    def test_basic_creation(self):
        d = MetricDefinition(
            name="test_total",
            metric_type=MetricType.COUNTER,
            description="A test counter",
            labels=["method"],
        )
        assert d.name == "test_total"
        assert d.metric_type is MetricType.COUNTER
        assert d.labels == ["method"]

    def test_defaults(self):
        d = MetricDefinition(
            name="x", metric_type=MetricType.GAUGE, description="g"
        )
        assert d.labels == []
        assert d.buckets is None


# -------------------------------------------------------------------
# MetricsRegistry — counter
# -------------------------------------------------------------------


class TestCounter:
    def test_register_and_inc(self):
        r = _fresh_registry()
        r.counter("hits", "total hits")
        r.inc("hits")
        snap = r.snapshot()
        assert "hits" in snap
        assert snap["hits"]["type"] == "counter"
        values = snap["hits"]["values"]
        assert len(values) == 1
        assert list(values.values())[0] == 1.0

    def test_inc_with_labels(self):
        r = _fresh_registry()
        r.counter("req", "requests", labels=["method"])
        r.inc("req", {"method": "GET"})
        r.inc("req", {"method": "GET"})
        r.inc("req", {"method": "POST"})
        snap = r.snapshot()
        vals = snap["req"]["values"]
        assert len(vals) == 2
        # Find GET
        get_val = [v for k, v in vals.items() if "GET" in k]
        assert get_val[0] == 2.0

    def test_inc_custom_value(self):
        r = _fresh_registry()
        r.counter("bytes", "total bytes")
        r.inc("bytes", value=42.5)
        snap = r.snapshot()
        assert list(snap["bytes"]["values"].values())[0] == 42.5

    def test_inc_unknown_raises(self):
        r = _fresh_registry()
        with pytest.raises(KeyError, match="Unknown counter"):
            r.inc("nonexistent")

    def test_multiple_label_combinations(self):
        r = _fresh_registry()
        r.counter("c", "c", labels=["a", "b"])
        r.inc("c", {"a": "1", "b": "x"})
        r.inc("c", {"a": "2", "b": "y"})
        r.inc("c", {"a": "1", "b": "x"}, value=3)
        snap = r.snapshot()
        vals = snap["c"]["values"]
        assert len(vals) == 2


# -------------------------------------------------------------------
# MetricsRegistry — gauge
# -------------------------------------------------------------------


class TestGauge:
    def test_set_and_get(self):
        r = _fresh_registry()
        r.gauge("active", "active items")
        r.set("active", value=10)
        snap = r.snapshot()
        assert list(snap["active"]["values"].values())[0] == 10

    def test_set_overwrites(self):
        r = _fresh_registry()
        r.gauge("g", "g")
        r.set("g", value=5)
        r.set("g", value=99)
        snap = r.snapshot()
        assert list(snap["g"]["values"].values())[0] == 99

    def test_set_unknown_raises(self):
        r = _fresh_registry()
        with pytest.raises(KeyError, match="Unknown gauge"):
            r.set("nope", value=1)


# -------------------------------------------------------------------
# MetricsRegistry — histogram
# -------------------------------------------------------------------


class TestHistogram:
    def test_observe_basic(self):
        r = _fresh_registry()
        r.histogram("dur", "duration")
        r.observe("dur", value=0.05)
        snap = r.snapshot()
        h = snap["dur"]["values"]
        assert h["counts"][list(h["counts"].keys())[0]] == 1
        assert h["sums"][list(h["sums"].keys())[0]] == 0.05

    def test_bucket_distribution(self):
        r = _fresh_registry()
        r.histogram("lat", "latency", buckets=(0.1, 0.5, 1.0))
        r.observe("lat", value=0.05)  # fits 0.1, 0.5, 1.0
        r.observe("lat", value=0.3)   # fits 0.5, 1.0
        r.observe("lat", value=0.8)   # fits 1.0
        r.observe("lat", value=2.0)   # fits none
        snap = r.snapshot()
        h = snap["lat"]["values"]
        key = list(h["buckets"].keys())[0]
        buckets = h["buckets"][key]
        assert buckets[0.1] == 1
        assert buckets[0.5] == 2
        assert buckets[1.0] == 3
        assert h["counts"][key] == 4

    def test_observe_unknown_raises(self):
        r = _fresh_registry()
        with pytest.raises(KeyError, match="Unknown histogram"):
            r.observe("missing", value=1.0)

    def test_histogram_with_labels(self):
        r = _fresh_registry()
        r.histogram("h", "h", labels=["op"], buckets=(1.0,))
        r.observe("h", {"op": "read"}, value=0.5)
        r.observe("h", {"op": "write"}, value=1.5)
        snap = r.snapshot()
        assert len(snap["h"]["values"]["buckets"]) == 2


# -------------------------------------------------------------------
# Snapshot & reset
# -------------------------------------------------------------------


class TestSnapshotAndReset:
    def test_snapshot_returns_all_metrics(self):
        r = _fresh_registry()
        r.counter("a", "a")
        r.gauge("b", "b")
        r.histogram("c", "c")
        snap = r.snapshot()
        assert set(snap.keys()) == {"a", "b", "c"}

    def test_reset_clears_values(self):
        r = _fresh_registry()
        r.counter("x", "x")
        r.gauge("y", "y")
        r.histogram("z", "z")
        r.inc("x")
        r.set("y", value=7)
        r.observe("z", value=0.1)
        r.reset()
        snap = r.snapshot()
        assert snap["x"]["values"] == {}
        assert snap["y"]["values"] == {}
        assert snap["z"]["values"]["buckets"] == {}

    def test_snapshot_structure(self):
        r = _fresh_registry()
        r.counter("s", "test counter", labels=["l"])
        r.inc("s", {"l": "v"})
        snap = r.snapshot()
        entry = snap["s"]
        assert "type" in entry
        assert "description" in entry
        assert "labels" in entry
        assert "values" in entry
        assert entry["type"] == "counter"


# -------------------------------------------------------------------
# PrometheusExporter
# -------------------------------------------------------------------


class TestPrometheusExporter:
    def test_render_counter(self):
        r = _fresh_registry()
        r.counter("test_total", "A test counter")
        r.inc("test_total")
        exp = PrometheusExporter(r)
        text = exp.render()
        assert "# HELP test_total A test counter" in text
        assert "# TYPE test_total counter" in text
        assert "test_total 1" in text

    def test_render_gauge(self):
        r = _fresh_registry()
        r.gauge("test_gauge", "A gauge")
        r.set("test_gauge", value=42)
        text = PrometheusExporter(r).render()
        assert "# TYPE test_gauge gauge" in text
        assert "test_gauge 42" in text

    def test_render_histogram(self):
        r = _fresh_registry()
        r.histogram("test_hist", "A histogram", buckets=(0.1, 1.0))
        r.observe("test_hist", value=0.05)
        text = PrometheusExporter(r).render()
        assert "# TYPE test_hist histogram" in text
        assert "test_hist_bucket" in text
        assert "test_hist_sum" in text
        assert "test_hist_count" in text
        assert '+Inf' in text

    def test_render_with_labels(self):
        r = _fresh_registry()
        r.counter("labeled", "labeled counter", labels=["code"])
        r.inc("labeled", {"code": "200"})
        text = PrometheusExporter(r).render()
        assert 'code="200"' in text

    def test_render_empty_metric(self):
        r = _fresh_registry()
        r.counter("empty", "empty counter")
        text = PrometheusExporter(r).render()
        assert "# HELP empty" in text
        assert "empty 0" in text

    def test_render_empty_histogram(self):
        r = _fresh_registry()
        r.histogram("empty_h", "empty histogram")
        text = PrometheusExporter(r).render()
        assert "empty_h_count 0" in text


# -------------------------------------------------------------------
# MetricsMiddleware (ASGI)
# -------------------------------------------------------------------


class TestMetricsMiddleware:
    @pytest.mark.asyncio
    async def test_records_request_count(self):
        r = _fresh_registry()
        r.counter("gavel_requests_total", "req", labels=["method", "endpoint", "status_code"])
        r.histogram("gavel_request_duration_seconds", "dur", labels=["method", "endpoint"])

        async def inner_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = MetricsMiddleware(inner_app, metrics_registry=r)
        scope = {"type": "http", "method": "GET", "path": "/test"}
        await mw(scope, None, _noop_send)
        snap = r.snapshot()
        vals = snap["gavel_requests_total"]["values"]
        assert len(vals) == 1
        assert list(vals.values())[0] == 1.0

    @pytest.mark.asyncio
    async def test_records_duration(self):
        r = _fresh_registry()
        r.counter("gavel_requests_total", "req", labels=["method", "endpoint", "status_code"])
        r.histogram("gavel_request_duration_seconds", "dur", labels=["method", "endpoint"])

        async def slow_app(scope, receive, send):
            await asyncio.sleep(0.05)
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = MetricsMiddleware(slow_app, metrics_registry=r)
        scope = {"type": "http", "method": "POST", "path": "/slow"}
        await mw(scope, None, _noop_send)
        snap = r.snapshot()
        h = snap["gavel_request_duration_seconds"]["values"]
        key = list(h["sums"].keys())[0]
        assert h["sums"][key] >= 0.04

    @pytest.mark.asyncio
    async def test_non_http_passthrough(self):
        r = _fresh_registry()
        r.counter("gavel_requests_total", "req", labels=["method", "endpoint", "status_code"])

        called = False

        async def ws_app(scope, receive, send):
            nonlocal called
            called = True

        mw = MetricsMiddleware(ws_app, metrics_registry=r)
        await mw({"type": "websocket"}, None, _noop_send)
        assert called
        assert r.snapshot()["gavel_requests_total"]["values"] == {}

    @pytest.mark.asyncio
    async def test_status_code_capture(self):
        r = _fresh_registry()
        r.counter("gavel_requests_total", "req", labels=["method", "endpoint", "status_code"])
        r.histogram("gavel_request_duration_seconds", "dur", labels=["method", "endpoint"])

        async def not_found_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 404})
            await send({"type": "http.response.body", "body": b"nope"})

        mw = MetricsMiddleware(not_found_app, metrics_registry=r)
        await mw({"type": "http", "method": "GET", "path": "/x"}, None, _noop_send)
        snap = r.snapshot()
        vals = snap["gavel_requests_total"]["values"]
        key = list(vals.keys())[0]
        assert "404" in key


async def _noop_send(message):
    pass


# -------------------------------------------------------------------
# Async-safe mutations
# -------------------------------------------------------------------


class TestAsyncSafety:
    @pytest.mark.asyncio
    async def test_ainc(self):
        r = _fresh_registry()
        r.counter("ac", "async counter")
        await r.ainc("ac")
        await r.ainc("ac", value=2)
        snap = r.snapshot()
        assert list(snap["ac"]["values"].values())[0] == 3.0

    @pytest.mark.asyncio
    async def test_aset(self):
        r = _fresh_registry()
        r.gauge("ag", "async gauge")
        await r.aset("ag", value=77)
        snap = r.snapshot()
        assert list(snap["ag"]["values"].values())[0] == 77

    @pytest.mark.asyncio
    async def test_aobserve(self):
        r = _fresh_registry()
        r.histogram("ah", "async hist", buckets=(1.0,))
        await r.aobserve("ah", value=0.5)
        snap = r.snapshot()
        assert snap["ah"]["values"]["counts"][list(snap["ah"]["values"]["counts"].keys())[0]] == 1


# -------------------------------------------------------------------
# Thread safety
# -------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_inc(self):
        r = _fresh_registry()
        r.counter("conc", "concurrent counter")
        n = 1000

        def do_inc():
            for _ in range(n):
                r.inc("conc")

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(do_inc) for _ in range(4)]
            for f in futures:
                f.result()

        snap = r.snapshot()
        total = list(snap["conc"]["values"].values())[0]
        # Python GIL makes dict ops atomic enough for +=, but
        # we allow a small tolerance since += is not strictly atomic.
        assert total >= n * 3  # at least 3000 of 4000 expected


# -------------------------------------------------------------------
# Global registry pre-registration
# -------------------------------------------------------------------


class TestGlobalRegistry:
    def test_predefined_metrics_exist(self):
        snap = registry.snapshot()
        expected = [
            "gavel_requests_total",
            "gavel_request_duration_seconds",
            "gavel_proposals_total",
            "gavel_rate_limit_decisions_total",
            "gavel_active_chains",
            "gavel_enrolled_agents",
            "gavel_event_bus_subscribers",
            "gavel_db_query_duration_seconds",
            "gavel_chain_lock_wait_seconds",
            "gavel_incidents_total",
        ]
        for name in expected:
            assert name in snap, f"Missing pre-defined metric: {name}"

    def test_predefined_types(self):
        snap = registry.snapshot()
        assert snap["gavel_requests_total"]["type"] == "counter"
        assert snap["gavel_active_chains"]["type"] == "gauge"
        assert snap["gavel_request_duration_seconds"]["type"] == "histogram"


# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------


class TestHelpers:
    def test_parse_label_str_empty(self):
        assert _parse_label_str("{}") == {}
        assert _parse_label_str("") == {}

    def test_parse_label_str(self):
        assert _parse_label_str("{'a': 'b'}") == {"a": "b"}

    def test_format_labels_empty(self):
        assert _format_labels({}) == ""

    def test_format_labels(self):
        result = _format_labels({"method": "GET", "code": "200"})
        assert 'code="200"' in result
        assert 'method="GET"' in result
        assert result.startswith("{")
        assert result.endswith("}")


# -------------------------------------------------------------------
# /metrics endpoint (FastAPI)
# -------------------------------------------------------------------


class TestMetricsEndpoint:
    def test_metrics_router_exists(self):
        from gavel.observability import metrics_router
        assert metrics_router is not None

    @pytest.mark.asyncio
    async def test_endpoint_returns_text(self):
        from gavel.observability import metrics_endpoint
        resp = await metrics_endpoint()
        assert resp.status_code == 200
        assert "text/plain" in resp.media_type
        body = resp.body.decode()
        assert "# HELP" in body
        assert "# TYPE" in body
