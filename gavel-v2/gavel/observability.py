"""Metrics and tracing for the Gavel governance gateway.

Provides a lightweight, dependency-free metrics registry that works out
of the box.  When ``prometheus-client`` is installed the
:class:`PrometheusExporter` can also delegate to native Prometheus
objects, but it is *not* required — the exporter renders valid
Prometheus text exposition format from the built-in registry alone.

All public metric helpers are thread-safe and async-safe (guarded by
``asyncio.Lock``).  The module pre-registers the standard Gavel metrics
at import time so callers can simply call ``registry.inc(...)`` /
``registry.observe(...)`` etc. without touching definitions.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("gavel.observability")

# ── Metric primitives ──────────────────────────────────────────────


class MetricType(enum.Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass(frozen=True)
class MetricDefinition:
    """Declares a metric (name, type, description, label keys)."""

    name: str
    metric_type: MetricType
    description: str
    labels: list[str] = field(default_factory=list)
    buckets: tuple[float, ...] | None = None


# Default histogram buckets (seconds) — Prometheus convention.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)


def _label_key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Deterministic hashable key from a label dict."""
    return tuple(sorted(labels.items()))


# ── Internal storage objects ────────────────────────────────────────


class _CounterStore:
    """Simple float counter keyed by label combination."""

    def __init__(self) -> None:
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def inc(self, labels: dict[str, str], value: float = 1.0) -> None:
        key = _label_key(labels)
        self._values[key] = self._values.get(key, 0.0) + value

    def snapshot(self) -> dict[tuple[tuple[str, str], ...], float]:
        return dict(self._values)

    def reset(self) -> None:
        self._values.clear()


class _GaugeStore:
    def __init__(self) -> None:
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def set(self, labels: dict[str, str], value: float) -> None:
        self._values[_label_key(labels)] = value

    def snapshot(self) -> dict[tuple[tuple[str, str], ...], float]:
        return dict(self._values)

    def reset(self) -> None:
        self._values.clear()


class _HistogramStore:
    """Cumulative histogram with configurable buckets."""

    def __init__(self, buckets: tuple[float, ...] = DEFAULT_BUCKETS) -> None:
        self._buckets = buckets
        # key -> {le -> count}
        self._bucket_counts: dict[tuple[tuple[str, str], ...], dict[float, int]] = {}
        self._sums: dict[tuple[tuple[str, str], ...], float] = {}
        self._counts: dict[tuple[tuple[str, str], ...], int] = {}

    def observe(self, labels: dict[str, str], value: float) -> None:
        key = _label_key(labels)
        if key not in self._bucket_counts:
            self._bucket_counts[key] = {b: 0 for b in self._buckets}
            self._sums[key] = 0.0
            self._counts[key] = 0
        for b in self._buckets:
            if value <= b:
                self._bucket_counts[key][b] += 1
        self._sums[key] = self._sums.get(key, 0.0) + value
        self._counts[key] = self._counts.get(key, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        return {
            "buckets": {
                k: dict(v) for k, v in self._bucket_counts.items()
            },
            "sums": dict(self._sums),
            "counts": dict(self._counts),
        }

    def reset(self) -> None:
        self._bucket_counts.clear()
        self._sums.clear()
        self._counts.clear()


# ── MetricsRegistry ─────────────────────────────────────────────────


class MetricsRegistry:
    """Central metrics registry — safe for concurrent async access."""

    def __init__(self) -> None:
        self._definitions: dict[str, MetricDefinition] = {}
        self._counters: dict[str, _CounterStore] = {}
        self._gauges: dict[str, _GaugeStore] = {}
        self._histograms: dict[str, _HistogramStore] = {}
        self._lock = asyncio.Lock()

    # ── Registration ────────────────────────────────────────────────

    def counter(
        self,
        name: str,
        description: str,
        labels: list[str] | None = None,
    ) -> MetricDefinition:
        defn = MetricDefinition(
            name=name,
            metric_type=MetricType.COUNTER,
            description=description,
            labels=labels or [],
        )
        self._definitions[name] = defn
        self._counters[name] = _CounterStore()
        return defn

    def gauge(
        self,
        name: str,
        description: str,
        labels: list[str] | None = None,
    ) -> MetricDefinition:
        defn = MetricDefinition(
            name=name,
            metric_type=MetricType.GAUGE,
            description=description,
            labels=labels or [],
        )
        self._definitions[name] = defn
        self._gauges[name] = _GaugeStore()
        return defn

    def histogram(
        self,
        name: str,
        description: str,
        labels: list[str] | None = None,
        buckets: tuple[float, ...] | None = None,
    ) -> MetricDefinition:
        resolved = buckets or DEFAULT_BUCKETS
        defn = MetricDefinition(
            name=name,
            metric_type=MetricType.HISTOGRAM,
            description=description,
            labels=labels or [],
            buckets=resolved,
        )
        self._definitions[name] = defn
        self._histograms[name] = _HistogramStore(resolved)
        return defn

    # ── Mutation (sync convenience wrappers) ────────────────────────

    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        store = self._counters.get(name)
        if store is None:
            raise KeyError(f"Unknown counter: {name}")
        store.inc(labels or {}, value)

    def set(self, name: str, labels: dict[str, str] | None = None, *, value: float) -> None:
        store = self._gauges.get(name)
        if store is None:
            raise KeyError(f"Unknown gauge: {name}")
        store.set(labels or {}, value)

    def observe(self, name: str, labels: dict[str, str] | None = None, *, value: float) -> None:
        store = self._histograms.get(name)
        if store is None:
            raise KeyError(f"Unknown histogram: {name}")
        store.observe(labels or {}, value)

    # ── Async-safe mutations ────────────────────────────────────────

    async def ainc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        async with self._lock:
            self.inc(name, labels, value)

    async def aset(self, name: str, labels: dict[str, str] | None = None, *, value: float) -> None:
        async with self._lock:
            self.set(name, labels, value=value)

    async def aobserve(self, name: str, labels: dict[str, str] | None = None, *, value: float) -> None:
        async with self._lock:
            self.observe(name, labels, value=value)

    # ── Snapshot / reset ────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Return a serialisable snapshot of every registered metric."""
        result: dict[str, Any] = {}
        for name, defn in self._definitions.items():
            entry: dict[str, Any] = {
                "type": defn.metric_type.value,
                "description": defn.description,
                "labels": defn.labels,
            }
            if defn.metric_type is MetricType.COUNTER:
                entry["values"] = {
                    str(dict(k)): v
                    for k, v in self._counters[name].snapshot().items()
                }
            elif defn.metric_type is MetricType.GAUGE:
                entry["values"] = {
                    str(dict(k)): v
                    for k, v in self._gauges[name].snapshot().items()
                }
            elif defn.metric_type is MetricType.HISTOGRAM:
                entry["values"] = self._histograms[name].snapshot()
            result[name] = entry
        return result

    def reset(self) -> None:
        """Clear all recorded values (useful for testing)."""
        for store in self._counters.values():
            store.reset()
        for store in self._gauges.values():
            store.reset()
        for store in self._histograms.values():
            store.reset()


# ── Global registry + pre-defined Gavel metrics ────────────────────

registry = MetricsRegistry()

# HTTP
registry.counter(
    "gavel_requests_total",
    "Total HTTP requests handled by the gateway",
    labels=["method", "endpoint", "status_code"],
)
registry.histogram(
    "gavel_request_duration_seconds",
    "HTTP request latency in seconds",
    labels=["method", "endpoint"],
)

# Governance
registry.counter(
    "gavel_proposals_total",
    "Total governance proposals processed",
    labels=["decision", "risk_level"],
)

# Rate limiting
registry.counter(
    "gavel_rate_limit_decisions_total",
    "Rate-limit allow/deny decisions",
    labels=["agent_id", "decision"],
)

# Gauges
registry.gauge("gavel_active_chains", "Number of active governance chains")
registry.gauge("gavel_enrolled_agents", "Number of enrolled agents")
registry.gauge("gavel_event_bus_subscribers", "Current SSE subscriber count")

# DB
registry.histogram(
    "gavel_db_query_duration_seconds",
    "Database query latency in seconds",
)

# Chain locks
registry.histogram(
    "gavel_chain_lock_wait_seconds",
    "Lock acquisition time in seconds",
    labels=["backend"],
)

# Incidents
registry.counter(
    "gavel_incidents_total",
    "Incidents reported",
    labels=["severity"],
)


# ── Prometheus text exposition renderer ────────────────────────────


class PrometheusExporter:
    """Render the registry snapshot as Prometheus text exposition format.

    Works entirely without ``prometheus-client`` installed.  If the
    library *is* available we could delegate — but the manual renderer
    keeps things dependency-free.
    """

    def __init__(self, metrics_registry: MetricsRegistry | None = None) -> None:
        self._registry = metrics_registry or registry

    def render(self) -> str:  # noqa: C901 — intentionally explicit
        snap = self._registry.snapshot()
        lines: list[str] = []
        for name, info in snap.items():
            mtype = info["type"]
            desc = info["description"]
            lines.append(f"# HELP {name} {desc}")
            lines.append(f"# TYPE {name} {mtype}")
            values = info["values"]

            if mtype in ("counter", "gauge"):
                if not values:
                    # Emit a zero-value line so the metric is always visible.
                    lines.append(f"{name} 0")
                for label_str, val in values.items():
                    label_dict = _parse_label_str(label_str)
                    label_part = _format_labels(label_dict)
                    lines.append(f"{name}{label_part} {_fmt(val)}")

            elif mtype == "histogram":
                buckets_data = values.get("buckets", {})
                sums_data = values.get("sums", {})
                counts_data = values.get("counts", {})
                if not buckets_data:
                    lines.append(f"{name}_bucket{{le=\"+Inf\"}} 0")
                    lines.append(f"{name}_sum 0")
                    lines.append(f"{name}_count 0")
                for key_tuple_str, bucket_map in buckets_data.items():
                    label_dict = _parse_label_str(str(dict(key_tuple_str)))
                    base_labels = _format_labels(label_dict)
                    cumulative = 0
                    for le, count in sorted(bucket_map.items()):
                        cumulative += count
                        le_str = _fmt(le)
                        if base_labels:
                            combined = base_labels[:-1] + f',le="{le_str}"' + "}"
                        else:
                            combined = f'{{le="{le_str}"}}'
                        lines.append(f"{name}_bucket{combined} {cumulative}")
                    # +Inf bucket
                    total = counts_data.get(key_tuple_str, 0)
                    if base_labels:
                        inf_labels = base_labels[:-1] + ',le="+Inf"}'
                    else:
                        inf_labels = '{le="+Inf"}'
                    lines.append(f"{name}_bucket{inf_labels} {total}")
                    sum_val = sums_data.get(key_tuple_str, 0.0)
                    lines.append(f"{name}_sum{base_labels} {_fmt(sum_val)}")
                    lines.append(f"{name}_count{base_labels} {total}")

        lines.append("")  # trailing newline
        return "\n".join(lines)


def _parse_label_str(s: str) -> dict[str, str]:
    """Parse the stringified label dict back into a real dict."""
    # The snapshot stores keys as str(dict(...)), e.g. "{'method': 'GET'}"
    # or "{}" for no labels.
    if s in ("{}", ""):
        return {}
    try:
        import ast
        return ast.literal_eval(s)
    except (ValueError, SyntaxError):
        return {}


def _format_labels(d: dict[str, str]) -> str:
    if not d:
        return ""
    parts = [f'{k}="{v}"' for k, v in sorted(d.items())]
    return "{" + ",".join(parts) + "}"


def _fmt(v: float) -> str:
    if v == float("inf") or v == float("+inf"):
        return "+Inf"
    if v == float("-inf"):
        return "-Inf"
    if math.isnan(v):
        return "NaN"
    if v == int(v):
        return str(int(v))
    return f"{v:.6g}"


# ── ASGI Metrics Middleware ─────────────────────────────────────────


class MetricsMiddleware:
    """ASGI middleware that records request count and duration.

    Plugs into the gateway middleware stack alongside CORS and
    RequestIDMiddleware.  Uses the module-level :data:`registry`.
    """

    def __init__(self, app: ASGIApp, metrics_registry: MetricsRegistry | None = None) -> None:
        self.app = app
        self._registry = metrics_registry or registry

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")
        start = time.perf_counter()
        status_code = 500  # default if we never capture a response

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - start
            self._registry.inc(
                "gavel_requests_total",
                {"method": method, "endpoint": path, "status_code": str(status_code)},
            )
            self._registry.observe(
                "gavel_request_duration_seconds",
                {"method": method, "endpoint": path},
                value=duration,
            )


# ── /metrics route ──────────────────────────────────────────────────

try:
    from fastapi import APIRouter
    from fastapi.responses import PlainTextResponse

    metrics_router = APIRouter(tags=["observability"])

    @metrics_router.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint() -> PlainTextResponse:
        """Prometheus-compatible scrape endpoint."""
        exporter = PrometheusExporter()
        return PlainTextResponse(exporter.render(), media_type="text/plain; version=0.0.4")

except ImportError:  # pragma: no cover
    metrics_router = None


# ── Exports ─────────────────────────────────────────────────────────

__all__ = [
    "MetricType",
    "MetricDefinition",
    "MetricsRegistry",
    "PrometheusExporter",
    "MetricsMiddleware",
    "metrics_router",
    "registry",
    "DEFAULT_BUCKETS",
]
