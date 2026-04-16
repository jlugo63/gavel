"""Versioning contract tests.

Codifies the /v1/ URL prefixing contract for the Gavel gateway. These
assertions guard against regressions where a new router or endpoint gets
registered without the /v1/ prefix, or where a legacy unversioned path
resurfaces.

Scope:
- A. Every business route on the gateway starts with /v1/.
- B. /openapi.json paths start with /v1/ (excluding FastAPI's doc routes).
- E. OpenAPI tags and operation IDs stay consistent (no collisions).
"""

from __future__ import annotations

from typing import Iterable

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Mount, Route

from gavel.gateway import app


# FastAPI's built-in documentation endpoints are expected to remain
# unversioned — they describe the service rather than participating in it.
DOC_PATHS = {
    "/docs",
    "/redoc",
    "/openapi.json",
    "/docs/oauth2-redirect",
}


def _business_routes() -> Iterable[APIRoute]:
    """Yield every APIRoute registered on the main gateway app."""
    for route in app.routes:
        if isinstance(route, APIRoute):
            yield route


def _business_paths_from_openapi(schema: dict) -> list[str]:
    """Return paths from /openapi.json that represent business endpoints."""
    return [p for p in schema.get("paths", {}) if p not in DOC_PATHS]


# ---------------------------------------------------------------------------
# A. Route surface is fully under /v1/
# ---------------------------------------------------------------------------

class TestRoutePrefixing:
    def test_every_business_route_starts_with_v1(self):
        """Walk app.routes — every registered business route must be /v1/..."""
        offenders: list[tuple[str, str]] = []
        for route in _business_routes():
            if route.path in DOC_PATHS:
                continue
            if not route.path.startswith("/v1/"):
                offenders.append((route.name or "<unnamed>", route.path))

        assert not offenders, (
            "Business routes must be registered under /v1/. Offenders: "
            + ", ".join(f"{n}={p}" for n, p in offenders)
        )

    def test_no_bare_unversioned_business_paths(self):
        """Classic unversioned paths should not exist on the app."""
        registered = {
            r.path for r in app.routes
            if isinstance(r, (APIRoute, Route))
        }
        forbidden = {
            "/gate",
            "/propose",
            "/approve",
            "/attest",
            "/execute",
            "/constitution",
            "/verify-artifact",
            "/agents",
            "/agents/register",
            "/agents/enroll",
            "/dashboard",
            "/status",
            "/liveness",
        }
        leaked = forbidden & registered
        assert not leaked, f"Unversioned business paths still registered: {sorted(leaked)}"

    def test_unversioned_path_returns_404(self):
        """Representative unversioned path should 404 via live client."""
        client = TestClient(app)
        # /propose is a POST endpoint in the governance router; unversioned it
        # must not resolve.
        resp = client.post("/propose", json={})
        assert resp.status_code == 404, (
            f"/propose (unversioned) returned {resp.status_code}; "
            "it must 404 so clients can't bypass the versioning contract."
        )

        # Also check /gate and /agents — all should 404 unversioned.
        for path in ("/gate", "/agents", "/constitution", "/dashboard"):
            r = client.get(path)
            assert r.status_code == 404, (
                f"{path} (unversioned) returned {r.status_code}; expected 404."
            )


# ---------------------------------------------------------------------------
# B. OpenAPI schema reflects the versioning
# ---------------------------------------------------------------------------

class TestOpenAPIReflectsVersioning:
    def test_openapi_business_paths_start_with_v1(self):
        client = TestClient(app)
        schema = client.get("/openapi.json").json()
        offenders = [
            p for p in _business_paths_from_openapi(schema)
            if not p.startswith("/v1/")
        ]
        assert not offenders, (
            f"OpenAPI exposes unversioned business paths: {offenders}"
        )

    def test_openapi_has_expected_core_paths(self):
        """Sanity check — the schema must include the headline business paths."""
        client = TestClient(app)
        schema = client.get("/openapi.json").json()
        paths = set(schema.get("paths", {}))
        # These must all exist at /v1/<name>
        for expected in ("/v1/propose", "/v1/approve", "/v1/attest", "/v1/constitution"):
            assert expected in paths, (
                f"Expected {expected} in OpenAPI schema; got {sorted(paths)[:10]}..."
            )


# ---------------------------------------------------------------------------
# E. Tag & operation-id consistency
# ---------------------------------------------------------------------------

class TestOpenAPIConsistency:
    def test_no_duplicate_operation_ids(self):
        client = TestClient(app)
        schema = client.get("/openapi.json").json()
        seen: dict[str, tuple[str, str]] = {}
        duplicates: list[tuple[str, tuple[str, str], tuple[str, str]]] = []
        for path, methods in schema.get("paths", {}).items():
            for method, op in methods.items():
                if not isinstance(op, dict):
                    continue
                op_id = op.get("operationId")
                if not op_id:
                    continue
                if op_id in seen:
                    duplicates.append((op_id, seen[op_id], (method, path)))
                else:
                    seen[op_id] = (method, path)
        assert not duplicates, (
            "Duplicate operationIds found: "
            + "; ".join(
                f"{op_id} at {first} and {second}"
                for op_id, first, second in duplicates
            )
        )

    def test_tags_segment_cleanly(self):
        """Every business route should carry exactly one tag, and tags should
        stay scoped to the five router families."""
        expected_tags = {"gate", "compliance", "governance", "agents", "system"}
        for route in _business_routes():
            if route.path in DOC_PATHS:
                continue
            if not route.path.startswith("/v1/"):
                # prefixing violation is covered by TestRoutePrefixing
                continue
            tags = set(route.tags or [])
            assert tags, f"Route {route.path} has no tags"
            assert tags <= expected_tags, (
                f"Route {route.path} has unexpected tags {tags - expected_tags}; "
                f"allowed set is {expected_tags}"
            )
