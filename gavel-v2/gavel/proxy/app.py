"""
Gavel Network Enforcement Proxy
================================

Transparent HTTP/HTTPS reverse proxy that intercepts AI API traffic and
enforces constitutional governance.  Requests to known AI API domains
(OpenAI, Anthropic, Cohere, Gemini, Ollama, Docker, Copilot, JetBrains,
Cursor, Warp) are blocked unless they carry a valid ``X-Gavel-Token``
header that can be validated against the main Gavel control plane.

Every enforcement decision -- ALLOWED or BLOCKED -- is recorded in an
append-only, hash-chained JSONL ledger identical in spirit to the
governance chains in ``gavel.chain``.

Architecture::

    [AI Agent] ---> [:8200 Gavel Proxy] ---> [api.openai.com / ...]
                         |
                    Token check
                    Ledger log
                         |
                    403 if invalid

    [Docker Client] ---> [:8201 Docker Socket Proxy] ---> [docker.sock]

Usage::

    python -m gavel.proxy                        # default-allow, port 8200
    python -m gavel.proxy --default-deny         # block ALL unless tokened
    python -m gavel.proxy --docker               # also proxy Docker socket
    python -m gavel.proxy --config domains.yaml  # custom domain list
    uvicorn gavel.proxy:app                      # ASGI import

Part of Gavel -- Constitutional governance for AI agents (EU AI Act).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from gavel.proxy.config import (
    DOCKER_PROXY_PORT,
    PROXY_PORT,
    TOKEN_HEADER,
    ProxyConfig,
)
from gavel.proxy.domain import DomainMatcher
from gavel.proxy.enforcement import (
    ProxyEnforcementAction as EnforcementAction,
    EnforcementLedger,
    LedgerEntry,
)
from gavel.proxy.token_validator import TokenValidator
from gavel.request_id import RequestIDMiddleware

# ---------------------------------------------------------------------------
# Logging -- mirrors other gavel modules (single getLogger, no handler setup
# so the root/app-level config controls output).
# ---------------------------------------------------------------------------

log = logging.getLogger("gavel.proxy")


# ---------------------------------------------------------------------------
# Helpers (module-private)
# ---------------------------------------------------------------------------


def _should_use_tls(host: str) -> bool:
    """Determine whether to use HTTPS for the upstream connection."""
    host_lower = host.lower()
    if any(local in host_lower for local in ("localhost", "127.0.0.1", "0.0.0.0")):
        return False
    return True


def _extract_token_id(token: str | None) -> str:
    """Extract a short identifier from a token for logging (never log full token)."""
    if not token:
        return ""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Proxy application factory
# ---------------------------------------------------------------------------


def create_proxy_app(config: ProxyConfig | None = None) -> FastAPI:
    """Create and configure the Gavel enforcement proxy FastAPI application."""

    cfg = config or ProxyConfig()

    matcher = DomainMatcher(cfg.effective_domains())
    ledger = EnforcementLedger(path=cfg.ledger_path)
    validator = TokenValidator(cfg)

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        mode = "DEFAULT-DENY" if cfg.default_deny else "DEFAULT-ALLOW (AI domains enforced)"
        log.info("Gavel Enforcement Proxy starting on :%d -- mode: %s", cfg.port, mode)
        yield
        await validator.close()
        log.info("Gavel Enforcement Proxy shut down.")

    app = FastAPI(
        title="Gavel Network Enforcement Proxy",
        version="0.1.0",
        description="Constitutional governance enforcement layer for AI agent traffic.",
        lifespan=lifespan,
    )

    app.add_middleware(RequestIDMiddleware)

    # -- health -------------------------------------------------------------

    @app.get("/healthz")
    async def health() -> dict:
        return {
            "status": "ok",
            "service": "gavel-enforcement-proxy",
            "mode": "default-deny" if cfg.default_deny else "default-allow",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # -- ledger integrity endpoint ------------------------------------------

    @app.get("/api/v1/ledger/verify")
    async def verify_ledger() -> dict:
        valid, count, errors = await ledger.verify_integrity()
        return {"valid": valid, "entries": count, "errors": errors}

    # -- ledger stats -------------------------------------------------------

    @app.get("/api/v1/ledger/stats")
    async def ledger_stats() -> dict:
        allowed = 0
        blocked = 0
        if ledger._path.exists():
            with open(ledger._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("action") == "ALLOWED":
                            allowed += 1
                        elif data.get("action") == "BLOCKED":
                            blocked += 1
                    except (json.JSONDecodeError, KeyError):
                        pass  # Malformed ledger line — skip
        return {
            "total": allowed + blocked,
            "allowed": allowed,
            "blocked": blocked,
            "ledger_path": str(ledger._path),
        }

    # -- main catch-all proxy route -----------------------------------------

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    )
    async def proxy_handler(request: Request, path: str) -> Response:
        """Intercept requests, enforce token checks on AI API domains."""

        target_host = (
            request.headers.get("X-Forwarded-Host")
            or request.headers.get("Host")
            or ""
        )

        if target_host.startswith("localhost") or target_host.startswith("127.0.0.1"):
            target_host = request.headers.get("X-Gavel-Target", target_host)

        is_ai, label = matcher.match(target_host)
        requires_token = is_ai or cfg.default_deny

        if not requires_token:
            return await _forward_request(request, target_host, path)

        # -- Token enforcement --
        token = request.headers.get(TOKEN_HEADER)
        valid, agent_id, reason = await validator.validate(token)

        if valid:
            await ledger.append(LedgerEntry(
                source_agent=agent_id,
                destination_domain=target_host,
                method=request.method,
                path=f"/{path}",
                action=EnforcementAction.ALLOWED,
                reason=reason,
                token_id=_extract_token_id(token),
            ))
            return await _forward_request(request, target_host, path)

        await ledger.append(LedgerEntry(
            source_agent=agent_id,
            destination_domain=target_host,
            method=request.method,
            path=f"/{path}",
            action=EnforcementAction.BLOCKED,
            reason=reason,
            token_id=_extract_token_id(token),
        ))
        return JSONResponse(
            status_code=403,
            content={
                "error": "gavel_enforcement_block",
                "message": (
                    f"Request to {label or target_host} blocked by Gavel enforcement proxy. "
                    f"Reason: {reason}. "
                    "Provide a valid X-Gavel-Token header to proceed."
                ),
                "domain": target_host,
                "reason": reason,
                "enforcement": "constitutional",
                "remediation": (
                    "Register your agent at the Gavel control plane and obtain "
                    "a governance token before making AI API calls."
                ),
            },
        )

    # -- forwarding logic ---------------------------------------------------

    async def _forward_request(
        request: Request, target_host: str, path: str
    ) -> Response:
        """Forward the request to the real destination."""
        scheme = "https" if _should_use_tls(target_host) else "http"
        url = f"{scheme}://{target_host}/{path}"
        if request.url.query:
            url += f"?{request.url.query}"

        headers = dict(request.headers)
        for drop_key in (TOKEN_HEADER.lower(), "x-gavel-target", "host"):
            headers.pop(drop_key, None)
        headers["Host"] = target_host.split(":")[0]

        body = await request.body()

        async with httpx.AsyncClient(
            timeout=30.0, follow_redirects=True, verify=True
        ) as client:
            try:
                upstream_resp = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body if body else None,
                )
            except httpx.ConnectError:
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": "upstream_unreachable",
                        "message": f"Could not connect to {target_host}",
                    },
                )
            except httpx.TimeoutException:
                return JSONResponse(
                    status_code=504,
                    content={
                        "error": "upstream_timeout",
                        "message": f"Upstream {target_host} timed out",
                    },
                )

        response_headers = dict(upstream_resp.headers)
        for hop in ("transfer-encoding", "connection", "keep-alive"):
            response_headers.pop(hop, None)
        response_headers["X-Gavel-Enforced"] = "true"

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=response_headers,
        )

    return app


# ---------------------------------------------------------------------------
# Docker socket proxy factory
# ---------------------------------------------------------------------------


def create_docker_proxy_app(config: ProxyConfig | None = None) -> FastAPI:
    """Create a proxy for the Docker socket that enforces Gavel token checks.

    Designed for Docker Gordon and similar AI-powered Docker tools that
    communicate via the Docker Engine API.
    """

    cfg = config or ProxyConfig()
    docker_socket = cfg.docker_socket
    ledger = EnforcementLedger(
        path=cfg.ledger_path.parent / "docker_enforcement_ledger.jsonl"
    )
    validator = TokenValidator(cfg)

    # Dangerous Docker API paths that AI agents should never access ungoverned
    SENSITIVE_PATHS = [
        re.compile(r"^/v[\d.]+/containers/\w+/exec$"),
        re.compile(r"^/v[\d.]+/containers/create$"),
        re.compile(r"^/v[\d.]+/images/create$"),
        re.compile(r"^/v[\d.]+/build$"),
        re.compile(r"^/v[\d.]+/volumes/create$"),
        re.compile(r"^/v[\d.]+/networks/create$"),
        re.compile(r"^/v[\d.]+/secrets/"),
        re.compile(r"^/v[\d.]+/configs/"),
    ]

    READONLY_PATHS = [
        re.compile(r"^/v[\d.]+/containers/json$"),
        re.compile(r"^/v[\d.]+/images/json$"),
        re.compile(r"^/v[\d.]+/info$"),
        re.compile(r"^/v[\d.]+/version$"),
        re.compile(r"^/_ping$"),
    ]

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        socket_exists = Path(docker_socket).exists()
        log.info(
            "Gavel Docker Socket Proxy starting on :%d -- socket=%s (exists=%s)",
            cfg.docker_port, docker_socket, socket_exists,
        )
        yield
        await validator.close()

    app = FastAPI(
        title="Gavel Docker Socket Proxy",
        version="0.1.0",
        description="Enforcement proxy for Docker Engine API -- blocks unregistered AI agents.",
        lifespan=lifespan,
    )

    app.add_middleware(RequestIDMiddleware)

    @app.get("/healthz")
    async def health() -> dict:
        return {
            "status": "ok",
            "service": "gavel-docker-proxy",
            "socket": docker_socket,
            "socket_exists": Path(docker_socket).exists(),
        }

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "HEAD"],
    )
    async def docker_proxy_handler(request: Request, path: str) -> Response:
        """Proxy Docker API requests through the Unix socket with enforcement."""
        request_path = f"/{path}"

        is_sensitive = any(p.match(request_path) for p in SENSITIVE_PATHS)
        is_readonly = any(p.match(request_path) for p in READONLY_PATHS)
        requires_token = is_sensitive or (not is_readonly and request.method != "GET")

        if not requires_token:
            return await _forward_to_socket(request, request_path)

        token = request.headers.get(TOKEN_HEADER)
        valid, agent_id, reason = await validator.validate(token)

        if valid:
            await ledger.append(LedgerEntry(
                source_agent=agent_id,
                destination_domain="docker.sock",
                method=request.method,
                path=request_path,
                action=EnforcementAction.ALLOWED,
                reason=reason,
                token_id=_extract_token_id(token),
            ))
            return await _forward_to_socket(request, request_path)

        await ledger.append(LedgerEntry(
            source_agent=agent_id,
            destination_domain="docker.sock",
            method=request.method,
            path=request_path,
            action=EnforcementAction.BLOCKED,
            reason=reason,
            token_id=_extract_token_id(token),
        ))
        return JSONResponse(
            status_code=403,
            content={
                "error": "gavel_docker_enforcement_block",
                "message": (
                    f"Docker API call to {request_path} blocked by Gavel enforcement. "
                    f"Reason: {reason}. "
                    "Register your agent and provide X-Gavel-Token."
                ),
                "path": request_path,
                "method": request.method,
                "sensitive": is_sensitive,
                "reason": reason,
            },
        )

    async def _forward_to_socket(request: Request, path: str) -> Response:
        """Forward the request to the Docker Unix socket."""
        url = f"http://localhost{path}"
        if request.url.query:
            url += f"?{request.url.query}"

        headers = dict(request.headers)
        for drop_key in (TOKEN_HEADER.lower(), "host"):
            headers.pop(drop_key, None)

        body = await request.body()

        transport = httpx.AsyncHTTPTransport(uds=docker_socket)
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                resp = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body if body else None,
                )
            except (httpx.ConnectError, FileNotFoundError):
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": "docker_socket_unreachable",
                        "message": f"Cannot connect to Docker socket at {docker_socket}",
                    },
                )

        response_headers = dict(resp.headers)
        for hop in ("transfer-encoding", "connection"):
            response_headers.pop(hop, None)
        response_headers["X-Gavel-Docker-Enforced"] = "true"

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=response_headers,
        )

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gavel-proxy",
        description="Gavel Network Enforcement Proxy -- constitutional governance for AI agent traffic.",
    )
    parser.add_argument(
        "--port", type=int, default=PROXY_PORT,
        help=f"HTTP proxy listen port (default: {PROXY_PORT})",
    )
    parser.add_argument(
        "--docker", action="store_true",
        help=f"Also start Docker socket proxy on port {DOCKER_PROXY_PORT}",
    )
    parser.add_argument(
        "--docker-port", type=int, default=DOCKER_PROXY_PORT,
        help=f"Docker proxy listen port (default: {DOCKER_PROXY_PORT})",
    )
    parser.add_argument(
        "--default-deny", action="store_true",
        help="Block ALL traffic unless a valid Gavel token is present",
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="Path to YAML file with AI domain patterns",
    )
    parser.add_argument(
        "--ledger", type=str, default=None,
        help="Path to enforcement ledger file (JSONL)",
    )
    parser.add_argument(
        "--host", type=str, default="0.0.0.0",
        help="Bind address (default: 0.0.0.0)",
    )
    return parser.parse_args(argv)


async def serve(args: argparse.Namespace) -> None:
    """Run the proxy (and optionally Docker proxy) as async servers."""

    cfg = ProxyConfig(
        port=args.port,
        host=args.host,
        default_deny=args.default_deny,
        docker_enabled=args.docker,
        docker_port=args.docker_port,
        ledger_path=Path(args.ledger) if args.ledger else ProxyConfig().ledger_path,
    )

    if args.config:
        matcher = DomainMatcher.from_yaml(args.config)
        cfg.ai_domains = matcher._domains

    proxy_app = create_proxy_app(config=cfg)

    proxy_config = uvicorn.Config(
        proxy_app,
        host=args.host,
        port=args.port,
        log_level="info",
        access_log=False,
    )
    proxy_server = uvicorn.Server(proxy_config)

    tasks = [proxy_server.serve()]

    if args.docker:
        docker_app = create_docker_proxy_app(config=cfg)
        docker_config = uvicorn.Config(
            docker_app,
            host=args.host,
            port=args.docker_port,
            log_level="info",
            access_log=False,
        )
        docker_server = uvicorn.Server(docker_config)
        tasks.append(docker_server.serve())

    await asyncio.gather(*tasks)


def main() -> None:
    args = parse_args()

    banner = (
        "\n"
        "====================================================================\n"
        "  GAVEL NETWORK ENFORCEMENT PROXY\n"
        "  Constitutional governance for AI agent traffic\n"
        "--------------------------------------------------------------------\n"
        f"  HTTP Proxy:    {args.host}:{args.port}\n"
    )
    if args.docker:
        banner += f"  Docker Proxy:  {args.host}:{args.docker_port}\n"
    banner += (
        f"  Mode:          {'DEFAULT-DENY' if args.default_deny else 'DEFAULT-ALLOW (AI domains enforced)'}\n"
        "  Ledger:        Hash-chained append-only JSONL\n"
        "====================================================================\n"
    )
    print(banner)

    asyncio.run(serve(args))
