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
import hmac
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import httpx
import uvicorn
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging -- mirrors other gavel modules (single getLogger, no handler setup
# so the root/app-level config controls output).
# ---------------------------------------------------------------------------

log = logging.getLogger("gavel.proxy")

# ---------------------------------------------------------------------------
# Configuration (pydantic)
# ---------------------------------------------------------------------------

PROXY_PORT = 8200
DOCKER_PROXY_PORT = 8201
TOKEN_HEADER = "X-Gavel-Token"


class DomainEntry(BaseModel):
    """A single AI API domain pattern with a human-readable label."""

    pattern: str
    label: str = ""


class ProxyConfig(BaseModel):
    """Top-level configuration for the enforcement proxy."""

    port: int = Field(default=PROXY_PORT, description="HTTP proxy listen port")
    host: str = Field(default="0.0.0.0", description="Bind address")
    default_deny: bool = Field(
        default=False,
        description="Block ALL traffic unless a valid Gavel token is present",
    )
    gavel_api_url: str = Field(
        default_factory=lambda: os.getenv("GAVEL_API_URL", "http://localhost:8100"),
        description="Base URL of the Gavel control-plane API",
    )
    shared_secret: str = Field(
        default_factory=lambda: os.getenv("GAVEL_SHARED_SECRET", ""),
        description="HMAC shared secret for local token validation",
    )
    ledger_path: Path = Field(
        default_factory=lambda: Path(
            os.getenv("GAVEL_ENFORCEMENT_LEDGER", "enforcement_ledger.jsonl")
        ),
        description="Path to the append-only enforcement ledger (JSONL)",
    )
    docker_socket: str = Field(
        default_factory=lambda: os.getenv("DOCKER_SOCKET", "/var/run/docker.sock"),
        description="Path to the Docker Engine unix socket",
    )
    docker_enabled: bool = Field(
        default=False, description="Also start Docker socket proxy"
    )
    docker_port: int = Field(
        default=DOCKER_PROXY_PORT, description="Docker proxy listen port"
    )
    ai_domains: list[DomainEntry] = Field(default_factory=list)

    def effective_domains(self) -> list[DomainEntry]:
        return self.ai_domains if self.ai_domains else _default_ai_domains()


def _default_ai_domains() -> list[DomainEntry]:
    return [
        DomainEntry(pattern="api.openai.com", label="OpenAI API"),
        DomainEntry(pattern="api.anthropic.com", label="Anthropic API"),
        DomainEntry(pattern="api.cohere.com", label="Cohere API"),
        DomainEntry(pattern="generativelanguage.googleapis.com", label="Google Gemini API"),
        DomainEntry(pattern="localhost:11434", label="Ollama (local)"),
        DomainEntry(pattern="127.0.0.1:11434", label="Ollama (local alt)"),
        DomainEntry(pattern="*.docker.com", label="Docker services"),
        DomainEntry(pattern="copilot.microsoft.com", label="GitHub Copilot"),
        DomainEntry(pattern="ai.jetbrains.com", label="JetBrains AI"),
        DomainEntry(pattern="api2.cursor.sh", label="Cursor AI"),
        DomainEntry(pattern="*.warp.dev", label="Warp terminal AI"),
    ]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class EnforcementAction(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"


class LedgerEntry(BaseModel):
    """Append-only, hash-chained enforcement event."""

    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_agent: str = ""
    destination_domain: str = ""
    method: str = ""
    path: str = ""
    action: EnforcementAction = EnforcementAction.BLOCKED
    reason: str = ""
    token_id: str = ""
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self, prev: str = "") -> str:
        """SHA-256 over deterministic JSON of the entry fields (excluding entry_hash)."""
        payload = self.model_dump(exclude={"entry_hash"})
        payload["prev_hash"] = prev
        raw = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Enforcement Ledger (append-only, hash-chained)
# ---------------------------------------------------------------------------

class EnforcementLedger:
    """
    Append-only hash-chained log.  Each entry's hash covers the previous
    entry's hash, making the ledger tamper-evident -- the same principle
    used by ``gavel.chain.GovernanceChain``.
    """

    def __init__(self, path: Path | None = None):
        self._path = path or Path("enforcement_ledger.jsonl")
        self._last_hash: str = "genesis"
        self._lock = asyncio.Lock()
        self._restore_chain_tip()

    def _restore_chain_tip(self) -> None:
        """Read the last line of an existing ledger to resume the hash chain."""
        if not self._path.exists():
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                last_line = ""
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
                if last_line:
                    data = json.loads(last_line)
                    self._last_hash = data.get("entry_hash", "genesis")
        except Exception:
            log.warning("Could not restore ledger chain tip; starting fresh chain.")

    async def append(self, entry: LedgerEntry) -> LedgerEntry:
        async with self._lock:
            entry.prev_hash = self._last_hash
            entry.entry_hash = entry.compute_hash(self._last_hash)
            self._last_hash = entry.entry_hash

            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(entry.model_dump_json() + "\n")

            log.info(
                "LEDGER %s | %s %s%s | agent=%s token=%s reason=%s hash=%s",
                entry.action.value,
                entry.method,
                entry.destination_domain,
                entry.path,
                entry.source_agent or "-",
                entry.token_id or "-",
                entry.reason,
                entry.entry_hash[:16],
            )
            return entry

    async def verify_integrity(self) -> tuple[bool, int, list[str]]:
        """Walk the full ledger and verify every hash link."""
        if not self._path.exists():
            return True, 0, []
        errors: list[str] = []
        prev_hash = "genesis"
        count = 0
        with open(self._path, "r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                count += 1
                try:
                    data = json.loads(raw)
                    entry = LedgerEntry(**data)
                    expected = entry.compute_hash(prev_hash)
                    if entry.entry_hash != expected:
                        errors.append(
                            f"Line {lineno}: hash mismatch "
                            f"(expected {expected[:16]}..., got {entry.entry_hash[:16]}...)"
                        )
                    if entry.prev_hash != prev_hash:
                        errors.append(
                            f"Line {lineno}: prev_hash mismatch "
                            f"(expected {prev_hash[:16]}..., got {entry.prev_hash[:16]}...)"
                        )
                    prev_hash = entry.entry_hash
                except Exception as exc:
                    errors.append(f"Line {lineno}: parse error -- {exc}")
        return len(errors) == 0, count, errors


# ---------------------------------------------------------------------------
# Domain matcher
# ---------------------------------------------------------------------------

class DomainMatcher:
    """Match request hosts against configured AI API domain patterns."""

    def __init__(self, domains: list[DomainEntry] | None = None):
        self._domains = domains or _default_ai_domains()
        self._compiled: list[tuple[re.Pattern, str]] = []
        for entry in self._domains:
            regex = self._glob_to_regex(entry.pattern)
            self._compiled.append((re.compile(regex, re.IGNORECASE), entry.label or entry.pattern))

    @staticmethod
    def _glob_to_regex(glob: str) -> str:
        """Convert a domain glob (e.g. ``*.docker.com``) to a regex."""
        escaped = re.escape(glob).replace(r"\*", r"[a-zA-Z0-9\-\.]*")
        return f"^{escaped}$"

    def match(self, host: str) -> tuple[bool, str]:
        """Returns ``(is_ai_domain, label)`` for a given host string."""
        host_no_port = host.split(":")[0] if ":" in host else host
        for pattern, label in self._compiled:
            if pattern.match(host) or pattern.match(host_no_port):
                return True, label
        return False, ""

    @classmethod
    def from_yaml(cls, path: str | Path) -> DomainMatcher:
        """Load domain config from a YAML file.

        Expected format::

            ai_domains:
              - pattern: "api.openai.com"
                label: "OpenAI API"
        """
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        raw = data.get("ai_domains", data if isinstance(data, list) else [])
        domains = [DomainEntry(**d) if isinstance(d, dict) else d for d in raw]
        return cls(domains)


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

class TokenValidator:
    """
    Validate Gavel governance tokens.

    Supports two modes:

    1. **Remote** -- POST to the Gavel API ``/api/v1/tokens/validate``.
    2. **Local** -- HMAC-SHA256 with a shared secret (offline fast path).

    Token format (local mode)::

        <agent_id>.<expiry_epoch>.<hmac_hex>

    Local validation is attempted first when a shared secret is configured;
    the validator falls back to remote validation when local is inconclusive.
    """

    def __init__(self, config: ProxyConfig):
        api_base = config.gavel_api_url.rstrip("/")
        self._validation_url = f"{api_base}/api/v1/tokens/validate"
        self._shared_secret = config.shared_secret.encode() if config.shared_secret else b""
        self._http_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=5.0)
        return self._http_client

    async def close(self) -> None:
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    # -- local HMAC validation ----------------------------------------------

    def _validate_local(self, token: str) -> tuple[bool, str, str]:
        """Validate token locally using HMAC-SHA256.  Returns ``(valid, agent_id, reason)``."""
        if not self._shared_secret:
            return False, "", "no_shared_secret"

        parts = token.split(".")
        if len(parts) != 3:
            return False, "", "malformed_token"

        agent_id, expiry_str, provided_mac = parts

        try:
            expiry = int(expiry_str)
        except ValueError:
            return False, agent_id, "invalid_expiry"

        if time.time() > expiry:
            return False, agent_id, "token_expired"

        message = f"{agent_id}.{expiry_str}".encode()
        expected_mac = hmac.new(self._shared_secret, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided_mac, expected_mac):
            return False, agent_id, "invalid_signature"

        return True, agent_id, "valid_local"

    # -- remote validation --------------------------------------------------

    async def _validate_remote(self, token: str) -> tuple[bool, str, str]:
        """Validate token via the Gavel API.  Returns ``(valid, agent_id, reason)``."""
        try:
            client = await self._get_client()
            resp = await client.post(
                self._validation_url,
                json={"token": token},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                body = resp.json()
                return (
                    body.get("valid", False),
                    body.get("agent_id", ""),
                    body.get("reason", "valid_remote"),
                )
            return False, "", f"registration_api_{resp.status_code}"
        except httpx.ConnectError:
            return False, "", "registration_api_unreachable"
        except Exception as exc:
            log.warning("Remote token validation error: %s", exc)
            return False, "", f"remote_error:{type(exc).__name__}"

    # -- public API ---------------------------------------------------------

    async def validate(self, token: str | None) -> tuple[bool, str, str]:
        """Validate a Gavel governance token.  Returns ``(valid, agent_id, reason)``."""
        if not token:
            return False, "", "missing_token"

        if self._shared_secret:
            valid, agent_id, reason = self._validate_local(token)
            if valid:
                return True, agent_id, reason
            if reason in ("invalid_signature", "token_expired"):
                return False, agent_id, reason

        return await self._validate_remote(token)


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

    matcher = (
        DomainMatcher.from_yaml(cfg.ai_domains[0].pattern)
        if False  # placeholder -- yaml loading handled via CLI --config
        else DomainMatcher(cfg.effective_domains())
    )
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
                    except Exception:
                        pass
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
# Module-level app instance (for ``uvicorn gavel.proxy:app``)
# ---------------------------------------------------------------------------

app: FastAPI = create_proxy_app()


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

    # Build config from CLI args
    cfg = ProxyConfig(
        port=args.port,
        host=args.host,
        default_deny=args.default_deny,
        docker_enabled=args.docker,
        docker_port=args.docker_port,
        ledger_path=Path(args.ledger) if args.ledger else ProxyConfig().ledger_path,
    )

    # Load custom domain config if provided
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


if __name__ == "__main__":
    main()
