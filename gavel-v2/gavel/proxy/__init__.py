"""
Gavel Network Enforcement Proxy package.

Re-exports the key objects so that existing import paths continue to work::

    from gavel.proxy import app              # ASGI app for uvicorn
    from gavel.proxy import create_proxy_app # factory function
    from gavel.proxy import ProxyConfig      # configuration model

Part of Gavel -- Constitutional governance for AI agents (EU AI Act).
"""

from __future__ import annotations

from gavel.proxy.app import (
    create_docker_proxy_app,
    create_proxy_app,
    main,
    parse_args,
    serve,
)
from gavel.proxy.config import (
    DOCKER_PROXY_PORT,
    PROXY_PORT,
    TOKEN_HEADER,
    DomainEntry,
    ProxyConfig,
)
from gavel.proxy.domain import DomainMatcher
from gavel.proxy.enforcement import (
    EnforcementAction,
    EnforcementLedger,
    LedgerEntry,
)
from gavel.proxy.token_validator import TokenValidator

# Module-level app instance (for ``uvicorn gavel.proxy:app``)
app = create_proxy_app()

__all__ = [
    "app",
    "create_docker_proxy_app",
    "create_proxy_app",
    "DOCKER_PROXY_PORT",
    "DomainEntry",
    "DomainMatcher",
    "EnforcementAction",
    "EnforcementLedger",
    "LedgerEntry",
    "main",
    "parse_args",
    "ProxyConfig",
    "PROXY_PORT",
    "serve",
    "TOKEN_HEADER",
    "TokenValidator",
]
