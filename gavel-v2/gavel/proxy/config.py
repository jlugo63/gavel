"""
Proxy configuration models and default domain list.

Part of Gavel -- Constitutional governance for AI agents (EU AI Act).
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROXY_PORT = 8200
DOCKER_PROXY_PORT = 8201
TOKEN_HEADER = "X-Gavel-Token"


# ---------------------------------------------------------------------------
# Configuration (pydantic)
# ---------------------------------------------------------------------------


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
