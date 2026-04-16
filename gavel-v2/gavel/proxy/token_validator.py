"""
Token validation for Gavel governance tokens.

Part of Gavel -- Constitutional governance for AI agents (EU AI Act).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time

import httpx

from gavel.proxy.config import ProxyConfig

log = logging.getLogger("gavel.proxy")


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
