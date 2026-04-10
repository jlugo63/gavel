"""
SSO/OIDC Integration — operator identity from enterprise IdPs.

Enterprise deployments authenticate operators via their existing identity
provider (Okta, Azure AD, Google Workspace, etc.) rather than local
credentials. This module provides:

  1. OIDCProvider configuration — issuer, client_id, JWKS endpoint
  2. OIDCTokenClaims — parsed and validated claims from an ID token
  3. OperatorIdentity — resolved identity bound to Gavel roles + tenant
  4. IdentityResolver — maps OIDC claims to Gavel operator profiles
  5. SessionManager — manages authenticated operator sessions

Design constraints:
  - No external HTTP calls in this module (JWKS fetching is the caller's
    responsibility — this module validates the parsed result)
  - Deterministic, testable without a real IdP
  - Claims-to-role mapping is configurable per org
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── OIDC Provider configuration ──────────────────────────────

class OIDCProvider(BaseModel):
    """Configuration for an OIDC identity provider."""
    provider_id: str = Field(default_factory=lambda: f"idp-{uuid.uuid4().hex[:8]}")
    issuer: str                          # e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
    client_id: str                       # OAuth client ID
    audience: str = ""                   # Expected audience claim (defaults to client_id)
    jwks_uri: str = ""                   # JWKS endpoint for key verification
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    org_id: str = ""                     # Which Gavel org this provider authenticates for
    claim_mapping: dict[str, str] = Field(default_factory=lambda: {
        "operator_id": "sub",
        "email": "email",
        "name": "name",
        "groups": "groups",
    })
    role_mapping: dict[str, str] = Field(default_factory=dict)  # IdP group -> Gavel role


class OIDCTokenClaims(BaseModel):
    """Parsed claims from a validated OIDC ID token."""
    sub: str                             # Subject (unique user ID from IdP)
    iss: str                             # Issuer URL
    aud: str                             # Audience
    exp: int                             # Expiration (Unix timestamp)
    iat: int                             # Issued at (Unix timestamp)
    email: str = ""
    name: str = ""
    groups: list[str] = Field(default_factory=list)
    raw_claims: dict[str, Any] = Field(default_factory=dict)


# ── Operator identity ─────────────────────────────────────────

class OperatorIdentity(BaseModel):
    """Resolved operator identity with Gavel roles and tenant context."""
    operator_id: str
    provider_id: str
    email: str = ""
    display_name: str = ""
    roles: list[str] = Field(default_factory=list)
    org_id: str = ""
    team_ids: list[str] = Field(default_factory=list)
    authenticated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    claims_hash: str = ""  # Hash of the original claims for audit


class AuthSession(BaseModel):
    """An authenticated operator session."""
    session_id: str = Field(default_factory=lambda: f"sess-{uuid.uuid4().hex[:12]}")
    operator_id: str
    identity: OperatorIdentity
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=8))
    revoked: bool = False
    session_token: str = ""


# ── Token validation ──────────────────────────────────────────

class TokenValidationError(str, Enum):
    EXPIRED = "token_expired"
    INVALID_ISSUER = "invalid_issuer"
    INVALID_AUDIENCE = "invalid_audience"
    MISSING_CLAIMS = "missing_required_claims"
    PROVIDER_NOT_FOUND = "provider_not_found"


class TokenValidationResult(BaseModel):
    """Result of validating an OIDC token's claims."""
    valid: bool
    claims: Optional[OIDCTokenClaims] = None
    error: Optional[TokenValidationError] = None
    error_detail: str = ""


def validate_token_claims(
    claims: OIDCTokenClaims,
    provider: OIDCProvider,
) -> TokenValidationResult:
    """Validate parsed OIDC token claims against a provider configuration.

    This does NOT verify the JWT signature (that's the caller's job using
    the JWKS keys). This validates the business-logic claims: issuer,
    audience, expiration, required fields.
    """
    now = int(datetime.now(timezone.utc).timestamp())

    if claims.exp <= now:
        return TokenValidationResult(
            valid=False,
            claims=claims,
            error=TokenValidationError.EXPIRED,
            error_detail=f"Token expired at {claims.exp}, current time {now}",
        )

    if claims.iss != provider.issuer:
        return TokenValidationResult(
            valid=False,
            claims=claims,
            error=TokenValidationError.INVALID_ISSUER,
            error_detail=f"Expected issuer {provider.issuer}, got {claims.iss}",
        )

    expected_aud = provider.audience or provider.client_id
    if claims.aud != expected_aud:
        return TokenValidationResult(
            valid=False,
            claims=claims,
            error=TokenValidationError.INVALID_AUDIENCE,
            error_detail=f"Expected audience {expected_aud}, got {claims.aud}",
        )

    if not claims.sub:
        return TokenValidationResult(
            valid=False,
            claims=claims,
            error=TokenValidationError.MISSING_CLAIMS,
            error_detail="Missing required claim: sub",
        )

    return TokenValidationResult(valid=True, claims=claims)


# ── Identity resolver ─────────────────────────────────────────

class IdentityResolver:
    """Maps OIDC claims to Gavel operator identities.

    Configurable per-org via the provider's role_mapping:
      {"SecurityTeam": "security_officer", "Engineers": "operator", ...}

    Operators whose groups don't match any mapping get "viewer" as default.
    """

    def __init__(self):
        self._providers: dict[str, OIDCProvider] = {}  # provider_id -> provider

    def register_provider(self, provider: OIDCProvider) -> None:
        self._providers[provider.provider_id] = provider

    def get_provider(self, provider_id: str) -> OIDCProvider | None:
        return self._providers.get(provider_id)

    def get_provider_by_issuer(self, issuer: str) -> OIDCProvider | None:
        for p in self._providers.values():
            if p.issuer == issuer:
                return p
        return None

    def resolve(self, claims: OIDCTokenClaims, provider_id: str) -> OperatorIdentity | None:
        """Resolve OIDC claims into a Gavel operator identity."""
        provider = self._providers.get(provider_id)
        if not provider:
            return None

        # Map claims to identity fields using the provider's claim_mapping
        cm = provider.claim_mapping
        operator_id = _extract_claim(claims, cm.get("operator_id", "sub"))
        email = _extract_claim(claims, cm.get("email", "email"))
        name = _extract_claim(claims, cm.get("name", "name"))
        groups_field = cm.get("groups", "groups")
        groups = getattr(claims, groups_field, []) if hasattr(claims, groups_field) else claims.raw_claims.get(groups_field, [])

        # Map IdP groups to Gavel roles
        roles = _map_groups_to_roles(groups, provider.role_mapping)
        if not roles:
            roles = ["viewer"]  # default role

        # Hash claims for audit trail
        claims_hash = hashlib.sha256(
            f"{claims.sub}:{claims.iss}:{claims.iat}".encode()
        ).hexdigest()[:16]

        return OperatorIdentity(
            operator_id=operator_id,
            provider_id=provider_id,
            email=email,
            display_name=name,
            roles=roles,
            org_id=provider.org_id,
            authenticated_at=datetime.now(timezone.utc),
            claims_hash=claims_hash,
        )


def _extract_claim(claims: OIDCTokenClaims, field: str) -> str:
    """Extract a claim value by field name."""
    if hasattr(claims, field):
        val = getattr(claims, field)
        return str(val) if val else ""
    return str(claims.raw_claims.get(field, ""))


def _map_groups_to_roles(groups: list[str], role_mapping: dict[str, str]) -> list[str]:
    """Map IdP group names to Gavel role names."""
    roles = set()
    for group in groups:
        if group in role_mapping:
            roles.add(role_mapping[group])
        # Also check case-insensitive
        for mapping_key, role in role_mapping.items():
            if group.lower() == mapping_key.lower():
                roles.add(role)
    return sorted(roles)


# ── Session manager ───────────────────────────────────────────

class SessionManager:
    """Manages authenticated operator sessions."""

    def __init__(self, session_ttl_hours: int = 8):
        self._sessions: dict[str, AuthSession] = {}  # session_id -> session
        self._by_operator: dict[str, list[str]] = {}  # operator_id -> [session_id, ...]
        self._session_ttl = timedelta(hours=session_ttl_hours)

    def create_session(self, identity: OperatorIdentity) -> AuthSession:
        """Create a new authenticated session for an operator."""
        now = datetime.now(timezone.utc)
        session_token = f"gvl_sess_{secrets.token_hex(32)}"
        session = AuthSession(
            operator_id=identity.operator_id,
            identity=identity,
            created_at=now,
            expires_at=now + self._session_ttl,
            session_token=session_token,
        )
        self._sessions[session.session_id] = session
        self._by_operator.setdefault(identity.operator_id, []).append(session.session_id)
        return session

    def validate_session(self, session_id: str) -> AuthSession | None:
        """Validate a session is active and not expired."""
        session = self._sessions.get(session_id)
        if not session:
            return None
        if session.revoked:
            return None
        if datetime.now(timezone.utc) >= session.expires_at:
            return None
        return session

    def validate_session_token(self, token: str) -> AuthSession | None:
        """Validate a session by its token string."""
        for session in self._sessions.values():
            if session.session_token == token and not session.revoked:
                if datetime.now(timezone.utc) < session.expires_at:
                    return session
        return None

    def revoke_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session:
            session.revoked = True
            return True
        return False

    def revoke_all_sessions(self, operator_id: str) -> int:
        """Revoke all sessions for an operator (e.g., on password change)."""
        sids = self._by_operator.get(operator_id, [])
        count = 0
        for sid in sids:
            session = self._sessions.get(sid)
            if session and not session.revoked:
                session.revoked = True
                count += 1
        return count

    def active_sessions(self, operator_id: str | None = None) -> list[AuthSession]:
        """List active (non-expired, non-revoked) sessions."""
        now = datetime.now(timezone.utc)
        sessions = self._sessions.values()
        if operator_id:
            sids = self._by_operator.get(operator_id, [])
            sessions = [self._sessions[sid] for sid in sids if sid in self._sessions]
        return [s for s in sessions if not s.revoked and now < s.expires_at]

    @property
    def session_count(self) -> int:
        return len(self._sessions)
