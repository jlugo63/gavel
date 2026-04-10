"""Tests for gavel.sso — SSO/OIDC integration."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gavel.sso import (
    AuthSession,
    IdentityResolver,
    OIDCProvider,
    OIDCTokenClaims,
    OperatorIdentity,
    SessionManager,
    TokenValidationError,
    validate_token_claims,
)


def _provider(**overrides) -> OIDCProvider:
    defaults = dict(
        issuer="https://login.example.com/v2",
        client_id="gavel-app-123",
        org_id="org-acme",
        role_mapping={
            "SecurityTeam": "security_officer",
            "Engineers": "operator",
            "Admins": "admin",
        },
    )
    defaults.update(overrides)
    return OIDCProvider(**defaults)


def _claims(**overrides) -> OIDCTokenClaims:
    now = int(datetime.now(timezone.utc).timestamp())
    defaults = dict(
        sub="user-12345",
        iss="https://login.example.com/v2",
        aud="gavel-app-123",
        exp=now + 3600,
        iat=now,
        email="alice@acme.com",
        name="Alice Engineer",
        groups=["Engineers", "DevOps"],
    )
    defaults.update(overrides)
    return OIDCTokenClaims(**defaults)


class TestTokenValidation:
    def test_valid_claims(self):
        result = validate_token_claims(_claims(), _provider())
        assert result.valid

    def test_expired_token(self):
        now = int(datetime.now(timezone.utc).timestamp())
        claims = _claims(exp=now - 100)
        result = validate_token_claims(claims, _provider())
        assert not result.valid
        assert result.error == TokenValidationError.EXPIRED

    def test_wrong_issuer(self):
        claims = _claims(iss="https://evil.com")
        result = validate_token_claims(claims, _provider())
        assert not result.valid
        assert result.error == TokenValidationError.INVALID_ISSUER

    def test_wrong_audience(self):
        claims = _claims(aud="wrong-client")
        result = validate_token_claims(claims, _provider())
        assert not result.valid
        assert result.error == TokenValidationError.INVALID_AUDIENCE

    def test_missing_subject(self):
        claims = _claims(sub="")
        result = validate_token_claims(claims, _provider())
        assert not result.valid
        assert result.error == TokenValidationError.MISSING_CLAIMS

    def test_audience_falls_back_to_client_id(self):
        provider = _provider(audience="")
        claims = _claims(aud="gavel-app-123")
        result = validate_token_claims(claims, provider)
        assert result.valid


class TestIdentityResolver:
    def test_resolve_maps_groups_to_roles(self):
        resolver = IdentityResolver()
        provider = _provider()
        resolver.register_provider(provider)
        claims = _claims(groups=["Engineers", "SecurityTeam"])
        identity = resolver.resolve(claims, provider.provider_id)
        assert identity is not None
        assert "operator" in identity.roles
        assert "security_officer" in identity.roles

    def test_resolve_default_viewer_role(self):
        resolver = IdentityResolver()
        provider = _provider()
        resolver.register_provider(provider)
        claims = _claims(groups=["RandomGroup"])
        identity = resolver.resolve(claims, provider.provider_id)
        assert identity is not None
        assert identity.roles == ["viewer"]

    def test_resolve_unknown_provider(self):
        resolver = IdentityResolver()
        identity = resolver.resolve(_claims(), "nonexistent")
        assert identity is None

    def test_resolve_sets_org_id(self):
        resolver = IdentityResolver()
        provider = _provider(org_id="org-acme")
        resolver.register_provider(provider)
        identity = resolver.resolve(_claims(), provider.provider_id)
        assert identity.org_id == "org-acme"

    def test_resolve_produces_claims_hash(self):
        resolver = IdentityResolver()
        provider = _provider()
        resolver.register_provider(provider)
        identity = resolver.resolve(_claims(), provider.provider_id)
        assert identity.claims_hash
        assert len(identity.claims_hash) == 16

    def test_get_provider_by_issuer(self):
        resolver = IdentityResolver()
        provider = _provider()
        resolver.register_provider(provider)
        found = resolver.get_provider_by_issuer("https://login.example.com/v2")
        assert found is not None
        assert found.provider_id == provider.provider_id

    def test_get_provider_by_issuer_not_found(self):
        resolver = IdentityResolver()
        assert resolver.get_provider_by_issuer("https://nope.com") is None


class TestSessionManager:
    def test_create_session(self):
        mgr = SessionManager()
        identity = OperatorIdentity(operator_id="op:alice", provider_id="idp-1")
        session = mgr.create_session(identity)
        assert session.session_id.startswith("sess-")
        assert session.session_token.startswith("gvl_sess_")
        assert not session.revoked

    def test_validate_session(self):
        mgr = SessionManager()
        identity = OperatorIdentity(operator_id="op:alice", provider_id="idp-1")
        session = mgr.create_session(identity)
        valid = mgr.validate_session(session.session_id)
        assert valid is not None
        assert valid.session_id == session.session_id

    def test_validate_revoked_session(self):
        mgr = SessionManager()
        identity = OperatorIdentity(operator_id="op:alice", provider_id="idp-1")
        session = mgr.create_session(identity)
        mgr.revoke_session(session.session_id)
        assert mgr.validate_session(session.session_id) is None

    def test_validate_nonexistent_session(self):
        mgr = SessionManager()
        assert mgr.validate_session("sess-nonexistent") is None

    def test_validate_session_token(self):
        mgr = SessionManager()
        identity = OperatorIdentity(operator_id="op:alice", provider_id="idp-1")
        session = mgr.create_session(identity)
        valid = mgr.validate_session_token(session.session_token)
        assert valid is not None

    def test_revoke_all_sessions(self):
        mgr = SessionManager()
        identity = OperatorIdentity(operator_id="op:alice", provider_id="idp-1")
        mgr.create_session(identity)
        mgr.create_session(identity)
        count = mgr.revoke_all_sessions("op:alice")
        assert count == 2
        assert len(mgr.active_sessions("op:alice")) == 0

    def test_active_sessions(self):
        mgr = SessionManager()
        i1 = OperatorIdentity(operator_id="op:alice", provider_id="idp-1")
        i2 = OperatorIdentity(operator_id="op:bob", provider_id="idp-1")
        mgr.create_session(i1)
        mgr.create_session(i2)
        assert len(mgr.active_sessions()) == 2
        assert len(mgr.active_sessions("op:alice")) == 1

    def test_session_count(self):
        mgr = SessionManager()
        assert mgr.session_count == 0
        identity = OperatorIdentity(operator_id="op:alice", provider_id="idp-1")
        mgr.create_session(identity)
        assert mgr.session_count == 1
