"""Phase 10 production hardening — engine TLS + pool tuning."""

from __future__ import annotations

import pytest

from gavel.db import engine as engine_mod
from gavel.db.engine import get_engine, reset_engine, resolve_database_url


@pytest.fixture(autouse=True)
def _reset_engine_cache():
    reset_engine()
    yield
    reset_engine()


def test_prod_postgres_url_gets_sslmode_appended(monkeypatch):
    monkeypatch.setenv("GAVEL_ENV", "production")
    monkeypatch.setenv("GAVEL_DB_URL", "postgresql+asyncpg://u:p@h/db")
    assert resolve_database_url() == "postgresql+asyncpg://u:p@h/db?sslmode=require"


def test_prod_postgres_url_with_existing_query_gets_ampersand(monkeypatch):
    monkeypatch.setenv("GAVEL_ENV", "production")
    monkeypatch.setenv("GAVEL_DB_URL", "postgresql+asyncpg://u:p@h/db?foo=bar")
    assert (
        resolve_database_url()
        == "postgresql+asyncpg://u:p@h/db?foo=bar&sslmode=require"
    )


def test_prod_postgres_url_with_sslmode_is_idempotent(monkeypatch):
    monkeypatch.setenv("GAVEL_ENV", "production")
    url = "postgresql+asyncpg://u:p@h/db?sslmode=require"
    monkeypatch.setenv("GAVEL_DB_URL", url)
    assert resolve_database_url() == url
    # Re-running produces the same string.
    assert resolve_database_url() == resolve_database_url()


def test_prod_sqlite_url_unchanged(monkeypatch):
    monkeypatch.setenv("GAVEL_ENV", "production")
    monkeypatch.setenv("GAVEL_DB_URL", "sqlite+aiosqlite:///./gavel.db")
    assert resolve_database_url() == "sqlite+aiosqlite:///./gavel.db"


def test_non_prod_postgres_url_unchanged(monkeypatch):
    monkeypatch.delenv("GAVEL_ENV", raising=False)
    monkeypatch.setenv("GAVEL_DB_URL", "postgresql+asyncpg://u:p@h/db")
    assert resolve_database_url() == "postgresql+asyncpg://u:p@h/db"


def test_staging_env_postgres_url_unchanged(monkeypatch):
    monkeypatch.setenv("GAVEL_ENV", "staging")
    monkeypatch.setenv("GAVEL_DB_URL", "postgresql+asyncpg://u:p@h/db")
    assert resolve_database_url() == "postgresql+asyncpg://u:p@h/db"


def test_engine_factory_postgres_passes_pool_kwargs(monkeypatch):
    captured: dict = {}

    def fake_create(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(engine_mod, "create_async_engine", fake_create)
    monkeypatch.setenv("GAVEL_DB_URL", "postgresql+asyncpg://u:p@h/db")

    get_engine()

    assert captured["kwargs"]["future"] is True
    assert captured["kwargs"]["pool_size"] == 20
    assert captured["kwargs"]["max_overflow"] == 5
    assert captured["kwargs"]["pool_pre_ping"] is True


def test_engine_factory_sqlite_omits_pool_kwargs(monkeypatch):
    captured: dict = {}

    def fake_create(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(engine_mod, "create_async_engine", fake_create)
    monkeypatch.setenv("GAVEL_DB_URL", "sqlite+aiosqlite:///:memory:")

    get_engine()

    assert captured["kwargs"] == {"future": True}
    assert "pool_size" not in captured["kwargs"]
    assert "max_overflow" not in captured["kwargs"]
    assert "pool_pre_ping" not in captured["kwargs"]
