"""Integration tests that exercise the full FastAPI + repo + asyncpg + Postgres stack.

These tests only run when ``GAVEL_INTEGRATION_DB_URL`` is set in the environment
(see ``tests/integration/conftest.py``). They are filtered out of the default
pytest run via the ``integration`` marker — run with ``pytest -m integration``.
"""
