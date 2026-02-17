"""
Audit Spine Manager
Constitutional Reference: §I.1 — Immutable History

Centralized interface for writing to the tamper-evident audit ledger.
Every write returns the event_id so callers can reference it downstream.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "governance_control_plane",
    "user": "admin",
    "password": "password123",
}

POLICY_VERSION = "1.0.0"


class AuditSpineManager:
    """
    Append-only writer for the audit_events ledger.

    All inserts go through this class so that every component
    (Gateway, PolicyEngine, future services) shares one interface.
    """

    def __init__(self, db_config: dict | None = None):
        self._db_config = db_config or DB_CONFIG

    def _connect(self):
        return psycopg2.connect(**self._db_config)

    def get_event(self, event_id: str) -> Optional[dict[str, Any]]:
        """
        Fetch a single audit event by ID. SELECT-only.
        Returns None if the event does not exist.
        """
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, created_at, actor_id, action_type, "
                "intent_payload, policy_version, event_hash, previous_event_hash "
                "FROM audit_events WHERE id = %s",
                (event_id,),
            )
            row = cur.fetchone()
            cur.close()
            if row is None:
                return None
            return {
                "id": str(row[0]),
                "created_at": row[1],
                "actor_id": row[2],
                "action_type": row[3],
                "intent_payload": row[4],
                "policy_version": row[5],
                "event_hash": row[6],
                "previous_event_hash": row[7],
            }
        finally:
            conn.close()

    def log_event(
        self,
        actor_id: str,
        action_type: str,
        intent_payload: dict[str, Any],
        policy_version: str = POLICY_VERSION,
        _max_retries: int = 3,
    ) -> str:
        """
        Write an event to the Audit Spine and return its UUID.

        The hash-chaining trigger in PostgreSQL handles event_hash
        and previous_event_hash automatically. Retries on
        UniqueViolation (concurrent inserts racing for the same
        previous_event_hash).
        """
        import time

        for attempt in range(_max_retries):
            conn = self._connect()
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO audit_events "
                    "(actor_id, action_type, intent_payload, policy_version) "
                    "VALUES (%s, %s, %s, %s) "
                    "RETURNING id",
                    (
                        actor_id,
                        action_type,
                        json.dumps(intent_payload),
                        policy_version,
                    ),
                )
                event_id = str(cur.fetchone()[0])
                conn.commit()
                cur.close()
                return event_id
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                if attempt < _max_retries - 1:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                raise
            finally:
                conn.close()
        raise RuntimeError("log_event: exhausted retries")
