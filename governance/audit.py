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
            except (psycopg2.errors.UniqueViolation, psycopg2.errors.DeadlockDetected):
                conn.rollback()
                if attempt < _max_retries - 1:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                raise
            finally:
                conn.close()
        raise RuntimeError("log_event: exhausted retries")

    def get_chain_role(
        self,
        chain_id: str,
        actor_id: str,
    ) -> Optional[str]:
        """
        Look up the role used by an actor on a given chain.

        Queries INBOUND_INTENT events for the first occurrence of this
        actor + chain_id combination and returns the role from the payload.
        Returns None if no prior events exist for this actor on this chain.
        """
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT intent_payload->>'role'
                FROM audit_events
                WHERE action_type = 'INBOUND_INTENT'
                  AND actor_id = %s
                  AND intent_payload->>'chain_id' = %s
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (actor_id, chain_id),
            )
            row = cur.fetchone()
            cur.close()
            return row[0] if row else None
        finally:
            conn.close()

    def find_policy_eval_for_intent(
        self, intent_event_id: str
    ) -> Optional[dict[str, Any]]:
        """
        Find the POLICY_EVAL event that corresponds to a given INBOUND_INTENT.

        Looks up the intent event, then finds the earliest POLICY_EVAL with
        the same actor_id created at or after the intent's timestamp.
        Returns None if no matching event is found.
        """
        intent = self.get_event(intent_event_id)
        if intent is None or intent["action_type"] != "INBOUND_INTENT":
            return None

        actor_id = intent["actor_id"]
        created_at = intent["created_at"]

        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, created_at, actor_id, action_type, "
                "intent_payload, policy_version, event_hash, previous_event_hash "
                "FROM audit_events "
                "WHERE action_type LIKE 'POLICY_EVAL:%%' "
                "  AND actor_id = %s "
                "  AND created_at >= %s "
                "ORDER BY created_at ASC "
                "LIMIT 1",
                (actor_id, created_at),
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

    def find_valid_approval(
        self,
        actor_id: str,
        action_type: str,
        content: str,
        ttl_seconds: int = 3600,
    ) -> Optional[dict[str, Any]]:
        """
        Find an unconsumed, unexpired HUMAN_APPROVAL_GRANTED event that
        matches the given (actor_id, action_type, content).

        The match is performed by joining the approval event back to its
        original INBOUND_INTENT (via intent_event_id in the approval
        payload) and comparing the intent's actor_id, action_type, and
        content fields.

        Returns the approval event dict, or None if no valid approval
        exists.
        """
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT a.id, a.created_at, a.actor_id, a.action_type,
                       a.intent_payload, a.policy_version,
                       a.event_hash, a.previous_event_hash
                FROM audit_events a
                JOIN audit_events intent
                  ON intent.id = (a.intent_payload->>'intent_event_id')::uuid
                WHERE a.action_type = 'HUMAN_APPROVAL_GRANTED'
                  AND a.created_at >= NOW() - make_interval(secs => %s)
                  AND intent.actor_id = %s
                  AND intent.intent_payload->>'action_type' = %s
                  AND intent.intent_payload->>'content' = %s
                  AND NOT EXISTS (
                      SELECT 1 FROM audit_events c
                      WHERE c.action_type = 'APPROVAL_CONSUMED'
                        AND c.intent_payload->>'approval_event_id' = a.id::text
                  )
                ORDER BY a.created_at DESC
                LIMIT 1
                """,
                (ttl_seconds, actor_id, action_type, content),
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
