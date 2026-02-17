"""
Audit Spine Chain Verifier
Constitutional Reference: §I.1 — Immutable History

Independently walks the audit_events ledger, recomputes every SHA-256 hash
outside of PostgreSQL, and confirms the chain has not been tampered with.
"""

import hashlib
import sys

import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "governance_control_plane",
    "user": "admin",
    "password": "password123",
}


def compute_event_hash(prev_hash: str, actor_id: str, action_type: str,
                       intent_payload: str, policy_version: str,
                       created_at: str) -> str:
    """Reproduce the exact hash formula used by the database trigger."""
    material = (
        f"{prev_hash}|{actor_id}|{action_type}"
        f"|{intent_payload}|{policy_version}|{created_at}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify() -> bool:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, created_at::text, actor_id, action_type, "
        "intent_payload::text, policy_version, event_hash, previous_event_hash "
        "FROM audit_events ORDER BY created_at ASC, id ASC"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    if not rows:
        print("Audit Spine is empty — nothing to verify.")
        return True

    print(f"Verifying chain of {len(rows)} event(s)...\n")

    all_valid = True
    for i, row in enumerate(rows):
        (event_id, created_at, actor_id, action_type,
         intent_payload, policy_version, stored_hash, prev_hash) = row

        expected_hash = compute_event_hash(
            prev_hash, actor_id, action_type,
            intent_payload, policy_version, created_at,
        )

        status = "OK" if expected_hash == stored_hash else "TAMPERED"
        if status == "TAMPERED":
            all_valid = False

        print(f"  [{status}] Event {i + 1}: {action_type}")
        print(f"         Actor:    {actor_id}")
        print(f"         Hash:     {stored_hash[:32]}...")
        print(f"         PrevHash: {prev_hash[:32] if prev_hash != 'GENESIS' else 'GENESIS'}...")
        if status == "TAMPERED":
            print(f"         EXPECTED: {expected_hash[:32]}...")
        print()

    if all_valid:
        print(f"CHAIN INTEGRITY: VALID — all {len(rows)} events verified.")
    else:
        print("CHAIN INTEGRITY: BROKEN — tampering detected!")

    return all_valid


if __name__ == "__main__":
    ok = verify()
    sys.exit(0 if ok else 1)
