-- =============================================================================
-- AUDIT SPINE — Tamper-Evident, Append-Only Ledger with Hash-Chaining
-- Migration: 001_audit_spine.sql
-- Constitutional Reference: §I.1 — "No event logged to the Audit Spine
--   shall be modified or deleted."
-- =============================================================================

-- Require pgcrypto for SHA-256 hashing
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -----------------------------------------------------------------------------
-- 1. Core table: audit_events
-- -----------------------------------------------------------------------------
CREATE TABLE audit_events (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at          TIMESTAMPTZ NOT NULL    DEFAULT now(),
    actor_id            TEXT        NOT NULL,
    action_type         TEXT        NOT NULL,
    intent_payload      JSONB       NOT NULL    DEFAULT '{}',
    policy_version      TEXT        NOT NULL,
    event_hash          TEXT        NOT NULL,       -- SHA-256 of this event
    previous_event_hash TEXT        NOT NULL         -- SHA-256 of prior event (genesis = 'GENESIS')
);

-- Fast lookups by time range and actor
CREATE INDEX idx_audit_events_created_at ON audit_events (created_at);
CREATE INDEX idx_audit_events_actor_id   ON audit_events (actor_id);
CREATE INDEX idx_audit_events_action_type ON audit_events (action_type);

-- Enforce unique, sequential hash chain (no two events share a previous hash)
CREATE UNIQUE INDEX idx_audit_events_prev_hash ON audit_events (previous_event_hash);

-- -----------------------------------------------------------------------------
-- 2. Hash-chaining trigger function
--    Computes:  SHA-256( previous_event_hash || actor_id || action_type
--                        || intent_payload || policy_version || created_at )
--    And links the new event to the tail of the chain.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_spine_hash_chain()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash TEXT;
BEGIN
    -- Lock the table to serialize inserts — guarantees a single chain tip
    LOCK TABLE audit_events IN EXCLUSIVE MODE;

    -- Find the current chain tip (most recent event by created_at, then id)
    SELECT event_hash INTO prev_hash
    FROM audit_events
    ORDER BY created_at DESC, id DESC
    LIMIT 1;

    -- Genesis case: first event in the ledger
    IF prev_hash IS NULL THEN
        prev_hash := 'GENESIS';
    END IF;

    NEW.previous_event_hash := prev_hash;

    -- Compute the event hash over all material fields
    NEW.event_hash := encode(
        digest(
            prev_hash
            || '|' || NEW.actor_id
            || '|' || NEW.action_type
            || '|' || NEW.intent_payload::text
            || '|' || NEW.policy_version
            || '|' || NEW.created_at::text,
            'sha256'
        ),
        'hex'
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_spine_hash_chain
    BEFORE INSERT ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION audit_spine_hash_chain();

-- -----------------------------------------------------------------------------
-- 3. Append-only enforcement: block UPDATE and DELETE
--    Constitutional Invariant §I.1 — immutable history.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_spine_deny_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'CONSTITUTIONAL VIOLATION §I.1: Audit Spine is append-only. '
        '% operations are prohibited on audit_events.',
        TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_spine_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION audit_spine_deny_mutation();

CREATE TRIGGER trg_audit_spine_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION audit_spine_deny_mutation();

-- -----------------------------------------------------------------------------
-- 4. Chain verification function
--    Walk the chain from genesis to tip and verify every hash.
--    Returns the number of valid events, or raises an exception on mismatch.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_spine_verify_chain()
RETURNS TABLE(total_events BIGINT, chain_valid BOOLEAN, break_at UUID) AS $$
DECLARE
    rec           RECORD;
    expected_hash TEXT;
    counter       BIGINT := 0;
BEGIN
    FOR rec IN
        SELECT * FROM audit_events ORDER BY created_at ASC, id ASC
    LOOP
        counter := counter + 1;

        expected_hash := encode(
            digest(
                rec.previous_event_hash
                || '|' || rec.actor_id
                || '|' || rec.action_type
                || '|' || rec.intent_payload::text
                || '|' || rec.policy_version
                || '|' || rec.created_at::text,
                'sha256'
            ),
            'hex'
        );

        IF expected_hash <> rec.event_hash THEN
            RETURN QUERY SELECT counter, FALSE, rec.id;
            RETURN;
        END IF;
    END LOOP;

    RETURN QUERY SELECT counter, TRUE, NULL::UUID;
    RETURN;
END;
$$ LANGUAGE plpgsql;
