-- =============================================================================
-- AUDIT SPINE — Smoke Test
-- Run after 001_audit_spine.sql to verify hash-chaining and immutability.
-- =============================================================================

-- Insert three events to build a chain
INSERT INTO audit_events (actor_id, action_type, intent_payload, policy_version)
VALUES ('system:bootstrap', 'SPINE_INITIALIZED', '{"msg": "genesis event"}', '1.0.0');

INSERT INTO audit_events (actor_id, action_type, intent_payload, policy_version)
VALUES ('agent:architect', 'SCHEMA_CREATED', '{"table": "audit_events"}', '1.0.0');

INSERT INTO audit_events (actor_id, action_type, intent_payload, policy_version)
VALUES ('agent:reviewer', 'REVIEW_APPROVED', '{"target": "001_audit_spine.sql"}', '1.0.0');

-- Verify the chain is intact
SELECT * FROM audit_spine_verify_chain();

-- Show the chain
SELECT id, created_at, actor_id, action_type,
       left(event_hash, 16) AS hash_prefix,
       left(previous_event_hash, 16) AS prev_hash_prefix
FROM audit_events
ORDER BY created_at ASC;

-- Verify immutability: this MUST fail with a constitutional violation
-- Uncomment to test:
-- UPDATE audit_events SET actor_id = 'attacker' WHERE actor_id = 'system:bootstrap';
-- DELETE FROM audit_events WHERE actor_id = 'system:bootstrap';
