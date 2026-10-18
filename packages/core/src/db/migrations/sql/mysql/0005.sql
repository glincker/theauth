/* Migration 0005: audit-event */

ALTER TABLE theauth_audit_logs ADD COLUMN event TEXT;

UPDATE theauth_audit_logs SET event = action WHERE event IS NULL AND action IN ('delegation.create', 'delegation.revoke', 'agent.cascade.revoked', 'approval.request', 'approval.approve', 'approval.deny', 'vault.read', 'audit.checkpoint', 'audit.write_failed', 'audit.erasure');

UPDATE theauth_audit_logs SET event = 'policy.evaluate' WHERE event IS NULL AND input_provenance IS NOT NULL AND decision_code IS NOT NULL;

UPDATE theauth_audit_logs SET event = 'authorize' WHERE event IS NULL AND decision_code IS NOT NULL;

CREATE INDEX theauth_audit_logs_event ON theauth_audit_logs (agent_id(191), event(64), recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0005', 'audit-event', '874694066ebfc5b503b578866fd278036e674c8b434d7a1557683eac5137f2b9', UTC_TIMESTAMP(3));
