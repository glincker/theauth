/* Migration 0005: audit-event */

ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS event TEXT;

UPDATE theauth_audit_logs SET event = action WHERE event IS NULL AND action IN ('delegation.create', 'delegation.revoke', 'agent.cascade.revoked', 'approval.request', 'approval.approve', 'approval.deny', 'vault.read', 'audit.checkpoint', 'audit.write_failed', 'audit.erasure');

UPDATE theauth_audit_logs SET event = 'policy.evaluate' WHERE event IS NULL AND input_provenance IS NOT NULL AND decision_code IS NOT NULL;

UPDATE theauth_audit_logs SET event = 'authorize' WHERE event IS NULL AND decision_code IS NOT NULL;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_event ON theauth_audit_logs (agent_id, event, recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0005', 'audit-event', 'f2525ada1a6d03d4a7a738561158a4aeffe9c38f238fed06f965236a544d94dd', NOW());
