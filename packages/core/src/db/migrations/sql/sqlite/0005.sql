/* Migration 0005: audit-event */

ALTER TABLE theauth_audit_logs ADD COLUMN event TEXT;

UPDATE theauth_audit_logs SET event = action WHERE event IS NULL AND action IN ('delegation.create', 'delegation.revoke', 'agent.cascade.revoked', 'approval.request', 'approval.approve', 'approval.deny', 'vault.read', 'audit.checkpoint', 'audit.write_failed', 'audit.erasure');

UPDATE theauth_audit_logs SET event = 'policy.evaluate' WHERE event IS NULL AND input_provenance IS NOT NULL AND decision_code IS NOT NULL;

UPDATE theauth_audit_logs SET event = 'authorize' WHERE event IS NULL AND decision_code IS NOT NULL;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_event ON theauth_audit_logs (agent_id, event, recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0005', 'audit-event', '76b356c9d9869c3d76a423266d6a6d90decfb95a716da9221ca8cfd527455d12', CAST(strftime('%s', 'now') AS INTEGER));
