/* Migration 0004: audit-recorded-at-ms */

ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS recorded_at_ms BIGINT;

UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0004', 'audit-recorded-at-ms', '4f7c1a5f0a8786680acb191e0a71e344f3b9d2bb83c831a3be02ac4082472eac', NOW());
