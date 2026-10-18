/* Migration 0003: audit-recorded-at-ms */

ALTER TABLE theauth_audit_logs ADD COLUMN recorded_at_ms BIGINT;

UPDATE theauth_audit_logs SET recorded_at_ms = CAST(UNIX_TIMESTAMP(timestamp) * 1000 AS SIGNED) WHERE recorded_at_ms IS NULL;

CREATE INDEX theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0003', 'audit-recorded-at-ms', '9db8b19b72e9bd26dcc54297bd4908152a3f4874cca7bdd9a8beee8ea9129c64', NOW(3));
