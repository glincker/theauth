/* Migration 0003: audit-recorded-at-ms */

ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS recorded_at_ms BIGINT;

UPDATE theauth_audit_logs SET recorded_at_ms = CAST(EXTRACT(EPOCH FROM timestamp) * 1000 AS BIGINT) WHERE recorded_at_ms IS NULL;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0003', 'audit-recorded-at-ms', '533d60646ead9482ea975234295690841dd141857a701608d9c7a8c142598684', NOW());
