/* Migration 0003: audit-recorded-at-ms */

ALTER TABLE theauth_audit_logs ADD COLUMN recorded_at_ms INTEGER;

UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0003', 'audit-recorded-at-ms', '2c89cfc45a8541d827eff0a06c0e51b4f631e6aaacaa0b0464c882a21fa8aa68', CAST(strftime('%s', 'now') AS INTEGER));
