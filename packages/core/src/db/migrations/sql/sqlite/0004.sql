/* Migration 0004: audit-recorded-at-ms */

ALTER TABLE theauth_audit_logs ADD COLUMN recorded_at_ms INTEGER;

UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0004', 'audit-recorded-at-ms', 'd3e8ef61d94bf93032170e50da4801113b91a10bef3cc5ab6977dae6b0a9c4f4', CAST(strftime('%s', 'now') AS INTEGER));
