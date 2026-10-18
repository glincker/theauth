/* Migration 0002: audit-decision-code */

ALTER TABLE theauth_audit_logs ADD COLUMN decision_code TEXT;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_code ON theauth_audit_logs (agent_id, decision_code);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0002', 'audit-decision-code', '92eeedd758afaa83a009d8bf757f8b0d45c39b78da0b11735b5b5a9460de10c1', CAST(strftime('%s', 'now') AS INTEGER));
