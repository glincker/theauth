/* Migration 0004: audit-recorded-at-ms */

ALTER TABLE theauth_audit_logs ADD COLUMN recorded_at_ms BIGINT;

UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL;

CREATE INDEX theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0004', 'audit-recorded-at-ms', 'd4681739a401b09fd8e43a9c9acca2ff1fc0be5f85ebee4b4b10420abf49f5e4', UTC_TIMESTAMP(3));
