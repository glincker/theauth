/* Migration 0002: audit-decision-code */

ALTER TABLE theauth_audit_logs ADD COLUMN decision_code TEXT;

CREATE INDEX theauth_audit_logs_code ON theauth_audit_logs (agent_id(191), decision_code(64));

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0002', 'audit-decision-code', '80c94f78edc80e5a561fa3e53f6cda80a285c1c803f790aee489afad4a7075ff', UTC_TIMESTAMP(3));
