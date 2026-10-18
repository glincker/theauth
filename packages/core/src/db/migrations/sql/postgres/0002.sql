/* Migration 0002: audit-decision-code */

ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS decision_code TEXT;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_code ON theauth_audit_logs (agent_id, decision_code);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0002', 'audit-decision-code', '97781c9afbdd744fb231282240a72aa44018eca57b41e6312dff07c2d9f33516', NOW());
