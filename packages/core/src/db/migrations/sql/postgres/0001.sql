/* Migration 0001: relation-and-cache-hit */

ALTER TABLE theauth_permissions ADD COLUMN IF NOT EXISTS relation TEXT;

ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN NOT NULL DEFAULT FALSE;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0001', 'relation-and-cache-hit', '8dd0606cfdaa1695730b512f86ae5d1ba07d4b9b8e9dc748b17ebb8614344b2e', NOW());
