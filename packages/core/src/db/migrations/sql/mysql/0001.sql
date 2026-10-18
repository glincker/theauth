/* Migration 0001: relation-and-cache-hit */

ALTER TABLE theauth_permissions ADD COLUMN relation TEXT;

ALTER TABLE theauth_audit_logs ADD COLUMN cache_hit TINYINT(1) NOT NULL DEFAULT 0;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0001', 'relation-and-cache-hit', 'b24b7e9f09c58b09143dca9474a3ddeec0e8f708589b6b39e2106f893a2fc19c', UTC_TIMESTAMP(3));
