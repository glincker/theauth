/* Migration 0001: relation-and-cache-hit */

ALTER TABLE theauth_permissions ADD COLUMN relation TEXT;

ALTER TABLE theauth_audit_logs ADD COLUMN cache_hit INTEGER NOT NULL DEFAULT 0;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0001', 'relation-and-cache-hit', '46017d90348ef32eac64b6dc48cf067a6e7cc4a9262e5494793cfe3b80c8bd85', CAST(strftime('%s', 'now') AS INTEGER));
