/* Migration 0008: cimd */

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_document TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_digest TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_fetched_at INTEGER;

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_expires_at INTEGER;

ALTER TABLE theauth_oauth_clients ADD COLUMN disabled_reason TEXT;

CREATE TABLE IF NOT EXISTS theauth_mcp_client_blocks (
  id          TEXT NOT NULL PRIMARY KEY,
  kind        TEXT NOT NULL,
  value       TEXT NOT NULL,
  reason      TEXT,
  created_by  TEXT,
  created_at  INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_mcp_client_blocks_rule ON theauth_mcp_client_blocks (kind, value);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0008', 'cimd', '1988962b76e3ecea370f5c425fd3d629ca969dc8c39a21c2372c6c333b1b96ac', CAST(strftime('%s', 'now') AS INTEGER));
