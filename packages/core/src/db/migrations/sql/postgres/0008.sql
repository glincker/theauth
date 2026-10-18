/* Migration 0008: cimd */

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS cimd_document JSONB;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS cimd_digest TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS cimd_fetched_at BIGINT;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS cimd_expires_at BIGINT;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS disabled_reason TEXT;

CREATE TABLE IF NOT EXISTS theauth_mcp_client_blocks (
  id          TEXT NOT NULL PRIMARY KEY,
  kind        TEXT NOT NULL,
  value       TEXT NOT NULL,
  reason      TEXT,
  created_by  TEXT,
  created_at  BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_mcp_client_blocks_rule ON theauth_mcp_client_blocks (kind, value);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0008', 'cimd', '491a756cd05b2f7e952563f773021ccc568fb8192b91e933567ed08ad2a921f3', NOW());
