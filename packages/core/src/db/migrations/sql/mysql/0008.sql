/* Migration 0008: cimd */

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_document JSON;

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_digest TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_fetched_at BIGINT;

ALTER TABLE theauth_oauth_clients ADD COLUMN cimd_expires_at BIGINT;

ALTER TABLE theauth_oauth_clients ADD COLUMN disabled_reason TEXT;

CREATE TABLE IF NOT EXISTS theauth_mcp_client_blocks (
  id          VARCHAR(191) NOT NULL PRIMARY KEY,
  kind        VARCHAR(191) NOT NULL,
  value       VARCHAR(512) NOT NULL,
  reason      TEXT,
  created_by  TEXT,
  created_at  BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE UNIQUE INDEX theauth_mcp_client_blocks_rule ON theauth_mcp_client_blocks (kind, value(191));

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0008', 'cimd', '08ea9f3a82cc7f44454fb7acef17e6601232d477f775aecdb1aeea0981688284', UTC_TIMESTAMP(3));
