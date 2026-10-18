/* Migration 0006: mcp-stores */

ALTER TABLE theauth_oauth_clients ADD COLUMN agent_id TEXT REFERENCES theauth_agents(id) ON DELETE SET NULL;

ALTER TABLE theauth_oauth_clients ADD COLUMN scope TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN logo_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN jwks TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN jwks_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN user_id TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN source TEXT;

CREATE INDEX IF NOT EXISTS theauth_oauth_clients_agent ON theauth_oauth_clients (agent_id);

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN jti TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN family_id TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN token_type TEXT NOT NULL DEFAULT 'Bearer';

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN dpop_jkt TEXT;

CREATE INDEX IF NOT EXISTS theauth_oauth_access_tokens_jti ON theauth_oauth_access_tokens (jti);

CREATE INDEX IF NOT EXISTS theauth_oauth_access_tokens_client ON theauth_oauth_access_tokens (client_id);

CREATE INDEX IF NOT EXISTS theauth_oauth_access_tokens_family ON theauth_oauth_access_tokens (family_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0006', 'mcp-stores', 'bba2d4cc1761ca64db065c88275b2b8b493f45490f2496a6771082d6daccb6df', CAST(strftime('%s', 'now') AS INTEGER));
