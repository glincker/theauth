/* Migration 0006: mcp-stores */

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS agent_id TEXT REFERENCES theauth_agents(id) ON DELETE SET NULL;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS scope TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS logo_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS jwks JSONB;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS jwks_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS user_id TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN IF NOT EXISTS source TEXT;

CREATE INDEX IF NOT EXISTS theauth_oauth_clients_agent ON theauth_oauth_clients (agent_id);

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN IF NOT EXISTS jti TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN IF NOT EXISTS family_id TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN IF NOT EXISTS token_type TEXT NOT NULL DEFAULT 'Bearer';

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN IF NOT EXISTS dpop_jkt TEXT;

CREATE INDEX IF NOT EXISTS theauth_oauth_access_tokens_jti ON theauth_oauth_access_tokens (jti);

CREATE INDEX IF NOT EXISTS theauth_oauth_access_tokens_client ON theauth_oauth_access_tokens (client_id);

CREATE INDEX IF NOT EXISTS theauth_oauth_access_tokens_family ON theauth_oauth_access_tokens (family_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0006', 'mcp-stores', '7a331ea076c3c1d627083f24d67a184e401455a7d6cacff08be9bdcb6809d725', NOW());
