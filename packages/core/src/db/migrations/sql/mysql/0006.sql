/* Migration 0006: mcp-stores */

ALTER TABLE theauth_oauth_clients ADD COLUMN agent_id TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN scope TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN logo_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN jwks JSON;

ALTER TABLE theauth_oauth_clients ADD COLUMN jwks_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN user_id TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN source TEXT;

CREATE INDEX theauth_oauth_clients_agent ON theauth_oauth_clients (agent_id(191));

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN jti TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN family_id TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN token_type TEXT NOT NULL DEFAULT 'Bearer';

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN dpop_jkt TEXT;

CREATE INDEX theauth_oauth_access_tokens_jti ON theauth_oauth_access_tokens (jti(191));

CREATE INDEX theauth_oauth_access_tokens_client ON theauth_oauth_access_tokens (client_id(191));

CREATE INDEX theauth_oauth_access_tokens_family ON theauth_oauth_access_tokens (family_id(191));

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0006', 'mcp-stores', '77c8d23596086dffc77fa0b789dce3e5be886664baaa6aef5a4782878754f5bd', NOW(3));
