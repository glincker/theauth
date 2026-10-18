/* Migration 0006: mcp-stores */

ALTER TABLE theauth_oauth_clients ADD COLUMN agent_id VARCHAR(191);

ALTER TABLE theauth_oauth_clients ADD CONSTRAINT theauth_oauth_clients_agent_fk FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE SET NULL;

ALTER TABLE theauth_oauth_clients ADD COLUMN scope TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN logo_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN jwks JSON;

ALTER TABLE theauth_oauth_clients ADD COLUMN jwks_uri TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN user_id TEXT;

ALTER TABLE theauth_oauth_clients ADD COLUMN source TEXT;

CREATE INDEX theauth_oauth_clients_agent ON theauth_oauth_clients (agent_id(191));

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN jti TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN family_id TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN token_type VARCHAR(32) NOT NULL DEFAULT 'Bearer';

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN dpop_jkt TEXT;

CREATE INDEX theauth_oauth_access_tokens_jti ON theauth_oauth_access_tokens (jti(191));

CREATE INDEX theauth_oauth_access_tokens_client ON theauth_oauth_access_tokens (client_id(191));

CREATE INDEX theauth_oauth_access_tokens_family ON theauth_oauth_access_tokens (family_id(191));

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0006', 'mcp-stores', 'b0e8f46dafd3cfc3f3e332c1c495404d3a01ace46b3732228ba6bd26194464f6', UTC_TIMESTAMP(3));
