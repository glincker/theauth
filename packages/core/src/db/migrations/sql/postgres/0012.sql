/* Migration 0012: oidc-refresh-family */

ALTER TABLE theauth_oidc_refresh_tokens ADD COLUMN IF NOT EXISTS family_id TEXT;

CREATE INDEX IF NOT EXISTS theauth_oidc_refresh_family ON theauth_oidc_refresh_tokens (family_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0012', 'oidc-refresh-family', '3b816971a2c1c13493d9d9c6a715f12e0d86f97d94af94ba0ac3db3d46d5533d', NOW());
