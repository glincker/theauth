/* Migration 0011: oauth-auth-evidence */

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN auth_acr TEXT;

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN auth_amr TEXT;

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN auth_time INTEGER;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN auth_acr TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN auth_amr TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN auth_time INTEGER;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0011', 'oauth-auth-evidence', '47e641bf53e9aa977b96e7590286fd4d2ef02fa61b2f55b9c6e5b0973935de85', CAST(strftime('%s', 'now') AS INTEGER));
