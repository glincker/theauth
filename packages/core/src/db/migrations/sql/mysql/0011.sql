/* Migration 0011: oauth-auth-evidence */

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN auth_acr TEXT;

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN auth_amr TEXT;

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN auth_time BIGINT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN auth_acr TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN auth_amr TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN auth_time BIGINT;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0011', 'oauth-auth-evidence', '200d89a422b2db52b4e6898f22da194cac5e9aacc7950d5e0970175dac0c2c77', UTC_TIMESTAMP(3));
