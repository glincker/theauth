/* Migration 0011: oauth-auth-evidence */

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN IF NOT EXISTS auth_acr TEXT;

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN IF NOT EXISTS auth_amr TEXT;

ALTER TABLE theauth_oauth_authorization_codes ADD COLUMN IF NOT EXISTS auth_time BIGINT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN IF NOT EXISTS auth_acr TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN IF NOT EXISTS auth_amr TEXT;

ALTER TABLE theauth_oauth_access_tokens ADD COLUMN IF NOT EXISTS auth_time BIGINT;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0011', 'oauth-auth-evidence', '316afddcadf394274085a588b68c0edfc72a433da1cb71d542e0992d31702387', NOW());
