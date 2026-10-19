/* Migration 0012: oidc-refresh-family */

ALTER TABLE theauth_oidc_refresh_tokens ADD COLUMN family_id VARCHAR(191);

CREATE INDEX theauth_oidc_refresh_family ON theauth_oidc_refresh_tokens (family_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0012', 'oidc-refresh-family', 'a11f41d79d494f75d33e988a0526509b35092bfd4904b036a76de662014db3d6', UTC_TIMESTAMP(3));
