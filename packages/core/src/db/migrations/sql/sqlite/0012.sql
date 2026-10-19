/* Migration 0012: oidc-refresh-family */

ALTER TABLE theauth_oidc_refresh_tokens ADD COLUMN family_id TEXT;

CREATE INDEX IF NOT EXISTS theauth_oidc_refresh_family ON theauth_oidc_refresh_tokens (family_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0012', 'oidc-refresh-family', '4c0906bd391266764e16d0fad413a59045df67c5904b3bda9c5871f09569c691', CAST(strftime('%s', 'now') AS INTEGER));
