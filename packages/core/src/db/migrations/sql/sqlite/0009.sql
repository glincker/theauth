/* Migration 0009: step-up-and-confirmation */

ALTER TABLE theauth_approval_requests ADD COLUMN required_acr TEXT;

ALTER TABLE theauth_approval_requests ADD COLUMN max_auth_age INTEGER;

ALTER TABLE theauth_agents ADD COLUMN cnf TEXT;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0009', 'step-up-and-confirmation', '6874e4fc971b5bb503750bb228c4acc6b48e14bd1c2a570b3cc3a37ba04ca8af', CAST(strftime('%s', 'now') AS INTEGER));
