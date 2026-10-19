/* Migration 0009: step-up-and-confirmation */

ALTER TABLE theauth_approval_requests ADD COLUMN required_acr TEXT;

ALTER TABLE theauth_approval_requests ADD COLUMN max_auth_age INTEGER;

ALTER TABLE theauth_agents ADD COLUMN cnf JSON;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0009', 'step-up-and-confirmation', 'a49b5ba198e2523cb0f6259a1d5e73be847061a1a09ec4c34cac82273685a7dd', UTC_TIMESTAMP(3));
