/* Migration 0009: step-up-and-confirmation */

ALTER TABLE theauth_approval_requests ADD COLUMN IF NOT EXISTS required_acr TEXT;

ALTER TABLE theauth_approval_requests ADD COLUMN IF NOT EXISTS max_auth_age INTEGER;

ALTER TABLE theauth_agents ADD COLUMN IF NOT EXISTS cnf JSONB;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0009', 'step-up-and-confirmation', '19336e84d41cbbc8bbd3617a1035818e66d306f70d6d0d9bca2ce8d6ae7c39e0', NOW());
