-- Migration 0002: add the machine-readable decision code to audit rows
--
-- audit_logs.decision_code: the DecisionCode of the authorization outcome
-- (for example allowed, no_permission, hook_denied, hook_timeout). Nullable,
-- so rows written before this migration stay valid and read back with no code.
--
-- The column is NOT part of the audit hash payload (hash version stays 2), so
-- existing chains and the Go verifier keep verifying. It is an index
-- convenience derived from the decision; `reason` remains the hashed text.
--
-- createTables() applies this automatically on startup unless
-- `database.skipMigrations` is set. Run it by hand in that case.
-- The statements below are for Postgres and SQLite. MySQL users replace the
-- index with:
--   CREATE INDEX theauth_audit_logs_code
--     ON theauth_audit_logs (agent_id(191), decision_code(64));
-- On SQLite, drop "IF NOT EXISTS" from the ALTER (SQLite does not support it).

ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS decision_code TEXT;

CREATE INDEX IF NOT EXISTS theauth_audit_logs_code
  ON theauth_audit_logs (agent_id, decision_code);
