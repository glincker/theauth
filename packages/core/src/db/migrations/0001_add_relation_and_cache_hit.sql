-- Migration 0001: add policy-engine columns
--
-- permissions.relation: optional ReBAC relation; when set, the policy engine
-- consults the relationship graph during evaluation.
--
-- audit_logs.cache_hit: marks whether the audit row corresponds to a
-- cache-hit evaluation (no cold evaluation was performed).
--
-- Both columns are additive; existing rows are unaffected.

ALTER TABLE kavach_permissions ADD COLUMN relation TEXT;

ALTER TABLE kavach_audit_logs ADD COLUMN cache_hit BOOLEAN NOT NULL DEFAULT FALSE;
