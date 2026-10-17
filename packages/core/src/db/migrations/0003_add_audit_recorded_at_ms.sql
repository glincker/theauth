-- Migration 0003: millisecond write order for audit rows
--
-- audit_logs.recorded_at_ms: epoch milliseconds assigned when the row is
-- written. `timestamp` only has 1 second resolution, so rows written in the
-- same second used to come back in unpredictable order. recorded_at_ms is
-- strictly increasing per agent chain (and per process), and audit reads order
-- by it (then timestamp, chain_seq, id, so ties are deterministic).
--
-- The column is NOT part of the audit hash payload (hash version stays 2), so
-- existing chains and the Go verifier keep verifying. Existing rows are
-- backfilled from their second-resolution timestamp; rows from the same second
-- keep a stable order through chain_seq and id.
--
-- createTables() applies this automatically on startup unless
-- `database.skipMigrations` is set. Run it by hand in that case.
-- The statements below are for Postgres. On SQLite drop "IF NOT EXISTS" from
-- the ALTER and use INTEGER. MySQL users use the variants in the comments.

-- SQLite: INTEGER.  Postgres and MySQL: BIGINT (epoch ms overflows 32 bits).
ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS recorded_at_ms BIGINT;

-- Backfill (pick one):
--   Postgres: UPDATE theauth_audit_logs
--               SET recorded_at_ms = CAST(EXTRACT(EPOCH FROM timestamp) * 1000 AS BIGINT)
--               WHERE recorded_at_ms IS NULL;
--   MySQL:    UPDATE theauth_audit_logs
--               SET recorded_at_ms = CAST(UNIX_TIMESTAMP(timestamp) * 1000 AS SIGNED)
--               WHERE recorded_at_ms IS NULL;
--   SQLite:   UPDATE theauth_audit_logs
--               SET recorded_at_ms = timestamp * 1000
--               WHERE recorded_at_ms IS NULL;
UPDATE theauth_audit_logs
  SET recorded_at_ms = CAST(EXTRACT(EPOCH FROM timestamp) * 1000 AS BIGINT)
  WHERE recorded_at_ms IS NULL;

-- MySQL has no CREATE INDEX IF NOT EXISTS: drop "IF NOT EXISTS" there.
CREATE INDEX IF NOT EXISTS theauth_audit_logs_order
  ON theauth_audit_logs (recorded_at_ms);
