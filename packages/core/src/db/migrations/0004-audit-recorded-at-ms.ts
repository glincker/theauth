import type { Migration } from "../migrate/types.js";

/**
 * Millisecond write order for audit rows. `timestamp` only has one second resolution, so rows written in the same second used to come back in unpredictable order. `recorded_at_ms` is strictly increasing per agent chain (and per process); audit reads order by it, then timestamp, chain_seq and id, so ties are deterministic.
 *
 * The column is NOT part of the audit hash payload (hash version stays 2), so existing chains keep verifying. Existing rows are backfilled from their second resolution timestamp (only NULL rows, so reruns are no-ops).
 */
export const auditRecordedAtMs: Migration = {
	id: "0004",
	name: "audit-recorded-at-ms",
	requires: ["audit"],
	up: {
		// INTEGER is 64 bit on SQLite. Postgres and MySQL need BIGINT (epoch ms overflows 32 bits).
		// Runs after 0003, so `timestamp` is integer epoch seconds on every dialect.
		sqlite: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN recorded_at_ms INTEGER",
			"UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL",
			"CREATE INDEX IF NOT EXISTS theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms)",
		],
		postgres: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS recorded_at_ms BIGINT",
			"UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL",
			"CREATE INDEX IF NOT EXISTS theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms)",
		],
		mysql: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN recorded_at_ms BIGINT",
			"UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL",
			"CREATE INDEX theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms)",
		],
	},
};
