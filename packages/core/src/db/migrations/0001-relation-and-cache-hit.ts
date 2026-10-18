import { columnNames } from "../migrate/probe.js";
import type { Migration } from "../migrate/types.js";

/**
 * Policy engine columns. `theauth_permissions.relation` (optional ReBAC relation) and `theauth_audit_logs.cache_hit` (marks cache-hit evaluations). Both are additive. Databases released as 1.x already have both columns: they are stamped as applied instead of re-run.
 */
export const relationAndCacheHit: Migration = {
	id: "0001",
	name: "relation-and-cache-hit",
	requires: ["agent", "audit"],
	detect: async (exec) =>
		(await columnNames(exec, "theauth_permissions")).has("relation") &&
		(await columnNames(exec, "theauth_audit_logs")).has("cache_hit"),
	up: {
		sqlite: [
			"ALTER TABLE theauth_permissions ADD COLUMN relation TEXT",
			"ALTER TABLE theauth_audit_logs ADD COLUMN cache_hit INTEGER NOT NULL DEFAULT 0",
		],
		postgres: [
			"ALTER TABLE theauth_permissions ADD COLUMN IF NOT EXISTS relation TEXT",
			"ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN NOT NULL DEFAULT FALSE",
		],
		mysql: [
			"ALTER TABLE theauth_permissions ADD COLUMN relation TEXT",
			"ALTER TABLE theauth_audit_logs ADD COLUMN cache_hit TINYINT(1) NOT NULL DEFAULT 0",
		],
	},
};
