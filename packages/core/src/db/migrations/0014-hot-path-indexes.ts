import type { Dialect, Migration } from "../migrate/types.js";

/**
 * Indexes for the lookups every authorize call and agent token check makes.
 *
 * Found with `EXPLAIN QUERY PLAN` on SQLite: without these, agent lookup by token hash, the
 * inbound and outbound delegation walks, the hourly rate limit read and the pending approval list
 * all scan their whole table (on 50,000 delegation and 200,000 permission rows an authorize through a three hop
 * chain took about 10 ms, and about 0.4 ms with the indexes; see docs/performance.mdx).
 *
 * Additive only, safe to re-run. The two delegation chain indexes carry the names migration 0007 gave them, so a
 * database that already has them keeps one copy (`IF NOT EXISTS`, and the runner tolerates "duplicate key name" on
 * MySQL). On MySQL the foreign key columns are already indexed by InnoDB, so only the composite and `TEXT` columns
 * are added there (`TEXT` needs a prefix length).
 */
function statements(dialect: Dialect): string[] {
	const my = dialect === "mysql";
	const idx = (name: string, table: string, cols: string, myCols = cols): string =>
		my
			? `CREATE INDEX ${name} ON ${table} (${myCols})`
			: `CREATE INDEX IF NOT EXISTS ${name} ON ${table} (${cols})`;
	const out = [
		idx("theauth_agents_token_hash", "theauth_agents", "token_hash", "token_hash(191)"),
		idx("theauth_agents_owner_status", "theauth_agents", "owner_id, status"),
		idx(
			"theauth_delegation_chains_to",
			"theauth_delegation_chains",
			"to_agent_id, status",
			"to_agent_id(191), status(16)",
		),
		idx(
			"theauth_delegation_chains_from",
			"theauth_delegation_chains",
			"from_agent_id, status",
			"from_agent_id(191), status(16)",
		),
		idx(
			"theauth_rate_limits_lookup",
			"theauth_rate_limits",
			"agent_id, resource, window_start",
			"agent_id, resource(191), window_start",
		),
		idx("theauth_approval_requests_status", "theauth_approval_requests", "status, created_at"),
	];
	// InnoDB already indexes the foreign key column.
	if (!my) out.push(idx("theauth_permissions_agent", "theauth_permissions", "agent_id"));
	return out;
}

export const hotPathIndexes: Migration = {
	id: "0014",
	name: "hot-path-indexes",
	requires: ["agent"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
