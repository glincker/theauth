import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * Shared MCP revocation list (jti, delegation, agent, subject and client entries) and the delegation chain indexes the live checks need.
 *
 * Additive only. The table needs the MCP feature (`requires`); the chain indexes are added only when the agent tables exist (`statementsFor`), so they are no-ops otherwise.
 */
function statements(dialect: Dialect, withAgents: boolean): string[] {
	const t = ddlTypes(dialect);
	const my = t.isMysql;
	const kind = my ? "VARCHAR(16)" : "TEXT";
	const idx = (name: string, table: string, cols: string, myCols: string): string =>
		my
			? `CREATE INDEX ${name} ON ${table} (${myCols})`
			: `CREATE INDEX IF NOT EXISTS ${name} ON ${table} (${cols})`;
	const out = [
		`CREATE TABLE IF NOT EXISTS theauth_mcp_revocations (
  kind          ${kind} NOT NULL,
  id            ${t.vc} NOT NULL,
  revoked_at_ms ${t.big} NOT NULL,
  expires_at    ${t.big} NOT NULL,
  reason        TEXT NOT NULL,
  source_id     TEXT,
  PRIMARY KEY (kind, id)
)`,
		idx("theauth_mcp_revocations_exp", "theauth_mcp_revocations", "expires_at", "expires_at"),
		idx("theauth_mcp_revocations_ms", "theauth_mcp_revocations", "revoked_at_ms", "revoked_at_ms"),
	];
	if (withAgents) {
		out.push(
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
		);
	}
	return out;
}

export const mcpRevocation: Migration = {
	id: "0007",
	name: "mcp-revocation",
	requires: ["mcp"],
	up: {
		sqlite: statements("sqlite", true),
		postgres: statements("postgres", true),
		mysql: statements("mysql", true),
	},
	// The chain indexes need the agent tables, which only exist when agents are enabled.
	statementsFor: (dialect, features) => statements(dialect, features.agent),
};
