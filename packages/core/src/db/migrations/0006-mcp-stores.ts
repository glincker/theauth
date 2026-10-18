import type { Migration } from "../migrate/types.js";

/**
 * Columns the database backed MCP stores need, plus the first class binding of an OAuth client to an agent.
 *
 * `theauth_oauth_clients`: `agent_id` (the agent this client acts as, set null when the agent row is deleted), `scope`, `logo_uri`, `jwks`, `jwks_uri`, `user_id`, `source`. `theauth_oauth_access_tokens`: `jti`, `family_id`, `token_type`, `dpop_jkt`, with indexes on `jti`, `client_id` and `family_id`.
 *
 * All additive and nullable (except `token_type`, which defaults to Bearer), so rows written before this migration stay valid. Stored token values stay SHA-256 digests.
 */
const AGENT_FK = "REFERENCES theauth_agents(id) ON DELETE SET NULL";

function statements(dialect: "sqlite" | "postgres" | "mysql", withAgentFk: boolean): string[] {
	const ine = dialect === "postgres" ? "IF NOT EXISTS " : "";
	const json = dialect === "postgres" ? "JSONB" : dialect === "mysql" ? "JSON" : "TEXT";
	const fk = withAgentFk && dialect !== "mysql" ? ` ${AGENT_FK}` : "";
	const idx = (name: string, table: string, column: string): string => {
		if (dialect === "mysql") return `CREATE INDEX ${name} ON ${table} (${column}(191))`;
		return `CREATE INDEX IF NOT EXISTS ${name} ON ${table} (${column})`;
	};
	return [
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}agent_id TEXT${fk}`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}scope TEXT`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}logo_uri TEXT`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}jwks ${json}`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}jwks_uri TEXT`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}user_id TEXT`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}source TEXT`,
		idx("theauth_oauth_clients_agent", "theauth_oauth_clients", "agent_id"),
		`ALTER TABLE theauth_oauth_access_tokens ADD COLUMN ${ine}jti TEXT`,
		`ALTER TABLE theauth_oauth_access_tokens ADD COLUMN ${ine}family_id TEXT`,
		`ALTER TABLE theauth_oauth_access_tokens ADD COLUMN ${ine}token_type TEXT NOT NULL DEFAULT 'Bearer'`,
		`ALTER TABLE theauth_oauth_access_tokens ADD COLUMN ${ine}dpop_jkt TEXT`,
		idx("theauth_oauth_access_tokens_jti", "theauth_oauth_access_tokens", "jti"),
		idx("theauth_oauth_access_tokens_client", "theauth_oauth_access_tokens", "client_id"),
		idx("theauth_oauth_access_tokens_family", "theauth_oauth_access_tokens", "family_id"),
	];
}

export const mcpStores: Migration = {
	id: "0006",
	name: "mcp-stores",
	requires: ["oauth"],
	up: {
		sqlite: statements("sqlite", true),
		postgres: statements("postgres", true),
		mysql: statements("mysql", true),
	},
	// The agent table only exists when agents are enabled: without it the foreign key could not be created.
	statementsFor: (dialect, features) => statements(dialect, features.agent),
};
