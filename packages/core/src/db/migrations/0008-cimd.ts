import { MYSQL_TABLE_OPTIONS } from "../ddl/mysql.js";
import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * Client ID Metadata Documents: the fetched snapshot and its expiry on `theauth_oauth_clients`, a reason for disabled clients, and `theauth_mcp_client_blocks` for admin blocks by URL or host.
 *
 * Additive and nullable, so rows written before this migration stay valid. The table only exists when the oauth feature is enabled (`requires`), and the new columns are added to `theauth_oauth_clients` only on the migrated path: the baseline DDL and the timestamp list stay frozen with migrations 0000 and 0003.
 */
function statements(dialect: Dialect): string[] {
	const t = ddlTypes(dialect);
	const ine = dialect === "postgres" ? "IF NOT EXISTS " : "";
	const key = t.vc;
	const value = dialect === "mysql" ? "VARCHAR(512)" : "TEXT";
	// The unique index covers the whole value (VARCHAR(512) plus the 191 char kind is 2812 bytes, under the 3072 limit): a prefix on a UNIQUE index would treat two long URLs with the same first 191 characters as duplicates.
	const blockIdx =
		dialect === "mysql"
			? "CREATE UNIQUE INDEX theauth_mcp_client_blocks_rule ON theauth_mcp_client_blocks (kind, value)"
			: "CREATE UNIQUE INDEX IF NOT EXISTS theauth_mcp_client_blocks_rule ON theauth_mcp_client_blocks (kind, value)";
	return [
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}cimd_document ${t.json}`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}cimd_digest TEXT`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}cimd_fetched_at ${t.ts}`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}cimd_expires_at ${t.ts}`,
		`ALTER TABLE theauth_oauth_clients ADD COLUMN ${ine}disabled_reason TEXT`,
		`CREATE TABLE IF NOT EXISTS theauth_mcp_client_blocks (
  id          ${key} NOT NULL PRIMARY KEY,
  kind        ${key} NOT NULL,
  value       ${value} NOT NULL,
  reason      TEXT,
  created_by  TEXT,
  created_at  ${t.ts} NOT NULL
)${dialect === "mysql" ? ` ${MYSQL_TABLE_OPTIONS}` : ""}`,
		blockIdx,
	];
}

export const cimd: Migration = {
	id: "0008",
	name: "cimd",
	requires: ["oauth"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
