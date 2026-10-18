import { is } from "drizzle-orm";
import { getTableConfig, SQLiteTable } from "drizzle-orm/sqlite-core";
import { describe, expect, it } from "vitest";
import * as oauthStores from "../src/auth/oauth/schema.js";
import { baselineStatements, TIMESTAMP_COLUMNS } from "../src/db/ddl/index.js";
import { epochTimestamps } from "../src/db/migrations/0003-epoch-timestamps.js";
import * as agentsExtra from "../src/db/schema/agents-extra.js";
import * as audit from "../src/db/schema/audit.js";
import { columnKind } from "../src/db/schema/columns.js";
import * as core from "../src/db/schema/core.js";
import * as enterprise from "../src/db/schema/enterprise.js";
import * as human from "../src/db/schema/human.js";
import * as oauth from "../src/db/schema/oauth.js";
import * as org from "../src/db/schema/org.js";
import * as signals from "../src/signals/schema.js";
import * as vault from "../src/vault/schema.js";

const MODULES: Array<Record<string, unknown>> = [
	agentsExtra,
	audit,
	core,
	enterprise,
	human,
	oauth,
	org,
	oauthStores,
	signals,
	vault,
];

function schemaTimestampColumns(): Set<string> {
	const found = new Set<string>();
	for (const mod of MODULES) {
		for (const value of Object.values(mod)) {
			if (!is(value, SQLiteTable)) continue;
			const cfg = getTableConfig(value);
			for (const col of cfg.columns) {
				const kind = columnKind(col);
				if (kind === "timestampSec") found.add(`${cfg.name}.${col.name}:seconds`);
				if (kind === "timestampMs") found.add(`${cfg.name}.${col.name}:ms`);
			}
		}
	}
	return found;
}

describe("TIMESTAMP_COLUMNS", () => {
	it("equals every timestampSec and timestampMs column of the Drizzle schema", () => {
		const listed = new Set(TIMESTAMP_COLUMNS.map((c) => `${c.table}.${c.column}:${c.unit}`));
		expect([...listed].sort()).toEqual([...schemaTimestampColumns()].sort());
		expect(listed.size).toBe(TIMESTAMP_COLUMNS.length);
	});

	it("lists only BIGINT columns of the Postgres baseline", () => {
		const sql = baselineStatements("postgres").map((s) => s.sql);
		for (const { table, column } of TIMESTAMP_COLUMNS) {
			const create = sql.find((s) => new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(`).test(s));
			expect(create, table).toBeDefined();
			expect(create, `${table}.${column}`).toMatch(new RegExp(`\\n\\s+${column}\\s+BIGINT\\b`));
		}
		for (const dialect of ["postgres", "mysql"] as const) {
			for (const { sql } of baselineStatements(dialect)) {
				expect(sql).not.toMatch(/TIMESTAMPTZ|DATETIME\(3\)/);
			}
		}
	});
});

describe("migration 0003-epoch-timestamps", () => {
	it("is a no-op on SQLite and MySQL", () => {
		expect(epochTimestamps.up.sqlite).toEqual([]);
		expect(epochTimestamps.up.mysql).toEqual([]);
	});

	it("converts only columns that are still TIMESTAMPTZ, one single line DO block per table", () => {
		const statements = epochTimestamps.up.postgres;
		const tables = new Set(TIMESTAMP_COLUMNS.map((c) => c.table));
		expect(statements).toHaveLength(tables.size);
		for (const sql of statements) {
			expect(sql).toMatch(/^DO \$\$ .* END \$\$$/);
			expect(sql).not.toContain(";\n");
			expect(sql).not.toContain("\n");
			expect(sql).toContain("data_type = 'timestamp with time zone'");
			expect(sql).toContain("USING floor(extract(epoch FROM %I) * %s)::bigint");
		}
		const login = statements.find((s) => s.includes("'theauth_login_history'"));
		expect(login).toContain("('timestamp', 1000)");
		const users = statements.find((s) => s.includes("'theauth_users'"));
		expect(users).toContain("('created_at', 1)");
	});
});
