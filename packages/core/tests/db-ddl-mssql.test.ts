import { isTable } from "drizzle-orm";
import { getTableConfig } from "drizzle-orm/sqlite-core";
import { describe, expect, it } from "vitest";
import { oauthStates } from "../src/auth/oauth/schema.js";
import { baselineStatements } from "../src/db/ddl/index.js";
import { declaredKeys, MSSQL_COLLATION, mssqlSchema } from "../src/db/ddl/mssql.js";
import { MIGRATIONS } from "../src/db/migrations/index.js";
import * as schema from "../src/db/schema.js";

const tables = Object.values(schema).filter((v) => isTable(v));
const ddl = mssqlSchema({ oauthStates });
const text = [...ddl.tables, ...ddl.indexes, ...ddl.foreignKeys.map((f) => f.sql)].join("\n");

describe("SQL Server DDL generator", () => {
	it("creates one table per schema table plus the plugin table, in an idempotent form", () => {
		expect(ddl.tables).toHaveLength(tables.length + 1);
		for (const statement of ddl.tables) {
			expect(statement).toMatch(
				/^IF OBJECT_ID\(N'theauth_\w+', N'U'\) IS NULL\nCREATE TABLE \[theauth_\w+\]/,
			);
		}
		expect(ddl.tables.some((s) => s.includes("[theauth_oauth_states]"))).toBe(true);
	});

	it("declares every column the schema has", () => {
		for (const table of tables) {
			const config = getTableConfig(table);
			const statement = ddl.tables.find((s) => s.includes(`CREATE TABLE [${config.name}] (`)) ?? "";
			for (const col of config.columns) expect(statement).toContain(`[${col.name}] `);
		}
	});

	it("keeps every index and multi column unique the portable DDL and the migrations declare", () => {
		const statements = [
			...baselineStatements("sqlite").map((s) => s.sql),
			...MIGRATIONS.flatMap((m) => (m.id === "0000" ? [] : m.up.sqlite)),
		];
		const declaredIndexes = statements.filter((s) => /^\s*CREATE\s+(UNIQUE\s+)?INDEX/i.test(s));
		expect(declaredKeys().filter((k) => k.name.startsWith("uq_")).length).toBeGreaterThan(0);
		for (const stmt of declaredIndexes) {
			const m = /INDEX\s+(?:IF NOT EXISTS\s+)?(\w+)\s+ON\s+(\w+)\s*\(([^)]*)\)/i.exec(
				stmt.replace(/\s+/g, " "),
			);
			const [, name = "", table = "", cols = ""] = m ?? [];
			const columns = cols.split(",").map((c) => c.trim().replace(/\s+(ASC|DESC)$/i, ""));
			// A unique index on one column the Drizzle schema already declares unique is created once, under the column's name.
			const sameKey = `[${table}] (${columns.map((c) => `[${c}]`).join(", ")}`;
			expect(text.includes(`[${name}]`) || text.includes(sameKey), `index ${name}`).toBe(true);
		}
	});

	it("makes the audit chain index unique and filtered, so legacy rows without a seq never collide", () => {
		const chain = ddl.indexes.find((s) => s.includes("[theauth_audit_logs_chain]")) ?? "";
		expect(chain).toContain("CREATE UNIQUE INDEX");
		expect(chain).toContain("([agent_id], [chain_seq]) WHERE [chain_seq] IS NOT NULL");
	});

	it("filters a unique key that has a nullable column, and only those", () => {
		const hw = ddl.indexes.find((s) => s.includes("[theauth_devices_owner_hw]")) ?? "";
		expect(hw).toContain("WHERE [hardware_id] IS NOT NULL");
		const lookup = ddl.indexes.find((s) => s.includes("[theauth_device_credentials_lookup]")) ?? "";
		expect(lookup).not.toMatch(/\) WHERE \[/);
	});

	it("uses a binary collation on every text column and bounded text for keys", () => {
		const nvarchar = text.match(/NVARCHAR\((?:\d+|MAX)\) COLLATE \S+/g) ?? [];
		expect(nvarchar.length).toBeGreaterThan(100);
		for (const t of nvarchar) expect(t.endsWith(MSSQL_COLLATION)).toBe(true);
		const users = ddl.tables.find((s) => s.includes("CREATE TABLE [theauth_users]")) ?? "";
		expect(users).toContain(`[email] NVARCHAR(`);
		expect(users).not.toMatch(/\[email\] NVARCHAR\(MAX\)/);
		expect(users).toMatch(/\[name\] NVARCHAR\(MAX\)/);
	});

	it("keeps every key inside the 1700 byte index limit and every name inside 128 characters", () => {
		for (const statement of ddl.tables) {
			const pk = /PRIMARY KEY (CLUSTERED|NONCLUSTERED) \(([^)]*)\)/.exec(statement);
			if (!pk) continue;
			const cols = (pk[2] as string).split(",").map((c) => c.trim());
			let bytes = 0;
			for (const col of cols) {
				const m = new RegExp(`${col.replace(/[[\]]/g, "\\$&")} (NVARCHAR\\((\\d+)\\)|BIGINT)`).exec(
					statement,
				);
				bytes += m?.[2] ? Number(m[2]) * 2 : 8;
			}
			expect(bytes).toBeLessThanOrEqual(pk[1] === "CLUSTERED" ? 900 : 1700);
		}
		for (const m of text.matchAll(/\[([^\]]+)\]/g))
			expect((m[1] as string).length).toBeLessThanOrEqual(128);
	});

	it("types numbers as BIGINT, booleans as BIT and JSON as NVARCHAR(MAX)", () => {
		const logs = ddl.tables.find((s) => s.includes("CREATE TABLE [theauth_audit_logs]")) ?? "";
		expect(logs).toContain("[duration_ms] BIGINT NOT NULL");
		expect(logs).toContain("[cache_hit] BIT NOT NULL DEFAULT 0");
		expect(logs).toContain("[parameters] NVARCHAR(MAX) NULL");
		expect(logs).toContain("[recorded_at_ms] BIGINT NULL");
	});

	it("adds foreign keys after the tables, each with a no-action fallback", () => {
		expect(ddl.foreignKeys.length).toBeGreaterThan(30);
		const cascade = ddl.foreignKeys.find((f) => f.sql.includes("ON DELETE CASCADE"));
		expect(cascade).toBeDefined();
		expect(cascade?.fallbackSql).not.toContain("ON DELETE");
		expect(ddl.foreignKeys.some((f) => f.sql.includes("ON DELETE SET NULL"))).toBe(true);
	});
});
