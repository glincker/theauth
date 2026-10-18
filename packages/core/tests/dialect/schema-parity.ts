import { is } from "drizzle-orm";
import { getTableConfig, SQLiteTable } from "drizzle-orm/sqlite-core";
import { describe, expect, it } from "vitest";
import * as oauthSchema from "../../src/auth/oauth/schema.js";
import type { SqlExecutor } from "../../src/db/migrate/types.js";
import type { ColumnKind } from "../../src/db/schema/columns.js";
import { columnKind } from "../../src/db/schema/columns.js";
import * as coreSchema from "../../src/db/schema.js";
import * as signalsSchema from "../../src/signals/schema.js";
import * as vaultSchema from "../../src/vault/schema.js";

type Provider = "postgres" | "mysql";

/** information_schema.columns data_type per helper kind, by dialect. */
const EXPECTED: Record<Provider, Record<ColumnKind, string[]>> = {
	postgres: {
		timestampSec: ["bigint"],
		timestampMs: ["bigint"],
		bigint: ["bigint"],
		json: ["jsonb"],
		bool: ["boolean"],
		flag01: ["boolean"],
		integer: ["integer"],
		text: ["text"],
	},
	mysql: {
		timestampSec: ["bigint"],
		timestampMs: ["bigint"],
		bigint: ["bigint"],
		json: ["json"],
		bool: ["tinyint"],
		flag01: ["tinyint"],
		integer: ["int"],
		text: ["text", "varchar"],
	},
};

/** Every table exported from the Drizzle schema modules, deduplicated by SQL name. */
export function allSchemaTables(): Map<string, SQLiteTable> {
	const tables = new Map<string, SQLiteTable>();
	for (const mod of [coreSchema, oauthSchema, vaultSchema, signalsSchema]) {
		for (const value of Object.values(mod)) {
			if (is(value, SQLiteTable)) tables.set(getTableConfig(value).name, value);
		}
	}
	return tables;
}

/**
 * Walks every exported Drizzle table and compares each column's helper kind with the type the
 * migrated database actually has. Reports every mismatch in one assertion so a run shows the full gap.
 */
export function defineSchemaParityTests(provider: Provider, getExec: () => SqlExecutor): void {
	describe("schema parity", () => {
		it("every Drizzle column matches the migrated column type", async () => {
			const exec = getExec();
			const where =
				provider === "postgres" ? "table_schema = current_schema()" : "table_schema = DATABASE()";
			const rows = await exec.all(
				`SELECT table_name AS t, column_name AS c, data_type AS d FROM information_schema.columns WHERE ${where} AND table_name LIKE 'theauth\\_%'`,
			);
			const actual = new Map<string, string>();
			for (const r of rows) actual.set(`${String(r.t)}.${String(r.c)}`, String(r.d).toLowerCase());

			const tables = allSchemaTables();
			expect(tables.size).toBeGreaterThan(40);
			const problems: string[] = [];
			for (const [name, table] of tables) {
				for (const col of getTableConfig(table).columns) {
					const key = `${name}.${col.name}`;
					const found = actual.get(key);
					const kind = columnKind(col);
					if (found === undefined) {
						problems.push(`${key}: column missing in database (declared ${kind})`);
					} else if (!EXPECTED[provider][kind].includes(found)) {
						problems.push(
							`${key}: ${kind} should be ${EXPECTED[provider][kind].join("|")}, database has ${found}`,
						);
					}
				}
			}
			expect(problems).toEqual([]);
		});

		it("no Drizzle table column is left as a native date type (the migration ledger keeps its own)", async () => {
			const exec = getExec();
			const where =
				provider === "postgres" ? "table_schema = current_schema()" : "table_schema = DATABASE()";
			const rows = await exec.all(
				`SELECT table_name AS t, column_name AS c, data_type AS d FROM information_schema.columns WHERE ${where} AND table_name LIKE 'theauth\\_%' AND table_name <> 'theauth_schema_migrations' AND (data_type LIKE 'timestamp%' OR data_type = 'datetime')`,
			);
			expect(rows.map((r) => `${String(r.t)}.${String(r.c)} ${String(r.d)}`)).toEqual([]);
		});
	});
}
