/** theauth-go and this library both create theauth_audit_secrets with different layouts. */

import { describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createExecutor } from "../src/db/migrate/executor.js";
import {
	AUDIT_SECRETS_LAYOUT_MISMATCH,
	AuditSecretsLayoutError,
	assertAuditSecretsLayout,
} from "../src/db/migrate/index.js";
import type { SqlExecutor, SqlRow } from "../src/db/migrate/types.js";
import { createTables, ensureSchema } from "../src/db/migrations.js";

// theauth-go storage/sqlite/migrations/0017_audit_accountability.sql
const GO_SQLITE = `CREATE TABLE theauth_audit_secrets (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  secret     BLOB NOT NULL,
  created_at INTEGER NOT NULL
)`;

async function memoryDb() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	return { db, exec: createExecutor(db, "sqlite") };
}

describe("theauth_audit_secrets layout guard (sqlite)", () => {
	it("throws AUDIT_SECRETS_LAYOUT_MISMATCH when the Go layout is present", async () => {
		const { db, exec } = await memoryDb();
		await exec.run(GO_SQLITE);
		const error = await createTables(db, "sqlite").catch((e: unknown) => e);
		expect(error).toBeInstanceOf(AuditSecretsLayoutError);
		expect((error as AuditSecretsLayoutError).code).toBe(AUDIT_SECRETS_LAYOUT_MISMATCH);
		expect((error as Error).message).toContain("separate database or schema");
		expect((error as Error).message).toContain("id integer");
	});

	it("also throws on the skipMigrations boot path", async () => {
		const { db, exec } = await memoryDb();
		await exec.run(GO_SQLITE);
		const config = {
			database: { provider: "sqlite" as const, url: ":memory:", skipMigrations: true },
		};
		await expect(ensureSchema(db, config)).rejects.toMatchObject({
			code: "AUDIT_SECRETS_LAYOUT_MISMATCH",
		});
	});

	it("does not touch the foreign table", async () => {
		const { db, exec } = await memoryDb();
		await exec.run(GO_SQLITE);
		await createTables(db, "sqlite").catch(() => undefined);
		const cols = await exec.all(
			"SELECT type AS type FROM pragma_table_info('theauth_audit_secrets')",
		);
		expect(cols.map((c) => c.type)).toContain("BLOB");
	});

	it("passes on a fresh database, and again on the table this library created", async () => {
		const { db, exec } = await memoryDb();
		await assertAuditSecretsLayout(exec);
		await createTables(db, "sqlite");
		await assertAuditSecretsLayout(exec);
		await createTables(db, "sqlite");
	});
});

function fake(dialect: SqlExecutor["dialect"], rows: SqlRow[]): SqlExecutor {
	return { dialect, run: async () => undefined, all: async () => rows };
}

describe("theauth_audit_secrets layout guard (row interpretation)", () => {
	const goPostgres = [
		{ name: "id", type: "smallint" },
		{ name: "secret", type: "bytea" },
		{ name: "created_at", type: "timestamp with time zone" },
	];
	const ours = [
		{ name: "id", type: "text" },
		{ name: "secret", type: "text" },
		{ name: "created_at", type: "bigint" },
	];

	it("rejects the Go postgres layout and accepts ours", async () => {
		await expect(assertAuditSecretsLayout(fake("postgres", goPostgres))).rejects.toBeInstanceOf(
			AuditSecretsLayoutError,
		);
		await expect(assertAuditSecretsLayout(fake("postgres", ours))).resolves.toBeUndefined();
	});

	it("rejects the Go mysql layout (upper case keys from the driver)", async () => {
		const goMysql = [
			{ NAME: "id", TYPE: "tinyint" },
			{ NAME: "secret", TYPE: "varbinary" },
			{ NAME: "created_at", TYPE: "datetime" },
		];
		await expect(assertAuditSecretsLayout(fake("mysql", goMysql))).rejects.toMatchObject({
			code: "AUDIT_SECRETS_LAYOUT_MISMATCH",
		});
	});

	it("rejects a table with missing columns", async () => {
		await expect(
			assertAuditSecretsLayout(fake("postgres", [{ name: "id", type: "text" }])),
		).rejects.toBeInstanceOf(AuditSecretsLayoutError);
	});
});

// Real Postgres check. Own env var, because the shared dialect suite drops every theauth_ table.
const PG_URL = process.env.THEAUTH_TEST_PG_GUARD_URL;
describe.skipIf(!PG_URL)("theauth_audit_secrets layout guard (postgres)", () => {
	it("detects the Go layout", async () => {
		const db = await createDatabase({ provider: "postgres", url: PG_URL as string });
		const exec = createExecutor(db, "postgres");
		try {
			await exec.run("DROP TABLE IF EXISTS theauth_audit_secrets");
			await exec.run(`CREATE TABLE theauth_audit_secrets (
  id smallint PRIMARY KEY CHECK (id = 1),
  secret bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
)`);
			await expect(assertAuditSecretsLayout(exec)).rejects.toMatchObject({
				code: "AUDIT_SECRETS_LAYOUT_MISMATCH",
			});
			await exec.run("DROP TABLE theauth_audit_secrets");
			await exec.run(
				"CREATE TABLE theauth_audit_secrets (id TEXT NOT NULL PRIMARY KEY, secret TEXT NOT NULL, created_at BIGINT NOT NULL)",
			);
			await expect(assertAuditSecretsLayout(exec)).resolves.toBeUndefined();
		} finally {
			await exec.run("DROP TABLE IF EXISTS theauth_audit_secrets");
		}
	});
});
