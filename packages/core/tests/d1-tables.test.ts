import initSqlJs from "sql.js";
import { describe, expect, it } from "vitest";
import type { D1DatabaseBinding } from "../src/db/database.js";
import { createTables, getMigrationStatements } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

type Row = Record<string, unknown>;

interface FakeD1 {
	binding: D1DatabaseBinding;
	calls: { prepare: string[]; batch: number; exec: number };
}

/**
 * A small D1 look-alike on top of sql.js. It mirrors the parts of the D1
 * contract the SDK relies on: prepare().bind().run()/all()/first()/raw() and
 * batch(). `exec` throws, because D1 splits it on newlines and multi line
 * DDL must never go through it.
 */
async function createFakeD1(): Promise<FakeD1> {
	const SQL = await initSqlJs();
	const sqlite = new SQL.Database();
	sqlite.run("PRAGMA foreign_keys = ON");
	const calls = { prepare: [] as string[], batch: 0, exec: 0 };

	function toResult(columns: string[], values: unknown[][]) {
		return values.map((v) => Object.fromEntries(columns.map((c, i) => [c, v[i]])) as Row);
	}

	function makeStatement(query: string, params: unknown[] = []) {
		const stmt = {
			bind(...values: unknown[]) {
				return makeStatement(query, values);
			},
			async run() {
				sqlite.run(query, params as never[]);
				return {
					results: [] as Row[],
					success: true,
					meta: { changes: sqlite.getRowsModified() },
				};
			},
			async all() {
				const out = sqlite.exec(query, params as never[]);
				const first = out[0];
				const results = first ? toResult(first.columns, first.values) : [];
				return { results, success: true, meta: {} };
			},
			async first(col?: string) {
				const { results } = await stmt.all();
				const row = results[0] ?? null;
				return (col && row ? row[col] : row) as never;
			},
			async raw() {
				const out = sqlite.exec(query, params as never[]);
				return (out[0]?.values ?? []) as never;
			},
		};
		return stmt;
	}

	const binding = {
		prepare(query: string) {
			calls.prepare.push(query);
			return makeStatement(query);
		},
		async batch(statements: { run(): Promise<unknown> }[]) {
			calls.batch += 1;
			sqlite.run("BEGIN");
			try {
				const out = [];
				for (const s of statements) out.push(await s.run());
				sqlite.run("COMMIT");
				return out;
			} catch (err) {
				sqlite.run("ROLLBACK");
				throw err;
			}
		},
		async exec(): Promise<never> {
			calls.exec += 1;
			throw new Error("exec is not safe for multi line statements on D1");
		},
	} as unknown as D1DatabaseBinding;

	return { binding, calls };
}

async function tableNames(binding: D1DatabaseBinding): Promise<string[]> {
	const { results } = await binding
		.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
		.all<{ name: string }>();
	return results.map((r) => r.name);
}

describe("createTables on Cloudflare D1", () => {
	it("creates the tables through prepare and batch, never exec", async () => {
		const d1 = await createFakeD1();
		const auth = await createTheAuth({
			database: { provider: "d1", binding: d1.binding },
			agents: { enabled: true },
			auth: { session: { secret: "d".repeat(40) } },
		});
		expect(auth).toBeTruthy();

		const names = await tableNames(d1.binding);
		for (const t of [
			"theauth_users",
			"theauth_agents",
			"theauth_permissions",
			"theauth_audit_logs",
		]) {
			expect(names).toContain(t);
		}
		expect(d1.calls.exec).toBe(0);
		expect(d1.calls.batch).toBe(1);
	});

	it("is idempotent", async () => {
		const d1 = await createFakeD1();
		const config = { agents: { enabled: true } };
		const auth = await createTheAuth({
			database: { provider: "d1", binding: d1.binding },
			...config,
		});
		const before = await tableNames(d1.binding);
		await expect(
			createTables(auth.db, "d1", { database: { provider: "d1", binding: d1.binding }, ...config }),
		).resolves.toBeUndefined();
		expect(await tableNames(d1.binding)).toEqual(before);
	});

	it("skipMigrations leaves the database untouched", async () => {
		const d1 = await createFakeD1();
		await createTheAuth({
			database: { provider: "d1", binding: d1.binding, skipMigrations: true },
			agents: { enabled: true },
		});
		expect(await tableNames(d1.binding)).toEqual([]);
		expect(d1.calls.batch).toBe(0);
	});

	it("can create an agent and authorize with agents enabled", async () => {
		const d1 = await createFakeD1();
		const auth = await createTheAuth({
			database: { provider: "d1", binding: d1.binding },
			agents: { enabled: true, auditAll: true },
		});
		await auth.db.insert(schema.users).values({
			id: "u1",
			email: "u1@example.com",
			name: "U",
			createdAt: new Date(),
			updatedAt: new Date(),
		});

		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "reader",
			type: "autonomous",
			permissions: [{ resource: "reports:monthly", actions: ["read"] }],
		});
		expect(agent.status).toBe("active");

		const allowed = await auth.authorize(agent.id, { action: "read", resource: "reports:monthly" });
		expect(allowed.allowed).toBe(true);
		const denied = await auth.authorize(agent.id, {
			action: "delete",
			resource: "reports:monthly",
		});
		expect(denied.allowed).toBe(false);
	});
});

describe("getMigrationStatements", () => {
	it("returns the statements createTables runs, one per entry, with no trailing semicolon", async () => {
		const stmts = getMigrationStatements("d1", { agents: { enabled: true } });
		expect(stmts.length).toBeGreaterThan(3);
		expect(stmts.every((s) => !s.trim().endsWith(";"))).toBe(true);
		expect(stmts.some((s) => s.includes("theauth_agents"))).toBe(true);
		expect(stmts.some((s) => s.includes("theauth_oauth_clients"))).toBe(false);
	});

	it("produces SQL that applies cleanly and matches createTables", async () => {
		const config = { agents: { enabled: true } };
		const viaCreate = await createFakeD1();
		await createTheAuth({ database: { provider: "d1", binding: viaCreate.binding }, ...config });

		const viaFile = await createFakeD1();
		for (const sql of getMigrationStatements("d1", config)) {
			await viaFile.binding.prepare(sql).run();
		}
		expect(await tableNames(viaFile.binding)).toEqual(await tableNames(viaCreate.binding));
	});
});
