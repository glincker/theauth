import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createExecutor } from "../src/db/migrate/executor.js";
import type { Dialect, SqlExecutor, SqlRow } from "../src/db/migrate/types.js";

/** Statements that create the 1.2.0 (last released, pre ledger) schema, per dialect. */
export function schemaV120(dialect: Dialect): string[] {
	const raw = readFileSync(join(__dirname, "fixtures", "schema-v1.2.0.json"), "utf8");
	return (JSON.parse(raw) as Record<Dialect, string[]>)[dialect];
}

export async function memoryDb(): Promise<{ db: Database; exec: SqlExecutor }> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	return { db, exec: createExecutor(db, "sqlite") };
}

/** A SQLite database shaped like 1.2.0: tables and data, no ledger, no decision_code or recorded_at_ms. */
export async function memoryDbV120(options: { withData?: boolean } = {}) {
	const handle = await memoryDb();
	for (const sql of schemaV120("sqlite")) await handle.exec.run(sql);
	if (options.withData) {
		await handle.exec.run(
			"INSERT INTO theauth_users (id, email, name, created_at, updated_at) VALUES ('u1', 'u1@example.com', 'U1', 1700000000, 1700000000)",
		);
		await handle.exec.run(
			"INSERT INTO theauth_agents (id, owner_id, name, type, status, token_hash, token_prefix, created_at, updated_at) VALUES ('a1', 'u1', 'a1', 'autonomous', 'active', 'h', 'p', 1700000000, 1700000000)",
		);
		for (const [id, ts] of [
			["r1", 1700000100],
			["r2", 1700000200],
		] as const) {
			await handle.exec.run(
				`INSERT INTO theauth_audit_logs (id, agent_id, user_id, action, resource, result, duration_ms, timestamp, chain_seq, hash_version) VALUES ('${id}', 'a1', 'u1', 'execute', 'mcp:x:y', 'allowed', 1, ${ts}, ${id === "r1" ? 1 : 2}, 2)`,
			);
		}
	}
	return handle;
}

export async function columnsOf(exec: SqlExecutor, table: string): Promise<string[]> {
	const rows = await exec.all(`SELECT name AS name FROM pragma_table_info('${table}')`);
	return rows.map((r) => String(r.name));
}

export async function indexNames(exec: SqlExecutor, table: string): Promise<string[]> {
	const rows = await exec.all(
		`SELECT name AS name FROM sqlite_master WHERE type = 'index' AND tbl_name = '${table}'`,
	);
	return rows.map((r) => String(r.name));
}

export async function ledgerIds(exec: SqlExecutor): Promise<string[]> {
	const rows: SqlRow[] = await exec.all(
		"SELECT id AS id FROM theauth_schema_migrations ORDER BY id",
	);
	return rows.map((r) => String(r.id));
}
