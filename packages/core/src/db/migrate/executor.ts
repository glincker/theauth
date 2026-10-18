import type { Database } from "../database.js";
import type { Dialect, SchemaProvider, SqlExecutor, SqlRow } from "./types.js";

/** Maps a configured provider onto the SQL dialect it speaks. D1 and unknown providers have no raw executor. */
export function toDialect(provider: SchemaProvider): Dialect {
	if (provider === "sqlite" || provider === "sqlite-native") return "sqlite";
	if (provider === "postgres" || provider === "mysql") return provider;
	throw new Error(`TheAuth schema: unsupported provider "${provider}"`);
}

/** Drivers hand rows back as objects, arrays or `{ rows }` wrappers. Normalise to objects. */
function asRows(value: unknown): SqlRow[] {
	if (Array.isArray(value)) return value.filter((r): r is SqlRow => !!r && typeof r === "object");
	if (value && typeof value === "object" && "rows" in value) {
		return asRows((value as { rows: unknown }).rows);
	}
	return [];
}

/** Raw executor over the Drizzle instance's underlying client. */
export function createExecutor(db: Database, provider: SchemaProvider): SqlExecutor {
	const dialect = toDialect(provider);
	// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw DDL
	const anyDb = db as any;

	if (dialect === "sqlite") {
		const session = anyDb.session;
		let write: (sql: string) => Promise<void>;
		if (session?.client?.exec) {
			write = async (sql) => {
				session.client.exec(`${sql};`);
			};
		} else if (session?.client?.run) {
			write = async (sql) => {
				session.client.run(sql);
			};
		} else {
			write = async (sql) => {
				await anyDb.run(sql);
			};
		}
		return {
			dialect,
			run: write,
			all: async (sql) => asRows(await anyDb.all(sql)),
		};
	}

	if (dialect === "postgres") {
		// drizzle-orm/node-postgres wraps a `pg` Pool; the pool is at db.$client or db.session.client
		const client: { query: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error("TheAuth schema: cannot access underlying pg client from Drizzle instance.");
		}
		return {
			dialect,
			run: async (sql) => {
				await client.query(sql);
			},
			all: async (sql) => asRows(await client.query(sql)),
		};
	}

	// drizzle-orm/mysql2 wraps a mysql2 Pool; exposed at db.$client.
	const client: { execute: (sql: string) => Promise<unknown> } =
		anyDb.$client ?? anyDb.session?.client;
	if (!client) {
		throw new Error(
			"TheAuth schema: cannot access underlying mysql2 client from Drizzle instance.",
		);
	}
	return {
		dialect,
		run: async (sql) => {
			await client.execute(sql);
		},
		// mysql2 resolves `[rows, fields]`.
		all: async (sql) => {
			const result = await client.execute(sql);
			return asRows(Array.isArray(result) ? result[0] : result);
		},
	};
}

/** True for the errors an idempotent re-run of DDL is expected to hit (object already there). Anything else is a real failure. */
export function isAlreadyExistsError(error: unknown): boolean {
	const seen = new Set<unknown>();
	let current: unknown = error;
	while (current && typeof current === "object" && !seen.has(current)) {
		seen.add(current);
		const e = current as { message?: unknown; code?: unknown; errno?: unknown; cause?: unknown };
		const message = typeof e.message === "string" ? e.message : "";
		if (/duplicate column name|already exists|duplicate key name/i.test(message)) return true;
		// pg: 42701 duplicate_column, 42P07 duplicate_table (also indexes). mysql: 1060, 1061.
		if (e.code === "42701" || e.code === "42P07") return true;
		if (e.code === "ER_DUP_FIELDNAME" || e.code === "ER_DUP_KEYNAME") return true;
		if (e.errno === 1060 || e.errno === 1061) return true;
		current = e.cause;
	}
	return false;
}
