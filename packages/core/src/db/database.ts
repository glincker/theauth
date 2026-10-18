import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import * as schema from "./schema.js";

// Cloudflare D1 minimal interfaces
// (avoids a hard dep on @cloudflare/workers-types)

/** Minimal Cloudflare D1 interface for type compatibility */
export interface D1DatabaseBinding {
	prepare(query: string): D1PreparedStatement;
	batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
	exec(query: string): Promise<D1ExecResult>;
}
interface D1PreparedStatement {
	bind(...values: unknown[]): D1PreparedStatement;
	first<T = unknown>(colName?: string): Promise<T | null>;
	run<T = unknown>(): Promise<D1Result<T>>;
	all<T = unknown>(): Promise<D1Result<T>>;
	raw<T = unknown>(): Promise<T[]>;
}
interface D1Result<T = unknown> {
	results: T[];
	success: boolean;
	meta: Record<string, unknown>;
}
interface D1ExecResult {
	count: number;
	duration: number;
}

/**
 * The fully-typed SQLite Drizzle database. Postgres and MySQL connections are cast to this type at the adapter boundary, so TheAuth queries every provider through the same typed interface.
 */
export type Database = BaseSQLiteDatabase<"sync" | "async", Record<string, unknown>, typeof schema>;

/** A wider union used internally when the provider is postgres or mysql. Using `unknown` with a discriminated tag keeps `any` contained to a single adapter-boundary cast below. */
export type AnyDatabase =
	| { provider: "sqlite"; db: Database }
	| { provider: "postgres"; db: PostgresDatabase }
	| { provider: "mysql"; db: MySQLDatabase }
	| { provider: "d1"; db: D1DrizzleDatabase };

// Import types lazily so the drivers stay optional peer deps.
// biome-ignore lint/suspicious/noExplicitAny: adapter boundary - drizzle pg/mysql types are not compatible with sqlite schema
type PostgresDatabase = any;
// biome-ignore lint/suspicious/noExplicitAny: adapter boundary - drizzle pg/mysql types are not compatible with sqlite schema
type MySQLDatabase = any;
// biome-ignore lint/suspicious/noExplicitAny: adapter boundary - D1 drizzle types differ from SQLite
type D1DrizzleDatabase = any;

export type DatabaseConfig =
	| {
			provider: "sqlite" | "sqlite-native" | "postgres" | "mysql";
			/** Connection URL / file path. Required for sqlite-native, postgres, and mysql. `sqlite` (sql.js) accepts only `:memory:` and throws THEAUTH_SQLITE_NOT_PERSISTENT for a file path. */
			url: string;
			/** Skip automatic table creation on init (default: false) */
			skipMigrations?: boolean;
			/** Opt in to the unsupported MySQL provider. Without it, `provider: "mysql"` throws THEAUTH_MYSQL_UNSUPPORTED. */
			experimental?: boolean;
	  }
	| {
			provider: "d1";
			/** Cloudflare D1 binding from the Worker environment. Required when provider is "d1". */
			binding: D1DatabaseBinding;
			/** Skip automatic table creation on init (default: false) */
			skipMigrations?: boolean;
	  };

/**
 * Create a database connection.
 * - **SQLite** (`sqlite`), fully typed Drizzle ORM via `sql.js` (WASM, in-memory only, `:memory:`).
 * - **SQLite** (`sqlite-native`), `better-sqlite3`, for a database file that persists.
 */
export async function createDatabase(config: DatabaseConfig): Promise<Database> {
	// SQLite (WASM, in-memory only)
	// Uses sql.js (SQLite compiled to WebAssembly). Zero native deps, never persists to disk.
	if (config.provider === "sqlite") {
		// sql.js is an in-memory engine. It never writes a database file, so a file URL would look
		// like it works and then lose every row on restart. Refuse it instead of accepting it.
		const url = config.url;
		if (url !== undefined && url !== "" && url !== ":memory:") {
			throw new Error(
				`THEAUTH_SQLITE_NOT_PERSISTENT: provider "sqlite" uses sql.js, which keeps the database in memory ` +
					`and does not write "${url}" to disk, so data would be lost on restart. ` +
					'For a database file use provider: "sqlite-native" (better-sqlite3; install it with: npm install better-sqlite3) ' +
					'or provider: "postgres" or "d1". For an ephemeral database pass url: ":memory:".',
			);
		}

		const initSqlJs = (
			await import("sql.js").catch(() => {
				throw new Error(
					'TheAuth: provider "sqlite" requires the "sql.js" package. ' +
						"Install it with: npm install sql.js",
				);
			})
		).default;
		const { drizzle: drizzleSqlJs } = await import("drizzle-orm/sql-js");

		const SQL = await initSqlJs();
		const db = new SQL.Database();
		db.run("PRAGMA foreign_keys = ON");

		return drizzleSqlJs(db, { schema }) as unknown as Database;
	}

	// SQLite (native, optional)
	// Uses better-sqlite3 for maximum performance. Requires C++ build tools.
	// Use this when you need the fastest possible SQLite on Node.js.
	if (config.provider === "sqlite-native") {
		const BetterSqlite3 = (
			await import("better-sqlite3").catch(() => {
				throw new Error(
					'TheAuth: provider "sqlite-native" requires the "better-sqlite3" package. ' +
						"Install it with: npm install better-sqlite3",
				);
			})
		).default;
		const { drizzle: drizzleSqlite } = await import("drizzle-orm/better-sqlite3");

		const sqlite = new BetterSqlite3(config.url);
		sqlite.pragma("journal_mode = WAL");
		sqlite.pragma("foreign_keys = ON");
		return drizzleSqlite(sqlite, { schema }) as unknown as Database;
	}

	if (config.provider === "postgres") {
		// Dynamic import keeps `pg` an optional peer dep.
		const { Pool } = await import("pg").catch(() => {
			throw new Error(
				'TheAuth: provider "postgres" requires the "pg" package. ' +
					"Install it with: npm install pg",
			);
		});
		const { drizzle } = await import("drizzle-orm/node-postgres");

		const pool = new Pool({ connectionString: config.url });
		// Cast to Database for API compatibility (see the Database type).
		// biome-ignore lint/suspicious/noExplicitAny: adapter boundary - cast pg drizzle to sqlite-typed Database
		return drizzle(pool) as any as Database;
	}

	if (config.provider === "mysql") {
		if (config.experimental !== true) {
			throw new Error(
				'THEAUTH_MYSQL_UNSUPPORTED: provider "mysql" is not supported yet. ' +
					"See docs/choose-storage for supported databases. " +
					"Set database.experimental: true to opt in to the unverified MySQL provider.",
			);
		}
		// Dynamic import keeps `mysql2` an optional peer dep.
		const mysql2 = await import("mysql2/promise").catch(() => {
			throw new Error(
				'TheAuth: provider "mysql" requires the "mysql2" package. ' +
					"Install it with: npm install mysql2",
			);
		});
		const { drizzle } = await import("drizzle-orm/mysql2");

		// UTC on the wire: the ledger's DATETIME(3) column holds UTC_TIMESTAMP(3), and every other timestamp is an integer epoch.
		const pool = mysql2.createPool({ uri: config.url, timezone: "Z" });
		// Cast to Database for API compatibility (see the Database type).
		// biome-ignore lint/suspicious/noExplicitAny: adapter boundary - cast mysql drizzle to sqlite-typed Database
		return drizzle(pool) as any as Database;
	}

	if (config.provider === "d1") {
		const { drizzle } = await import("drizzle-orm/d1");
		// biome-ignore lint/suspicious/noExplicitAny: adapter boundary - D1 drizzle types differ from SQLite
		return drizzle(config.binding as any, { schema }) as unknown as Database;
	}

	throw new Error(
		`TheAuth: unsupported database provider "${(config as DatabaseConfig).provider}". ` +
			'Valid values are "sqlite", "sqlite-native", "postgres", "mysql", "d1".',
	);
}

/**
 * Synchronous SQLite-only factory kept for backwards compatibility with code that cannot use async initialisation. Throws if a non-SQLite provider is supplied.
 *
 * @deprecated Prefer the async `createDatabase()` which supports all providers.
 */
export function createDatabaseSync(config: DatabaseConfig): Database {
	if (config.provider !== "sqlite") {
		throw new Error(
			`createDatabaseSync() only supports SQLite. ` +
				`Use the async createDatabase() for provider "${config.provider}".`,
		);
	}
	// Sync path: use createRequire for Node.js-only sync loading.
	// This function is deprecated; prefer the async createDatabase().
	// biome-ignore lint/suspicious/noExplicitAny: sync require bridge for deprecated API
	const { createRequire } = require("node:module") as any;
	const req = createRequire(import.meta.url);
	const BetterSqlite3Mod = req("better-sqlite3");
	const { drizzle: drizzleSqliteMod } = req("drizzle-orm/better-sqlite3");

	const sqlite = new BetterSqlite3Mod(config.url);
	sqlite.pragma("journal_mode = WAL");
	sqlite.pragma("foreign_keys = ON");
	return drizzleSqliteMod(sqlite, { schema }) as unknown as Database;
}
