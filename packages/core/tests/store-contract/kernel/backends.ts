import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import type { Kysely } from "kysely";
import {
	Kysely as KyselyClass,
	MssqlDialect,
	MysqlDialect,
	PostgresDialect,
	SqliteDialect,
	sql,
} from "kysely";
import mysql2 from "mysql2";
import { Pool } from "pg";
import * as tarn from "tarn";
import * as tedious from "tedious";
import { oauthStates } from "../../../src/auth/oauth/schema.js";
import type { Database, DatabaseConfig } from "../../../src/db/database.js";
import { createDatabase } from "../../../src/db/database.js";
import { applyMssqlSchema } from "../../../src/db/ddl/mssql.js";
import { runMigrations } from "../../../src/db/migrate/index.js";
import { storesFor, storesFromKernel } from "../../../src/db/store/index.js";
import type { KyselyDialect } from "../../../src/db/store/kysely/index.js";
import { createKyselyKernel } from "../../../src/db/store/kysely/index.js";
import { closeDatabase } from "../boot.js";
import { withQueryLatency } from "../latency.js";
import { dropScratchDatabase, ensureScratchDatabase, scratchUrl } from "../scratch.js";
import type { KernelTarget, MakeTarget } from "./target.js";

export const tmpRoot = (): { dir: string; remove: () => void } => {
	const dir = mkdtempSync(join(tmpdir(), "theauth-kernel-contract-"));
	return { dir, remove: () => rmSync(dir, { recursive: true, force: true }) };
};

/** The Drizzle kernel on a database this call migrates once. Each `make()` opens a fresh handle. */
export async function drizzleBackend(
	config: () => DatabaseConfig,
	dialect: "sqlite" | "postgres" | "mysql",
	shared: boolean,
): Promise<MakeTarget> {
	if (shared) {
		const setup = await createDatabase(config());
		await runMigrations(setup, dialect);
		await closeDatabase(setup);
	}
	const open = async (): Promise<KernelTarget> => {
		const db = await createDatabase(config());
		// An in-memory database is private to its handle, so each one is migrated on its own.
		if (!shared) await runMigrations(db, dialect);
		return {
			stores: storesFor(db),
			peer: shared ? open : undefined,
			close: () => closeDatabase(db),
		};
	};
	return open;
}

/** The Drizzle kernel on better-sqlite3 with every query yielding first, so a read then write claim is observable. */
export function latencyBackend(file: string): MakeTarget {
	const open = async (): Promise<KernelTarget> => {
		const sqlite = new BetterSqlite3(file);
		sqlite.pragma("journal_mode = WAL");
		sqlite.pragma("busy_timeout = 5000");
		sqlite.pragma("foreign_keys = ON");
		const db = withQueryLatency(drizzle(sqlite)) as unknown as Database;
		return {
			stores: storesFor(db),
			peer: open,
			close: async () => {
				sqlite.close();
			},
		};
	};
	return open;
}

export async function migrateSqliteFile(file: string): Promise<void> {
	const db = await createDatabase({ provider: "sqlite-native", url: file });
	await runMigrations(db, "sqlite");
	await closeDatabase(db);
}

/** The Kysely kernel on an already migrated database. */
export function kyselyBackend(
	makeKysely: () => Kysely<unknown>,
	dialect: KyselyDialect,
	shared: boolean,
): MakeTarget {
	const open = async (): Promise<KernelTarget> => {
		const k = makeKysely();
		return {
			stores: storesFromKernel(createKyselyKernel(k, dialect, { extraTables: { oauthStates } })),
			peer: shared ? open : undefined,
			close: () => k.destroy(),
		};
	};
	return open;
}

export const sqliteKysely = (file: string): Kysely<unknown> => {
	const database = new BetterSqlite3(file);
	database.pragma("journal_mode = WAL");
	database.pragma("busy_timeout = 5000");
	database.pragma("foreign_keys = ON");
	return new KyselyClass<unknown>({ dialect: new SqliteDialect({ database }) });
};

export const postgresKysely = (url: string): Kysely<unknown> =>
	new KyselyClass<unknown>({
		dialect: new PostgresDialect({ pool: new Pool({ connectionString: url, max: 12 }) }),
	});

export const mysqlKysely = (url: string): Kysely<unknown> =>
	new KyselyClass<unknown>({
		dialect: new MysqlDialect({
			pool: mysql2.createPool({ uri: url, timezone: "Z", connectionLimit: 12 }),
		}),
	});

export interface MssqlTarget {
	server: string;
	port: number;
	user: string;
	password: string;
}

export function parseMssqlUrl(url: string): MssqlTarget {
	const u = new URL(url);
	return {
		server: u.hostname,
		port: Number(u.port || 1433),
		user: decodeURIComponent(u.username),
		password: decodeURIComponent(u.password),
	};
}

export const mssqlKysely = (target: MssqlTarget, database: string): Kysely<unknown> =>
	new KyselyClass<unknown>({
		dialect: new MssqlDialect({
			tarn: { ...tarn, options: { min: 0, max: 12 } },
			tedious: {
				...tedious,
				connectionFactory: () =>
					new tedious.Connection({
						server: target.server,
						authentication: {
							type: "default",
							options: { userName: target.user, password: target.password },
						},
						options: {
							port: target.port,
							database,
							trustServerCertificate: true,
							encrypt: false,
						},
					}),
			},
		}),
	});

export async function createMssqlScratch(target: MssqlTarget, name: string): Promise<void> {
	const master = mssqlKysely(target, "master");
	try {
		await sql
			.raw(
				`IF DB_ID(N'${name}') IS NOT NULL BEGIN ALTER DATABASE [${name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [${name}]; END`,
			)
			.execute(master);
		await sql.raw(`CREATE DATABASE [${name}] COLLATE Latin1_General_100_BIN2`).execute(master);
	} finally {
		await master.destroy();
	}
	const k = mssqlKysely(target, name);
	try {
		const { downgraded } = await applyMssqlSchema(
			async (statement) => {
				await sql.raw(statement).execute(k);
			},
			{ oauthStates },
		);
		if (downgraded.length > 0)
			process.stderr.write(`[mssql] cascades dropped: ${downgraded.join(", ")}
`);
	} finally {
		await k.destroy();
	}
}

export async function dropMssqlScratch(target: MssqlTarget, name: string): Promise<void> {
	const master = mssqlKysely(target, "master");
	try {
		await sql
			.raw(
				`IF DB_ID(N'${name}') IS NOT NULL BEGIN ALTER DATABASE [${name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [${name}]; END`,
			)
			.execute(master);
	} finally {
		await master.destroy();
	}
}

export { dropScratchDatabase, ensureScratchDatabase, scratchUrl };
