import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { drizzle as drizzleMysql } from "drizzle-orm/mysql2";
import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import mysql2 from "mysql2/promise";
import { Pool } from "pg";
import { afterAll } from "vitest";
import { runStoreContract } from "../../../test-utils/src/store-contract/index.js";
import { bootTarget } from "./boot.js";
import { withQueryLatency } from "./latency.js";
import { dropScratchDatabase, ensureScratchDatabase, scratchUrl } from "./scratch.js";

/**
 * The store contract on every backend this machine can reach. SQLite always runs. Postgres and MySQL
 * run when THEAUTH_TEST_PG_URL / THEAUTH_TEST_MYSQL_URL are set, each in its own scratch database.
 */

// sql.js, in memory: one process, no peer.
runStoreContract("sqlite (sql.js)", () =>
	bootTarget(() => ({ provider: "sqlite", url: ":memory:" }), false),
);

// better-sqlite3 on a file: two handles on one file stand for two processes.
const dir = mkdtempSync(join(tmpdir(), "theauth-contract-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

runStoreContract("sqlite-native (file)", () =>
	bootTarget(() => ({ provider: "sqlite-native", url: join(dir, "native.db") }), true),
);

// The same engine through the bring-your-own-Drizzle config.
runStoreContract("drizzle instance (better-sqlite3 file)", () =>
	bootTarget(() => {
		const sqlite = new BetterSqlite3(join(dir, "byo.db"));
		sqlite.pragma("journal_mode = WAL");
		sqlite.pragma("foreign_keys = ON");
		return { drizzle: drizzle(sqlite), dialect: "sqlite" };
	}, true),
);

// Same engine, but every query yields first. This is what makes a read-then-write claim observable
// on SQLite, where the drivers otherwise answer synchronously (see latency.ts).
runStoreContract("drizzle instance (better-sqlite3 file, query latency)", () =>
	bootTarget(() => {
		const sqlite = new BetterSqlite3(join(dir, "latency.db"));
		sqlite.pragma("journal_mode = WAL");
		sqlite.pragma("busy_timeout = 5000");
		sqlite.pragma("foreign_keys = ON");
		return { drizzle: withQueryLatency(drizzle(sqlite)), dialect: "sqlite" };
	}, true),
);

const pgUrl = process.env.THEAUTH_TEST_PG_URL;
const mysqlUrl = process.env.THEAUTH_TEST_MYSQL_URL;

if (pgUrl) {
	const scratch = scratchUrl(pgUrl, "theauth_w9_contract_pg");
	await ensureScratchDatabase("postgres", pgUrl, "theauth_w9_contract_pg");
	afterAll(() => dropScratchDatabase("postgres", pgUrl, "theauth_w9_contract_pg"));
	runStoreContract("postgres", () =>
		bootTarget(() => ({ provider: "postgres", url: scratch }), true),
	);
	runStoreContract("drizzle instance (postgres)", () =>
		bootTarget(
			() => ({
				drizzle: drizzlePg(new Pool({ connectionString: scratch })),
				dialect: "postgres",
			}),
			true,
		),
	);
} else {
	runStoreContract("postgres", () => Promise.reject(new Error("unreachable")), { skip: true });
}

if (mysqlUrl) {
	const scratch = scratchUrl(mysqlUrl, "theauth_w9_contract_my");
	await ensureScratchDatabase("mysql", mysqlUrl, "theauth_w9_contract_my");
	afterAll(() => dropScratchDatabase("mysql", mysqlUrl, "theauth_w9_contract_my"));
	runStoreContract("mysql", () =>
		bootTarget(() => ({ provider: "mysql", url: scratch, experimental: true }), true),
	);
	runStoreContract("drizzle instance (mysql)", () =>
		bootTarget(
			() => ({
				drizzle: drizzleMysql(mysql2.createPool({ uri: scratch, timezone: "Z" })),
				dialect: "mysql",
			}),
			true,
		),
	);
} else {
	runStoreContract("mysql", () => Promise.reject(new Error("unreachable")), { skip: true });
}
