import { afterAll } from "vitest";
import {
	createMssqlScratch,
	drizzleBackend,
	dropMssqlScratch,
	dropScratchDatabase,
	ensureScratchDatabase,
	kyselyBackend,
	latencyBackend,
	migrateSqliteFile,
	mssqlKysely,
	mysqlKysely,
	parseMssqlUrl,
	postgresKysely,
	scratchUrl,
	sqliteKysely,
	tmpRoot,
} from "./store-contract/kernel/backends.js";
import { runKernelContract } from "./store-contract/kernel/index.js";

/**
 * The kernel and repository contract on every backend this machine can reach. SQLite always runs.
 * Postgres, MySQL and SQL Server run when THEAUTH_TEST_PG_URL, THEAUTH_TEST_MYSQL_URL and
 * THEAUTH_TEST_MSSQL_URL (mssql://user:password@host:port) are set, each in a scratch database.
 */
const root = tmpRoot();
afterAll(root.remove);

const sqlitePath = (name: string): string => `${root.dir}/${name}.db`;

runKernelContract(
	"drizzle sqlite (sql.js)",
	await drizzleBackend(() => ({ provider: "sqlite", url: ":memory:" }), "sqlite", false),
);

const drizzleFile = sqlitePath("drizzle");
runKernelContract(
	"drizzle sqlite (better-sqlite3 file)",
	await drizzleBackend(() => ({ provider: "sqlite-native", url: drizzleFile }), "sqlite", true),
);

const latencyFile = sqlitePath("latency");
await migrateSqliteFile(latencyFile);
runKernelContract(
	"drizzle sqlite (better-sqlite3 file, query latency)",
	latencyBackend(latencyFile),
);

const kyselyFile = sqlitePath("kysely");
await migrateSqliteFile(kyselyFile);
runKernelContract(
	"kysely sqlite (better-sqlite3 file)",
	kyselyBackend(() => sqliteKysely(kyselyFile), "sqlite", true),
);

const pgUrl = process.env.THEAUTH_TEST_PG_URL;
if (pgUrl) {
	const drizzleDb = "theauth_w9k_drizzle_pg";
	const kyselyDb = "theauth_w9k_kysely_pg";
	for (const name of [drizzleDb, kyselyDb]) await ensureScratchDatabase("postgres", pgUrl, name);
	afterAll(async () => {
		for (const name of [drizzleDb, kyselyDb]) await dropScratchDatabase("postgres", pgUrl, name);
	});
	const drizzleUrl = scratchUrl(pgUrl, drizzleDb);
	const kyselyUrl = scratchUrl(pgUrl, kyselyDb);
	runKernelContract(
		"drizzle postgres",
		await drizzleBackend(() => ({ provider: "postgres", url: drizzleUrl }), "postgres", true),
	);
	await drizzleBackend(() => ({ provider: "postgres", url: kyselyUrl }), "postgres", true);
	runKernelContract(
		"kysely postgres",
		kyselyBackend(() => postgresKysely(kyselyUrl), "postgres", true),
	);
}

const mysqlUrl = process.env.THEAUTH_TEST_MYSQL_URL;
if (mysqlUrl) {
	const drizzleDb = "theauth_w9k_drizzle_my";
	const kyselyDb = "theauth_w9k_kysely_my";
	for (const name of [drizzleDb, kyselyDb]) await ensureScratchDatabase("mysql", mysqlUrl, name);
	afterAll(async () => {
		for (const name of [drizzleDb, kyselyDb]) await dropScratchDatabase("mysql", mysqlUrl, name);
	});
	const drizzleUrl = scratchUrl(mysqlUrl, drizzleDb);
	const kyselyUrl = scratchUrl(mysqlUrl, kyselyDb);
	runKernelContract(
		"drizzle mysql",
		await drizzleBackend(
			() => ({ provider: "mysql", url: drizzleUrl, experimental: true }),
			"mysql",
			true,
		),
	);
	await drizzleBackend(
		() => ({ provider: "mysql", url: kyselyUrl, experimental: true }),
		"mysql",
		true,
	);
	runKernelContract(
		"kysely mysql",
		kyselyBackend(() => mysqlKysely(kyselyUrl), "mysql", true),
	);
}

const mssqlUrl = process.env.THEAUTH_TEST_MSSQL_URL;
if (mssqlUrl) {
	const target = parseMssqlUrl(mssqlUrl);
	const name = "theauth_w9k_kysely_ms";
	await createMssqlScratch(target, name);
	afterAll(() => dropMssqlScratch(target, name));
	runKernelContract(
		"kysely mssql",
		kyselyBackend(() => mssqlKysely(target, name), "mssql", true),
	);
}
