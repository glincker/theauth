import { afterAll } from "vitest";
import { runStoreContract } from "../../test-utils/src/store-contract/index.js";
import { oauthStates } from "../src/auth/oauth/schema.js";
import type { Database } from "../src/db/database.js";
import { overrideStores, storesFromKernel } from "../src/db/store/index.js";
import type { KyselyDialect } from "../src/db/store/kysely/index.js";
import { createKyselyKernel } from "../src/db/store/kysely/index.js";
import { bootTarget } from "./store-contract/boot.js";
import {
	mysqlKysely,
	postgresKysely,
	sqliteKysely,
	tmpRoot,
} from "./store-contract/kernel/backends.js";
import {
	dropScratchDatabase,
	ensureScratchDatabase,
	scratchUrl,
} from "./store-contract/scratch.js";

/**
 * The whole instance-level store contract (claim races, approvals, unique conflicts, audit chain
 * order, rate limits) with the single-use repositories and the audit write path routed through the
 * Kysely kernel. Everything not yet ported to a repository still runs on the Drizzle handle, so
 * both talk to the same database. SQL Server has no Drizzle driver and cannot boot an instance,
 * so it is covered by the kernel and repository contract in store-kernel-contract.test.ts.
 */
function routeThroughKysely(
	makeKysely: () => ReturnType<typeof sqliteKysely>,
	dialect: KyselyDialect,
): (db: Database) => { close(): Promise<void> } {
	return (db) => {
		const k = makeKysely();
		overrideStores(
			db,
			storesFromKernel(createKyselyKernel(k, dialect, { extraTables: { oauthStates } })),
			(extraTables) => createKyselyKernel(k, dialect, { extraTables }),
		);
		return { close: () => k.destroy() };
	};
}

const root = tmpRoot();
afterAll(root.remove);

const file = `${root.dir}/hybrid.db`;
runStoreContract("kysely kernel on sqlite-native (file)", () =>
	bootTarget(
		() => ({ provider: "sqlite-native", url: file }),
		true,
		routeThroughKysely(() => sqliteKysely(file), "sqlite"),
	),
);

const pgUrl = process.env.THEAUTH_TEST_PG_URL;
if (pgUrl) {
	const name = "theauth_w9k_hybrid_pg";
	await ensureScratchDatabase("postgres", pgUrl, name);
	afterAll(() => dropScratchDatabase("postgres", pgUrl, name));
	const url = scratchUrl(pgUrl, name);
	runStoreContract("kysely kernel on postgres", () =>
		bootTarget(
			() => ({ provider: "postgres", url }),
			true,
			routeThroughKysely(() => postgresKysely(url), "postgres"),
		),
	);
} else {
	runStoreContract("kysely kernel on postgres", () => Promise.reject(new Error("unreachable")), {
		skip: true,
	});
}

const mysqlUrl = process.env.THEAUTH_TEST_MYSQL_URL;
if (mysqlUrl) {
	const name = "theauth_w9k_hybrid_my";
	await ensureScratchDatabase("mysql", mysqlUrl, name);
	afterAll(() => dropScratchDatabase("mysql", mysqlUrl, name));
	const url = scratchUrl(mysqlUrl, name);
	runStoreContract("kysely kernel on mysql", () =>
		bootTarget(
			() => ({ provider: "mysql", url, experimental: true }),
			true,
			routeThroughKysely(() => mysqlKysely(url), "mysql"),
		),
	);
} else {
	runStoreContract("kysely kernel on mysql", () => Promise.reject(new Error("unreachable")), {
		skip: true,
	});
}
