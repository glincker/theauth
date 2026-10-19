import { createClient } from "@libsql/client";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runStoreContract } from "../../../test-utils/src/store-contract/index.js";
import type { DatabaseConfig } from "../../src/db/database.js";
import { createTheAuth } from "../../src/theauth.js";
import { bootTarget } from "./boot.js";

/**
 * Opt-in suites against real hosted databases. Each one is skipped unless its variable is set,
 * so a plain `vitest run` never touches the network.
 *
 *   THEAUTH_TEST_TURSO_URL         libsql://... (a throwaway Turso database)
 *   THEAUTH_TEST_TURSO_AUTH_TOKEN  its auth token
 *   THEAUTH_TEST_NEON_URL          postgres://... Neon connection string (the -pooler host works too)
 *   THEAUTH_TEST_SUPABASE_URL      postgres://... Supabase string (direct, session or transaction pooler)
 *   THEAUTH_TEST_HOSTED_RESET=1    drop the theauth_* tables of each configured database before its suite
 *
 * Point them at empty, disposable databases: the contract suite writes users, agents, sessions and
 * audit rows. It only creates new rows with random ids, so it never reads or edits existing data, but
 * it does not clean up after itself. `THEAUTH_TEST_HOSTED_RESET=1` removes only tables named
 * `theauth_*`. See docs/hosted-databases.mdx.
 */
const TIMEOUT_MS = 300_000; // a remote round trip costs far more than a local one
const reset = process.env.THEAUTH_TEST_HOSTED_RESET === "1";

const turso = {
	url: process.env.THEAUTH_TEST_TURSO_URL,
	authToken: process.env.THEAUTH_TEST_TURSO_AUTH_TOKEN,
};
const neonUrl = process.env.THEAUTH_TEST_NEON_URL;
const supabaseUrl = process.env.THEAUTH_TEST_SUPABASE_URL;

/** Drops the theauth_ tables of a Postgres database. Foreign keys are cleared by CASCADE. */
async function dropPostgresTables(url: string): Promise<void> {
	const pool = new pg.Pool({ connectionString: url, max: 1 });
	try {
		const { rows } = await pool.query<{ tablename: string }>(
			"SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'theauth\\_%'",
		);
		for (const row of rows) await pool.query(`DROP TABLE IF EXISTS "${row.tablename}" CASCADE`);
	} finally {
		await pool.end();
	}
}

/** Drops the theauth_ tables of a libSQL database, retrying in passes for foreign keys. */
async function dropLibsqlTables(url: string, authToken: string | undefined): Promise<void> {
	const client = createClient({ url, ...(authToken && { authToken }) });
	try {
		for (let pass = 0; pass < 12; pass++) {
			const { rows } = await client.execute(
				"SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'theauth\\_%' ESCAPE '\\'",
			);
			if (rows.length === 0) return;
			for (const row of rows) {
				try {
					await client.execute(`DROP TABLE IF EXISTS "${String(row.name)}"`);
				} catch {
					// Referenced by another table: the next pass gets it.
				}
			}
		}
	} finally {
		client.close();
	}
}

function hostedSuite(
	name: string,
	configured: boolean,
	config: () => DatabaseConfig,
	clean: () => Promise<void>,
	parallel = 10,
): void {
	if (!configured) {
		runStoreContract(name, () => Promise.reject(new Error("unreachable")), { skip: true });
		return;
	}
	describe(`hosted: ${name}`, () => {
		beforeAll(async () => {
			if (reset) await clean();
		}, TIMEOUT_MS);
		afterAll(async () => {
			if (reset) await clean();
		}, TIMEOUT_MS);

		it(
			"keeps data across a restart and passes the schema check with skipMigrations",
			async () => {
				const first = await createTheAuth({ database: config() });
				const email = `restart-${Math.random().toString(36).slice(2)}@hosted.test`;
				const user = await first.user.create({ email });
				const second = await createTheAuth({
					database: { ...config(), skipMigrations: true } as DatabaseConfig,
				});
				expect((await second.user.get(email))?.id).toBe(user.id);
				expect((await second.schema.status()).pending).toEqual([]);
			},
			TIMEOUT_MS,
		);
	});
	runStoreContract(name, () => bootTarget(config, true), { parallel, timeoutMs: TIMEOUT_MS });
}

hostedSuite(
	"Turso (libsql)",
	Boolean(turso.url),
	() => ({
		provider: "libsql",
		url: turso.url ?? "",
		...(turso.authToken && { authToken: turso.authToken }),
	}),
	() => dropLibsqlTables(turso.url ?? "", turso.authToken),
);

hostedSuite(
	"Neon (postgres provider)",
	Boolean(neonUrl),
	() => ({ provider: "postgres", url: neonUrl ?? "" }),
	() => dropPostgresTables(neonUrl ?? ""),
);

hostedSuite(
	"Supabase (postgres provider)",
	Boolean(supabaseUrl),
	() => ({ provider: "postgres", url: supabaseUrl ?? "" }),
	() => dropPostgresTables(supabaseUrl ?? ""),
);

/**
 * Neon's WebSocket `Pool` is a separate code path from `pg`, and the one the docs recommend on
 * serverless. It runs when THEAUTH_TEST_NEON_URL is set and `@neondatabase/serverless` is
 * installed (it is not a dependency of this repository: `pnpm add -D @neondatabase/serverless`
 * in packages/core to try it, then drop the change).
 */
const neonDriver = neonUrl
	? await import("@neondatabase/serverless" as string).catch(() => null)
	: null;

if (neonUrl && neonDriver) {
	const { Pool } = neonDriver as { Pool: new (opts: { connectionString: string }) => unknown };
	const { drizzle } = (await import("drizzle-orm/neon-serverless" as string)) as {
		drizzle: (opts: { client: unknown }) => unknown;
	};
	runStoreContract(
		"Neon (WebSocket Pool)",
		() =>
			bootTarget(
				() =>
					({
						drizzle: drizzle({ client: new Pool({ connectionString: neonUrl }) }),
						dialect: "postgres",
					}) as unknown as DatabaseConfig,
				true,
			),
		{ parallel: 10, timeoutMs: TIMEOUT_MS },
	);
} else {
	runStoreContract("Neon (WebSocket Pool)", () => Promise.reject(new Error("unreachable")), {
		skip: true,
	});
}
