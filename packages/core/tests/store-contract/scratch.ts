import { createDatabase } from "../../src/db/database.js";
import { createExecutor } from "../../src/db/migrate/executor.js";
import { closeDatabase } from "./boot.js";

/** The same server and credentials as `base`, a different database name. */
export function scratchUrl(base: string, name: string): string {
	const u = new URL(base);
	u.pathname = `/${name}`;
	return u.toString();
}

async function admin(provider: "postgres" | "mysql", base: string, sql: string): Promise<void> {
	const db = await createDatabase(
		provider === "mysql" ? { provider, url: base, experimental: true } : { provider, url: base },
	);
	try {
		await createExecutor(db, provider).run(sql);
	} finally {
		await closeDatabase(db);
	}
}

/** Drops and recreates the scratch database, so a run never sees rows from the last one. */
export async function ensureScratchDatabase(
	provider: "postgres" | "mysql",
	base: string,
	name: string,
): Promise<void> {
	await admin(provider, base, `DROP DATABASE IF EXISTS ${name}`);
	await admin(
		provider,
		base,
		provider === "mysql"
			? `CREATE DATABASE ${name} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`
			: `CREATE DATABASE ${name}`,
	);
}

export async function dropScratchDatabase(
	provider: "postgres" | "mysql",
	base: string,
	name: string,
): Promise<void> {
	await admin(provider, base, `DROP DATABASE IF EXISTS ${name}`);
}
