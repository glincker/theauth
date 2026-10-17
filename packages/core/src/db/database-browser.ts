import { drizzle as drizzleSqlJs } from "drizzle-orm/sql-js";
import type { SqlJsStatic } from "sql.js";
import type { Database, DatabaseConfig } from "./database.js";
import * as schema from "./schema.js";

/** A caller-supplied sql.js loader, e.g. `() => initSqlJs({ locateFile })`. */
export type SqlJsLoader = () => Promise<SqlJsStatic>;

/**
 * Open a database without importing any Node-only driver.
 * File URLs are not read or written here; persistence is the caller's concern. Postgres, MySQL and native SQLite are rejected: use the root export on Node.
 */
export function createBrowserDatabaseOpener(
	loadSqlJs?: SqlJsLoader,
): (config: DatabaseConfig) => Promise<Database> {
	return async (config) => {
		if (config.provider === "sqlite") {
			if (!loadSqlJs) {
				throw new Error(
					'TheAuth: provider "sqlite" in the browser entry needs a sqlJs loader. ' +
						"Pass `sqlJs: () => initSqlJs({ locateFile })`.",
				);
			}
			const SQL = await loadSqlJs();
			const db = new SQL.Database();
			db.run("PRAGMA foreign_keys = ON");
			return drizzleSqlJs(db, { schema }) as unknown as Database;
		}
		if (config.provider === "d1") {
			const { drizzle } = await import("drizzle-orm/d1");
			return drizzle(config.binding as never, { schema }) as unknown as Database;
		}
		throw new Error(
			`TheAuth: provider "${config.provider}" is not available in the browser entry. ` +
				'Use "sqlite" with a sqlJs loader, "d1", or import from "@glinr/theauth" on Node.',
		);
	};
}
