/**
 * Browser and edge safe entry: `@glinr/theauth/browser`.
 * Exposes the agent-security core (guardTool, taint labels, policy engine, signed audit checkpoints and receipts) and a `createTheAuth` that never loads a Node-only driver (pg, mysql2, better-sqlite3, libsql, nodemailer, node:zlib, node:fs).
 */

import type { SqlJsLoader } from "./db/database-browser.js";
import { createBrowserDatabaseOpener } from "./db/database-browser.js";
import type { TheAuth } from "./theauth-core.js";
import { createTheAuthWith } from "./theauth-core.js";
import type { TheAuthConfig } from "./types.js";

export type { SqlJsLoader, TheAuth, TheAuthConfig };

export interface BrowserTheAuthConfig extends TheAuthConfig {
	/** Loader for the sql.js WASM build. Required when `database.provider` is "sqlite". */
	sqlJs?: SqlJsLoader;
}

export async function createTheAuth(config: BrowserTheAuthConfig): Promise<TheAuth> {
	const { sqlJs, ...rest } = config;
	return createTheAuthWith(rest, createBrowserDatabaseOpener(sqlJs));
}

export * from "./agent-tools/index.js";
export * from "./audit/index.js";
export { users } from "./db/schema.js";
export * from "./policy/index.js";
export * from "./taint/index.js";
