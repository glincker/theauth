import { createDatabase } from "./db/database.js";
import type { PermissionCatalog, TypedTheAuth } from "./permission/typed.js";
import type { TheAuth } from "./theauth-core.js";
import { createTheAuthWith } from "./theauth-core.js";
import type { TheAuthConfig } from "./types.js";

export type { TheAuth, TypedTheAuth };

/**
 * Create a TheAuth instance.
 * The factory is **async** so it can open database connections for Postgres and MySQL (which require async driver initialisation) and optionally run `CREATE TABLE IF NOT EXISTS` for all schema tables.
 *
 * @example SQLite (simplest)
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 *
 * const auth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 * });
 * ```
 *
 * For a browser or other driver-free runtime use `@glinr/theauth/browser`.
 */
export async function createTheAuth<const C extends PermissionCatalog>(
	config: TheAuthConfig & { permissions: C },
): Promise<TypedTheAuth<C>>;
export async function createTheAuth(config: TheAuthConfig): Promise<TheAuth>;
export async function createTheAuth(config: TheAuthConfig): Promise<TheAuth> {
	return createTheAuthWith(config, createDatabase);
}

/**
 * @deprecated Use `createTheAuth` instead. Will be removed in a future major version.
 */
export const createAuth = createTheAuth;

/**
 * @deprecated Use `TheAuth` instead. Will be removed in a future major version.
 */
export type Auth = TheAuth;
