import type { SQLiteTable } from "drizzle-orm/sqlite-core";
import type { Database } from "../database.js";
import { createAuditLogRepo } from "./audit-repo.js";
import { createDrizzleKernel } from "./drizzle-kernel.js";
import { createSingleUseStores } from "./single-use.js";
import type { SingleUseStores, StoreKernel, Stores } from "./types.js";

const cache = new WeakMap<object, Stores>();

/** Builds the repositories on a kernel. A backend implements the kernel and gets every repository. */
export function storesFromKernel(kernel: StoreKernel): Stores {
	return { kernel, singleUse: createSingleUseStores(kernel), audit: createAuditLogRepo(kernel) };
}

/** The repositories for a Drizzle handle, built once per handle. */
export function storesFor(db: Database): Stores {
	let stores = cache.get(db);
	if (!stores) {
		stores = storesFromKernel(createDrizzleKernel(db));
		cache.set(db, stores);
	}
	return stores;
}

type KernelFactory = (extraTables: Record<string, SQLiteTable>) => StoreKernel;

const factories = new WeakMap<object, KernelFactory>();
const withTables = new WeakMap<object, WeakMap<object, SingleUseStores>>();

/**
 * Routes the repositories of one handle to another kernel (the Kysely kernel, in the contract suite). `kernelFor` builds that kernel for a plugin's extra tables. Everything not yet ported to a repository keeps using the Drizzle handle, so both must point at the same database. Call it before the first query.
 */
export function overrideStores(db: Database, stores: Stores, kernelFor?: KernelFactory): void {
	cache.set(db, stores);
	withTables.delete(db);
	if (kernelFor) factories.set(db, kernelFor);
	else factories.delete(db);
}

/**
 * The single-use repositories for a handle, over the core tables plus a plugin's own tables (the OAuth client module's state table). Pass the same `tables` object each time, so the repositories are built once per handle.
 */
export function singleUseWithTables(
	db: Database,
	tables: Record<string, SQLiteTable>,
): SingleUseStores {
	let byTables = withTables.get(db);
	if (!byTables) {
		byTables = new WeakMap();
		withTables.set(db, byTables);
	}
	let stores = byTables.get(tables);
	if (!stores) {
		const factory = factories.get(db);
		stores = createSingleUseStores(
			factory ? factory(tables) : createDrizzleKernel(db, { extraTables: tables }),
		);
		byTables.set(tables, stores);
	}
	return stores;
}

/** The single-use repositories for a Drizzle handle. */
export function singleUseFor(db: Database): SingleUseStores {
	return storesFor(db).singleUse;
}
