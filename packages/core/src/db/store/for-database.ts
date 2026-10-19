import type { Database } from "../database.js";
import { createDrizzleKernel } from "./drizzle-kernel.js";
import { createSingleUseStores } from "./single-use.js";
import type { SingleUseStores } from "./types.js";

const cache = new WeakMap<object, SingleUseStores>();

/** The single-use repositories for a Drizzle handle, built once per handle. */
export function singleUseFor(db: Database): SingleUseStores {
	let stores = cache.get(db);
	if (!stores) {
		stores = createSingleUseStores(createDrizzleKernel(db));
		cache.set(db, stores);
	}
	return stores;
}
