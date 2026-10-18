import { getEnvNumber } from "../runtime/env.js";
import type { McpRevocationStore } from "./revocation-types.js";
import { MCP_REVOCATION_DEFAULTS } from "./revocation-types.js";

/** Default gap between opportunistic prunes per instance and store. Env THEAUTH_MCP_REVOCATION_PRUNE_INTERVAL_MS. */
export const DEFAULT_PRUNE_INTERVAL_MS = 60_000;
/** Batches one prune run may delete, so a single request never deletes an unbounded number of rows. */
const MAX_BATCHES_PER_RUN = 4;

export interface McpPruneOptions {
	/** Minimum gap between opportunistic prunes. 0 prunes on every call. */
	intervalMs?: number;
	/** Rows per delete batch. Default 500. */
	batchSize?: number;
}

const LAST_PRUNE = new WeakMap<McpRevocationStore, number>();

/** Delete expired rows in LIMITed batches until a batch is not full (at most a few batches). Returns rows deleted. */
export async function pruneStore(
	store: McpRevocationStore,
	now: Date,
	batchSize: number = MCP_REVOCATION_DEFAULTS.pruneLimit,
): Promise<number> {
	let total = 0;
	for (let i = 0; i < MAX_BATCHES_PER_RUN; i++) {
		const n = await store.prune(now, batchSize);
		total += n;
		if (n < batchSize) break;
	}
	return total;
}

/**
 * Prune after a write, at most once per interval per instance. No timers: Workers have none, so
 * pruning rides on the writes that grow the table. Never throws. A clock that moved backwards
 * makes a prune due, never overdue.
 */
export async function pruneIfDue(
	store: McpRevocationStore,
	options: McpPruneOptions = {},
	now: Date = new Date(),
): Promise<number> {
	const intervalMs =
		options.intervalMs ??
		getEnvNumber("THEAUTH_MCP_REVOCATION_PRUNE_INTERVAL_MS") ??
		DEFAULT_PRUNE_INTERVAL_MS;
	const t = now.getTime();
	const last = LAST_PRUNE.get(store);
	if (last !== undefined && t >= last && t - last < intervalMs) return 0;
	// Claim the slot before the await so concurrent writes do not all prune.
	LAST_PRUNE.set(store, t);
	try {
		return await pruneStore(store, now, options.batchSize);
	} catch {
		return 0;
	}
}
