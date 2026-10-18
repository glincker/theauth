import type { TheAuthLogger } from "../observability/types.js";
import { getEnvNumber } from "../runtime/env.js";
import type { McpPruneOptions } from "./revocation-prune.js";
import { pruneIfDue, pruneStore } from "./revocation-prune.js";
import type {
	McpRevocationBus,
	McpRevocationBusOptions,
	McpRevocationEntry,
	McpRevocationEvent,
} from "./revocation-types.js";

/** What a failed push reports. Ids only, never a token value. */
export interface McpRevocationPushFailure {
	kind: McpRevocationEvent["kind"];
	ids: string[];
	reason: string;
	/** Push attempts made (2 means the retry also failed). */
	attempts: number;
	error: string;
}

export interface RevocationBusOptions extends McpRevocationBusOptions {
	/** Failures are logged here (warn on a retried attempt, error when the retry also failed). Default: silent. */
	logger?: TheAuthLogger;
	/** Called for every push that failed after its retry. Errors swallowed. */
	onPushFailure?: (failure: McpRevocationPushFailure) => void;
	/** Wait before the single retry. Default 50. */
	retryDelayMs?: number;
	/** Opportunistic pruning after writes. `intervalMs: 0` prunes after every push. */
	prune?: McpPruneOptions;
}

export interface RevocationBusStats {
	/** Publish calls. */
	published: number;
	/** Rows written to the store (after in-call dedupe). */
	rowsPushed: number;
	/** First attempts that failed and were retried. */
	retries: number;
	/** Pushes that failed after the retry. The counter an operator alerts on. */
	pushFailures: number;
	/** Failed attempts of any kind, including ones the retry recovered. Alert on a rising rate. */
	attemptFailures: number;
	/** Expired rows deleted by prune (opportunistic and manual). */
	pruned: number;
}

export interface RevocationBus extends McpRevocationBus {
	stats(): RevocationBusStats;
	/** Delete expired denylist rows now, in LIMITed batches. For cron. Resolves to rows deleted, 0 without a store. */
	prune(now?: Date): Promise<number>;
}

/** Rows for things with no expiry are kept this long (env override: THEAUTH_MCP_REVOCATION_RETENTION_MS). */
const DEFAULT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
/** Floor on a row's lifetime, so a row for an already expired link outlives clock skew. */
const MIN_RETENTION_MS = 60 * 1000;

/** When a denylist row may be pruned: the denied thing's own expiry (nothing it signed outlives it), floored, or a retention window when it has none. */
export function revocationRowExpiry(expiresAt: Date | null | undefined, now: Date): Date {
	const floor = now.getTime() + MIN_RETENTION_MS;
	if (!expiresAt) {
		// getEnv is safe on runtimes without `process` (Workers, Deno): a bare process.env would throw here.
		const raw = getEnvNumber("THEAUTH_MCP_REVOCATION_RETENTION_MS");
		const retention = raw !== undefined && raw > 0 ? raw : DEFAULT_RETENTION_MS;
		return new Date(now.getTime() + retention);
	}
	return new Date(Math.max(expiresAt.getTime(), floor));
}

function dedupe(entries: McpRevocationEntry[]): McpRevocationEntry[] {
	const seen = new Map<string, McpRevocationEntry>();
	for (const entry of entries) {
		const key = `${entry.kind}:${entry.id}`;
		const prior = seen.get(key);
		if (!prior || entry.expiresAt > prior.expiresAt) seen.set(key, entry);
	}
	return [...seen.values()];
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Collects revocation events and pushes them to the shared denylist. The store upsert is idempotent,
 * so publishing the same event twice is safe. A store failure never throws into the revoking caller:
 * it is retried once, then logged, counted and reported. Without a store the bus only notifies
 * in-process listeners, which is what the cached freshness layer needs on the revoking instance.
 */
export function createRevocationBus(options: RevocationBusOptions = {}): RevocationBus {
	const { store, onRevoked, logger, onPushFailure } = options;
	const retryDelayMs = options.retryDelayMs ?? 50;
	const listeners = new Set<(event: McpRevocationEvent) => void>();
	const clearers = new Set<(event: McpRevocationEvent) => void>();
	const counters: RevocationBusStats = {
		published: 0,
		rowsPushed: 0,
		retries: 0,
		pushFailures: 0,
		attemptFailures: 0,
		pruned: 0,
	};

	async function pushRows(rows: McpRevocationEntry[], revokedAt: Date): Promise<Error | null> {
		if (!store || rows.length === 0) return null;
		try {
			await store.revokeMany(rows, revokedAt);
			counters.rowsPushed += rows.length;
			return null;
		} catch (error) {
			counters.attemptFailures += 1;
			return error instanceof Error ? error : new Error(String(error));
		}
	}

	function notify(set: Set<(event: McpRevocationEvent) => void>, event: McpRevocationEvent): void {
		for (const listener of [...set]) {
			try {
				listener(event);
			} catch {
				// A bad listener must not stop the others or the revoke.
			}
		}
	}

	function warn(message: string, fields: Record<string, unknown>): void {
		try {
			logger?.warn(message, fields);
		} catch {
			// A broken logger must not break a revoke.
		}
	}

	function report(event: McpRevocationEvent, error: Error): void {
		counters.pushFailures += 1;
		const failure: McpRevocationPushFailure = {
			kind: event.kind,
			ids: event.ids,
			reason: event.reason,
			attempts: 2,
			error: error.message,
		};
		try {
			logger?.error("[mcp-revocation] push to the shared denylist failed", { ...failure });
		} catch {
			// A broken logger must not break a revoke.
		}
		try {
			onPushFailure?.(failure);
		} catch {
			// Reporting is best effort.
		}
	}

	return {
		async publish(event, entries) {
			counters.published += 1;
			// Clear the local cache FIRST: whatever happens to the push, this instance stops serving
			// positive cached verdicts for the revoked thing at once.
			notify(clearers, event);
			const rows = dedupe(entries);
			let failure = await pushRows(rows, event.revokedAt);
			if (failure) {
				counters.retries += 1;
				warn("[mcp-revocation] push to the shared denylist failed, retrying", {
					kind: event.kind,
					ids: event.ids,
					error: failure.message,
				});
				await sleep(retryDelayMs);
				failure = await pushRows(rows, event.revokedAt);
				if (failure) report(event, failure);
			}
			// Again after the push: a read that started between the first clear and the row write
			// may have cached a verdict that predates the row.
			notify(clearers, event);
			notify(listeners, event);
			if (store && rows.length > 0 && !failure) {
				void pruneIfDue(store, options.prune)
					.then((n) => {
						counters.pruned += n;
					})
					.catch(() => undefined);
			}
			if (onRevoked) {
				// Asynchronous on purpose: receivers can be slow, the revoke must not wait for them.
				void Promise.resolve()
					.then(() => onRevoked(event))
					.catch(() => undefined);
			}
		},

		async prune(now = new Date()) {
			if (!store) return 0;
			const n = await pruneStore(store, now, options.prune?.batchSize);
			counters.pruned += n;
			return n;
		},

		subscribeClear(listener) {
			clearers.add(listener);
			return () => {
				clearers.delete(listener);
			};
		},

		subscribe(listener) {
			listeners.add(listener);
			return () => {
				listeners.delete(listener);
			};
		},

		stats: () => ({ ...counters }),
	};
}
