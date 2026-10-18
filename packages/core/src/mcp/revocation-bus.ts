import type { TheAuthLogger } from "../observability/types.js";
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
	/** Failures are logged here at error level. Default: silent. */
	logger?: TheAuthLogger;
	/** Called for every push that failed after its retry. Errors swallowed. */
	onPushFailure?: (failure: McpRevocationPushFailure) => void;
	/** Wait before the single retry. Default 50. */
	retryDelayMs?: number;
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
}

export interface RevocationBus extends McpRevocationBus {
	stats(): RevocationBusStats;
}

/** Rows for things with no expiry are kept this long (env override: THEAUTH_MCP_REVOCATION_RETENTION_MS). */
const DEFAULT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
/** Floor on a row's lifetime, so a row for an already expired link outlives clock skew. */
const MIN_RETENTION_MS = 60 * 1000;

/** When a denylist row may be pruned: the denied thing's own expiry (nothing it signed outlives it), floored, or a retention window when it has none. */
export function revocationRowExpiry(expiresAt: Date | null | undefined, now: Date): Date {
	const floor = now.getTime() + MIN_RETENTION_MS;
	if (!expiresAt) {
		const raw = Number(process.env.THEAUTH_MCP_REVOCATION_RETENTION_MS);
		const retention = Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_RETENTION_MS;
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
	const counters: RevocationBusStats = { published: 0, rowsPushed: 0, retries: 0, pushFailures: 0 };

	async function pushRows(rows: McpRevocationEntry[], revokedAt: Date): Promise<Error | null> {
		if (!store || rows.length === 0) return null;
		try {
			await store.revokeMany(rows, revokedAt);
			counters.rowsPushed += rows.length;
			return null;
		} catch (error) {
			return error instanceof Error ? error : new Error(String(error));
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
			const rows = dedupe(entries);
			let failure = await pushRows(rows, event.revokedAt);
			if (failure) {
				counters.retries += 1;
				await sleep(retryDelayMs);
				failure = await pushRows(rows, event.revokedAt);
				if (failure) report(event, failure);
			}
			for (const listener of [...listeners]) {
				try {
					listener(event);
				} catch {
					// A bad listener must not stop the others or the revoke.
				}
			}
			if (onRevoked) {
				// Asynchronous on purpose: receivers can be slow, the revoke must not wait for them.
				void Promise.resolve()
					.then(() => onRevoked(event))
					.catch(() => undefined);
			}
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
