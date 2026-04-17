// Process-local LRU cache. Map insertion order is the LRU order; re-inserting
// a key on read promotes it. TTL is checked lazily on get. Zero deps so this
// stays compatible with Workers, Bun, and Deno.

import type { PolicyCacheConfig, PolicyCacheStats, PolicyDecision } from "./types.js";

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface PolicyCache {
	get(key: string): PolicyDecision | undefined;
	set(key: string, value: PolicyDecision, options?: { skipCache?: boolean }): void;
	delete(key: string): boolean;
	clear(): void;
	/** Deletes all entries whose key starts with `prefix`. Returns count deleted. */
	invalidatePrefix(prefix: string): number;
	stats(): PolicyCacheStats;
}

// ---------------------------------------------------------------------------
// Internal entry shape
// ---------------------------------------------------------------------------

interface CacheEntry {
	value: PolicyDecision;
	expiresAt: number;
}

// ---------------------------------------------------------------------------
// Env-var helpers (edge-safe)
// ---------------------------------------------------------------------------

function readEnvNumber(name: string): number | undefined {
	if (typeof process === "undefined") return undefined;
	const raw = process.env[name];
	if (raw === undefined || raw === "") return undefined;
	const n = Number(raw);
	return Number.isFinite(n) ? n : undefined;
}

function readEnvBool(name: string): boolean | undefined {
	if (typeof process === "undefined") return undefined;
	const raw = process.env[name];
	if (raw === undefined || raw === "") return undefined;
	return raw.toLowerCase() !== "false" && raw !== "0";
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_ENTRIES = 10_000;
const DEFAULT_TTL_MS = 60_000;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createPolicyCache(config: PolicyCacheConfig): PolicyCache {
	const maxEntries =
		config.maxEntries ?? readEnvNumber("KAVACH_POLICY_CACHE_MAX") ?? DEFAULT_MAX_ENTRIES;

	const ttlMs = config.ttlMs ?? readEnvNumber("KAVACH_POLICY_CACHE_TTL_MS") ?? DEFAULT_TTL_MS;

	const enabled = config.enabled ?? readEnvBool("KAVACH_POLICY_CACHE") ?? true;

	const store = new Map<string, CacheEntry>();

	let hits = 0;
	let misses = 0;
	let evictions = 0;

	// ── Internal helpers ─────────────────────────────────────────────────────

	/**
	 * Remove the oldest entry (first key in Map iteration).
	 * Called when the store exceeds maxEntries.
	 */
	function evictOldest(): void {
		const firstKey = store.keys().next().value;
		if (firstKey !== undefined) {
			store.delete(firstKey);
			evictions++;
		}
	}

	/**
	 * Purge a single entry if it has expired. Returns true when expired.
	 */
	function isExpired(entry: CacheEntry): boolean {
		return Date.now() >= entry.expiresAt;
	}

	// ── Public methods ───────────────────────────────────────────────────────

	function get(key: string): PolicyDecision | undefined {
		if (!enabled) {
			misses++;
			return undefined;
		}

		const entry = store.get(key);

		if (entry === undefined) {
			misses++;
			return undefined;
		}

		if (isExpired(entry)) {
			store.delete(key);
			evictions++;
			misses++;
			return undefined;
		}

		// Move to most-recently-used position by re-inserting.
		store.delete(key);
		store.set(key, entry);

		hits++;
		return entry.value;
	}

	function set(key: string, value: PolicyDecision, options?: { skipCache?: boolean }): void {
		if (!enabled || options?.skipCache === true) return;

		// Evict stale entry for the same key before checking capacity.
		const existing = store.get(key);
		if (existing !== undefined) {
			store.delete(key);
		}

		// Evict oldest entries until we have room for one more.
		while (store.size >= maxEntries) {
			evictOldest();
		}

		store.set(key, { value, expiresAt: Date.now() + ttlMs });
	}

	function del(key: string): boolean {
		return store.delete(key);
	}

	function clear(): void {
		store.clear();
	}

	function invalidatePrefix(prefix: string): number {
		let count = 0;
		for (const key of store.keys()) {
			if (key.startsWith(prefix)) {
				store.delete(key);
				count++;
			}
		}
		return count;
	}

	function stats(): PolicyCacheStats {
		return {
			hits,
			misses,
			size: store.size,
			evictions,
		};
	}

	return { get, set, delete: del, clear, invalidatePrefix, stats };
}
