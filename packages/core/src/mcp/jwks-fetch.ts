import type { JWK } from "jose";
import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { SafeFetchOptions } from "./safe-fetch.js";
import { safeFetchJson } from "./safe-fetch.js";
import type { McpAuthContext } from "./types.js";

/** Remote JWKS retrieval for `private_key_jwt` clients and jwt-bearer trusted issuers. Goes through the SSRF-safe fetcher and caches per module instance. */

const JWKS_MAX_BYTES = 16 * 1024;
const JWKS_MAX_KEYS = 20;
/** Entries per module instance. Least recently used goes first. */
const JWKS_MAX_ENTRIES = 256;
const JWKS_CACHE_MS = 5 * 60 * 1000;
const JWKS_MIN_TTL_MS = 60 * 1000;
const JWKS_MAX_TTL_MS = 60 * 60 * 1000;
/** Do not refetch a JWKS more often than this, even for an unknown `kid`. */
const JWKS_MIN_REFETCH_MS = 30 * 1000;

interface CacheEntry {
	keys: JWK[];
	fetchedAt: number;
	ttlMs: number;
}

/** Server chosen lifetime: `max-age` clamped to [1 min, 1 h], else 5 min. */
function ttlFrom(cacheControl: string | undefined): number {
	const match = /(?:^|,)\s*max-age=(\d{1,9})\s*(?:,|$)/i.exec(cacheControl ?? "");
	if (!match?.[1]) return JWKS_CACHE_MS;
	return Math.min(JWKS_MAX_TTL_MS, Math.max(JWKS_MIN_TTL_MS, Number(match[1]) * 1000));
}

const caches = new WeakMap<object, Map<string, CacheEntry>>();
const storages = new WeakMap<object, SecondaryStorage>();

function cacheFor(ctx: McpAuthContext): Map<string, CacheEntry> {
	let cache = caches.get(ctx);
	if (!cache) {
		cache = new Map();
		caches.set(ctx, cache);
	}
	return cache;
}

function isJwkArray(value: unknown): value is JWK[] {
	return (
		Array.isArray(value) &&
		value.every((k) => typeof k === "object" && k !== null && !Array.isArray(k))
	);
}

/** Fetch a JWKS document. `forceRefresh` re-reads it (used when a `kid` is not in the cached set), rate limited so a hostile `kid` cannot drive fetches. */
export async function loadRemoteJwks(
	ctx: McpAuthContext,
	uri: string,
	fetchOptions: SafeFetchOptions,
	forceRefresh = false,
): Promise<{ ok: true; keys: JWK[] } | { ok: false; message: string }> {
	const cache = cacheFor(ctx);
	const cached = cache.get(uri);
	const age = cached ? Date.now() - cached.fetchedAt : Number.POSITIVE_INFINITY;
	if (cached && age < cached.ttlMs && !(forceRefresh && age >= JWKS_MIN_REFETCH_MS)) {
		// Re-insert so the entry counts as recently used.
		cache.delete(uri);
		cache.set(uri, cached);
		return { ok: true, keys: cached.keys };
	}
	const fetched = await safeFetchJson(uri, {
		...fetchOptions,
		maxBytes: Math.min(fetchOptions.maxBytes ?? JWKS_MAX_BYTES, JWKS_MAX_BYTES),
	});
	if (!fetched.ok) {
		// A stale copy beats failing every request during a short outage.
		if (cached && age < cached.ttlMs * 6) return { ok: true, keys: cached.keys };
		// Generic on purpose: the cause (blocked, unresolvable, timeout) must not reach the requester.
		return { ok: false, message: "jwks unavailable" };
	}
	const doc = fetched.json;
	const keys =
		typeof doc === "object" && doc !== null ? (doc as { keys?: unknown }).keys : undefined;
	if (!isJwkArray(keys) || keys.length === 0 || keys.length > JWKS_MAX_KEYS) {
		return { ok: false, message: "jwks unavailable" };
	}
	cache.delete(uri);
	cache.set(uri, { keys, fetchedAt: Date.now(), ttlMs: ttlFrom(fetched.cacheControl) });
	while (cache.size > JWKS_MAX_ENTRIES) {
		const oldest = cache.keys().next();
		if (oldest.done) break;
		cache.delete(oldest.value);
	}
	return { ok: true, keys };
}

/** Replay-cache storage for assertions: configured, else per-module memory. */
export function getAssertionStorage(ctx: McpAuthContext): SecondaryStorage {
	const configured = ctx.config.assertionStorage;
	if (configured) return configured;
	let store = storages.get(ctx);
	if (!store) {
		store = memoryStorage();
		storages.set(ctx, store);
	}
	return store;
}
