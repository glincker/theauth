import type { JWK } from "jose";
import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { SafeFetchOptions } from "./safe-fetch.js";
import { safeFetchJson } from "./safe-fetch.js";
import type { McpAuthContext } from "./types.js";

/**
 * Remote JWKS retrieval for `private_key_jwt` clients and jwt-bearer trusted
 * issuers. Goes through the SSRF-safe fetcher and caches per module instance.
 */

const JWKS_MAX_BYTES = 64 * 1024;
const JWKS_CACHE_MS = 5 * 60 * 1000;
/** Do not refetch a JWKS more often than this, even for an unknown `kid`. */
const JWKS_MIN_REFETCH_MS = 30 * 1000;

interface CacheEntry {
	keys: JWK[];
	fetchedAt: number;
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

/**
 * Fetch a JWKS document. `forceRefresh` re-reads it (used when a `kid` is not
 * in the cached set), rate limited so a hostile `kid` cannot drive fetches.
 */
export async function loadRemoteJwks(
	ctx: McpAuthContext,
	uri: string,
	fetchOptions: SafeFetchOptions,
	forceRefresh = false,
): Promise<{ ok: true; keys: JWK[] } | { ok: false; message: string }> {
	const cache = cacheFor(ctx);
	const cached = cache.get(uri);
	const age = cached ? Date.now() - cached.fetchedAt : Number.POSITIVE_INFINITY;
	if (cached && age < JWKS_CACHE_MS && !(forceRefresh && age >= JWKS_MIN_REFETCH_MS)) {
		return { ok: true, keys: cached.keys };
	}
	const fetched = await safeFetchJson(uri, { ...fetchOptions, maxBytes: JWKS_MAX_BYTES });
	if (!fetched.ok) {
		// A stale copy beats failing every request during a short outage.
		if (cached && age < JWKS_CACHE_MS * 6) return { ok: true, keys: cached.keys };
		return { ok: false, message: `jwks fetch failed: ${fetched.message}` };
	}
	const doc = fetched.json;
	const keys =
		typeof doc === "object" && doc !== null ? (doc as { keys?: unknown }).keys : undefined;
	if (!isJwkArray(keys) || keys.length === 0) {
		return { ok: false, message: "jwks document has no keys" };
	}
	cache.set(uri, { keys, fetchedAt: Date.now() });
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
