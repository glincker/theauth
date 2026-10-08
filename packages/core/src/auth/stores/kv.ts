/**
 * Rate limit store on top of Cloudflare KV (back-compat wrapper).
 *
 * New code should use `cloudflareKvStorage()` from the secondary storage
 * module; this class now delegates to it. Pass a SecondaryStorage with an
 * atomic `incr` (database, Redis, Durable Object) instead of a raw KV
 * namespace to get race-free counting.
 *
 * KV limitation: a raw KV namespace has no atomic increment and is eventually
 * consistent, so concurrent requests can under-count. Treat KV limits as soft.
 */

import { cloudflareKvStorage } from "../../storage/cloudflare-kv.js";
import { isSecondaryStorage, rateLimitStoreFromStorage } from "../../storage/rate-limit-store.js";
import type { SecondaryStorage } from "../../storage/types.js";
import type { RateLimitStore } from "./types.js";

/** Minimal KV namespace interface — compatible with Cloudflare Workers KVNamespace */
export interface KVNamespace {
	get(key: string): Promise<string | null>;
	put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
	delete(key: string): Promise<void>;
}

export class KVStore implements RateLimitStore {
	private readonly inner: RateLimitStore;

	constructor(kv: KVNamespace | SecondaryStorage) {
		this.inner = rateLimitStoreFromStorage(isSecondaryStorage(kv) ? kv : cloudflareKvStorage(kv));
	}

	increment(key: string, windowMs: number): Promise<{ count: number; resetAt: number }> {
		return this.inner.increment(key, windowMs);
	}

	reset(key: string): Promise<void> {
		return this.inner.reset(key);
	}
}

/** Factory function to create a KVStore from a KV namespace binding or any SecondaryStorage */
export function kvStore(kv: KVNamespace | SecondaryStorage): KVStore {
	return new KVStore(kv);
}
