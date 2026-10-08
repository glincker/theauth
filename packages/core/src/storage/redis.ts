import type { IncrResult, SecondaryStorage } from "./types.js";

/**
 * The smallest Redis surface we need. ioredis, node-redis (v4+) and the Upstash
 * REST client all satisfy it structurally, so TheAuth has no Redis dependency.
 *
 * Methods are looked up by their lowercase name first and the camelCase name
 * node-redis uses second (`pexpire` / `pExpire`, `pttl` / `pTTL`, `psetex` /
 * `pSetEx`). Declare whichever your client has; at runtime either works.
 */
export interface RedisLikeClient {
	get(key: string): Promise<string | null>;
	del(key: string | string[]): Promise<unknown>;
	incr(key: string): Promise<number>;
	/** Optional: only needed for list(). O(N) on the server, avoid on big keyspaces. */
	keys?(pattern: string): Promise<string[]>;
	[method: string]: unknown;
}

type AnyFn = (...args: unknown[]) => Promise<unknown>;

function method(client: RedisLikeClient, names: string[]): AnyFn | null {
	for (const name of names) {
		const fn = client[name];
		if (typeof fn === "function") return (fn as AnyFn).bind(client);
	}
	return null;
}

function requireMethod(client: RedisLikeClient, names: string[]): AnyFn {
	const fn = method(client, names);
	if (!fn) throw new Error(`redisStorage: client has no ${names.join(" or ")} method`);
	return fn;
}

/** Escape glob metacharacters so a prefix is matched literally by KEYS. */
function escapeGlob(prefix: string): string {
	return prefix.replace(/[\\*?[\]]/g, "\\$&");
}

/**
 * Redis-compatible storage (Redis, Valkey, Upstash, Dragonfly, KeyDB).
 *
 * `incr` is atomic: INCR is atomic on the server, and the TTL is applied right
 * after the key is created. If the process dies between INCR and PEXPIRE the
 * next caller sees a counter with no TTL (PTTL = -1) and repairs it, so a
 * counter can never become permanent.
 */
export function redisStorage(client: RedisLikeClient): SecondaryStorage {
	const pexpire = requireMethod(client, ["pexpire", "pExpire"]);
	const pttl = requireMethod(client, ["pttl", "pTTL"]);
	const psetex = method(client, ["psetex", "pSetEx"]);
	const setFn = method(client, ["set"]);

	const storage: SecondaryStorage = {
		atomicIncr: true,
		async get(key) {
			const value = await client.get(key);
			return value === null || value === undefined ? null : String(value);
		},
		async set(key, value, ttlSeconds) {
			if (ttlSeconds === undefined) {
				if (!setFn) throw new Error("redisStorage: client has no set method");
				await setFn(key, value);
				return;
			}
			const ms = Math.max(Math.ceil(ttlSeconds * 1000), 1);
			if (psetex) {
				await psetex(key, ms, value);
				return;
			}
			if (!setFn) throw new Error("redisStorage: client has no set or psetex method");
			await setFn(key, value);
			await pexpire(key, ms);
		},
		async delete(key) {
			await client.del(key);
		},
		async incr(key, ttlSeconds): Promise<IncrResult> {
			const ttlMs = Math.max(Math.ceil(ttlSeconds * 1000), 1);
			const count = Number(await client.incr(key));
			let remaining = Number(await pttl(key));
			if (count === 1 || remaining < 0) {
				await pexpire(key, ttlMs);
				remaining = ttlMs;
			}
			return { count, expiresAt: Date.now() + remaining };
		},
	};

	if (typeof client.keys === "function") {
		const keysFn = client.keys.bind(client);
		storage.list = async (prefix) => keysFn(`${escapeGlob(prefix)}*`);
	}

	return storage;
}
