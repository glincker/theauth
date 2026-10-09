/**
 * SecondaryStorage: the small key/value contract TheAuth uses for short-lived,
 * high-churn state (rate limit counters, device codes, nonces, caches).
 *
 * Keep the surface tiny on purpose so any backend fits: a Map, a SQL table,
 * Cloudflare KV, Redis, or something you write yourself.
 */

/** Result of an atomic increment. */
export interface IncrResult {
	/** Counter value after the increment. */
	count: number;
	/** Unix time in ms when the counter expires (the window resets). */
	expiresAt: number;
}

export interface SecondaryStorage {
	/** Read a string value. Returns null when missing or expired. */
	get(key: string): Promise<string | null>;
	/** Write a string value. `ttlSeconds` omitted means no expiry. */
	set(key: string, value: string, ttlSeconds?: number): Promise<void>;
	/** Delete a key. Deleting a missing key is not an error. */
	delete(key: string): Promise<void>;
	/**
	 * Increment a counter by one and return the new value.
	 *
	 * When the key is missing or expired it is created with value 1 and a TTL of
	 * `ttlSeconds`. An existing live counter keeps its original expiry (fixed
	 * window). Backends that cannot do this atomically must set
	 * `atomicIncr = false` so callers and docs can tell.
	 */
	incr(key: string, ttlSeconds: number): Promise<IncrResult>;
	/** Optional: list live keys that start with `prefix`. */
	list?(prefix: string): Promise<string[]>;
	/**
	 * True when `incr` is atomic across concurrent callers and instances.
	 * Omitted means true. Eventually consistent stores (Cloudflare KV) set false.
	 */
	readonly atomicIncr?: boolean;
}

/** Features that read from secondary storage. */
export const SECONDARY_STORAGE_FEATURES = [
	"rateLimit",
	"deviceCodes",
	"oneTimeTokens",
	"nonces",
	"sessionsCache",
	"tokenVault",
] as const;

export type SecondaryStorageFeature = (typeof SECONDARY_STORAGE_FEATURES)[number];

/** A storage value in config: an instance, or a named built-in. */
export type SecondaryStorageOption = SecondaryStorage | "memory" | "database";

/**
 * `secondaryStorage` config on `createTheAuth`.
 *
 * Pass a single storage (or "memory" / "database") to use it everywhere, or an
 * object with `default` plus per-feature overrides.
 */
export type SecondaryStorageConfig =
	| SecondaryStorageOption
	| ({ default?: SecondaryStorageOption } & Partial<
			Record<SecondaryStorageFeature, SecondaryStorageOption>
	  >);

/** Resolver handed to plugins. Keys are namespaced per feature automatically. */
export interface SecondaryStorageResolver {
	/** Storage for a feature, with `theauth:<feature>:` prefixed onto every key. */
	for(feature: SecondaryStorageFeature): SecondaryStorage;
}
