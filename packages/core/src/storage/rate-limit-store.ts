import type { RateLimitStore } from "../auth/stores/types.js";
import type { SecondaryStorage } from "./types.js";

/**
 * Adapt a SecondaryStorage to the older RateLimitStore interface so existing
 * `rateLimit({ store })` code keeps working with any backend.
 */
export function rateLimitStoreFromStorage(storage: SecondaryStorage): RateLimitStore {
	return {
		async increment(key, windowMs) {
			const ttlSeconds = Math.max(Math.ceil(windowMs / 1000), 1);
			const { count, expiresAt } = await storage.incr(key, ttlSeconds);
			return { count, resetAt: expiresAt };
		},
		async reset(key) {
			await storage.delete(key);
		},
	};
}

/** Type guard: is this value a SecondaryStorage rather than a RateLimitStore? */
export function isSecondaryStorage(value: unknown): value is SecondaryStorage {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof (value as SecondaryStorage).incr === "function" &&
		typeof (value as SecondaryStorage).get === "function"
	);
}
