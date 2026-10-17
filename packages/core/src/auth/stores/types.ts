/** Shared store interface for the rateLimit() plugin. Kept in a separate file to avoid circular imports between rate-limit.ts and the individual store implementations. */

/** Store backend interface for the rateLimit() plugin. */
export interface RateLimitStore {
	/** Increment the hit count for `key` within a `windowMs`-millisecond window. Returns the updated count and the unix timestamp (ms) when the window resets. */
	increment(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
	/** Clear all recorded hits for a key. */
	reset(key: string): Promise<void>;
}
