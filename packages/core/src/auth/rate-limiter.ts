/**
 * In-memory sliding window rate limiter for auth endpoints.
 * Expired timestamps are pruned on every check so memory stays bounded.
 */

export interface RateLimitConfig {
	/** Max requests allowed within the window */
	max: number;
	/** Window duration in seconds */
	window: number;
}

export interface RateLimitResult {
	allowed: boolean;
	/** Requests remaining in the current window */
	remaining: number;
	/** When the oldest in-window request expires and a slot re-opens */
	resetAt: Date;
}

export interface RateLimiter {
	/** Check whether the key is within its limit. Consumes one slot when allowed. */
	check(key: string): RateLimitResult;
	/** Clear all recorded hits for a key (useful in tests or on successful auth). */
	reset(key: string): void;
}

export function createRateLimiter(config: RateLimitConfig): RateLimiter {
	const { max, window: windowSeconds } = config;
	const windowMs = windowSeconds * 1000;

	// Map<key, sorted list of hit timestamps (ms since epoch)>
	const store = new Map<string, number[]>();

	function prune(timestamps: number[], now: number): number[] {
		const cutoff = now - windowMs;
		// Timestamps are appended in order, so we can slice from the front.
		let i = 0;
		while (i < timestamps.length && (timestamps[i] ?? Infinity) <= cutoff) {
			i++;
		}
		return i === 0 ? timestamps : timestamps.slice(i);
	}

	return {
		check(key: string): RateLimitResult {
			const now = Date.now();
			const raw = store.get(key) ?? [];
			const hits = prune(raw, now);

			if (hits.length >= max) {
				// The window resets when the oldest hit exits the window.
				// hits is non-empty here (length >= max >= 1), so the index is safe.
				const oldest = hits[0] ?? now;
				const resetAt = new Date(oldest + windowMs);
				store.set(key, hits);
				return { allowed: false, remaining: 0, resetAt };
			}

			hits.push(now);
			store.set(key, hits);

			const remaining = max - hits.length;
			// hits has at least one entry (the one we just pushed).
			const oldest = hits[0] ?? now;
			const resetAt = new Date(oldest + windowMs);
			return { allowed: true, remaining, resetAt };
		},

		reset(key: string): void {
			store.delete(key);
		},
	};
}
