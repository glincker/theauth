/**
 * In-memory rate limit store.
 *
 * Uses a Map keyed by a caller-supplied string. Each entry tracks the current
 * hit count and the unix timestamp (ms) at which the window resets. Expired
 * windows are reset on the next increment so memory stays bounded without
 * needing a background sweep.
 */

import type { RateLimitStore } from "./types.js";

interface Entry {
	count: number;
	resetAt: number;
}

/** Smallest map size that triggers a sweep of expired windows. */
const MIN_SWEEP_SIZE = 1024;

export class MemoryStore implements RateLimitStore {
	private readonly entries = new Map<string, Entry>();
	/** Map size at which the next sweep runs. Doubles after each sweep, so sweeps stay amortized O(1). */
	private sweepAt = MIN_SWEEP_SIZE;

	/** Drop windows that have already expired. An expired key behaves like a missing one, so this changes no decision. */
	private sweep(now: number): void {
		for (const [key, entry] of this.entries) {
			if (entry.resetAt <= now) this.entries.delete(key);
		}
		this.sweepAt = Math.max(this.entries.size * 2, MIN_SWEEP_SIZE);
	}

	async increment(key: string, windowMs: number): Promise<{ count: number; resetAt: number }> {
		const now = Date.now();
		if (this.entries.size >= this.sweepAt) this.sweep(now);
		const existing = this.entries.get(key);

		if (!existing || existing.resetAt <= now) {
			// New window
			const resetAt = now + windowMs;
			this.entries.set(key, { count: 1, resetAt });
			return { count: 1, resetAt };
		}

		existing.count += 1;
		return { count: existing.count, resetAt: existing.resetAt };
	}

	async reset(key: string): Promise<void> {
		this.entries.delete(key);
	}
}
