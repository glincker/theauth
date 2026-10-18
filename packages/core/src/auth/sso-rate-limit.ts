/** In-memory fixed-window rate limiter for SSO login attempts. */

interface RateLimitEntry {
	timestamps: number[];
}

export class RateLimiter {
	private readonly entries = new Map<string, RateLimitEntry>();
	private readonly maxAttempts: number;
	private readonly windowMs: number;

	constructor(maxAttempts: number, windowSeconds: number) {
		this.maxAttempts = maxAttempts;
		this.windowMs = windowSeconds * 1000;
	}

	check(key: string): boolean {
		const now = Date.now();
		const entry = this.entries.get(key);

		if (!entry) {
			this.entries.set(key, { timestamps: [now] });
			return true;
		}

		entry.timestamps = entry.timestamps.filter((t) => now - t < this.windowMs);
		if (entry.timestamps.length >= this.maxAttempts) {
			return false;
		}

		entry.timestamps.push(now);
		return true;
	}

	prune(): void {
		const now = Date.now();
		for (const [key, entry] of this.entries) {
			entry.timestamps = entry.timestamps.filter((t) => now - t < this.windowMs);
			if (entry.timestamps.length === 0) {
				this.entries.delete(key);
			}
		}
	}
}
