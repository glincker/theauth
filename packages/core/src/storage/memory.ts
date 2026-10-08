import type { IncrResult, SecondaryStorage } from "./types.js";

interface Entry {
	value: string;
	/** ms timestamp, or null for no expiry */
	expiresAt: number | null;
}

const SWEEP_EVERY = 256;

/**
 * In-process storage. The default. State is lost on restart and not shared
 * between instances, so use it for dev, tests and single-process servers.
 */
export function memoryStorage(): SecondaryStorage {
	const entries = new Map<string, Entry>();
	let ops = 0;

	function live(key: string, now: number): Entry | undefined {
		const entry = entries.get(key);
		if (!entry) return undefined;
		if (entry.expiresAt !== null && entry.expiresAt <= now) {
			entries.delete(key);
			return undefined;
		}
		return entry;
	}

	function sweep(now: number): void {
		ops += 1;
		if (ops % SWEEP_EVERY !== 0) return;
		for (const [key, entry] of entries) {
			if (entry.expiresAt !== null && entry.expiresAt <= now) entries.delete(key);
		}
	}

	return {
		atomicIncr: true,
		async get(key) {
			const now = Date.now();
			sweep(now);
			return live(key, now)?.value ?? null;
		},
		async set(key, value, ttlSeconds) {
			const now = Date.now();
			sweep(now);
			entries.set(key, {
				value,
				expiresAt: ttlSeconds === undefined ? null : now + ttlSeconds * 1000,
			});
		},
		async delete(key) {
			entries.delete(key);
		},
		async incr(key, ttlSeconds): Promise<IncrResult> {
			const now = Date.now();
			sweep(now);
			const existing = live(key, now);
			const parsed = existing ? Number.parseInt(existing.value, 10) : Number.NaN;
			if (existing && Number.isFinite(parsed) && existing.expiresAt !== null) {
				existing.value = String(parsed + 1);
				return { count: parsed + 1, expiresAt: existing.expiresAt };
			}
			const expiresAt = now + ttlSeconds * 1000;
			entries.set(key, { value: "1", expiresAt });
			return { count: 1, expiresAt };
		},
		async list(prefix) {
			const now = Date.now();
			const out: string[] = [];
			for (const key of [...entries.keys()]) {
				if (key.startsWith(prefix) && live(key, now)) out.push(key);
			}
			return out;
		},
	};
}
