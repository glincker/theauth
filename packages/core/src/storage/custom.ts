import type { IncrResult, SecondaryStorage } from "./types.js";

/** What you provide to build a custom store. `incr` and `list` are optional. */
export interface CustomSecondaryStorage {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, ttlSeconds?: number): Promise<void>;
	delete(key: string): Promise<void>;
	/** Provide this if your backend can increment atomically. */
	incr?(key: string, ttlSeconds: number): Promise<IncrResult>;
	list?(prefix: string): Promise<string[]>;
}

/**
 * Build a SecondaryStorage from get/set/delete. When `incr` is omitted it is
 * synthesised from get + set, which is NOT atomic: concurrent callers can lose
 * counts. The result is marked `atomicIncr = false` so you can tell.
 */
export function defineSecondaryStorage(impl: CustomSecondaryStorage): SecondaryStorage {
	const synthesised: SecondaryStorage["incr"] = async (key, ttlSeconds) => {
		const raw = await impl.get(key);
		// The expiry lives next to the count so a fixed window survives the read.
		const parts = raw === null ? [] : raw.split("|");
		const prev = Number.parseInt(parts[0] ?? "", 10);
		const prevExpiry = Number.parseInt(parts[1] ?? "", 10);
		const now = Date.now();
		if (Number.isFinite(prev) && Number.isFinite(prevExpiry) && prevExpiry > now) {
			const count = prev + 1;
			await impl.set(
				key,
				`${count}|${prevExpiry}`,
				Math.max(Math.ceil((prevExpiry - now) / 1000), 1),
			);
			return { count, expiresAt: prevExpiry };
		}
		const expiresAt = now + ttlSeconds * 1000;
		await impl.set(key, `1|${expiresAt}`, ttlSeconds);
		return { count: 1, expiresAt };
	};

	const storage: SecondaryStorage = {
		atomicIncr: impl.incr !== undefined,
		get: (key) => impl.get(key),
		set: (key, value, ttl) => impl.set(key, value, ttl),
		delete: (key) => impl.delete(key),
		incr: impl.incr
			? (key, ttl) => (impl.incr as NonNullable<typeof impl.incr>)(key, ttl)
			: synthesised,
	};
	if (impl.list) {
		const listFn = impl.list.bind(impl);
		storage.list = (prefix) => listFn(prefix);
	}
	return storage;
}

/** Prefix every key. Used to namespace features inside one shared store. */
export function withPrefix(storage: SecondaryStorage, prefix: string): SecondaryStorage {
	const out: SecondaryStorage = {
		atomicIncr: storage.atomicIncr,
		get: (key) => storage.get(prefix + key),
		set: (key, value, ttl) => storage.set(prefix + key, value, ttl),
		delete: (key) => storage.delete(prefix + key),
		incr: (key, ttl) => storage.incr(prefix + key, ttl),
	};
	if (storage.list) {
		const listFn = storage.list.bind(storage);
		out.list = async (p) => (await listFn(prefix + p)).map((k) => k.slice(prefix.length));
	}
	return out;
}
