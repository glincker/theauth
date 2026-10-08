import type { KVNamespace } from "../auth/stores/kv.js";
import type { IncrResult, SecondaryStorage } from "./types.js";

/** KV rejects expirationTtl below 60 seconds. */
const KV_MIN_TTL_SECONDS = 60;

/** KV binding with the optional list() method Workers expose. */
export interface KVNamespaceWithList extends KVNamespace {
	list?(options: { prefix?: string; cursor?: string }): Promise<{
		keys: Array<{ name: string }>;
		list_complete: boolean;
		cursor?: string;
	}>;
}

interface Envelope {
	v: string;
	/** ms timestamp or null */
	e: number | null;
}

function parseEnvelope(raw: string | null): Envelope | null {
	if (raw === null) return null;
	try {
		const parsed: unknown = JSON.parse(raw);
		if (
			parsed !== null &&
			typeof parsed === "object" &&
			typeof (parsed as Envelope).v === "string" &&
			((parsed as Envelope).e === null || typeof (parsed as Envelope).e === "number")
		) {
			return parsed as Envelope;
		}
	} catch {
		// fall through: corrupt or foreign value counts as missing
	}
	return null;
}

/**
 * Cloudflare Workers KV storage.
 *
 * KV is eventually consistent and has no atomic increment, so `incr` is a
 * read-modify-write. Two requests landing in different locations at the same
 * moment can both read the same count, and writes take up to ~60 seconds to
 * propagate. That makes counters approximate: fine for soft abuse limits, not
 * for strict ones. For strict counters use `databaseStorage` (D1), a Durable
 * Object, or Redis. Plain get/set values (device codes, caches) are fine on KV
 * as long as you tolerate the propagation delay.
 *
 * Expiry is enforced by an envelope stored with the value, so TTLs shorter than
 * KV's 60 second minimum still behave correctly on read.
 */
export function cloudflareKvStorage(kv: KVNamespaceWithList): SecondaryStorage {
	async function read(key: string): Promise<Envelope | null> {
		const env = parseEnvelope(await kv.get(key));
		if (!env) return null;
		if (env.e !== null && env.e <= Date.now()) return null;
		return env;
	}

	async function write(key: string, env: Envelope): Promise<void> {
		const options =
			env.e === null
				? undefined
				: {
						expirationTtl: Math.max(Math.ceil((env.e - Date.now()) / 1000), KV_MIN_TTL_SECONDS),
					};
		await kv.put(key, JSON.stringify(env), options);
	}

	const storage: SecondaryStorage = {
		atomicIncr: false,
		async get(key) {
			return (await read(key))?.v ?? null;
		},
		async set(key, value, ttlSeconds) {
			await write(key, {
				v: value,
				e: ttlSeconds === undefined ? null : Date.now() + ttlSeconds * 1000,
			});
		},
		async delete(key) {
			await kv.delete(key);
		},
		async incr(key, ttlSeconds): Promise<IncrResult> {
			const existing = await read(key);
			const parsed = existing ? Number.parseInt(existing.v, 10) : Number.NaN;
			if (existing && Number.isFinite(parsed) && existing.e !== null) {
				const count = parsed + 1;
				await write(key, { v: String(count), e: existing.e });
				return { count, expiresAt: existing.e };
			}
			const expiresAt = Date.now() + ttlSeconds * 1000;
			await write(key, { v: "1", e: expiresAt });
			return { count: 1, expiresAt };
		},
	};

	if (typeof kv.list === "function") {
		const listFn = kv.list.bind(kv);
		storage.list = async (prefix) => {
			const out: string[] = [];
			let cursor: string | undefined;
			for (;;) {
				const page = await listFn({ prefix, cursor });
				for (const k of page.keys) out.push(k.name);
				if (page.list_complete || !page.cursor) break;
				cursor = page.cursor;
			}
			return out;
		};
	}

	return storage;
}
