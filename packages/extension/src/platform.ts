import type {
	ExtensionStorageLike,
	IdentityLike,
	KeyStore,
	RuntimeLike,
	StorageAreaLike,
} from "./types.js";

interface WebExtensionGlobal {
	storage?: ExtensionStorageLike;
	identity?: IdentityLike;
	runtime?: RuntimeLike;
}

/** `browser` (Firefox, Safari) when present, else `chrome`. */
export function webExtensionGlobal(): WebExtensionGlobal | undefined {
	const g = globalThis as unknown as { browser?: WebExtensionGlobal; chrome?: WebExtensionGlobal };
	return g.browser ?? g.chrome;
}

export function createMemoryArea(): StorageAreaLike {
	const map = new Map<string, unknown>();
	return {
		async get(keys) {
			const out: Record<string, unknown> = {};
			for (const k of Array.isArray(keys) ? keys : [keys]) {
				if (map.has(k)) out[k] = map.get(k);
			}
			return out;
		},
		async set(items) {
			for (const [k, v] of Object.entries(items)) map.set(k, v);
		},
		async remove(keys) {
			for (const k of Array.isArray(keys) ? keys : [keys]) map.delete(k);
		},
	};
}

export function createMemoryKeyStore(): KeyStore {
	const map = new Map<string, CryptoKey | CryptoKeyPair>();
	return {
		async get(name) {
			return map.get(name);
		},
		async put(name, key) {
			map.set(name, key);
		},
		async remove(name) {
			map.delete(name);
		},
	};
}

const DB_NAME = "theauth-extension";
const STORE = "keys";

function openDb(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, 1);
		req.onupgradeneeded = () => req.result.createObjectStore(STORE);
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error ?? new Error("IndexedDB open failed"));
	});
}

async function run<T>(
	mode: IDBTransactionMode,
	fn: (s: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
	const db = await openDb();
	try {
		return await new Promise<T>((resolve, reject) => {
			const req = fn(db.transaction(STORE, mode).objectStore(STORE));
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error ?? new Error("IndexedDB request failed"));
		});
	} finally {
		db.close();
	}
}

/** IndexedDB-backed key store. CryptoKeys are stored by structured clone, never exported. */
export function createIndexedDbKeyStore(): KeyStore {
	return {
		async get(name) {
			const v = await run<unknown>("readonly", (s) => s.get(name));
			return v === undefined ? undefined : (v as CryptoKey | CryptoKeyPair);
		},
		async put(name, key) {
			await run("readwrite", (s) => s.put(key, name));
		},
		async remove(name) {
			await run("readwrite", (s) => s.delete(name));
		},
	};
}
