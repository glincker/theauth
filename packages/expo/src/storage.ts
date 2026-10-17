import type { TheAuthStorage } from "./types.js";

/** In-memory fallback when no storage adapter is given. Tokens are lost on JS runtime reload. */
export function createMemoryStorage(): TheAuthStorage {
	const store = new Map<string, string>();
	return {
		async getItem(key: string): Promise<string | null> {
			return store.get(key) ?? null;
		},
		async setItem(key: string, value: string): Promise<void> {
			store.set(key, value);
		},
		async removeItem(key: string): Promise<void> {
			store.delete(key);
		},
	};
}

export interface SecureStoreLike {
	getItemAsync(key: string): Promise<string | null>;
	setItemAsync(key: string, value: string): Promise<void>;
	deleteItemAsync(key: string): Promise<void>;
}

/** Backed by `expo-secure-store` (Keychain on iOS, Keystore on Android). */
export function createSecureStoreStorage(secureStore: SecureStoreLike): TheAuthStorage {
	return {
		getItem: (key) => secureStore.getItemAsync(key),
		setItem: (key, value) => secureStore.setItemAsync(key, value),
		removeItem: (key) => secureStore.deleteItemAsync(key),
	};
}
