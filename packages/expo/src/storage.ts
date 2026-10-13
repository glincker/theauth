import type { TheAuthStorage } from "./types.js";

/**
 * Minimal in-memory storage fallback used when no storage adapter is provided.
 * Tokens are lost when the JS runtime reloads. Pass a real adapter
 * (AsyncStorage, SecureStore) via TheAuthExpoConfig.storage.
 */
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

/** The slice of `expo-secure-store` used by `createSecureStoreStorage`. */
export interface SecureStoreLike {
	getItemAsync(key: string): Promise<string | null>;
	setItemAsync(key: string, value: string): Promise<void>;
	deleteItemAsync(key: string): Promise<void>;
}

/**
 * Storage backed by `expo-secure-store` (Keychain on iOS, Keystore on
 * Android). Pass the module: `createSecureStoreStorage(SecureStore)`.
 */
export function createSecureStoreStorage(secureStore: SecureStoreLike): TheAuthStorage {
	return {
		getItem: (key) => secureStore.getItemAsync(key),
		setItem: (key, value) => secureStore.setItemAsync(key, value),
		removeItem: (key) => secureStore.deleteItemAsync(key),
	};
}
