import type { AuthStorage } from "./types.js";

/**
 * Minimal in-memory storage fallback used when no storage adapter is provided.
 * Tokens are lost when the JS runtime reloads. Pass a real adapter
 * (AsyncStorage, SecureStore) via KavachExpoConfig.storage.
 */
export function createMemoryStorage(): AuthStorage {
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
