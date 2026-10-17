import { ExtensionAuthError } from "./errors.js";
import { isSealedValue, openSealed, sealString } from "./seal.js";
import type { ExtensionStorageLike, KeyStore, StorageAreaLike } from "./types.js";

export interface StoredAccess {
	accessToken: string;
	tokenType: "Bearer" | "DPoP";
	scope: string;
	expiresAt: number;
	idToken?: string;
}

export interface TokenStore {
	readAccess(): Promise<StoredAccess | null>;
	writeAccess(value: StoredAccess): Promise<void>;
	readRefreshToken(): Promise<string | null>;
	writeRefreshToken(token: string): Promise<void>;
	clear(): Promise<void>;
	readLock(): Promise<StoredLock | null>;
	writeLock(lock: StoredLock): Promise<void>;
	clearLock(): Promise<void>;
}

export interface StoredLock {
	owner: string;
	expiresAt: number;
}

function isStoredAccess(v: unknown): v is StoredAccess {
	if (typeof v !== "object" || v === null) return false;
	const o = v as Record<string, unknown>;
	return (
		typeof o.accessToken === "string" &&
		(o.tokenType === "Bearer" || o.tokenType === "DPoP") &&
		typeof o.scope === "string" &&
		typeof o.expiresAt === "number"
	);
}

function isStoredLock(v: unknown): v is StoredLock {
	if (typeof v !== "object" || v === null) return false;
	const o = v as Record<string, unknown>;
	return typeof o.owner === "string" && typeof o.expiresAt === "number";
}

export interface TokenStoreOptions {
	prefix: string;
	storage: ExtensionStorageLike;
	/** Fallback for the access token area when `storage.session` is missing. */
	memoryArea: StorageAreaLike;
	keyStore: KeyStore;
	encryptRefreshToken: boolean;
}

export function createTokenStore(options: TokenStoreOptions): TokenStore {
	const { prefix, storage, keyStore } = options;
	const accessArea = storage.session ?? options.memoryArea;
	const accessKey = `${prefix}:access`;
	const refreshKey = `${prefix}:refresh`;
	const lockKey = `${prefix}:refresh-lock`;
	const sealKeyName = `${prefix}:seal`;

	return {
		async readAccess() {
			const v = (await accessArea.get(accessKey))[accessKey];
			return isStoredAccess(v) ? v : null;
		},
		async writeAccess(value) {
			await accessArea.set({ [accessKey]: value });
		},
		async readRefreshToken() {
			const v = (await storage.local.get(refreshKey))[refreshKey];
			if (v === undefined || v === null) return null;
			if (options.encryptRefreshToken) {
				if (!isSealedValue(v)) {
					throw new ExtensionAuthError("refresh_failed", "Stored refresh token is not sealed");
				}
				try {
					return await openSealed(keyStore, sealKeyName, v, refreshKey);
				} catch {
					throw new ExtensionAuthError(
						"refresh_failed",
						"Stored refresh token failed integrity check",
					);
				}
			}
			return typeof v === "string" ? v : null;
		},
		async writeRefreshToken(token) {
			const value = options.encryptRefreshToken
				? await sealString(keyStore, sealKeyName, token, refreshKey)
				: token;
			await storage.local.set({ [refreshKey]: value });
		},
		async clear() {
			await accessArea.remove(accessKey);
			await storage.local.remove([refreshKey, lockKey]);
		},
		async readLock() {
			const v = (await storage.local.get(lockKey))[lockKey];
			return isStoredLock(v) ? v : null;
		},
		async writeLock(lock) {
			await storage.local.set({ [lockKey]: lock });
		},
		async clearLock() {
			await storage.local.remove(lockKey);
		},
	};
}
