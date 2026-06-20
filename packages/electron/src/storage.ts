import * as fs from "node:fs";
import * as path from "node:path";
import type { ElectronSafeStorage } from "./electron-api.js";
import { getElectronApi } from "./electron-api.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ElectronStorageConfig {
	/** File name for the session data. Defaults to "kavach-session.json". */
	fileName?: string;
	/** Optional additional encryption key applied on top of safeStorage. */
	encryptionKey?: string;
}

export interface SecureStorage {
	get(key: string): Promise<string | null>;
	set(key: string, value: string): Promise<void>;
	remove(key: string): Promise<void>;
	clear(): Promise<void>;
}

// ─── XOR cipher for optional encryptionKey ────────────────────────────────────

function xorWithKey(data: Uint8Array, key: string): Uint8Array {
	if (key.length === 0) return data;
	const encoder = new TextEncoder();
	const keyBytes = encoder.encode(key);
	const result = new Uint8Array(data.length);
	for (let i = 0; i < data.length; i++) {
		result[i] = (data[i] ?? 0) ^ (keyBytes[i % keyBytes.length] ?? 0);
	}
	return result;
}

// ─── Base64 helpers (no Buffer) ───────────────────────────────────────────────

function uint8ArrayToBase64(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i] ?? 0);
	}
	return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

// ─── Storage file helpers ─────────────────────────────────────────────────────

type StorageMap = Record<string, string>;

function readStorageFile(filePath: string): StorageMap {
	try {
		const raw = fs.readFileSync(filePath, "utf8");
		const parsed: unknown = JSON.parse(raw);
		if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as StorageMap;
		}
		return {};
	} catch {
		return {};
	}
}

function writeStorageFile(filePath: string, data: StorageMap): void {
	const dir = path.dirname(filePath);
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(filePath, JSON.stringify(data), "utf8");
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Creates a SecureStorage adapter backed by Electron's safeStorage API.
 *
 * Values are encrypted with safeStorage before being written to a JSON file
 * in the app's userData directory. If safeStorage is unavailable (e.g. during
 * testing or on headless Linux without a keychain), values are stored as
 * plaintext and a warning is emitted once.
 */
export function createElectronStorage(config?: ElectronStorageConfig): SecureStorage {
	const fileName = config?.fileName ?? "kavach-session.json";
	const encryptionKey = config?.encryptionKey ?? "";

	let warned = false;
	let filePath: string | null = null;

	function getFilePath(): string {
		if (filePath) return filePath;
		const electron = getElectronApi();
		const resolved = path.join(electron.app.getPath("userData"), fileName);
		filePath = resolved;
		return resolved;
	}

	function getSafeStorage(): ElectronSafeStorage | null {
		const electron = getElectronApi();
		if (!electron.safeStorage.isEncryptionAvailable()) {
			if (!warned) {
				warned = true;
				// biome-ignore lint/suspicious/noConsole: intentional user-facing warning
				console.warn(
					"TheAuth: safeStorage encryption unavailable — storing session data in plaintext",
				);
			}
			return null;
		}
		return electron.safeStorage;
	}

	function encryptValue(value: string): string {
		const safeStorage = getSafeStorage();
		if (!safeStorage) return value;
		const encrypted = safeStorage.encryptString(value);
		const keyed = encryptionKey ? xorWithKey(encrypted, encryptionKey) : encrypted;
		return uint8ArrayToBase64(keyed);
	}

	function decryptValue(stored: string): string {
		const safeStorage = getSafeStorage();
		if (!safeStorage) return stored;
		try {
			let bytes = base64ToUint8Array(stored);
			if (encryptionKey) {
				bytes = xorWithKey(bytes, encryptionKey);
			}
			return safeStorage.decryptString(bytes);
		} catch {
			return stored;
		}
	}

	return {
		async get(key: string): Promise<string | null> {
			const map = readStorageFile(getFilePath());
			const stored = map[key];
			if (stored === undefined) return null;
			return decryptValue(stored);
		},

		async set(key: string, value: string): Promise<void> {
			const fp = getFilePath();
			const map = readStorageFile(fp);
			map[key] = encryptValue(value);
			writeStorageFile(fp, map);
		},

		async remove(key: string): Promise<void> {
			const fp = getFilePath();
			const map = readStorageFile(fp);
			// Functional deletion without `delete` operator
			const next: StorageMap = {};
			for (const [k, v] of Object.entries(map)) {
				if (k !== key) next[k] = v;
			}
			writeStorageFile(fp, next);
		},

		async clear(): Promise<void> {
			const fp = getFilePath();
			writeStorageFile(fp, {});
		},
	};
}

/**
 * Creates a SecureStorage adapter that operates entirely in memory.
 * Useful for testing or when you explicitly do not want disk persistence.
 */
export function createMemoryStorage(): SecureStorage {
	const store = new Map<string, string>();
	return {
		async get(key: string): Promise<string | null> {
			return store.get(key) ?? null;
		},
		async set(key: string, value: string): Promise<void> {
			store.set(key, value);
		},
		async remove(key: string): Promise<void> {
			store.delete(key);
		},
		async clear(): Promise<void> {
			store.clear();
		},
	};
}
