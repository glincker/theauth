import { getElectronApi } from "./electron-api.js";
import type { SecureStorage } from "./storage.js";

// ─── IPC channel names ────────────────────────────────────────────────────────

const CHANNEL_GET = "kavach:storage:get";
const CHANNEL_SET = "kavach:storage:set";
const CHANNEL_REMOVE = "kavach:storage:remove";
const CHANNEL_CLEAR = "kavach:storage:clear";

// ─── Request/response types ───────────────────────────────────────────────────

interface StorageGetRequest {
	key: string;
}

interface StorageSetRequest {
	key: string;
	value: string;
}

interface StorageRemoveRequest {
	key: string;
}

interface StorageGetResponse {
	value: string | null;
}

// ─── Main process side ────────────────────────────────────────────────────────

/**
 * Registers IPC handlers in the main process so the renderer can securely
 * access storage without needing direct Node.js access.
 *
 * Call this once from your main process entry point after creating your
 * SecureStorage instance via createElectronStorage().
 */
export function setupTheAuthIpc(storage: SecureStorage): void {
	const { ipcMain } = getElectronApi();

	// Remove any previously registered handlers to allow re-initialization.
	ipcMain.removeHandler(CHANNEL_GET);
	ipcMain.removeHandler(CHANNEL_SET);
	ipcMain.removeHandler(CHANNEL_REMOVE);
	ipcMain.removeHandler(CHANNEL_CLEAR);

	ipcMain.handle(CHANNEL_GET, async (_event, req: unknown): Promise<StorageGetResponse> => {
		const { key } = req as StorageGetRequest;
		const value = await storage.get(key);
		return { value };
	});

	ipcMain.handle(CHANNEL_SET, async (_event, req: unknown): Promise<void> => {
		const { key, value } = req as StorageSetRequest;
		await storage.set(key, value);
	});

	ipcMain.handle(CHANNEL_REMOVE, async (_event, req: unknown): Promise<void> => {
		const { key } = req as StorageRemoveRequest;
		await storage.remove(key);
	});

	ipcMain.handle(CHANNEL_CLEAR, async (): Promise<void> => {
		await storage.clear();
	});
}

// ─── Renderer process side ────────────────────────────────────────────────────

/**
 * Creates a SecureStorage implementation that delegates all operations to the
 * main process via IPC. Use this in the renderer process in place of a direct
 * storage adapter so that Node.js APIs and encryption stay in the main process.
 *
 * Requires contextIsolation to be enabled and the IPC channels to be exposed
 * via a preload script, or for contextIsolation to be disabled (not recommended).
 */
export function createIpcStorage(): SecureStorage {
	const { ipcRenderer } = getElectronApi();

	return {
		async get(key: string): Promise<string | null> {
			const req: StorageGetRequest = { key };
			const res = (await ipcRenderer.invoke(CHANNEL_GET, req)) as StorageGetResponse;
			return res.value;
		},

		async set(key: string, value: string): Promise<void> {
			const req: StorageSetRequest = { key, value };
			await ipcRenderer.invoke(CHANNEL_SET, req);
		},

		async remove(key: string): Promise<void> {
			const req: StorageRemoveRequest = { key };
			await ipcRenderer.invoke(CHANNEL_REMOVE, req);
		},

		async clear(): Promise<void> {
			await ipcRenderer.invoke(CHANNEL_CLEAR);
		},
	};
}

// ─── Preload bridge helper ────────────────────────────────────────────────────

/**
 * The IPC channel names exposed for use in a preload script with contextBridge.
 * If you use contextIsolation (recommended), expose these channels explicitly:
 *
 * ```ts
 * import { contextBridge, ipcRenderer } from "electron";
 * import { THEAUTH_IPC_CHANNELS } from "@glinr/theauth-electron";
 *
 * contextBridge.exposeInMainWorld("theauthStorage", {
 *   invoke: (channel: string, ...args: unknown[]) => {
 *     if (!Object.values(THEAUTH_IPC_CHANNELS).includes(channel)) {
 *       throw new Error(`Blocked IPC channel: ${channel}`);
 *     }
 *     return ipcRenderer.invoke(channel, ...args);
 *   },
 * });
 * ```
 */
export const THEAUTH_IPC_CHANNELS = {
	GET: CHANNEL_GET,
	SET: CHANNEL_SET,
	REMOVE: CHANNEL_REMOVE,
	CLEAR: CHANNEL_CLEAR,
} as const;

// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `setupTheAuthIpc` instead. Will be removed in a future major version. */
export const setupKavachIpc = setupTheAuthIpc;

/** @deprecated Use `THEAUTH_IPC_CHANNELS` instead. Will be removed in a future major version. */
export const KAVACH_IPC_CHANNELS = THEAUTH_IPC_CHANNELS;
