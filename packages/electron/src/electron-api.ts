// ─── Electron API injection ───────────────────────────────────────────────────
//
// Modules that need Electron APIs call getElectronApi() to retrieve the live
// bindings. In a real Electron process this resolves to the real electron
// module; in tests it resolves to the mock set via setElectronApiForTesting().

import type { SecureStorage } from "./storage.js";

// ─── Surface interfaces ───────────────────────────────────────────────────────

export interface ElectronSafeStorage {
	isEncryptionAvailable(): boolean;
	encryptString(value: string): Uint8Array;
	decryptString(encrypted: Uint8Array): string;
}

export interface ElectronApp {
	getPath(name: "userData"): string;
}

export interface BrowserWindowOptions {
	width: number;
	height: number;
	webPreferences: {
		nodeIntegration: boolean;
		contextIsolation: boolean;
		sandbox: boolean;
	};
	title: string;
	resizable: boolean;
	minimizable: boolean;
	maximizable: boolean;
	show: boolean;
}

export interface BrowserWindowInstance {
	loadURL(url: string): Promise<void>;
	on(event: "closed", listener: () => void): void;
	webContents: {
		on(
			event: "will-redirect" | "will-navigate",
			listener: (event: unknown, url: string) => void,
		): void;
		session: {
			cookies: {
				get(filter: { url: string }): Promise<Array<{ name: string; value: string }>>;
			};
		};
	};
	destroy(): void;
	show(): void;
}

export interface BrowserWindowConstructor {
	new (options: BrowserWindowOptions): BrowserWindowInstance;
}

export type IpcMainListener = (
	event: { reply(channel: string, ...args: unknown[]): void },
	...args: unknown[]
) => Promise<unknown>;

export interface ElectronIpcMain {
	handle(channel: string, listener: IpcMainListener): void;
	removeHandler(channel: string): void;
}

export interface ElectronIpcRenderer {
	invoke(channel: string, ...args: unknown[]): Promise<unknown>;
}

export interface ElectronApi {
	safeStorage: ElectronSafeStorage;
	app: ElectronApp;
	BrowserWindow: BrowserWindowConstructor;
	ipcMain: ElectronIpcMain;
	ipcRenderer: ElectronIpcRenderer;
}

// ─── Singleton ────────────────────────────────────────────────────────────────

let _override: ElectronApi | null = null;

function loadElectron(): ElectronApi | null {
	if (_override) return _override;
	try {
		// eslint-disable-next-line @typescript-eslint/no-require-imports
		return require("electron") as ElectronApi;
	} catch {
		return null;
	}
}

export function getElectronApi(): ElectronApi {
	const api = loadElectron();
	if (!api) {
		throw new Error(
			"[TheAuth] Electron API not available. Ensure this code runs in an Electron process.",
		);
	}
	return api;
}

/**
 * For testing only — injects a mock Electron API so modules don't need a real
 * Electron runtime. Call setElectronApiForTesting(null) to reset.
 */
export function setElectronApiForTesting(mock: ElectronApi | null): void {
	_override = mock;
}

// Re-export SecureStorage so ipc.ts can reference it without a circular dep
export type { SecureStorage };
