// ─── Electron API injection (for testing) ────────────────────────────────────

export type { ElectronApi } from "./electron-api.js";
export { setElectronApiForTesting } from "./electron-api.js";

// ─── Storage ──────────────────────────────────────────────────────────────────

export type { ElectronStorageConfig, SecureStorage } from "./storage.js";
export { createElectronStorage, createMemoryStorage } from "./storage.js";

// ─── OAuth window ─────────────────────────────────────────────────────────────

export type { OAuthWindowConfig, OAuthWindowResult } from "./oauth-window.js";
export { openOAuthWindow } from "./oauth-window.js";

// ─── IPC bridge ───────────────────────────────────────────────────────────────

export {
	createIpcStorage,
	KAVACH_IPC_CHANNELS,
	setupKavachIpc,
	setupTheAuthIpc,
	THEAUTH_IPC_CHANNELS,
} from "./ipc.js";

// ─── Provider ─────────────────────────────────────────────────────────────────

export type { ElectronKavachProviderProps, ElectronTheAuthProviderProps } from "./provider.js";
export {
	ElectronKavachContext,
	ElectronKavachProvider,
	ElectronTheAuthContext,
	ElectronTheAuthProvider,
	useElectronKavachContext,
	useElectronTheAuthContext,
} from "./provider.js";
