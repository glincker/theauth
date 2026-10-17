// Electron API injection (for testing)

export type { ElectronApi } from "./electron-api.js";
export { setElectronApiForTesting } from "./electron-api.js";
export {
	createIpcStorage,
	setupTheAuthIpc,
	THEAUTH_IPC_CHANNELS,
} from "./ipc.js";
export type { OAuthWindowConfig, OAuthWindowResult } from "./oauth-window.js";
export { openOAuthWindow } from "./oauth-window.js";
export type { ElectronTheAuthProviderProps } from "./provider.js";
export {
	ElectronTheAuthContext,
	ElectronTheAuthProvider,
	useElectronTheAuthContext,
} from "./provider.js";
export type { ElectronStorageConfig, SecureStorage } from "./storage.js";
export { createElectronStorage, createMemoryStorage } from "./storage.js";
