export { createExtensionAuth } from "./auth.js";
export { metadataUrl } from "./discovery.js";
export type { ExtensionAuthErrorCode } from "./errors.js";
export { ExtensionAuthError, isExtensionAuthError } from "./errors.js";
export type { AuthClient, AuthClientOptions, ExposeAuthOptions } from "./messaging.js";
export { createAuthClient, exposeAuthToBackground } from "./messaging.js";
export { createIndexedDbKeyStore, createMemoryKeyStore } from "./platform.js";
export type {
	AuthorizationServerEndpoints,
	DPoPClientLike,
	DPoPModuleLike,
	DPoPOptions,
	ExtensionAuth,
	ExtensionAuthOptions,
	ExtensionSession,
	ExtensionStorageLike,
	IdentityLike,
	KeyStore,
	MessageSenderLike,
	RuntimeLike,
	SignOutResult,
	StorageAreaLike,
} from "./types.js";
