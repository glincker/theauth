// Provider + context

// Hooks
export {
	useAgents,
	usePasskeys,
	useSession,
	useSignIn,
	useSignOut,
	useSignUp,
	useSocialSignIn,
	useUser,
} from "./hooks.js";
export { runPasskeyRegistration, runPasskeySignIn } from "./passkey.js";
export type {
	AuthExpoProviderProps,
	TheAuthExpoProviderProps,
} from "./provider.js";
export {
	AuthExpoContext,
	AuthExpoProvider,
	TheAuthExpoContext,
	TheAuthExpoProvider,
	useAuthContext,
	useTheAuthContext,
} from "./provider.js";
export { runSocialSignIn } from "./social.js";
export type { SecureStoreLike } from "./storage.js";
export { createMemoryStorage, createSecureStoreStorage } from "./storage.js";

// Types
export type {
	ActionResult,
	AppStateLike,
	AuthAgent,
	AuthContextValue,
	AuthExpoConfig,
	AuthPermission,
	AuthSession,
	AuthStorage,
	AuthUser,
	CreateAgentInput,
	PasskeyAuthenticator,
	SocialSignInConfig,
	TheAuthAgent,
	TheAuthContextValue,
	TheAuthExpoConfig,
	TheAuthPermission,
	TheAuthSession,
	TheAuthStorage,
	TheAuthUser,
} from "./types.js";
