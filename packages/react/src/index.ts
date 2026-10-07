// Provider + context

export type { AuthProviderProps, TheAuthProviderProps } from "./context.js";
export {
	AuthContext,
	AuthProvider,
	TheAuthContext,
	TheAuthProvider,
	useAuthContext,
	useTheAuthContext,
} from "./context.js";

// Hooks
export {
	useAgents,
	useRotateSession,
	useSession,
	useSignIn,
	useSignOut,
	useSignUp,
	useUser,
} from "./hooks.js";

// Types
export type {
	ActionResult,
	AuthAgent,
	AuthContextValue,
	AuthPermission,
	AuthSession,
	AuthUser,
	CreateAgentInput,
	ExternalAuthConfig,
	RotateErrorCode,
	RotateResult,
	RotateRetryConfig,
	RotationStatus,
	TheAuthAgent,
	TheAuthContextValue,
	TheAuthPermission,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";
