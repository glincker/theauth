// Plugin

// Composables
export {
	useAgents,
	useSession,
	useSignIn,
	useSignOut,
	useSignUp,
	useUser,
} from "./composables.js";
export type { AuthPluginOptions, KavachPluginOptions } from "./plugin.js";
export {
	AUTH_KEY,
	createAuthPlugin,
	createKavachPlugin,
	KAVACH_KEY,
	useRequiredContext,
} from "./plugin.js";

// Types
export type {
	ActionResult,
	AuthAgent,
	AuthContextValue,
	AuthPermission,
	AuthSession,
	AuthUser,
	CreateAgentInput,
	KavachAgent,
	KavachContextValue,
	KavachPermission,
	KavachSession,
	KavachUser,
} from "./types.js";
