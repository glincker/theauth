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
export type { AuthPluginOptions, KavachPluginOptions, TheAuthPluginOptions } from "./plugin.js";
export {
	AUTH_KEY,
	createAuthPlugin,
	createKavachPlugin,
	createTheAuthPlugin,
	KAVACH_KEY,
	THEAUTH_KEY,
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
	TheAuthAgent,
	TheAuthContextValue,
	TheAuthPermission,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";
