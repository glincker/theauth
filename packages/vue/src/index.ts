export {
	useAgents,
	useEmailPassword,
	useSession,
	useSignIn,
	useSignOut,
	useSignUp,
	useUser,
} from "./composables.js";
export type { AuthPluginOptions, TheAuthPluginOptions } from "./plugin.js";
export {
	AUTH_KEY,
	createAuthPlugin,
	createTheAuthPlugin,
	THEAUTH_KEY,
	useRequiredContext,
} from "./plugin.js";

export type {
	ActionResult,
	AuthAgent,
	AuthContextValue,
	AuthPermission,
	AuthSession,
	AuthUser,
	CreateAgentInput,
	SignUpData,
	TheAuthAgent,
	TheAuthContextValue,
	TheAuthPermission,
	TheAuthSession,
	TheAuthUser,
} from "./types.js";
